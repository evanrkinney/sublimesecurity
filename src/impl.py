# File: impl.py
#
# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

"""Business logic for Sublime Security SOAR actions."""

from __future__ import annotations

import base64
import csv as csv_mod
import io
import json
from typing import Any

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger

from . import consts
from .client import SublimeClient
from .helpers import (
    build_review_body,
    clamp_limit,
    coerce_many,
    coerce_output,
    get_file_as_base64,
    get_file_bytes,
    iter_image_bytes,
    parse_comma_list,
    safe_id,
    save_to_vault,
)

logger = getLogger()


def _client(asset: Any) -> SublimeClient:
    return SublimeClient(asset)


def _pget(params: Any, name: str, default: Any = None) -> Any:
    return getattr(params, name, default)


def _maybe_bool(params: Any, name: str) -> Any:
    val = getattr(params, name, None)
    if val is None:
        return None
    return bool(val)


def _summary(soar: SOARClient, summary_cls: type[ActionOutput] | None, data: dict[str, Any]) -> None:
    if summary_cls is None:
        return
    soar.set_summary(coerce_output(summary_cls, data))


# ---------------------------------------------------------------------------
# Connectivity
# ---------------------------------------------------------------------------


def test_connectivity(soar: SOARClient, asset: Any) -> None:
    logger.info("Connecting to Sublime Security...")
    try:
        _client(asset).get(consts.MAILBOXES_ENDPOINT)
    except ActionFailure:
        logger.error(consts.ERR_CONNECTIVITY_TEST)
        raise
    logger.info(consts.SUCC_CONNECTIVITY_TEST)
    soar.set_message(consts.SUCC_CONNECTIVITY_TEST)


# ---------------------------------------------------------------------------
# BinExplode
# ---------------------------------------------------------------------------


def upload_binary(params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]) -> ActionOutput:
    file_bytes = get_file_bytes(
        soar,
        vault_id=_pget(params, "vault_id"),
        base64_data=_pget(params, "base64_data"),
        strict_base64=True,
    )
    if len(file_bytes) > consts.BINEXPLODE_MAX_FILE_SIZE_BYTES:
        raise ActionFailure(
            f"File size ({len(file_bytes)} bytes) exceeds the maximum allowed size of "
            f"{consts.BINEXPLODE_MAX_FILE_SIZE_BYTES} bytes"
        )
    body = {
        "file_contents": base64.b64encode(file_bytes).decode("utf-8"),
        "file_name": params.file_name,
    }
    response = _client(asset).post(consts.BINEXPLODE_SCAN_ENDPOINT, json_data=body)
    return coerce_output(output_cls, response)


def get_binexplode_results(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> list[ActionOutput]:
    endpoint = consts.BINEXPLODE_SCAN_RESULT_ENDPOINT.format(id=safe_id(params.task_id))
    response = _client(asset).get(endpoint)
    results = response.get("results", []) if isinstance(response, dict) else []
    return coerce_many(output_cls, results)


# ---------------------------------------------------------------------------
# Link analysis
# ---------------------------------------------------------------------------


def analyze_link(
    params: Any,
    soar: SOARClient,
    asset: Any,
    output_cls: type[ActionOutput],
    summary_cls: type[ActionOutput] | None = None,
) -> ActionOutput:
    body: dict[str, Any] = {"url": params.url}
    if _pget(params, "no_logo_detect"):
        body["no_logo_detect"] = True
    response = _client(asset).post(consts.LINK_ANALYSIS_ENDPOINT, json_data=body)
    summary: dict[str, Any] = {"analyzed": response.get("analyzed", False)}
    credphish = response.get("credphish") or {}
    if credphish:
        summary["disposition"] = credphish.get("disposition", "unknown")
        summary["confidence"] = credphish.get("confidence", "")
        brand = credphish.get("brand") or {}
        if brand:
            summary["brand_name"] = brand.get("name", "")
    effective_url = response.get("effective_url") or {}
    if effective_url:
        summary["effective_url"] = effective_url.get("url", "")

    screenshot = response.get("screenshot") or {}
    if screenshot.get("raw"):
        screenshot_bytes = base64.b64decode(screenshot["raw"])
        file_name = screenshot.get("file_name", "link_analysis_screenshot.png")
        vault_id = save_to_vault(soar, screenshot_bytes, file_name)
        summary["screenshot_vault_id"] = vault_id

    _summary(soar, summary_cls, summary)
    return coerce_output(output_cls, response)


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------


def list_audit_events(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> list[ActionOutput]:
    query: dict[str, Any] = {}
    if _pget(params, "start_time"):
        query["created_at[gte]"] = params.start_time
    if _pget(params, "end_time"):
        query["created_at[lt]"] = params.end_time
    if _pget(params, "event_type"):
        query["type"] = params.event_type
    if _pget(params, "user_ids"):
        query["user_ids"] = parse_comma_list(params.user_ids)
    query["limit"] = clamp_limit(_pget(params, "limit"))
    query["offset"] = int(_pget(params, "offset") or 0)
    response = _client(asset).get(consts.AUDIT_EVENTS_ENDPOINT, params=query)
    return coerce_many(output_cls, response.get("events", []))


def list_audit_event_types(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> list[ActionOutput]:
    response = _client(asset).get(consts.AUDIT_EVENT_TYPES_ENDPOINT)
    return coerce_many(output_cls, response.get("event_types", []))


def get_audit_event(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    endpoint = consts.AUDIT_EVENT_ENDPOINT.format(id=safe_id(params.event_id))
    return coerce_output(output_cls, _client(asset).get(endpoint))


# ---------------------------------------------------------------------------
# Hunt jobs
# ---------------------------------------------------------------------------


def start_hunt_job(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    body: dict[str, Any] = {
        "source": params.source,
        "range_start_time": params.range_start_time,
        "range_end_time": params.range_end_time,
    }
    if _pget(params, "name"):
        body["name"] = params.name
    if _pget(params, "private"):
        body["private"] = True
    for key in ("triage_flagged", "triage_reported", "triage_email_bomb", "triage_dlp_rule_matched"):
        val = _maybe_bool(params, key)
        if val is not None:
            body[key] = val
    return coerce_output(output_cls, _client(asset).post(consts.HUNT_JOBS_ENDPOINT, json_data=body))


def get_hunt_job(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    endpoint = consts.HUNT_JOB_ENDPOINT.format(id=safe_id(params.hunt_job_id))
    return coerce_output(output_cls, _client(asset).get(endpoint))


def get_hunt_job_results(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> list[ActionOutput]:
    endpoint = consts.HUNT_JOB_RESULTS_ENDPOINT.format(id=safe_id(params.hunt_job_id))
    query = {
        "limit": clamp_limit(_pget(params, "limit")),
        "offset": int(_pget(params, "offset") or 0),
    }
    response = _client(asset).get(endpoint, params=query)
    return coerce_many(output_cls, response.get("message_groups", []))


# ---------------------------------------------------------------------------
# Lists
# ---------------------------------------------------------------------------


def list_lists(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> list[ActionOutput]:
    query: dict[str, Any] = {}
    if _pget(params, "entry_type"):
        query["entry_type"] = params.entry_type
    if _pget(params, "name"):
        query["name"] = params.name
    response = _client(asset).get(consts.LISTS_ENDPOINT, params=query)
    return coerce_many(output_cls, response.get("lists", []))


def create_list(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    body = {"name": params.name, "description": params.description}
    return coerce_output(output_cls, _client(asset).post(consts.LISTS_ENDPOINT, json_data=body))


def delete_list(params: Any, soar: SOARClient, asset: Any) -> ActionOutput:
    endpoint = consts.LIST_ENDPOINT.format(id=safe_id(params.list_id))
    _client(asset).delete(endpoint)
    soar.set_message("List deleted successfully")
    return ActionOutput()


def get_list(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    endpoint = consts.LIST_ENDPOINT.format(id=safe_id(params.list_id))
    return coerce_output(output_cls, _client(asset).get(endpoint))


def patch_list(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    endpoint = consts.LIST_ENDPOINT.format(id=safe_id(params.list_id))
    body = {"description": params.description}
    return coerce_output(output_cls, _client(asset).patch(endpoint, json_data=body))


def get_list_entries(
    params: Any,
    soar: SOARClient,
    asset: Any,
    output_cls: type[ActionOutput],
    summary_cls: type[ActionOutput] | None = None,
) -> list[ActionOutput]:
    endpoint = consts.LIST_ENTRIES_ENDPOINT.format(id=safe_id(params.list_id))
    response = _client(asset).get(endpoint)
    entries = response.get("entries", []) if isinstance(response, dict) else []
    outputs = coerce_many(output_cls, [{"entry": e} for e in entries])
    summary: dict[str, Any] = {"total_entries": len(entries)}
    if _pget(params, "save_to_vault"):
        buf = io.StringIO()
        writer = csv_mod.writer(buf)
        writer.writerow(["entry"])
        for e in entries:
            writer.writerow([e])
        csv_bytes = buf.getvalue().encode("utf-8")
        file_name = _pget(params, "csv_file_name") or f"list_{params.list_id}_entries.csv"
        vault_id = save_to_vault(soar, csv_bytes, file_name)
        summary["vault_id"] = vault_id
    _summary(soar, summary_cls, summary)
    return outputs


def set_list_entries(params: Any, soar: SOARClient, asset: Any) -> ActionOutput:
    endpoint = consts.LIST_ENTRIES_ENDPOINT.format(id=safe_id(params.list_id))
    entries: list[str] = []
    vault_id = _pget(params, "vault_id")
    entries_str = _pget(params, "entries")
    if vault_id:
        file_bytes = get_file_bytes(soar, vault_id=vault_id, strict_base64=True)
        try:
            text = file_bytes.decode("utf-8", errors="replace")
            reader = csv_mod.reader(io.StringIO(text))
            for row in reader:
                for cell in row:
                    cell = cell.strip()
                    if cell and cell.lower() != "entry":
                        entries.append(cell)
        except Exception as e:
            raise ActionFailure(f"Error parsing CSV from vault: {e!s}") from e
    elif entries_str:
        entries = parse_comma_list(entries_str)
    else:
        raise ActionFailure("Either entries or vault_id must be provided")
    _client(asset).put(endpoint, json_data={"entries": entries})
    soar.set_message(f"Set {len(entries)} entries successfully")
    return ActionOutput()


def delete_list_entry(params: Any, soar: SOARClient, asset: Any) -> ActionOutput:
    endpoint = consts.LIST_ENTRY_ENDPOINT.format(id=safe_id(params.list_id))
    _client(asset).delete(endpoint, params={"string": params.entry})
    soar.set_message("Entry deleted successfully")
    return ActionOutput()


def get_list_entry(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> list[ActionOutput]:
    endpoint = consts.LIST_ENTRY_ENDPOINT.format(id=safe_id(params.list_id))
    raw = params.entry
    entries_to_check = parse_comma_list(raw) if "," in raw else [raw.strip()]
    results = []
    client = _client(asset)
    for entry in entries_to_check:
        result, status_code = client.get(
            endpoint, params={"string": entry}, return_status_code=True
        )
        if result is not None and status_code is not None and 200 <= status_code < 300:
            found = True
        elif status_code == 404:
            found = False
        else:
            raise ActionFailure(f"Failed to check entry '{entry}'")
        results.append({"entry": entry, "found": found})
    return coerce_many(output_cls, results)


def add_list_entry(params: Any, soar: SOARClient, asset: Any) -> ActionOutput:
    endpoint = consts.LIST_ENTRY_ENDPOINT.format(id=safe_id(params.list_id))
    _client(asset).post(endpoint, json_data={"string": params.entry})
    soar.set_message("Entry added successfully")
    return ActionOutput()


# ---------------------------------------------------------------------------
# Raw message / mailboxes
# ---------------------------------------------------------------------------


def process_raw_message(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    b64_data = get_file_as_base64(
        soar, vault_id=_pget(params, "vault_id"), base64_data=_pget(params, "base64_data")
    )
    body: dict[str, Any] = {
        "raw_message": b64_data,
        "mailbox_email_address": params.mailbox_email_address,
        "message_source_id": params.message_source_id,
    }
    if _pget(params, "create_mailbox"):
        body["create_mailbox"] = True
    if _pget(params, "analyze_async"):
        body["analyze_async"] = True
    for key in (
        "canonical_id",
        "external_message_id",
        "external_thread_id",
        "external_created_at",
        "folder",
        "route_type",
    ):
        if _pget(params, key):
            body[key] = getattr(params, key)
    if _pget(params, "labels"):
        body["labels"] = parse_comma_list(params.labels)
    if _pget(params, "message_type"):
        mt = params.message_type
        body["message_type"] = {mt: True} if mt in ("inbound", "internal", "outbound") else {}
    response = _client(asset).post(consts.RAW_MESSAGE_ANALYZE_ENDPOINT, json_data=body)
    return coerce_output(output_cls, response)


def list_mailboxes(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> list[ActionOutput]:
    query: dict[str, Any] = {
        "limit": clamp_limit(_pget(params, "limit")),
        "offset": int(_pget(params, "offset") or 0),
    }
    if _pget(params, "active") is not None:
        query["active"] = params.active
    if _maybe_bool(params, "marked_active") is not None:
        query["marked_active"] = bool(params.marked_active)
    if _pget(params, "search"):
        query["search"] = params.search
    for key in ("email_addresses", "mailbox_types", "sub_error_types", "message_source_id"):
        if _pget(params, key):
            query[key] = getattr(params, key)
    response = _client(asset).get(consts.MAILBOXES_ENDPOINT, params=query)
    return coerce_many(output_cls, response.get("mailboxes", []))


# ---------------------------------------------------------------------------
# Message groups
# ---------------------------------------------------------------------------


def list_message_groups(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> list[ActionOutput]:
    query: dict[str, Any] = {
        "limit": clamp_limit(_pget(params, "limit")),
        "offset": int(_pget(params, "offset") or 0),
    }
    if _pget(params, "start_time"):
        query["created_at__gte"] = params.start_time
    if _pget(params, "end_time"):
        query["created_at__lt"] = params.end_time
    if _pget(params, "first_message_reported_at_gte"):
        query["first_message_reported_at__gte"] = params.first_message_reported_at_gte
    for key in ("flagged", "reviewed", "user_reported"):
        if _pget(params, key) is not None:
            query[key] = getattr(params, key)
    if _pget(params, "attack_surface_reduction") is not None:
        query["attack_surface_reduction__filter"] = params.attack_surface_reduction
    array_filter_map = {
        "sender_email": "sender_email__is",
        "sender_domain": "sender_domain__is",
        "sender_display_name": "sender_display_name__is",
        "mailbox_email": "mailbox_email__is",
        "recipient_email": "recipient_email__is",
        "subject": "subject__is",
        "canonical_id": "canonical_id__is",
        "attachment_name": "attachment_name__is",
        "attachment_sha256": "attachment_sha256__is",
        "attack_score_verdict": "attack_score_verdict__is",
        "flagged_rule_id": "flagged_rule_id__is",
        "flagged_rule_severity": "flagged_rule_severity__is",
        "historically_flagged_rule_id": "historically_flagged_rule_id__is",
        "historically_flagged_rule_severity": "historically_flagged_rule_severity__is",
        "reported_as_phish_by": "reported_as_phish_by__is",
        "spam_status": "spam__is",
        "vendor_id": "vendor_id__is",
    }
    for pkey, qkey in array_filter_map.items():
        if _pget(params, pkey):
            query[qkey] = parse_comma_list(getattr(params, pkey))
    response = _client(asset).get(consts.MESSAGE_GROUPS_ENDPOINT, params=query)
    return coerce_many(output_cls, response.get("message_groups", []))


def dismiss_message_groups(params: Any, soar: SOARClient, asset: Any) -> ActionOutput:
    _client(asset).post(
        consts.MESSAGE_GROUPS_DISMISS_ENDPOINT, json_data=build_review_body(params)
    )
    soar.set_message("Message groups dismissed successfully")
    return ActionOutput()


def quarantine_message_groups(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    response = _client(asset).post(
        consts.MESSAGE_GROUPS_QUARANTINE_ENDPOINT, json_data=build_review_body(params)
    )
    return coerce_output(output_cls, response)


def graymail_message_groups(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    response = _client(asset).post(
        consts.MESSAGE_GROUPS_GRAYMAIL_ENDPOINT, json_data=build_review_body(params)
    )
    return coerce_output(output_cls, response)


def restore_message_groups(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    response = _client(asset).post(
        consts.MESSAGE_GROUPS_RESTORE_ENDPOINT, json_data=build_review_body(params)
    )
    return coerce_output(output_cls, response)


def review_message_groups(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    body: dict[str, Any] = {
        "message_group_ids": parse_comma_list(params.message_group_ids),
        "classification": params.classification,
    }
    if _pget(params, "action"):
        body["action"] = params.action
    if _pget(params, "review_comment"):
        body["review_comment"] = params.review_comment
    if _pget(params, "share_with_sublime"):
        body["share_with_sublime"] = True
    response = _client(asset).post(consts.MESSAGE_GROUPS_REVIEW_ENDPOINT, json_data=body)
    return coerce_output(output_cls, response)


def search_message_groups(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> list[ActionOutput]:
    query: dict[str, Any] = {
        "limit": clamp_limit(_pget(params, "limit")),
        "offset": int(_pget(params, "offset") or 0),
    }
    for key in (
        "any",
        "sender",
        "to",
        "mailbox",
        "subject",
        "message_id",
        "type",
        "file_name",
        "attachment_md5",
        "attachment_sha1",
        "attachment_sha256",
    ):
        if _pget(params, key):
            query[key] = getattr(params, key)
    if _pget(params, "states"):
        query["states"] = parse_comma_list(params.states)
    if _pget(params, "start_time"):
        query["created_at[gte]"] = params.start_time
    if _pget(params, "end_time"):
        query["created_at[lt]"] = params.end_time
    if _pget(params, "first_reported_as_phish_at_gte"):
        query["first_reported_as_phish_at[gte]"] = params.first_reported_as_phish_at_gte
    if _pget(params, "first_reported_as_phish_at_lt"):
        query["first_reported_as_phish_at[lt]"] = params.first_reported_as_phish_at_lt
    response = _client(asset).get(consts.MESSAGE_GROUPS_SEARCH_ENDPOINT, params=query)
    return coerce_many(output_cls, response.get("message_groups", []))


def trash_message_groups(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    response = _client(asset).post(
        consts.MESSAGE_GROUPS_TRASH_ENDPOINT, json_data=build_review_body(params)
    )
    return coerce_output(output_cls, response)


def get_message_group(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    endpoint = consts.MESSAGE_GROUP_ENDPOINT.format(id=safe_id(params.message_group_id))
    return coerce_output(output_cls, _client(asset).get(endpoint))


def dismiss_message_group(params: Any, soar: SOARClient, asset: Any) -> ActionOutput:
    endpoint = consts.MESSAGE_GROUP_DISMISS_ENDPOINT.format(
        id=safe_id(params.message_group_id)
    )
    _client(asset).post(endpoint, json_data=build_review_body(params, include_ids=False))
    soar.set_message("Message group dismissed successfully")
    return ActionOutput()


def quarantine_message_group(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    endpoint = consts.MESSAGE_GROUP_QUARANTINE_ENDPOINT.format(
        id=safe_id(params.message_group_id)
    )
    response = _client(asset).post(
        endpoint, json_data=build_review_body(params, include_ids=False)
    )
    return coerce_output(output_cls, response)


def restore_message_group(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    endpoint = consts.MESSAGE_GROUP_RESTORE_ENDPOINT.format(
        id=safe_id(params.message_group_id)
    )
    response = _client(asset).post(
        endpoint, json_data=build_review_body(params, include_ids=False)
    )
    return coerce_output(output_cls, response)


def share_with_sublime(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    endpoint = consts.MESSAGE_GROUP_SHARE_ENDPOINT.format(
        id=safe_id(params.message_group_id)
    )
    body: dict[str, Any] = {}
    if _pget(params, "report_label"):
        body["report_label"] = params.report_label
    if _pget(params, "review_comment"):
        body["review_comment"] = params.review_comment
    response = _client(asset).post(endpoint, json_data=body)
    return coerce_output(output_cls, response)


def trash_message_group(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    endpoint = consts.MESSAGE_GROUP_TRASH_ENDPOINT.format(
        id=safe_id(params.message_group_id)
    )
    response = _client(asset).post(
        endpoint, json_data=build_review_body(params, include_ids=False)
    )
    return coerce_output(output_cls, response)


# ---------------------------------------------------------------------------
# Messages
# ---------------------------------------------------------------------------


def analyze_raw_message(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    b64_data = get_file_as_base64(
        soar, vault_id=_pget(params, "vault_id"), base64_data=_pget(params, "base64_data")
    )
    body: dict[str, Any] = {"raw_message": b64_data}
    for key in ("run_active_detection_rules", "run_all_detection_rules", "run_all_insights"):
        if _pget(params, key):
            body[key] = True
    return coerce_output(
        output_cls, _client(asset).post(consts.MESSAGES_ANALYZE_ENDPOINT, json_data=body)
    )


def render_attachment_image(
    params: Any,
    soar: SOARClient,
    asset: Any,
    output_cls: type[ActionOutput],
    summary_cls: type[ActionOutput] | None = None,
) -> ActionOutput:
    b64_data = get_file_as_base64(
        soar, vault_id=_pget(params, "vault_id"), base64_data=_pget(params, "base64_data")
    )
    body: dict[str, Any] = {"raw": b64_data}
    if _pget(params, "file_type"):
        body["file_type"] = params.file_type
    response = _client(asset).post(
        consts.MESSAGES_ATTACHMENT_IMAGE_RAW_ENDPOINT, json_data=body
    )
    summary: dict[str, Any] = {}
    for idx, img_bytes in enumerate(iter_image_bytes(response.get("data"))):
        vault_id = save_to_vault(soar, img_bytes, f"attachment_render_{idx}.png")
        summary["screenshot_vault_id"] = vault_id
    _summary(soar, summary_cls, summary)
    return coerce_output(output_cls, response)


def get_attack_score_raw(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    b64_data = get_file_as_base64(
        soar, vault_id=_pget(params, "vault_id"), base64_data=_pget(params, "base64_data")
    )
    body = {"raw_message": b64_data}
    return coerce_output(
        output_cls,
        _client(asset).post(consts.MESSAGES_ATTACK_SCORE_ENDPOINT, json_data=body),
    )


def create_message(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    b64_data = get_file_as_base64(
        soar, vault_id=_pget(params, "vault_id"), base64_data=_pget(params, "base64_data")
    )
    body: dict[str, Any] = {"raw_message": b64_data}
    for key in (
        "mailbox_email_address",
        "canonical_id",
        "external_message_id",
        "external_thread_id",
        "external_created_at",
        "folder",
        "route_type",
    ):
        if _pget(params, key):
            body[key] = getattr(params, key)
    if _pget(params, "labels"):
        body["labels"] = parse_comma_list(params.labels)
    if _pget(params, "message_type"):
        mt = params.message_type
        body["message_type"] = {mt: True} if mt in ("inbound", "internal", "outbound") else {}
    return coerce_output(
        output_cls, _client(asset).post(consts.MESSAGES_CREATE_ENDPOINT, json_data=body)
    )


def get_action_state(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> list[ActionOutput]:
    endpoint = consts.MESSAGE_GROUP_ACTION_STATE_ENDPOINT.format(
        id=safe_id(params.message_group_id)
    )
    query = {
        "limit": min(int(_pget(params, "limit") or 10), 50),
        "offset": int(_pget(params, "offset") or 0),
    }
    response = _client(asset).get(endpoint, params=query)
    return coerce_many(output_cls, response.get("actions", []))


def get_message(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    endpoint = consts.MESSAGE_ENDPOINT.format(id=safe_id(params.message_id))
    return coerce_output(output_cls, _client(asset).get(endpoint))


def action_message(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    endpoint = consts.MESSAGE_ACTIONS_ENDPOINT.format(id=safe_id(params.message_id))
    body: dict[str, Any] = {}
    if _pget(params, "action"):
        body["action"] = params.action
    if _pget(params, "share_with_sublime"):
        body["share_with_sublime"] = True
    return coerce_output(output_cls, _client(asset).post(endpoint, json_data=body))


def analyze_message_by_id(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    endpoint = consts.MESSAGE_ANALYZE_BY_ID_ENDPOINT.format(id=safe_id(params.message_id))
    body: dict[str, Any] = {}
    for key in ("run_active_detection_rules", "run_all_detection_rules", "run_all_insights"):
        if _pget(params, key):
            body[key] = True
    return coerce_output(output_cls, _client(asset).post(endpoint, json_data=body))


def get_asa_report(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    endpoint = consts.MESSAGE_ASA_REPORT_ENDPOINT.format(id=safe_id(params.message_id))
    return coerce_output(output_cls, _client(asset).get(endpoint))


def get_asa_verdict(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    endpoint = consts.MESSAGE_ASA_VERDICT_ENDPOINT.format(id=safe_id(params.message_id))
    return coerce_output(output_cls, _client(asset).get(endpoint))


def get_attachment_image(
    params: Any,
    soar: SOARClient,
    asset: Any,
    output_cls: type[ActionOutput],
    summary_cls: type[ActionOutput] | None = None,
) -> ActionOutput:
    endpoint = consts.MESSAGE_ATTACHMENT_IMAGE_ENDPOINT.format(
        id=safe_id(params.message_id), hash=safe_id(params.attachment_hash)
    )
    response = _client(asset).get(endpoint)
    summary: dict[str, Any] = {}
    for idx, img_bytes in enumerate(iter_image_bytes(response.get("data"))):
        vault_id = save_to_vault(
            soar, img_bytes, f"attachment_{params.attachment_hash}_{idx}.png"
        )
        summary["screenshot_vault_id"] = vault_id
    _summary(soar, summary_cls, summary)
    return coerce_output(output_cls, response)


def get_attack_score(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    endpoint = consts.MESSAGE_ATTACK_SCORE_ENDPOINT.format(id=safe_id(params.message_id))
    return coerce_output(output_cls, _client(asset).get(endpoint))


def get_message_image(
    params: Any,
    soar: SOARClient,
    asset: Any,
    output_cls: type[ActionOutput],
    summary_cls: type[ActionOutput] | None = None,
) -> ActionOutput:
    endpoint = consts.MESSAGE_IMAGE_ENDPOINT.format(id=safe_id(params.message_id))
    response = _client(asset).get(endpoint)
    mime_type = response.get("mime_type", "image/png")
    ext = mime_type.split("/")[-1] if mime_type else "png"
    summary: dict[str, Any] = {}
    for idx, img_bytes in enumerate(iter_image_bytes(response.get("data"))):
        suffix = "" if idx == 0 else f"_{idx}"
        vault_id = save_to_vault(
            soar, img_bytes, f"message_{params.message_id}{suffix}.{ext}"
        )
        summary["screenshot_vault_id"] = vault_id
    _summary(soar, summary_cls, summary)
    return coerce_output(output_cls, response)


def get_message_eml(
    params: Any,
    soar: SOARClient,
    asset: Any,
    summary_cls: type[ActionOutput] | None = None,
) -> ActionOutput:
    endpoint = consts.MESSAGE_EML_ENDPOINT.format(id=safe_id(params.message_id))
    raw_content, _content_type = _client(asset).get_raw(endpoint)
    vault_id = save_to_vault(soar, raw_content, f"message_{params.message_id}.eml")
    _summary(soar, summary_cls, {"vault_id": vault_id})
    return ActionOutput()


def get_message_image_link(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    endpoint = consts.MESSAGE_IMAGE_LINK_ENDPOINT.format(id=safe_id(params.message_id))
    query: dict[str, Any] = {}
    if _pget(params, "link_duration_seconds"):
        query["link_duration_seconds"] = int(params.link_duration_seconds)
    if _pget(params, "platform_link") is not None:
        query["platform_link"] = bool(params.platform_link)
    return coerce_output(output_cls, _client(asset).get(endpoint, params=query))


def set_access_justification(params: Any, soar: SOARClient, asset: Any) -> ActionOutput:
    endpoint = consts.MESSAGE_JUSTIFICATION_ENDPOINT.format(id=safe_id(params.message_id))
    _client(asset).post(endpoint, json_data={"justification": params.justification})
    soar.set_message("Access justification set successfully")
    return ActionOutput()


def get_message_data_model(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    endpoint = consts.MESSAGE_MDM_ENDPOINT.format(id=safe_id(params.message_id))
    return coerce_output(output_cls, _client(asset).get(endpoint))


def restore_message(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    endpoint = consts.MESSAGE_RESTORE_ENDPOINT.format(id=safe_id(params.message_id))
    return coerce_output(output_cls, _client(asset).post(endpoint))


def trash_message(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    endpoint = consts.MESSAGE_TRASH_ENDPOINT.format(id=safe_id(params.message_id))
    return coerce_output(output_cls, _client(asset).post(endpoint))


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


def _rule_body_from_params(params: Any, *, include_name_source: bool = True) -> dict[str, Any]:
    body: dict[str, Any] = {}
    if include_name_source:
        if _pget(params, "name"):
            body["name"] = params.name
        if _pget(params, "source"):
            body["source"] = params.source
    for key in (
        "type",
        "severity",
        "description",
        "label",
        "maturity",
        "auto_review_classification",
    ):
        if _pget(params, key):
            body[key] = getattr(params, key)
    if _pget(params, "active"):
        body["active"] = True
    if _maybe_bool(params, "auto_review_auto_share") is not None:
        body["auto_review_auto_share"] = bool(params.auto_review_auto_share)
    for key in (
        "triage_abuse_reports",
        "triage_flagged_messages",
        "triage_classification_changes",
        "triage_dlp_rule_matched",
        "run_triage_on_excluded_messages",
    ):
        val = _maybe_bool(params, key)
        if val is not None:
            body[key] = val
    for key in (
        "tags",
        "user_provided_tags",
        "attack_types",
        "detection_methods",
        "tactics_and_techniques",
        "false_positives",
        "references",
        "action_ids",
    ):
        if _pget(params, key):
            body[key] = parse_comma_list(getattr(params, key))
    if _pget(params, "authors"):
        try:
            parsed = json.loads(params.authors)
            if isinstance(parsed, list):
                body["authors"] = parsed
            else:
                raise ActionFailure("authors must be a JSON array of {name, twitter} objects")
        except ActionFailure:
            raise
        except Exception as e:
            raise ActionFailure(
                "authors must be a JSON array of {name, twitter} objects"
            ) from e
    return body


def list_rules(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> list[ActionOutput]:
    query: dict[str, Any] = {
        "limit": clamp_limit(_pget(params, "limit")),
        "offset": int(_pget(params, "offset") or 0),
    }
    if _pget(params, "search"):
        query["search"] = params.search
    if _maybe_bool(params, "in_feed") is not None:
        query["in_feed"] = bool(params.in_feed)
    response = _client(asset).get(consts.RULES_ENDPOINT, params=query)
    return coerce_many(output_cls, response.get("rules", []))


def create_rule(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    body = _rule_body_from_params(params)
    body["name"] = params.name
    body["source"] = params.source
    return coerce_output(output_cls, _client(asset).post(consts.RULES_ENDPOINT, json_data=body))


def list_rule_history(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    query: dict[str, Any] = {
        "classification_created_at[gte]": params.start_time,
        "classification_created_at[lte]": params.end_time,
    }
    if _maybe_bool(params, "active") is not None:
        query["active"] = bool(params.active)
    if _maybe_bool(params, "in_feed") is not None:
        query["in_feed"] = bool(params.in_feed)
    if _pget(params, "type"):
        query["type"] = parse_comma_list(params.type)
    if _pget(params, "count") is not None:
        query["count"] = int(params.count)
    if _pget(params, "offset") is not None:
        query["offset"] = int(params.offset)
    return coerce_output(
        output_cls, _client(asset).get(consts.RULES_HISTORY_ENDPOINT, params=query)
    )


def validate_rule(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    body = {"name": params.name, "source": params.source}
    return coerce_output(
        output_cls, _client(asset).post(consts.RULES_VALIDATE_ENDPOINT, json_data=body)
    )


def delete_rule(params: Any, soar: SOARClient, asset: Any) -> ActionOutput:
    endpoint = consts.RULE_ENDPOINT.format(id=safe_id(params.rule_id))
    _client(asset).delete(endpoint)
    soar.set_message("Rule deleted successfully")
    return ActionOutput()


def get_rule(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    endpoint = consts.RULE_ENDPOINT.format(id=safe_id(params.rule_id))
    return coerce_output(output_cls, _client(asset).get(endpoint))


def update_rule(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    endpoint = consts.RULE_ENDPOINT.format(id=safe_id(params.rule_id))
    body = _rule_body_from_params(params)
    return coerce_output(output_cls, _client(asset).put(endpoint, json_data=body))


def activate_rule(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    endpoint = consts.RULE_ACTIVATE_ENDPOINT.format(id=safe_id(params.rule_id))
    return coerce_output(output_cls, _client(asset).post(endpoint))


def deactivate_rule(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    endpoint = consts.RULE_DEACTIVATE_ENDPOINT.format(id=safe_id(params.rule_id))
    return coerce_output(output_cls, _client(asset).post(endpoint))


def get_rule_history(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    endpoint = consts.RULE_HISTORY_ENDPOINT.format(id=safe_id(params.rule_id))
    query: dict[str, Any] = {}
    if _pget(params, "start_time"):
        query["classification_created_at[gte]"] = params.start_time
    if _pget(params, "end_time"):
        query["classification_created_at[lte]"] = params.end_time
    if _maybe_bool(params, "use_rule_last_updated_as_created_at") is not None:
        query["use_rule_last_updated_as_created_at"] = bool(
            params.use_rule_last_updated_as_created_at
        )
    return coerce_output(output_cls, _client(asset).get(endpoint, params=query))


# ---------------------------------------------------------------------------
# Tasks / user reports / roles
# ---------------------------------------------------------------------------


def get_task(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    endpoint = consts.TASK_ENDPOINT.format(id=safe_id(params.task_id))
    return coerce_output(output_cls, _client(asset).get(endpoint))


def list_user_reports(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> list[ActionOutput]:
    query: dict[str, Any] = {}
    if _pget(params, "start_time"):
        query["reported_at[gte]"] = params.start_time
    if _pget(params, "end_time"):
        query["reported_at[lt]"] = params.end_time
    if _pget(params, "limit"):
        query["limit"] = clamp_limit(params.limit)
    response = _client(asset).get(consts.USER_REPORTS_ENDPOINT, params=query)
    return coerce_many(output_cls, response.get("user_reports", []))


def assign_role(params: Any, soar: SOARClient, asset: Any) -> ActionOutput:
    body = {"email_address": params.email_address, "role_title": params.role_title}
    _client(asset).put(consts.ASSIGN_ROLE_ENDPOINT, json_data=body)
    soar.set_message("Role assigned successfully")
    return ActionOutput()


# ---------------------------------------------------------------------------
# SCIM
# ---------------------------------------------------------------------------


def list_scim_resource_types(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> list[ActionOutput]:
    response = _client(asset).get(consts.SCIM_RESOURCE_TYPES_ENDPOINT)
    return coerce_many(output_cls, response.get("Resources", []))


def get_scim_resource_type(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    endpoint = consts.SCIM_RESOURCE_TYPE_ENDPOINT.format(
        id=safe_id(params.resource_type_id)
    )
    return coerce_output(output_cls, _client(asset).get(endpoint))


def list_scim_users(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> list[ActionOutput]:
    query = {
        "count": min(int(_pget(params, "count") or consts.SCIM_DEFAULT_COUNT), consts.SCIM_MAX_COUNT),
        "startIndex": max(int(_pget(params, "start_index") or 1), 1),
    }
    if _pget(params, "filter"):
        query["filter"] = params.filter
    response = _client(asset).get(consts.SCIM_USERS_ENDPOINT, params=query)
    return coerce_many(output_cls, response.get("Resources", []))


def create_scim_user(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    body = {
        "userName": params.user_name,
        "name": {"givenName": params.given_name, "familyName": params.family_name},
        "emails": [{"value": params.email, "type": "work", "primary": True}],
        "active": True if _pget(params, "active") is None else bool(params.active),
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    }
    return coerce_output(
        output_cls, _client(asset).post(consts.SCIM_USERS_ENDPOINT, json_data=body)
    )


def get_scim_user(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    endpoint = consts.SCIM_USER_ENDPOINT.format(id=safe_id(params.user_id))
    return coerce_output(output_cls, _client(asset).get(endpoint))


def delete_scim_user(params: Any, soar: SOARClient, asset: Any) -> ActionOutput:
    endpoint = consts.SCIM_USER_ENDPOINT.format(id=safe_id(params.user_id))
    _client(asset).delete(endpoint)
    soar.set_message("SCIM user deleted successfully")
    return ActionOutput()


def update_scim_user(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    endpoint = consts.SCIM_USER_ENDPOINT.format(id=safe_id(params.user_id))
    body = {
        "userName": params.user_name,
        "name": {"givenName": params.given_name, "familyName": params.family_name},
        "emails": [{"value": params.email, "type": "work", "primary": True}],
        "active": True if _pget(params, "active") is None else bool(params.active),
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    }
    return coerce_output(output_cls, _client(asset).put(endpoint, json_data=body))


def patch_scim_user(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    endpoint = consts.SCIM_USER_ENDPOINT.format(id=safe_id(params.user_id))
    try:
        operations = json.loads(params.operations_json)
    except (json.JSONDecodeError, TypeError) as e:
        raise ActionFailure(f"Invalid operations_json: {e!s}") from e
    body = {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": operations,
    }
    return coerce_output(output_cls, _client(asset).patch(endpoint, json_data=body))


def validate_scim_auth(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    return coerce_output(output_cls, _client(asset).get(consts.SCIM_VALIDATE_AUTH_ENDPOINT))


def list_scim_schemas(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> list[ActionOutput]:
    response = _client(asset).get(consts.SCIM_SCHEMAS_ENDPOINT)
    return coerce_many(output_cls, response.get("Resources", []))


def get_scim_schema(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    endpoint = consts.SCIM_SCHEMA_ENDPOINT.format(id=safe_id(params.schema_id))
    return coerce_output(output_cls, _client(asset).get(endpoint))


def get_scim_service_provider_config(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    return coerce_output(
        output_cls, _client(asset).get(consts.SCIM_SERVICE_PROVIDER_CONFIG_ENDPOINT)
    )


# ---------------------------------------------------------------------------
# Organizations (multi-tenancy)
# ---------------------------------------------------------------------------


def list_child_organizations(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> list[ActionOutput]:
    query: dict[str, Any] = {
        "limit": clamp_limit(_pget(params, "limit")),
        "offset": int(_pget(params, "offset") or 0),
    }
    if _pget(params, "active") is not None:
        query["active"] = bool(params.active)
    if _pget(params, "max_depth") is not None:
        query["max_depth"] = int(params.max_depth)
    if _pget(params, "parent_org_id"):
        query["parent_org_id"] = params.parent_org_id
    if _pget(params, "search"):
        query["search"] = params.search
    response = _client(asset).get(consts.CHILD_ORGANIZATIONS_ENDPOINT, params=query)
    orgs = response.get("organizations") or response.get("child_organizations") or []
    if isinstance(response, list):
        orgs = response
    return coerce_many(output_cls, orgs)


def create_child_organization(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    body: dict[str, Any] = {"name": params.name}
    if _pget(params, "licenses_json"):
        try:
            body["licenses"] = json.loads(params.licenses_json)
        except json.JSONDecodeError as e:
            raise ActionFailure(f"Invalid licenses_json: {e}") from e
    return coerce_output(
        output_cls,
        _client(asset).post(consts.CHILD_ORGANIZATIONS_ENDPOINT, json_data=body),
    )


def patch_child_organization(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    endpoint = consts.CHILD_ORGANIZATION_ENDPOINT.format(id=safe_id(params.organization_id))
    body: dict[str, Any] = {}
    if _pget(params, "name"):
        body["name"] = params.name
    if _pget(params, "delegation_json"):
        try:
            body.update(json.loads(params.delegation_json))
        except json.JSONDecodeError as e:
            raise ActionFailure(f"Invalid delegation_json: {e}") from e
    if not body:
        raise ActionFailure("Provide name and/or delegation_json to patch")
    return coerce_output(output_cls, _client(asset).patch(endpoint, json_data=body))


def patch_child_organization_licensing(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    endpoint = consts.CHILD_ORGANIZATION_LICENSING_ENDPOINT.format(
        id=safe_id(params.organization_id)
    )
    try:
        body = json.loads(params.licensing_json)
    except json.JSONDecodeError as e:
        raise ActionFailure(f"Invalid licensing_json: {e}") from e
    return coerce_output(output_cls, _client(asset).patch(endpoint, json_data=body))


def bulk_patch_child_organization_licensing(
    params: Any, soar: SOARClient, asset: Any, output_cls: type[ActionOutput]
) -> ActionOutput:
    try:
        body = json.loads(params.bulk_licensing_json)
    except json.JSONDecodeError as e:
        raise ActionFailure(f"Invalid bulk_licensing_json: {e}") from e
    return coerce_output(
        output_cls,
        _client(asset).post(
            consts.CHILD_ORGANIZATIONS_BULK_LICENSING_ENDPOINT, json_data=body
        ),
    )
