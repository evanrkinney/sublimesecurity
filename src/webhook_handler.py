# File: webhook_handler.py
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

"""Inbound Sublime Security webhook processing."""

from __future__ import annotations

import base64
import json
import time
from typing import Any

import requests
from soar_sdk.abstract import SOARClient
from soar_sdk.logging import getLogger
from soar_sdk.webhooks.models import WebhookRequest, WebhookResponse

from .client import SublimeClient
from .consts import BASE_URLS
from .helpers import (
    extract_email,
    header_get,
    safe_id,
    safe_filename,
    verify_sublime_signature,
)

logger = getLogger()

# Keep webhook acknowledgement within ~10s: use short timeouts for SOAR + EML calls.
_SOAR_TIMEOUT = 5
_EML_TIMEOUT = (3, 5)


def _respond(status_code: int, body: dict[str, Any]) -> WebhookResponse:
    return WebhookResponse.json_response(body, status_code=status_code)


def _soar_headers(auth_token: str) -> dict[str, str]:
    return {"ph-auth-token": auth_token, "Content-Type": "application/json"}


def _rest_base(soar_base_url: str) -> str:
    base = (soar_base_url or "").rstrip("/")
    if not base.endswith("/rest"):
        base = f"{base}/rest"
    return f"{base}/"


def _lookup_container_id_by_sdi(
    rest_base_url: str,
    soar_headers: dict[str, str],
    sdi: str,
    label: str,
    asset_id: int | None,
) -> int | None:
    try:
        params: dict[str, Any] = {
            "_filter_source_data_identifier": f'"{sdi}"',
            "_filter_label": f'"{label}"',
            "page_size": 1,
            "sort": "id",
            "order": "desc",
        }
        if asset_id is not None:
            params["_filter_asset"] = asset_id
        resp = requests.get(
            f"{rest_base_url}container",
            headers=soar_headers,
            params=params,
            verify=False,
            timeout=_SOAR_TIMEOUT,
        )
        if resp.status_code != 200:
            logger.warning(
                "Sublime webhook: container lookup by SDI failed: HTTP %s",
                resp.status_code,
            )
            return None
        rows = resp.json().get("data") or []
        if rows and isinstance(rows, list):
            return rows[0].get("id")
    except Exception as e:
        logger.warning("Sublime webhook: container lookup by SDI exception: %s", e)
    return None


def _create_error_container(
    rest_base_url: str,
    soar_headers: dict[str, str],
    *,
    reason: str,
    payload: Any,
    cfg_label: str,
    cfg_sensitivity: str,
    message_id: str | None = None,
    extra: Any = None,
    body_len: int = 0,
) -> int | None:
    ident = f"sublime-webhook-error-{int(time.time() * 1000)}-{message_id or 'event'}"
    container = {
        "name": f"Sublime Security webhook error: {reason}"[:255],
        "description": reason,
        "source_data_identifier": ident,
        "label": cfg_label,
        "severity": "high",
        "status": "open",
        "sensitivity": cfg_sensitivity,
        "tags": ["error", "sublime-webhook"],
    }
    try:
        c_resp = requests.post(
            f"{rest_base_url}container",
            headers=soar_headers,
            json=container,
            verify=False,
            timeout=_SOAR_TIMEOUT,
        )
        c_json = c_resp.json() if c_resp.content else {}
        container_id = c_json.get("id")
        if not (c_resp.status_code in (200, 201) and container_id):
            logger.warning(
                "Sublime webhook: error container create failed: HTTP %s",
                c_resp.status_code,
            )
            return None
    except Exception as e:
        logger.warning("Sublime webhook: error container create exception: %s", e)
        return None

    try:
        debug_doc = {
            "reason": reason,
            "message_id": message_id,
            "parsed_payload": payload,
            "raw_body_bytes": body_len,
        }
        if extra:
            debug_doc["extra"] = extra
        debug_bytes = json.dumps(debug_doc, indent=2, default=str).encode("utf-8")
        debug_b64 = base64.b64encode(debug_bytes).decode("utf-8")
        requests.post(
            f"{rest_base_url}container_attachment",
            headers=soar_headers,
            json={
                "container_id": container_id,
                "file_name": f"sublime-webhook-error-{int(time.time())}.json",
                "file_content": debug_b64,
                "metadata": {"contains": ["vault id"]},
            },
            verify=False,
            timeout=_SOAR_TIMEOUT,
        )
    except Exception as e:
        logger.warning("Sublime webhook: error debug attachment exception: %s", e)

    try:
        status_resp = requests.post(
            f"{rest_base_url}container/{container_id}",
            headers=soar_headers,
            json={"status": "error"},
            verify=False,
            timeout=_SOAR_TIMEOUT,
        )
        if status_resp.status_code not in (200, 201):
            logger.warning(
                "Sublime webhook: could not set container status to 'error': HTTP %s",
                status_resp.status_code,
            )
    except Exception as e:
        logger.warning(
            "Sublime webhook: could not set container status to 'error': %s", e
        )

    return container_id


def _build_artifact_from_webhook_message(
    data: dict[str, Any], event: dict[str, Any], container_id: int
) -> dict[str, Any]:
    if not isinstance(data, dict):
        data = {}

    message = data.get("message") or {}
    if not isinstance(message, dict):
        message = {}

    subject_field = data.get("subject")
    if isinstance(subject_field, dict):
        subject = subject_field.get("subject") or subject_field.get("base") or ""
        subject_base = subject_field.get("base") or ""
        subject_is_reply = bool(subject_field.get("is_reply"))
        subject_is_forward = bool(subject_field.get("is_forward"))
    else:
        subject = subject_field or ""
        subject_base = ""
        subject_is_reply = False
        subject_is_forward = False

    sender = data.get("sender") or {}
    sender_email = extract_email(sender)
    sender_display = sender.get("display_name", "") if isinstance(sender, dict) else ""
    sender_domain = ""
    if isinstance(sender, dict):
        inner = sender.get("email")
        if isinstance(inner, dict):
            domain = inner.get("domain")
            sender_domain = (
                domain.get("domain", "") if isinstance(domain, dict) else ""
            )

    recipients = data.get("recipients") or {}
    to_list = recipients.get("to") if isinstance(recipients, dict) else None
    cc_list = recipients.get("cc") if isinstance(recipients, dict) else None
    bcc_list = recipients.get("bcc") if isinstance(recipients, dict) else None
    to_emails = [extract_email(r) for r in (to_list or []) if r]
    cc_emails = [extract_email(r) for r in (cc_list or []) if r]
    bcc_emails = [extract_email(r) for r in (bcc_list or []) if r]
    recipient_count = len([e for e in to_emails + cc_emails + bcc_emails if e])

    reply_to_list = data.get("reply_to") or []
    reply_to_emails = (
        [extract_email(r) for r in (reply_to_list or []) if r]
        if isinstance(reply_to_list, list)
        else []
    )

    mailbox_full = data.get("mailbox") or {}
    mailbox_email = (
        extract_email(mailbox_full) if isinstance(mailbox_full, dict) else ""
    )
    mailbox_ref = message.get("mailbox") or {}

    external = data.get("external") or {}
    message_type = data.get("message_type") or {}

    attack_score_verdict = data.get("attack_score_verdict", "")
    attack_score = data.get("attack_score")
    graymail_score = data.get("graymail_score")
    top_signals = data.get("attack_score_top_signals") or []
    signal_categories = [
        s.get("category", "")
        for s in top_signals
        if isinstance(s, dict) and s.get("category")
    ]
    signal_names = [
        s.get("name", "") for s in top_signals if isinstance(s, dict) and s.get("name")
    ]

    flagged_rules = data.get("flagged_rules") or []
    triggered_actions = data.get("triggered_actions") or []
    rule_names = [r.get("name", "") for r in flagged_rules if isinstance(r, dict)]
    rule_ids = [r.get("id", "") for r in flagged_rules if isinstance(r, dict)]
    rule_severities = [
        r.get("severity", "")
        for r in flagged_rules
        if isinstance(r, dict) and r.get("severity")
    ]
    rule_tags = sorted(
        {
            t
            for r in flagged_rules
            if isinstance(r, dict)
            for t in (r.get("tags") or [])
            if t
        }
    )
    action_types = [
        a.get("type", "") for a in triggered_actions if isinstance(a, dict)
    ]
    action_names = [
        a.get("name", "")
        for a in triggered_actions
        if isinstance(a, dict) and a.get("name")
    ]

    headers = data.get("headers") or {}
    if not isinstance(headers, dict):
        headers = {}
    header_message_id = headers.get("message_id", "") or ""
    header_date = headers.get("date", "") or ""
    header_in_reply_to = headers.get("in_reply_to", "") or ""
    header_references = headers.get("references", "") or ""
    auth_summary = headers.get("auth_summary") or {}
    spf_result = (
        (auth_summary.get("spf") or {}).get("pass")
        if isinstance(auth_summary.get("spf"), dict)
        else None
    )
    dkim_result = (
        (auth_summary.get("dkim") or {}).get("pass")
        if isinstance(auth_summary.get("dkim"), dict)
        else None
    )
    dmarc_result = (
        (auth_summary.get("dmarc") or {}).get("pass")
        if isinstance(auth_summary.get("dmarc"), dict)
        else None
    )

    attachments = data.get("attachments") or []
    if not isinstance(attachments, list):
        attachments = []
    attachment_names = [
        a.get("file_name", "")
        for a in attachments
        if isinstance(a, dict) and a.get("file_name")
    ]
    attachment_hashes = [
        a.get("md5", "") for a in attachments if isinstance(a, dict) and a.get("md5")
    ]

    links = data.get("links") or []
    if not isinstance(links, list):
        links = []
    link_urls = []
    for ln in links:
        if isinstance(ln, dict) and ln.get("href_url"):
            href = ln["href_url"]
            if isinstance(href, dict):
                link_urls.append(href.get("url", "") or "")
            else:
                link_urls.append(str(href))
        elif isinstance(ln, str):
            link_urls.append(ln)
    link_urls = [u for u in link_urls if u]

    cef = {
        "messageId": message.get("id", ""),
        "canonicalId": message.get("canonical_id", ""),
        "externalMessageId": message.get("external_id", "")
        or external.get("message_id", ""),
        "messageSourceId": message.get("message_source_id", ""),
        "rfc822MessageId": header_message_id,
        "mailboxId": mailbox_ref.get("id", "") if isinstance(mailbox_ref, dict) else "",
        "mailboxExternalId": (
            mailbox_ref.get("external_id", "") if isinstance(mailbox_ref, dict) else ""
        ),
        "mailboxEmail": mailbox_email,
        "subject": subject,
        "subjectBase": subject_base,
        "subjectIsReply": subject_is_reply if subject_is_reply else None,
        "subjectIsForward": subject_is_forward if subject_is_forward else None,
        "senderEmail": sender_email,
        "senderDisplayName": sender_display,
        "senderDomain": sender_domain,
        "fromEmail": sender_email,
        "replyToEmails": ", ".join([e for e in reply_to_emails if e]),
        "toRecipients": ", ".join([e for e in to_emails if e]),
        "ccRecipients": ", ".join([e for e in cc_emails if e]),
        "bccRecipients": ", ".join([e for e in bcc_emails if e]),
        "recipientCount": recipient_count or None,
        "routeType": external.get("route_type", ""),
        "externalCreatedAt": external.get("created_at", ""),
        "headerDate": header_date,
        "inReplyTo": header_in_reply_to,
        "references": header_references,
        "spfPass": spf_result,
        "dkimPass": dkim_result,
        "dmarcPass": dmarc_result,
        "isInbound": bool(message_type.get("inbound"))
        if isinstance(message_type, dict)
        else None,
        "isOutbound": bool(message_type.get("outbound"))
        if isinstance(message_type, dict)
        else None,
        "isInternal": bool(message_type.get("internal"))
        if isinstance(message_type, dict)
        else None,
        "attackScoreVerdict": attack_score_verdict,
        "attackScore": attack_score if isinstance(attack_score, (int, float)) else None,
        "graymailScore": graymail_score
        if isinstance(graymail_score, (int, float))
        else None,
        "attackScoreTopSignals": ", ".join(signal_categories),
        "attackScoreTopSignalNames": ", ".join(signal_names),
        "flaggedRuleNames": ", ".join([n for n in rule_names if n]),
        "flaggedRuleIds": ", ".join([i for i in rule_ids if i]),
        "flaggedRuleSeverities": ", ".join([s for s in rule_severities if s]),
        "flaggedRuleTags": ", ".join(rule_tags),
        "triggeredActionTypes": ", ".join([t for t in action_types if t]),
        "triggeredActionNames": ", ".join([n for n in action_names if n]),
        "attachmentNames": ", ".join(attachment_names),
        "attachmentHashes": ", ".join(attachment_hashes),
        "requestURL": link_urls[0] if link_urls else "",
        "urls": ", ".join(link_urls[:25]),
        "eventType": event.get("type", "") if isinstance(event, dict) else "",
        "eventId": event.get("id", "") if isinstance(event, dict) else "",
    }

    return {
        "name": subject or f"Sublime message {message.get('id', '')}" or "Sublime message",
        "label": "email",
        "container_id": container_id,
        "source_data_identifier": message.get("id")
        or message.get("canonical_id")
        or event.get("id")
        or f"sublime-{int(time.time() * 1000)}",
        "severity": "medium",
        "cef": {k: v for k, v in cef.items() if v is not None and v != ""},
        "cef_types": {
            "messageId": ["message id"],
            "canonicalId": ["message id"],
            "senderEmail": ["email"],
            "fromEmail": ["email"],
            "mailboxEmail": ["email"],
            "toRecipients": ["email"],
            "requestURL": ["url"],
            "attachmentHashes": ["md5"],
            "senderDomain": ["domain"],
        },
        "data": data,
        "raw_data": event,
        "run_automation": True,
    }


def handle_sublime_webhook(
    request: WebhookRequest, soar: SOARClient | None = None
) -> WebhookResponse:
    """Process an inbound Sublime Security webhook using ``request.asset``.

    Fail closed on signature verification issues. Avoids logging raw webhook
    body bytes. Uses short timeouts so the handler can acknowledge within ~10s.
    """
    asset = request.asset
    if asset is None:
        return _respond(
            500,
            {"error": "Failed to resolve asset configuration for signature verification"},
        )

    if request.method.upper() != "POST":
        return _respond(405, {"error": "Method Not Allowed. Use POST."})

    raw_body = request.body
    if isinstance(raw_body, str):
        raw_bytes = raw_body.encode("utf-8")
    elif isinstance(raw_body, (bytes, bytearray)):
        raw_bytes = bytes(raw_body)
    else:
        raw_bytes = b""

    cfg_label = asset.webhook_container_label or "events"
    cfg_severity = asset.webhook_container_severity or "medium"
    cfg_sensitivity = asset.webhook_container_sensitivity or "amber"
    signing_secret = asset.webhook_signing_secret or None
    try:
        signature_tolerance = int(asset.webhook_signature_tolerance_seconds or 300)
    except (TypeError, ValueError):
        signature_tolerance = 300
    fetch_eml = bool(asset.webhook_fetch_eml)
    sdi_strategy = (asset.webhook_container_sdi_strategy or "canonical_id").lower()

    # Fail closed: if a signing secret is configured, signature must verify.
    # Also fail closed when the signature header is present but secret is missing
    # (misconfiguration) — reject rather than silently accept.
    sig_header = header_get(request.headers, "X-Sublime-Signature")
    if signing_secret:
        ok, reason = verify_sublime_signature(
            sig_header, raw_bytes, signing_secret, signature_tolerance
        )
        if not ok:
            return _respond(401, {"error": f"signature verification failed: {reason}"})
    elif sig_header:
        return _respond(
            401,
            {
                "error": "signature verification failed: no signing secret configured"
            },
        )

    rest_base_url = _rest_base(request.soar_base_url)
    soar_headers = _soar_headers(request.soar_auth_token)
    asset_id = request.asset_id

    try:
        payload = json.loads(raw_bytes.decode("utf-8")) if raw_bytes else {}
    except Exception as e:
        _create_error_container(
            rest_base_url,
            soar_headers,
            reason=f"Invalid JSON: {e!s}",
            payload=None,
            cfg_label=cfg_label,
            cfg_sensitivity=cfg_sensitivity,
            body_len=len(raw_bytes),
        )
        return _respond(400, {"error": f"Invalid JSON: {e!s}"})

    if not isinstance(payload, dict):
        _create_error_container(
            rest_base_url,
            soar_headers,
            reason="Payload must be a JSON object",
            payload=payload,
            cfg_label=cfg_label,
            cfg_sensitivity=cfg_sensitivity,
            body_len=len(raw_bytes),
        )
        return _respond(400, {"error": "Payload must be a JSON object"})

    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    data_blocks: list[dict[str, Any]] = []

    if isinstance(data.get("messages"), list) and data["messages"]:
        shared = {k: v for k, v in data.items() if k != "messages"}
        for msg in data["messages"]:
            if not isinstance(msg, dict):
                continue
            merged = dict(shared)
            for k, v in msg.items():
                merged[k] = v
            if "message" not in merged and ("id" in msg or "canonical_id" in msg):
                merged["message"] = msg
            data_blocks.append(merged)
    elif isinstance(payload.get("events"), list) and payload["events"]:
        for ev in payload["events"]:
            if isinstance(ev, dict) and isinstance(ev.get("data"), dict):
                data_blocks.append(ev["data"])
    else:
        data_blocks.append(data)

    event_type = payload.get("type", "message.flagged")
    event_id = payload.get("id", "")
    severity_rank = {
        "informational": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }

    def _derive_severity(rules: list[Any]) -> str:
        if str(cfg_severity).lower() != "use alert severity":
            return str(cfg_severity)
        best_rank = -1
        best = None
        for r in rules or []:
            if not isinstance(r, dict):
                continue
            sev = (r.get("severity") or "").lower()
            rk = severity_rank.get(sev, -1)
            if rk > best_rank:
                best_rank = rk
                best = sev
        if best == "informational":
            best = "low"
        elif best == "critical":
            best = "high"
        return best or "medium"

    def _derive_subject(d: dict[str, Any]) -> str:
        sf = d.get("subject") if isinstance(d, dict) else None
        if isinstance(sf, dict):
            return sf.get("subject") or sf.get("base") or ""
        return sf or ""

    results: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

    for block in data_blocks:
        if not isinstance(block, dict):
            block = {}
        message = block.get("message") if isinstance(block.get("message"), dict) else {}
        flagged_rules = block.get("flagged_rules") or []
        if not isinstance(flagged_rules, list):
            flagged_rules = []

        message_id = message.get("id") or block.get("id") or event_id or "unknown"
        canonical_id = (
            message.get("canonical_id") or block.get("canonical_id") or message_id
        )

        subject = _derive_subject(block)
        first_rule_name = ""
        if flagged_rules and isinstance(flagged_rules[0], dict):
            first_rule_name = flagged_rules[0].get("name", "") or ""

        if subject:
            container_name = f"Message Flagged: {subject}"
        elif first_rule_name:
            container_name = f"Message Flagged: {first_rule_name}"
        else:
            container_name = f"Message Flagged: {event_id or message_id}"

        if sdi_strategy == "message_id":
            container_sdi = message_id
        elif sdi_strategy == "event_message_id":
            container_sdi = f"{event_id or 'event'}-{message_id}"
        else:
            container_sdi = canonical_id

        container = {
            "name": container_name,
            "description": f"Sublime Security {event_type} event for message {message_id}",
            "source_data_identifier": container_sdi,
            "label": cfg_label,
            "severity": _derive_severity(flagged_rules),
            "sensitivity": cfg_sensitivity,
            "tags": [
                t
                for r in flagged_rules
                if isinstance(r, dict)
                for t in (r.get("tags") or [])
            ],
            "data": payload,
        }

        container_id = None
        merged_into_existing = False
        try:
            c_resp = requests.post(
                f"{rest_base_url}container",
                headers=soar_headers,
                json=container,
                verify=False,
                timeout=_SOAR_TIMEOUT,
            )
            c_json = c_resp.json() if c_resp.content else {}
            container_id = c_json.get("id")

            err_text_lower = (c_resp.text or "").lower()
            sdi_collision = (
                "source_data_identifier" in err_text_lower
                or "source data identifier" in err_text_lower
                or ("already exists" in err_text_lower and "asset" in err_text_lower)
            )
            if c_resp.status_code == 400 and sdi_collision:
                existing_id = (
                    c_json.get("existing_container_id")
                    if isinstance(c_json, dict)
                    else None
                )
                if not existing_id:
                    existing_id = _lookup_container_id_by_sdi(
                        rest_base_url,
                        soar_headers,
                        container_sdi,
                        cfg_label,
                        asset_id,
                    )
                if existing_id:
                    container_id = existing_id
                    merged_into_existing = True
                else:
                    reason = (
                        f"container dedup but lookup failed: HTTP {c_resp.status_code}"
                    )
                    err_cid = _create_error_container(
                        rest_base_url,
                        soar_headers,
                        reason=reason,
                        payload=payload,
                        cfg_label=cfg_label,
                        cfg_sensitivity=cfg_sensitivity,
                        message_id=message_id,
                        extra={"failed_container": container},
                        body_len=len(raw_bytes),
                    )
                    errors.append(
                        {
                            "message_id": message_id,
                            "error": reason,
                            "error_container_id": err_cid,
                        }
                    )
                    continue
            elif not (c_resp.status_code in (200, 201) and container_id):
                reason = f"container create failed: HTTP {c_resp.status_code}"
                err_cid = _create_error_container(
                    rest_base_url,
                    soar_headers,
                    reason=reason,
                    payload=payload,
                    cfg_label=cfg_label,
                    cfg_sensitivity=cfg_sensitivity,
                    message_id=message_id,
                    extra={"failed_container": container},
                    body_len=len(raw_bytes),
                )
                errors.append(
                    {
                        "message_id": message_id,
                        "error": reason,
                        "error_container_id": err_cid,
                    }
                )
                continue
        except Exception as e:
            reason = f"container create exception: {e!s}"
            err_cid = _create_error_container(
                rest_base_url,
                soar_headers,
                reason=reason,
                payload=payload,
                cfg_label=cfg_label,
                cfg_sensitivity=cfg_sensitivity,
                message_id=message_id,
                extra={"failed_container": container},
                body_len=len(raw_bytes),
            )
            errors.append(
                {
                    "message_id": message_id,
                    "error": reason,
                    "error_container_id": err_cid,
                }
            )
            continue

        try:
            artifact = _build_artifact_from_webhook_message(block, payload, container_id)
        except Exception as e:
            reason = f"artifact build exception: {e!s}"
            err_cid = _create_error_container(
                rest_base_url,
                soar_headers,
                reason=reason,
                payload=payload,
                cfg_label=cfg_label,
                cfg_sensitivity=cfg_sensitivity,
                message_id=message_id,
                body_len=len(raw_bytes),
            )
            errors.append(
                {
                    "message_id": message_id,
                    "container_id": container_id,
                    "error": reason,
                    "error_container_id": err_cid,
                }
            )
            continue

        try:
            a_resp = requests.post(
                f"{rest_base_url}artifact",
                headers=soar_headers,
                json=artifact,
                verify=False,
                timeout=_SOAR_TIMEOUT,
            )
            a_json = a_resp.json() if a_resp.content else {}
            if a_resp.status_code not in (200, 201) or not a_json.get("id"):
                reason = f"artifact create failed: HTTP {a_resp.status_code}"
                err_cid = _create_error_container(
                    rest_base_url,
                    soar_headers,
                    reason=reason,
                    payload=payload,
                    cfg_label=cfg_label,
                    cfg_sensitivity=cfg_sensitivity,
                    message_id=message_id,
                    extra={"failed_artifact_keys": list(artifact.keys())},
                    body_len=len(raw_bytes),
                )
                errors.append(
                    {
                        "message_id": message_id,
                        "container_id": container_id,
                        "error": reason,
                        "error_container_id": err_cid,
                    }
                )
                continue
        except Exception as e:
            reason = f"artifact create exception: {e!s}"
            err_cid = _create_error_container(
                rest_base_url,
                soar_headers,
                reason=reason,
                payload=payload,
                cfg_label=cfg_label,
                cfg_sensitivity=cfg_sensitivity,
                message_id=message_id,
                body_len=len(raw_bytes),
            )
            errors.append(
                {
                    "message_id": message_id,
                    "container_id": container_id,
                    "error": reason,
                    "error_container_id": err_cid,
                }
            )
            continue

        eml_vault_id = None
        if (
            fetch_eml
            and message_id
            and message_id != "unknown"
        ):
            try:
                client = SublimeClient(asset)
                eml_endpoint = f"/v0/messages/{safe_id(message_id)}/eml"
                raw_content, _ct = client.get_raw(eml_endpoint, timeout=_EML_TIMEOUT)
                if raw_content:
                    file_name = safe_filename(f"message_{message_id}.eml")
                    eml_b64 = base64.b64encode(raw_content).decode("utf-8")
                    va_resp = requests.post(
                        f"{rest_base_url}container_attachment",
                        headers=soar_headers,
                        json={
                            "container_id": container_id,
                            "file_name": file_name,
                            "file_content": eml_b64,
                            "metadata": {"contains": ["vault id"]},
                        },
                        verify=False,
                        timeout=_SOAR_TIMEOUT,
                    )
                    if va_resp.status_code in (200, 201):
                        va_json = va_resp.json() if va_resp.content else {}
                        eml_vault_id = (
                            va_json.get("vault_id")
                            or va_json.get("hash")
                            or va_json.get("id")
                        )
                        if eml_vault_id:
                            requests.post(
                                f"{rest_base_url}artifact",
                                headers=soar_headers,
                                json={
                                    "name": f"EML: {message_id}",
                                    "label": "email",
                                    "container_id": container_id,
                                    "source_data_identifier": f"eml-{message_id}",
                                    "cef": {
                                        "vaultId": eml_vault_id,
                                        "fileName": file_name,
                                        "messageId": message_id,
                                    },
                                    "cef_types": {
                                        "vaultId": ["vault id"],
                                        "fileName": ["file name"],
                                        "messageId": ["message id"],
                                    },
                                    "run_automation": False,
                                },
                                verify=False,
                                timeout=_SOAR_TIMEOUT,
                            )
                    else:
                        logger.warning(
                            "Sublime webhook: vault upload failed for message %s: HTTP %s",
                            message_id,
                            va_resp.status_code,
                        )
            except Exception as e:
                logger.warning(
                    "Sublime webhook: EML fetch/upload exception for message %s: %s",
                    message_id,
                    e,
                )

        result_entry = {
            "message_id": message_id,
            "canonical_id": canonical_id,
            "container_id": container_id,
            "container_sdi": container_sdi,
            "merged_into_existing": merged_into_existing,
        }
        if eml_vault_id:
            result_entry["eml_vault_id"] = eml_vault_id
        results.append(result_entry)

    response_body: dict[str, Any] = {
        "status": "success"
        if not errors
        else ("partial_success" if results else "error"),
        "event_id": event_id,
        "event_type": event_type,
        "containers_created": len(results),
        "results": results,
    }
    if errors:
        response_body["errors"] = errors

    if not results:
        status_code = 500
    elif errors:
        status_code = 207
    else:
        status_code = 200

    return _respond(status_code, response_body)
