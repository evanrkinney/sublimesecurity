# File: sublimesecurity_connector.py
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

import base64
import json

import phantom.app as phantom
import phantom.vault as ph_vault
import requests
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector
from phantom.vault import Vault

from sublimesecurity_consts import *


class SublimeSecurityConnector(BaseConnector):
    """Connector for the Sublime Security Platform API."""

    def __init__(self):
        super().__init__()
        self._base_url = None
        self._api_key = None
        self._verify = False
        self._headers = None

    def _get_file_data(self, action_result, vault_id=None, base64_data=None):
        """Retrieve file data from either a Vault ID or base64 encoded string.

        Returns (status, file_bytes) tuple.
        """
        if vault_id:
            try:
                success, message, vault_info = ph_vault.vault_info(vault_id=vault_id)
                if not success or not vault_info:
                    return action_result.set_status(phantom.APP_ERROR, f"Could not find vault file: {message}"), None

                vault_info = list(vault_info)
                if not vault_info:
                    return action_result.set_status(phantom.APP_ERROR, "No vault file found for the provided Vault ID"), None

                file_path = vault_info[0].get("path")
                if not file_path:
                    return action_result.set_status(phantom.APP_ERROR, "Could not determine file path from vault"), None

                with open(file_path, "rb") as f:
                    file_bytes = f.read()

                return phantom.APP_SUCCESS, file_bytes
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, f"Error reading vault file: {e!s}"), None

        elif base64_data:
            try:
                file_bytes = base64.b64decode(base64_data)
                return phantom.APP_SUCCESS, file_bytes
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, f"Error decoding base64 data: {e!s}"), None

        return action_result.set_status(phantom.APP_ERROR, "Either vault_id or base64_data must be provided"), None

    def _get_file_as_base64(self, action_result, param):
        """Get file as base64 string from vault_id or base64_data param.

        Returns (status, base64_string) tuple.
        """
        vault_id = param.get("vault_id")
        base64_data = param.get("base64_data")

        if vault_id:
            ret_val, file_bytes = self._get_file_data(action_result, vault_id=vault_id)
            if phantom.is_fail(ret_val):
                return ret_val, None
            return phantom.APP_SUCCESS, base64.b64encode(file_bytes).decode("utf-8")
        elif base64_data:
            return phantom.APP_SUCCESS, base64_data
        else:
            return action_result.set_status(phantom.APP_ERROR, "Either vault_id or base64_data must be provided"), None

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, json_data=None, method="get"):
        """Make a REST API call to the Sublime Security platform."""
        try:
            url = f"{self._base_url}{endpoint}"
            self.debug_print(f"Making REST call to: {url}")

            request_headers = dict(self._headers)
            if headers:
                request_headers.update(headers)

            request_func = getattr(requests, method.lower())

            response = request_func(
                url,
                json=json_data,
                data=data,
                headers=request_headers,
                params=params,
                verify=self._verify,
            )

            if hasattr(action_result, "add_debug_data"):
                action_result.add_debug_data({"r_status_code": response.status_code})
                action_result.add_debug_data({"r_text": response.text})
                action_result.add_debug_data({"r_headers": dict(response.headers)})

            if 200 <= response.status_code < 300:
                # 204 No Content
                if response.status_code == 204 or not response.text:
                    return phantom.APP_SUCCESS, {}
                try:
                    return phantom.APP_SUCCESS, response.json()
                except ValueError:
                    return phantom.APP_SUCCESS, response.text

            error_message = f"Error from server. Status Code: {response.status_code}"
            if response.text:
                try:
                    resp_json = response.json()
                    server_error = resp_json.get("error", resp_json.get("message", "Unknown error"))
                    error_message = f"Error from server. Status Code: {response.status_code}. Error: {server_error}"
                except ValueError:
                    error_message = f"Error from server. Status Code: {response.status_code}. Error: {response.text}"

            return action_result.set_status(phantom.APP_ERROR, error_message), None

        except requests.exceptions.ConnectionError as e:
            return action_result.set_status(phantom.APP_ERROR, f"Connection error: {e!s}"), None
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, f"Error making REST call: {e!s}"), None

    def _make_rest_call_raw(self, endpoint, action_result, headers=None, params=None, method="get"):
        """Make a REST call that returns raw bytes (for EML, images)."""
        try:
            url = f"{self._base_url}{endpoint}"
            request_headers = dict(self._headers)
            if headers:
                request_headers.update(headers)

            request_func = getattr(requests, method.lower())
            response = request_func(url, headers=request_headers, params=params, verify=self._verify)

            if 200 <= response.status_code < 300:
                return phantom.APP_SUCCESS, response.content, response.headers.get("Content-Type", "")

            error_message = f"Error from server. Status Code: {response.status_code}"
            return action_result.set_status(phantom.APP_ERROR, error_message), None, None

        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, f"Error making REST call: {e!s}"), None, None

    def _save_to_vault(self, action_result, data_bytes, file_name, container_id=None):
        """Save bytes to the SOAR vault. Returns vault_id or None."""
        try:
            if container_id is None:
                container_id = self.get_container_id()
            tmp_dir = Vault.get_vault_tmp_dir()
            file_path = f"{tmp_dir}/{file_name}"
            with open(file_path, "wb") as f:
                f.write(data_bytes)
            vault_ret = Vault.add_attachment(file_path, container_id, file_name=file_name)
            if vault_ret.get("succeeded"):
                return vault_ret.get("vault_id", "")
        except Exception as e:
            self.debug_print(f"Could not save to vault: {e!s}")
        return None

    def _iter_image_bytes(self, data):
        """Yield image byte blobs from a Sublime image response.

        The API returns image data as a base64 string, a list of ints
        (single image), or a list of lists of ints (multiple images).
        """
        if not data:
            return
        if isinstance(data, (bytes, bytearray)):
            yield bytes(data)
            return
        if isinstance(data, str):
            try:
                yield base64.b64decode(data)
            except Exception as e:
                self.debug_print(f"Failed to base64-decode image data: {e!s}")
            return
        if isinstance(data, list):
            if not data:
                return
            if all(isinstance(el, (list, tuple)) for el in data):
                for el in data:
                    try:
                        yield bytes(el)
                    except Exception as e:
                        self.debug_print(f"Failed to convert image list: {e!s}")
            elif all(isinstance(el, str) for el in data):
                for el in data:
                    try:
                        yield base64.b64decode(el)
                    except Exception as e:
                        self.debug_print(f"Failed to base64-decode image entry: {e!s}")
            else:
                try:
                    yield bytes(data)
                except Exception as e:
                    self.debug_print(f"Failed to convert image list: {e!s}")

    def _clamp_limit(self, limit, maximum=None):
        """Clamp limit to max value."""
        if maximum is None:
            maximum = MAX_LIMIT
        if limit is None:
            return DEFAULT_LIMIT
        return min(int(limit), maximum)

    def _parse_comma_list(self, value):
        """Parse a comma-separated string into a list of stripped strings."""
        if not value:
            return []
        return [v.strip() for v in value.split(",") if v.strip()]

    # =========================================================================
    # Bulk message group review body builder
    # =========================================================================

    def _build_review_body(self, param):
        """Build the standard review request body for message group actions."""
        body = {"message_group_ids": self._parse_comma_list(param["message_group_ids"])}
        if param.get("classification"):
            body["classification"] = param["classification"]
        if param.get("report_label"):
            body["report_label"] = param["report_label"]
        if param.get("review_comment"):
            body["review_comment"] = param["review_comment"]
        return body

    def _build_single_review_body(self, param):
        """Build review body for single message group actions (no IDs)."""
        body = {}
        if param.get("classification"):
            body["classification"] = param["classification"]
        if param.get("report_label"):
            body["report_label"] = param["report_label"]
        if param.get("review_comment"):
            body["review_comment"] = param["review_comment"]
        return body

    # =========================================================================
    # Action handlers
    # =========================================================================

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Connecting to Sublime Security...")
        ret_val, _ = self._make_rest_call(AUDIT_EVENT_TYPES_ENDPOINT, action_result)
        if phantom.is_fail(ret_val):
            self.save_progress(ERR_CONNECTIVITY_TEST)
            return action_result.get_status()
        self.save_progress(SUCC_CONNECTIVITY_TEST)
        return action_result.set_status(phantom.APP_SUCCESS)

    # --- BinExplode ---

    def _handle_upload_binary(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val, b64_data = self._get_file_as_base64(action_result, param)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        body = {"file_contents": b64_data, "file_name": param["file_name"]}
        ret_val, response = self._make_rest_call(BINEXPLODE_SCAN_ENDPOINT, action_result, json_data=body, method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"task_id": response.get("task_id", ""), "total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_binexplode_results(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = BINEXPLODE_SCAN_RESULT_ENDPOINT.format(id=param["task_id"])
        ret_val, response = self._make_rest_call(endpoint, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        results = response.get("results", [])
        for r in results:
            action_result.add_data(r)

        task_response = response.get("task_response", {})
        action_result.update_summary(
            {
                "total_results": len(results),
                "task_state": task_response.get("state", "unknown"),
                "total_objects": len(results),
                "total_objects_successful": len(results),
            }
        )
        return action_result.set_status(phantom.APP_SUCCESS)

    # --- Link Analysis ---

    def _handle_analyze_link(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        body = {"url": param["url"]}
        if param.get("no_logo_detect"):
            body["no_logo_detect"] = True

        ret_val, response = self._make_rest_call(LINK_ANALYSIS_ENDPOINT, action_result, json_data=body, method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        summary = {"analyzed": response.get("analyzed", False)}
        credphish = response.get("credphish")
        if credphish:
            summary["disposition"] = credphish.get("disposition", "unknown")
            summary["confidence"] = credphish.get("confidence", "")
            brand = credphish.get("brand")
            if brand:
                summary["brand_name"] = brand.get("name", "")

        effective_url = response.get("effective_url")
        if effective_url:
            summary["effective_url"] = effective_url.get("url", "")
        action_result.update_summary(summary)

        screenshot = response.get("screenshot")
        if screenshot and screenshot.get("raw"):
            screenshot_bytes = base64.b64decode(screenshot["raw"])
            file_name = screenshot.get("file_name", "link_analysis_screenshot.png")
            vault_id = self._save_to_vault(action_result, screenshot_bytes, file_name)
            if vault_id:
                action_result.update_summary({"screenshot_vault_id": vault_id})

        action_result.update_summary({"total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    # --- Audit Log ---

    def _handle_list_audit_events(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        query_params = {}
        if param.get("start_time"):
            query_params["created_at[gte]"] = param["start_time"]
        if param.get("end_time"):
            query_params["created_at[lt]"] = param["end_time"]
        if param.get("event_type"):
            query_params["type"] = param["event_type"]
        if param.get("user_ids"):
            query_params["user_ids"] = self._parse_comma_list(param["user_ids"])
        query_params["limit"] = self._clamp_limit(param.get("limit"))
        query_params["offset"] = int(param.get("offset", 0))

        ret_val, response = self._make_rest_call(AUDIT_EVENTS_ENDPOINT, action_result, params=query_params)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        events = response.get("events", [])
        for event in events:
            action_result.add_data(event)
        action_result.update_summary(
            {
                "total_events": response.get("total", 0),
                "events_returned": len(events),
                "total_objects": len(events),
                "total_objects_successful": len(events),
            }
        )
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_audit_event_types(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val, response = self._make_rest_call(AUDIT_EVENT_TYPES_ENDPOINT, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        event_types = response.get("event_types", [])
        for et in event_types:
            action_result.add_data(et)
        action_result.update_summary(
            {"total_event_types": len(event_types), "total_objects": len(event_types), "total_objects_successful": len(event_types)}
        )
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_audit_event(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = AUDIT_EVENT_ENDPOINT.format(id=param["event_id"])
        ret_val, response = self._make_rest_call(endpoint, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    # --- Hunt Jobs ---

    def _handle_start_hunt_job(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        body = {
            "source": param["source"],
            "range_start_time": param["range_start_time"],
            "range_end_time": param["range_end_time"],
        }
        if param.get("name"):
            body["name"] = param["name"]
        if param.get("private"):
            body["private"] = True
        for key in ("triage_flagged", "triage_reported", "triage_email_bomb", "triage_dlp_rule_matched"):
            if param.get(key) is not None:
                body[key] = bool(param[key])

        ret_val, response = self._make_rest_call(HUNT_JOBS_ENDPOINT, action_result, json_data=body, method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"hunt_job_id": response.get("hunt_job_id", ""), "total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_hunt_job(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = HUNT_JOB_ENDPOINT.format(id=param["hunt_job_id"])
        ret_val, response = self._make_rest_call(endpoint, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"hunt_status": response.get("status", "unknown"), "total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_hunt_job_results(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = HUNT_JOB_RESULTS_ENDPOINT.format(id=param["hunt_job_id"])
        query_params = {
            "limit": self._clamp_limit(param.get("limit")),
            "offset": int(param.get("offset", 0)),
        }
        ret_val, response = self._make_rest_call(endpoint, action_result, params=query_params)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        groups = response.get("message_groups", [])
        for g in groups:
            action_result.add_data(g)
        action_result.update_summary(
            {
                "total_group_count": response.get("total_group_count", 0),
                "groups_returned": len(groups),
                "total_objects": len(groups),
                "total_objects_successful": len(groups),
            }
        )
        return action_result.set_status(phantom.APP_SUCCESS)

    # --- Lists ---

    def _handle_list_lists(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        query_params = {"entry_type": "string"}
        if param.get("name"):
            query_params["name"] = param["name"]

        ret_val, response = self._make_rest_call(LISTS_ENDPOINT, action_result, params=query_params)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        lists = response.get("lists", [])
        for l in lists:
            action_result.add_data(l)
        action_result.update_summary({"total_lists": len(lists), "total_objects": len(lists), "total_objects_successful": len(lists)})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_create_list(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        body = {"name": param["name"], "description": param["description"]}
        ret_val, response = self._make_rest_call(LISTS_ENDPOINT, action_result, json_data=body, method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"list_id": response.get("id", ""), "total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_delete_list(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = LIST_ENDPOINT.format(id=param["list_id"])
        ret_val, _ = self._make_rest_call(endpoint, action_result, method="delete")
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        action_result.update_summary({"total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS, "List deleted successfully")

    def _handle_get_list(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = LIST_ENDPOINT.format(id=param["list_id"])
        ret_val, response = self._make_rest_call(endpoint, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_patch_list(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = LIST_ENDPOINT.format(id=param["list_id"])
        body = {"description": param["description"]}
        ret_val, response = self._make_rest_call(endpoint, action_result, json_data=body, method="patch")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_list_entries(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = LIST_ENTRIES_ENDPOINT.format(id=param["list_id"])
        ret_val, response = self._make_rest_call(endpoint, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        entries = response.get("entries", [])
        for entry in entries:
            action_result.add_data({"entry": entry})
        action_result.update_summary({"total_entries": len(entries), "total_objects": len(entries), "total_objects_successful": len(entries)})

        if param.get("save_to_vault"):
            try:
                import csv as csv_mod
                import io

                buf = io.StringIO()
                writer = csv_mod.writer(buf)
                writer.writerow(["entry"])
                for e in entries:
                    writer.writerow([e])
                csv_bytes = buf.getvalue().encode("utf-8")
                file_name = param.get("csv_file_name") or f"list_{param['list_id']}_entries.csv"
                vault_id = self._save_to_vault(action_result, csv_bytes, file_name)
                if vault_id:
                    action_result.update_summary({"vault_id": vault_id})
            except Exception as e:
                self.debug_print(f"Could not save list entries CSV to vault: {e!s}")

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_set_list_entries(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = LIST_ENTRIES_ENDPOINT.format(id=param["list_id"])

        entries = []
        vault_id = param.get("vault_id")
        entries_str = param.get("entries")

        if vault_id:
            ret_val, file_bytes = self._get_file_data(action_result, vault_id=vault_id)
            if phantom.is_fail(ret_val):
                return action_result.get_status()
            try:
                import csv as csv_mod
                import io

                text = file_bytes.decode("utf-8", errors="replace")
                reader = csv_mod.reader(io.StringIO(text))
                for row in reader:
                    for cell in row:
                        cell = cell.strip()
                        if cell and cell.lower() != "entry":
                            entries.append(cell)
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, f"Error parsing CSV from vault: {e!s}")
        elif entries_str:
            entries = self._parse_comma_list(entries_str)
        else:
            return action_result.set_status(phantom.APP_ERROR, "Either entries or vault_id must be provided")

        body = {"entries": entries}
        ret_val, _ = self._make_rest_call(endpoint, action_result, json_data=body, method="put")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.update_summary({"entries_set": len(entries), "total_objects": len(entries), "total_objects_successful": len(entries)})
        return action_result.set_status(phantom.APP_SUCCESS, f"Set {len(entries)} entries successfully")

    def _handle_delete_list_entry(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = LIST_ENTRY_ENDPOINT.format(id=param["list_id"])
        query_params = {"string": param["entry"]}
        ret_val, _ = self._make_rest_call(endpoint, action_result, params=query_params, method="delete")
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        action_result.update_summary({"total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS, "Entry deleted successfully")

    def _handle_get_list_entry(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = LIST_ENTRY_ENDPOINT.format(id=param["list_id"])

        raw = param["entry"]
        entries_to_check = self._parse_comma_list(raw) if "," in raw else [raw.strip()]

        found_count = 0
        for entry in entries_to_check:
            scratch = ActionResult()
            ret_val, _ = self._make_rest_call(endpoint, scratch, params={"string": entry})
            found = phantom.is_success(ret_val)

            action_result.add_data({"entry": entry, "found": found})
            if found:
                found_count += 1

        action_result.update_summary(
            {
                "total_checked": len(entries_to_check),
                "total_found": found_count,
                "total_objects": len(entries_to_check),
                "total_objects_successful": found_count,
            }
        )
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_add_list_entry(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = LIST_ENTRY_ENDPOINT.format(id=param["list_id"])
        body = {"string": param["entry"]}
        ret_val, _ = self._make_rest_call(endpoint, action_result, json_data=body, method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        action_result.update_summary({"total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS, "Entry added successfully")

    # --- Raw Message Processing ---

    def _handle_process_raw_message(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val, b64_data = self._get_file_as_base64(action_result, param)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        body = {
            "raw_message": b64_data,
            "mailbox_email_address": param["mailbox_email_address"],
            "message_source_id": param["message_source_id"],
        }
        if param.get("create_mailbox"):
            body["create_mailbox"] = True
        if param.get("analyze_async"):
            body["analyze_async"] = True
        if param.get("canonical_id"):
            body["canonical_id"] = param["canonical_id"]
        if param.get("external_message_id"):
            body["external_message_id"] = param["external_message_id"]
        if param.get("external_thread_id"):
            body["external_thread_id"] = param["external_thread_id"]
        if param.get("external_created_at"):
            body["external_created_at"] = param["external_created_at"]
        if param.get("folder"):
            body["folder"] = param["folder"]
        if param.get("labels"):
            body["labels"] = [lbl.strip() for lbl in str(param["labels"]).split(",") if lbl.strip()]
        if param.get("route_type"):
            body["route_type"] = param["route_type"]
        if param.get("message_type"):
            mt = param["message_type"]
            body["message_type"] = {mt: True} if mt in ("inbound", "internal", "outbound") else {}

        ret_val, response = self._make_rest_call(RAW_MESSAGE_ANALYZE_ENDPOINT, action_result, json_data=body, method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        flagged_rules = response.get("flagged_rules", [])
        action_result.update_summary(
            {
                "message_id": response.get("message_id", ""),
                "flagged_rules_count": len(flagged_rules),
                "total_objects": 1,
                "total_objects_successful": 1,
            }
        )
        return action_result.set_status(phantom.APP_SUCCESS)

    # --- Mailboxes ---

    def _handle_list_mailboxes(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        query_params = {
            "limit": self._clamp_limit(param.get("limit")),
            "offset": int(param.get("offset", 0)),
        }
        if param.get("active") is not None:
            query_params["active"] = param["active"]
        if param.get("marked_active") is not None:
            query_params["marked_active"] = bool(param["marked_active"])
        if param.get("search"):
            query_params["search"] = param["search"]
        for key in ("email_addresses", "mailbox_types", "sub_error_types", "message_source_id"):
            if param.get(key):
                query_params[key] = param[key]

        ret_val, response = self._make_rest_call(MAILBOXES_ENDPOINT, action_result, params=query_params)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        mailboxes = response.get("mailboxes", [])
        for mb in mailboxes:
            action_result.add_data(mb)
        action_result.update_summary(
            {
                "total_mailboxes": response.get("total", 0),
                "active_mailboxes": response.get("active", 0),
                "total_objects": len(mailboxes),
                "total_objects_successful": len(mailboxes),
            }
        )
        return action_result.set_status(phantom.APP_SUCCESS)

    # --- Message Groups ---

    def _handle_list_message_groups(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        query_params = {
            "limit": self._clamp_limit(param.get("limit")),
            "offset": int(param.get("offset", 0)),
        }
        if param.get("start_time"):
            query_params["created_at__gte"] = param["start_time"]
        if param.get("end_time"):
            query_params["created_at__lt"] = param["end_time"]
        if param.get("first_message_reported_at_gte"):
            query_params["first_message_reported_at__gte"] = param["first_message_reported_at_gte"]
        if param.get("flagged") is not None:
            query_params["flagged"] = param["flagged"]
        if param.get("reviewed") is not None:
            query_params["reviewed"] = param["reviewed"]
        if param.get("user_reported") is not None:
            query_params["user_reported"] = param["user_reported"]
        if param.get("attack_surface_reduction") is not None:
            query_params["attack_surface_reduction__filter"] = param["attack_surface_reduction"]

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
            if param.get(pkey):
                query_params[qkey] = self._parse_comma_list(param[pkey])

        ret_val, response = self._make_rest_call(MESSAGE_GROUPS_ENDPOINT, action_result, params=query_params)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        groups = response.get("message_groups", [])
        for g in groups:
            action_result.add_data(g)
        action_result.update_summary(
            {
                "total_groups": response.get("total", 0),
                "groups_returned": len(groups),
                "total_objects": len(groups),
                "total_objects_successful": len(groups),
            }
        )
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_dismiss_message_groups(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        body = self._build_review_body(param)
        ret_val, _ = self._make_rest_call(MESSAGE_GROUPS_DISMISS_ENDPOINT, action_result, json_data=body, method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        action_result.update_summary({"total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS, "Message groups dismissed successfully")

    def _handle_quarantine_message_groups(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        body = self._build_review_body(param)
        ret_val, response = self._make_rest_call(MESSAGE_GROUPS_QUARANTINE_ENDPOINT, action_result, json_data=body, method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"task_id": response.get("task_id", ""), "total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_graymail_message_groups(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        body = self._build_review_body(param)
        ret_val, response = self._make_rest_call(MESSAGE_GROUPS_GRAYMAIL_ENDPOINT, action_result, json_data=body, method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"task_id": response.get("task_id", ""), "total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_restore_message_groups(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        body = self._build_review_body(param)
        ret_val, response = self._make_rest_call(MESSAGE_GROUPS_RESTORE_ENDPOINT, action_result, json_data=body, method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"task_id": response.get("task_id", ""), "total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_review_message_groups(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        body = {
            "message_group_ids": self._parse_comma_list(param["message_group_ids"]),
            "classification": param["classification"],
        }
        if param.get("action"):
            body["action"] = param["action"]
        if param.get("review_comment"):
            body["review_comment"] = param["review_comment"]
        if param.get("share_with_sublime"):
            body["share_with_sublime"] = True

        ret_val, response = self._make_rest_call(MESSAGE_GROUPS_REVIEW_ENDPOINT, action_result, json_data=body, method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"task_id": response.get("task_id", ""), "total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_search_message_groups(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        query_params = {
            "limit": self._clamp_limit(param.get("limit")),
            "offset": int(param.get("offset", 0)),
        }
        for key in ("any", "sender", "to", "mailbox", "subject", "message_id", "type", "file_name"):
            if param.get(key):
                query_params[key] = param[key]
        for key in ("attachment_md5", "attachment_sha1", "attachment_sha256"):
            if param.get(key):
                query_params[key] = param[key]
        if param.get("states"):
            query_params["states"] = self._parse_comma_list(param["states"])
        if param.get("start_time"):
            query_params["created_at[gte]"] = param["start_time"]
        if param.get("end_time"):
            query_params["created_at[lt]"] = param["end_time"]
        if param.get("first_reported_as_phish_at_gte"):
            query_params["first_reported_as_phish_at[gte]"] = param["first_reported_as_phish_at_gte"]
        if param.get("first_reported_as_phish_at_lt"):
            query_params["first_reported_as_phish_at[lt]"] = param["first_reported_as_phish_at_lt"]

        ret_val, response = self._make_rest_call(MESSAGE_GROUPS_SEARCH_ENDPOINT, action_result, params=query_params)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        groups = response.get("message_groups", [])
        for g in groups:
            action_result.add_data(g)
        action_result.update_summary(
            {
                "total_groups": response.get("total", 0),
                "groups_returned": len(groups),
                "total_objects": len(groups),
                "total_objects_successful": len(groups),
            }
        )
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_trash_message_groups(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        body = self._build_review_body(param)
        ret_val, response = self._make_rest_call(MESSAGE_GROUPS_TRASH_ENDPOINT, action_result, json_data=body, method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"task_id": response.get("task_id", ""), "total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_message_group(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = MESSAGE_GROUP_ENDPOINT.format(id=param["message_group_id"])
        ret_val, response = self._make_rest_call(endpoint, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_dismiss_message_group(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = MESSAGE_GROUP_DISMISS_ENDPOINT.format(id=param["message_group_id"])
        body = self._build_single_review_body(param)
        ret_val, _ = self._make_rest_call(endpoint, action_result, json_data=body, method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        action_result.update_summary({"total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS, "Message group dismissed successfully")

    def _handle_quarantine_message_group(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = MESSAGE_GROUP_QUARANTINE_ENDPOINT.format(id=param["message_group_id"])
        body = self._build_single_review_body(param)
        ret_val, response = self._make_rest_call(endpoint, action_result, json_data=body, method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"task_id": response.get("task_id", ""), "total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_restore_message_group(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = MESSAGE_GROUP_RESTORE_ENDPOINT.format(id=param["message_group_id"])
        body = self._build_single_review_body(param)
        ret_val, response = self._make_rest_call(endpoint, action_result, json_data=body, method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"task_id": response.get("task_id", ""), "total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_share_with_sublime(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = MESSAGE_GROUP_SHARE_ENDPOINT.format(id=param["message_group_id"])
        body = {}
        if param.get("report_label"):
            body["report_label"] = param["report_label"]
        if param.get("review_comment"):
            body["review_comment"] = param["review_comment"]

        ret_val, response = self._make_rest_call(endpoint, action_result, json_data=body, method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"task_id": response.get("task_id", ""), "total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_trash_message_group(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = MESSAGE_GROUP_TRASH_ENDPOINT.format(id=param["message_group_id"])
        body = self._build_single_review_body(param)
        ret_val, response = self._make_rest_call(endpoint, action_result, json_data=body, method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"task_id": response.get("task_id", ""), "total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    # --- Messages ---

    def _handle_analyze_raw_message(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val, b64_data = self._get_file_as_base64(action_result, param)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        body = {"raw_message": b64_data}
        if param.get("run_active_detection_rules"):
            body["run_active_detection_rules"] = True
        if param.get("run_all_detection_rules"):
            body["run_all_detection_rules"] = True
        if param.get("run_all_insights"):
            body["run_all_insights"] = True

        ret_val, response = self._make_rest_call(MESSAGES_ANALYZE_ENDPOINT, action_result, json_data=body, method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        rule_results = response.get("rule_results", [])
        matched = sum(1 for r in rule_results if r.get("matched"))
        action_result.update_summary(
            {"matched_rules": matched, "total_rules_evaluated": len(rule_results), "total_objects": 1, "total_objects_successful": 1}
        )
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_render_attachment_image(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val, b64_data = self._get_file_as_base64(action_result, param)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        body = {"raw": b64_data}
        if param.get("file_type"):
            body["file_type"] = param["file_type"]

        ret_val, response = self._make_rest_call(MESSAGES_ATTACHMENT_IMAGE_RAW_ENDPOINT, action_result, json_data=body, method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        image_data = response.get("data")
        for idx, img_bytes in enumerate(self._iter_image_bytes(image_data)):
            vault_id = self._save_to_vault(action_result, img_bytes, f"attachment_render_{idx}.png")
            if vault_id:
                action_result.update_summary({"screenshot_vault_id": vault_id})

        action_result.update_summary({"total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_attack_score_raw(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val, b64_data = self._get_file_as_base64(action_result, param)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        body = {"raw_message": b64_data}
        ret_val, response = self._make_rest_call(MESSAGES_ATTACK_SCORE_ENDPOINT, action_result, json_data=body, method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary(
            {"verdict": response.get("verdict", ""), "score": response.get("score"), "total_objects": 1, "total_objects_successful": 1}
        )
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_create_message(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val, b64_data = self._get_file_as_base64(action_result, param)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        body = {"raw_message": b64_data}
        if param.get("mailbox_email_address"):
            body["mailbox_email_address"] = param["mailbox_email_address"]
        if param.get("canonical_id"):
            body["canonical_id"] = param["canonical_id"]
        if param.get("external_message_id"):
            body["external_message_id"] = param["external_message_id"]
        if param.get("external_thread_id"):
            body["external_thread_id"] = param["external_thread_id"]
        if param.get("external_created_at"):
            body["external_created_at"] = param["external_created_at"]
        if param.get("folder"):
            body["folder"] = param["folder"]
        if param.get("labels"):
            body["labels"] = [lbl.strip() for lbl in str(param["labels"]).split(",") if lbl.strip()]
        if param.get("route_type"):
            body["route_type"] = param["route_type"]
        if param.get("message_type"):
            mt = param["message_type"]
            body["message_type"] = {mt: True} if mt in ("inbound", "internal", "outbound") else {}

        ret_val, response = self._make_rest_call(MESSAGES_CREATE_ENDPOINT, action_result, json_data=body, method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"message_id": response.get("id", ""), "total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_action_state(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = MESSAGE_GROUP_ACTION_STATE_ENDPOINT.format(id=param["message_group_id"])
        query_params = {
            "limit": min(int(param.get("limit", 10)), 50),
            "offset": int(param.get("offset", 0)),
        }
        ret_val, response = self._make_rest_call(endpoint, action_result, params=query_params)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        actions = response.get("actions", [])
        for a in actions:
            action_result.add_data(a)
        action_result.update_summary({"total_objects": len(actions), "total_objects_successful": len(actions)})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_message(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = MESSAGE_ENDPOINT.format(id=param["message_id"])
        ret_val, response = self._make_rest_call(endpoint, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_action_message(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = MESSAGE_ACTIONS_ENDPOINT.format(id=param["message_id"])
        body = {}
        if param.get("action"):
            body["action"] = param["action"]
        if param.get("share_with_sublime"):
            body["share_with_sublime"] = True

        ret_val, response = self._make_rest_call(endpoint, action_result, json_data=body, method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"task_id": response.get("task_id", ""), "total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_analyze_message_by_id(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = MESSAGE_ANALYZE_BY_ID_ENDPOINT.format(id=param["message_id"])
        body = {}
        if param.get("run_active_detection_rules"):
            body["run_active_detection_rules"] = True
        if param.get("run_all_detection_rules"):
            body["run_all_detection_rules"] = True
        if param.get("run_all_insights"):
            body["run_all_insights"] = True

        ret_val, response = self._make_rest_call(endpoint, action_result, json_data=body, method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        rule_results = response.get("rule_results", [])
        matched = sum(1 for r in rule_results if r.get("matched"))
        action_result.update_summary(
            {"matched_rules": matched, "total_rules_evaluated": len(rule_results), "total_objects": 1, "total_objects_successful": 1}
        )
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_asa_report(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = MESSAGE_ASA_REPORT_ENDPOINT.format(id=param["message_id"])
        ret_val, response = self._make_rest_call(endpoint, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"verdict": response.get("verdict", ""), "total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_asa_verdict(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = MESSAGE_ASA_VERDICT_ENDPOINT.format(id=param["message_id"])
        ret_val, response = self._make_rest_call(endpoint, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"verdict": response.get("verdict", ""), "total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_attachment_image(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = MESSAGE_ATTACHMENT_IMAGE_ENDPOINT.format(id=param["message_id"], hash=param["attachment_hash"])
        ret_val, response = self._make_rest_call(endpoint, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        image_data = response.get("data")
        for idx, img_bytes in enumerate(self._iter_image_bytes(image_data)):
            vault_id = self._save_to_vault(action_result, img_bytes, f"attachment_{param['attachment_hash']}_{idx}.png")
            if vault_id:
                action_result.update_summary({"screenshot_vault_id": vault_id})

        action_result.update_summary({"total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_attack_score(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = MESSAGE_ATTACK_SCORE_ENDPOINT.format(id=param["message_id"])
        ret_val, response = self._make_rest_call(endpoint, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary(
            {"verdict": response.get("verdict", ""), "score": response.get("score"), "total_objects": 1, "total_objects_successful": 1}
        )
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_message_image(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = MESSAGE_IMAGE_ENDPOINT.format(id=param["message_id"])
        ret_val, response = self._make_rest_call(endpoint, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        mime_type = response.get("mime_type", "image/png")
        ext = mime_type.split("/")[-1] if mime_type else "png"
        for idx, img_bytes in enumerate(self._iter_image_bytes(response.get("data"))):
            suffix = "" if idx == 0 else f"_{idx}"
            vault_id = self._save_to_vault(action_result, img_bytes, f"message_{param['message_id']}{suffix}.{ext}")
            if vault_id:
                action_result.update_summary({"screenshot_vault_id": vault_id})

        action_result.update_summary({"total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_message_eml(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = MESSAGE_EML_ENDPOINT.format(id=param["message_id"])
        ret_val, raw_content, content_type = self._make_rest_call_raw(endpoint, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        vault_id = self._save_to_vault(action_result, raw_content, f"message_{param['message_id']}.eml")
        if vault_id:
            action_result.update_summary({"vault_id": vault_id})

        action_result.update_summary({"total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_message_image_link(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = MESSAGE_IMAGE_LINK_ENDPOINT.format(id=param["message_id"])
        query_params = {}
        if param.get("link_duration_seconds"):
            query_params["link_duration_seconds"] = int(param["link_duration_seconds"])
        if param.get("platform_link") is not None:
            query_params["platform_link"] = bool(param["platform_link"])

        ret_val, response = self._make_rest_call(endpoint, action_result, params=query_params)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_set_access_justification(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = MESSAGE_JUSTIFICATION_ENDPOINT.format(id=param["message_id"])
        body = {"justification": param["justification"]}
        ret_val, _ = self._make_rest_call(endpoint, action_result, json_data=body, method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        action_result.update_summary({"total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS, "Access justification set successfully")

    def _handle_get_message_data_model(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = MESSAGE_MDM_ENDPOINT.format(id=param["message_id"])
        ret_val, response = self._make_rest_call(endpoint, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_restore_message(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = MESSAGE_RESTORE_ENDPOINT.format(id=param["message_id"])
        ret_val, response = self._make_rest_call(endpoint, action_result, method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"task_id": response.get("task_id", ""), "total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_trash_message(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = MESSAGE_TRASH_ENDPOINT.format(id=param["message_id"])
        ret_val, response = self._make_rest_call(endpoint, action_result, method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"task_id": response.get("task_id", ""), "total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    # --- Rules ---

    def _handle_list_rules(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        query_params = {
            "limit": self._clamp_limit(param.get("limit")),
            "offset": int(param.get("offset", 0)),
        }
        if param.get("search"):
            query_params["search"] = param["search"]
        if param.get("in_feed") is not None:
            query_params["in_feed"] = bool(param["in_feed"])

        ret_val, response = self._make_rest_call(RULES_ENDPOINT, action_result, params=query_params)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        rules = response.get("rules", [])
        for r in rules:
            action_result.add_data(r)
        action_result.update_summary(
            {
                "total_rules": response.get("total", 0),
                "rules_returned": len(rules),
                "total_objects": len(rules),
                "total_objects_successful": len(rules),
            }
        )
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_create_rule(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        body = {"name": param["name"], "source": param["source"]}
        for key in ("type", "severity", "description", "label", "maturity", "auto_review_classification"):
            if param.get(key):
                body[key] = param[key]
        if param.get("active"):
            body["active"] = True
        if param.get("auto_review_auto_share") is not None:
            body["auto_review_auto_share"] = bool(param["auto_review_auto_share"])
        for key in (
            "triage_abuse_reports",
            "triage_flagged_messages",
            "triage_classification_changes",
            "triage_dlp_rule_matched",
            "run_triage_on_excluded_messages",
        ):
            if param.get(key) is not None:
                body[key] = bool(param[key])
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
            if param.get(key):
                body[key] = self._parse_comma_list(param[key])
        if param.get("authors"):
            try:
                import json as _json

                parsed = _json.loads(param["authors"])
                if isinstance(parsed, list):
                    body["authors"] = parsed
            except Exception:
                return action_result.set_status(phantom.APP_ERROR, "authors must be a JSON array of {name, twitter} objects")

        ret_val, response = self._make_rest_call(RULES_ENDPOINT, action_result, json_data=body, method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"rule_id": response.get("id", ""), "total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_rule_history(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        query_params = {
            "classification_created_at[gte]": param["start_time"],
            "classification_created_at[lte]": param["end_time"],
        }
        if param.get("active") is not None:
            query_params["active"] = bool(param["active"])
        if param.get("in_feed") is not None:
            query_params["in_feed"] = bool(param["in_feed"])
        if param.get("type"):
            query_params["type"] = self._parse_comma_list(param["type"])
        if param.get("count") is not None:
            query_params["count"] = int(param["count"])
        if param.get("offset") is not None:
            query_params["offset"] = int(param["offset"])
        ret_val, response = self._make_rest_call(RULES_HISTORY_ENDPOINT, action_result, params=query_params)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_validate_rule(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        body = {"name": param["name"], "source": param["source"]}
        ret_val, response = self._make_rest_call(RULES_VALIDATE_ENDPOINT, action_result, json_data=body, method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_delete_rule(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = RULE_ENDPOINT.format(id=param["rule_id"])
        ret_val, _ = self._make_rest_call(endpoint, action_result, method="delete")
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        action_result.update_summary({"total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS, "Rule deleted successfully")

    def _handle_get_rule(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = RULE_ENDPOINT.format(id=param["rule_id"])
        ret_val, response = self._make_rest_call(endpoint, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_rule(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = RULE_ENDPOINT.format(id=param["rule_id"])
        body = {}
        for key in ("name", "source", "severity", "description", "label", "maturity", "auto_review_classification"):
            if param.get(key):
                body[key] = param[key]
        if param.get("auto_review_auto_share") is not None:
            body["auto_review_auto_share"] = bool(param["auto_review_auto_share"])
        for key in (
            "triage_abuse_reports",
            "triage_flagged_messages",
            "triage_classification_changes",
            "triage_dlp_rule_matched",
            "run_triage_on_excluded_messages",
        ):
            if param.get(key) is not None:
                body[key] = bool(param[key])
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
            if param.get(key):
                body[key] = self._parse_comma_list(param[key])
        if param.get("authors"):
            try:
                import json as _json

                parsed = _json.loads(param["authors"])
                if isinstance(parsed, list):
                    body["authors"] = parsed
            except Exception:
                return action_result.set_status(phantom.APP_ERROR, "authors must be a JSON array of {name, twitter} objects")

        ret_val, response = self._make_rest_call(endpoint, action_result, json_data=body, method="put")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_activate_rule(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = RULE_ACTIVATE_ENDPOINT.format(id=param["rule_id"])
        ret_val, response = self._make_rest_call(endpoint, action_result, method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_deactivate_rule(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = RULE_DEACTIVATE_ENDPOINT.format(id=param["rule_id"])
        ret_val, response = self._make_rest_call(endpoint, action_result, method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_rule_history(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = RULE_HISTORY_ENDPOINT.format(id=param["rule_id"])
        query_params = {}
        if param.get("start_time"):
            query_params["classification_created_at[gte]"] = param["start_time"]
        if param.get("end_time"):
            query_params["classification_created_at[lte]"] = param["end_time"]
        if param.get("use_rule_last_updated_as_created_at") is not None:
            query_params["use_rule_last_updated_as_created_at"] = bool(param["use_rule_last_updated_as_created_at"])

        ret_val, response = self._make_rest_call(endpoint, action_result, params=query_params)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    # --- Tasks ---

    def _handle_get_task(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = TASK_ENDPOINT.format(id=param["task_id"])
        ret_val, response = self._make_rest_call(endpoint, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"task_state": response.get("state", "unknown"), "total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    # --- User Reports ---

    def _handle_list_user_reports(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        query_params = {}
        if param.get("start_time"):
            query_params["reported_at[gte]"] = param["start_time"]
        if param.get("end_time"):
            query_params["reported_at[lt]"] = param["end_time"]
        if param.get("limit"):
            query_params["limit"] = self._clamp_limit(param.get("limit"))

        ret_val, response = self._make_rest_call(USER_REPORTS_ENDPOINT, action_result, params=query_params)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        reports = response.get("user_reports", [])
        for r in reports:
            action_result.add_data(r)
        action_result.update_summary(
            {"total_reports": response.get("count", len(reports)), "total_objects": len(reports), "total_objects_successful": len(reports)}
        )
        return action_result.set_status(phantom.APP_SUCCESS)

    # --- Users/Roles ---

    def _handle_assign_role(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        body = {"email_address": param["email_address"], "role_title": param["role_title"]}
        ret_val, _ = self._make_rest_call(ASSIGN_ROLE_ENDPOINT, action_result, json_data=body, method="put")
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        action_result.update_summary({"total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS, "Role assigned successfully")

    # --- SCIM ---

    def _handle_list_scim_resource_types(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val, response = self._make_rest_call(SCIM_RESOURCE_TYPES_ENDPOINT, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        resources = response.get("Resources", [])
        for r in resources:
            action_result.add_data(r)
        action_result.update_summary(
            {"total_resource_types": len(resources), "total_objects": len(resources), "total_objects_successful": len(resources)}
        )
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_scim_resource_type(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = SCIM_RESOURCE_TYPE_ENDPOINT.format(id=param["resource_type_id"])
        ret_val, response = self._make_rest_call(endpoint, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_scim_users(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        query_params = {
            "count": min(int(param.get("count", 100)), SCIM_MAX_COUNT),
            "startIndex": max(int(param.get("start_index", 1)), 1),
        }
        if param.get("filter"):
            query_params["filter"] = param["filter"]

        ret_val, response = self._make_rest_call(SCIM_USERS_ENDPOINT, action_result, params=query_params)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        users = response.get("Resources", [])
        for u in users:
            action_result.add_data(u)
        action_result.update_summary(
            {"total_results": response.get("totalResults", len(users)), "total_objects": len(users), "total_objects_successful": len(users)}
        )
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_create_scim_user(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        body = {
            "userName": param["user_name"],
            "name": {"givenName": param["given_name"], "familyName": param["family_name"]},
            "emails": [{"value": param["email"], "type": "work", "primary": True}],
            "active": param.get("active", True),
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        }
        ret_val, response = self._make_rest_call(SCIM_USERS_ENDPOINT, action_result, json_data=body, method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"user_id": response.get("id", ""), "total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_scim_user(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = SCIM_USER_ENDPOINT.format(id=param["user_id"])
        ret_val, response = self._make_rest_call(endpoint, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_delete_scim_user(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = SCIM_USER_ENDPOINT.format(id=param["user_id"])
        ret_val, _ = self._make_rest_call(endpoint, action_result, method="delete")
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        action_result.update_summary({"total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS, "SCIM user deleted successfully")

    def _handle_update_scim_user(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = SCIM_USER_ENDPOINT.format(id=param["user_id"])
        body = {
            "userName": param["user_name"],
            "name": {"givenName": param["given_name"], "familyName": param["family_name"]},
            "emails": [{"value": param["email"], "type": "work", "primary": True}],
            "active": param.get("active", True),
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        }
        ret_val, response = self._make_rest_call(endpoint, action_result, json_data=body, method="put")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_patch_scim_user(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = SCIM_USER_ENDPOINT.format(id=param["user_id"])
        try:
            operations = json.loads(param["operations_json"])
        except (json.JSONDecodeError, TypeError) as e:
            return action_result.set_status(phantom.APP_ERROR, f"Invalid operations_json: {e!s}")

        body = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": operations,
        }
        ret_val, response = self._make_rest_call(endpoint, action_result, json_data=body, method="patch")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_validate_scim_auth(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val, response = self._make_rest_call(SCIM_VALIDATE_AUTH_ENDPOINT, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_scim_schemas(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val, response = self._make_rest_call(SCIM_SCHEMAS_ENDPOINT, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        schemas = response.get("Resources", [])
        for s in schemas:
            action_result.add_data(s)
        action_result.update_summary({"total_schemas": len(schemas), "total_objects": len(schemas), "total_objects_successful": len(schemas)})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_scim_schema(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = SCIM_SCHEMA_ENDPOINT.format(id=param["schema_id"])
        ret_val, response = self._make_rest_call(endpoint, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_scim_service_provider_config(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val, response = self._make_rest_call(SCIM_SERVICE_PROVIDER_CONFIG_ENDPOINT, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"total_objects": 1, "total_objects_successful": 1})
        return action_result.set_status(phantom.APP_SUCCESS)

    # =========================================================================
    # Connector lifecycle
    # =========================================================================

    def initialize(self):
        self.debug_print("Initializing Sublime Security connector")
        config = self.get_config()

        region = config.get("region", "NA-East")
        if region == "Custom":
            self._base_url = config.get("base_url", "").rstrip("/")
            if not self._base_url:
                return self.set_status(phantom.APP_ERROR, "Custom region selected but no base URL provided")
        else:
            self._base_url = BASE_URLS.get(region, BASE_URLS["NA-East"])

        self._api_key = config["api_key"]
        self._verify = config.get("verify_server_cert", True)

        self._headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        return phantom.APP_SUCCESS

    def handle_action(self, param):
        self.debug_print("action_id", self.get_action_identifier())

        action_mapping = {
            "test_connectivity": self._handle_test_connectivity,
            # BinExplode
            "upload_binary": self._handle_upload_binary,
            "get_binexplode_results": self._handle_get_binexplode_results,
            # Enrichment
            "analyze_link": self._handle_analyze_link,
            # Audit Log
            "list_audit_events": self._handle_list_audit_events,
            "list_audit_event_types": self._handle_list_audit_event_types,
            "get_audit_event": self._handle_get_audit_event,
            # Hunt Jobs
            "start_hunt_job": self._handle_start_hunt_job,
            "get_hunt_job": self._handle_get_hunt_job,
            "get_hunt_job_results": self._handle_get_hunt_job_results,
            # Lists
            "list_lists": self._handle_list_lists,
            "create_list": self._handle_create_list,
            "delete_list": self._handle_delete_list,
            "get_list": self._handle_get_list,
            "patch_list": self._handle_patch_list,
            "get_list_entries": self._handle_get_list_entries,
            "set_list_entries": self._handle_set_list_entries,
            "delete_list_entry": self._handle_delete_list_entry,
            "get_list_entry": self._handle_get_list_entry,
            "add_list_entry": self._handle_add_list_entry,
            # Raw Message Processing
            "process_raw_message": self._handle_process_raw_message,
            # Mailboxes
            "list_mailboxes": self._handle_list_mailboxes,
            # Message Groups (bulk)
            "list_message_groups": self._handle_list_message_groups,
            "dismiss_message_groups": self._handle_dismiss_message_groups,
            "quarantine_message_groups": self._handle_quarantine_message_groups,
            "graymail_message_groups": self._handle_graymail_message_groups,
            "restore_message_groups": self._handle_restore_message_groups,
            "review_message_groups": self._handle_review_message_groups,
            "search_message_groups": self._handle_search_message_groups,
            "trash_message_groups": self._handle_trash_message_groups,
            # Message Groups (single)
            "get_message_group": self._handle_get_message_group,
            "dismiss_message_group": self._handle_dismiss_message_group,
            "quarantine_message_group": self._handle_quarantine_message_group,
            "restore_message_group": self._handle_restore_message_group,
            "share_with_sublime": self._handle_share_with_sublime,
            "trash_message_group": self._handle_trash_message_group,
            # Messages
            "analyze_raw_message": self._handle_analyze_raw_message,
            "render_attachment_image": self._handle_render_attachment_image,
            "get_attack_score_raw": self._handle_get_attack_score_raw,
            "create_message": self._handle_create_message,
            "get_action_state": self._handle_get_action_state,
            "get_message": self._handle_get_message,
            "action_message": self._handle_action_message,
            "analyze_message_by_id": self._handle_analyze_message_by_id,
            "get_asa_report": self._handle_get_asa_report,
            "get_asa_verdict": self._handle_get_asa_verdict,
            "get_attachment_image": self._handle_get_attachment_image,
            "get_attack_score": self._handle_get_attack_score,
            "get_message_image": self._handle_get_message_image,
            "get_message_eml": self._handle_get_message_eml,
            "get_message_image_link": self._handle_get_message_image_link,
            "set_access_justification": self._handle_set_access_justification,
            "get_message_data_model": self._handle_get_message_data_model,
            "restore_message": self._handle_restore_message,
            "trash_message": self._handle_trash_message,
            # Rules
            "list_rules": self._handle_list_rules,
            "create_rule": self._handle_create_rule,
            "list_rule_history": self._handle_list_rule_history,
            "validate_rule": self._handle_validate_rule,
            "delete_rule": self._handle_delete_rule,
            "get_rule": self._handle_get_rule,
            "update_rule": self._handle_update_rule,
            "activate_rule": self._handle_activate_rule,
            "deactivate_rule": self._handle_deactivate_rule,
            "get_rule_history": self._handle_get_rule_history,
            # Tasks
            "get_task": self._handle_get_task,
            # User Reports
            "list_user_reports": self._handle_list_user_reports,
            # Users/Roles
            "assign_role": self._handle_assign_role,
            # SCIM
            "list_scim_resource_types": self._handle_list_scim_resource_types,
            "get_scim_resource_type": self._handle_get_scim_resource_type,
            "list_scim_users": self._handle_list_scim_users,
            "create_scim_user": self._handle_create_scim_user,
            "get_scim_user": self._handle_get_scim_user,
            "delete_scim_user": self._handle_delete_scim_user,
            "update_scim_user": self._handle_update_scim_user,
            "patch_scim_user": self._handle_patch_scim_user,
            "validate_scim_auth": self._handle_validate_scim_auth,
            "list_scim_schemas": self._handle_list_scim_schemas,
            "get_scim_schema": self._handle_get_scim_schema,
            "get_scim_service_provider_config": self._handle_get_scim_service_provider_config,
        }

        action = self.get_action_identifier()
        action_execution_status = phantom.APP_SUCCESS

        if action in action_mapping:
            action_execution_status = action_mapping[action](param)

        return action_execution_status

    def finalize(self):
        return phantom.APP_SUCCESS


# =========================================================================
# REST Handler - Inbound Webhook from Sublime Security
# =========================================================================
# See README.md for the webhook configuration, authentication model, and
# payload shape.


def _candidate_secret_keys(signing_secret):
    """Yield HMAC key candidates for a configured Sublime signing secret.

    Sublime presents the signing secret as base64 text in the UI, but admins
    sometimes paste it verbatim and sometimes paste the decoded form. To stay
    compatible with both, try the literal UTF-8 bytes first, then any plausible
    base64 decoding (standard + URL-safe, with and without padding).
    """
    import base64 as _b64

    if signing_secret is None:
        return
    if isinstance(signing_secret, (bytes, bytearray)):
        yield bytes(signing_secret)
        return

    s = str(signing_secret).strip()
    if not s:
        return

    # 1) Raw UTF-8 bytes of whatever was pasted.
    raw = s.encode("utf-8")
    yield raw
    seen = {raw}

    # 2) Hex decode (Sublime may display the secret as hex).
    if all(c in "0123456789abcdefABCDEF" for c in s) and len(s) % 2 == 0:
        try:
            hex_bytes = bytes.fromhex(s)
        except ValueError:
            hex_bytes = None
        if hex_bytes and hex_bytes not in seen:
            seen.add(hex_bytes)
            yield hex_bytes

    # 3) base64 decode attempts (standard + URL-safe, padded + unpadded). These
    #    only produce extra candidates when the string decodes cleanly.
    for decoder in (_b64.b64decode, _b64.urlsafe_b64decode):
        for padded in (s, s + "=" * (-len(s) % 4)):
            try:
                decoded = decoder(padded)
            except Exception:
                continue
            if decoded and decoded not in seen:
                seen.add(decoded)
                yield decoded


def _verify_sublime_signature(header_value, raw_body_bytes, signing_secret, tolerance_seconds):
    """Verify the X-Sublime-Signature header. Returns (ok, reason)."""
    import hashlib
    import hmac
    import logging
    import time

    logger = logging.getLogger(__name__)

    if not header_value:
        return False, "missing X-Sublime-Signature header"
    if not signing_secret:
        return False, "no signing secret configured"

    timestamp = None
    signatures = []
    for part in str(header_value).split(","):
        part = part.strip()
        if "=" not in part:
            continue
        k, _, v = part.partition("=")
        if k == "t":
            timestamp = v
        elif k == "v0":
            signatures.append(v)

    if not timestamp or not signatures:
        return False, "malformed signature header"

    try:
        ts_int = int(timestamp)
    except ValueError:
        return False, "invalid timestamp in signature header"

    if tolerance_seconds and abs(time.time() - ts_int) > int(tolerance_seconds):
        return False, "signature timestamp outside tolerance window"

    if isinstance(raw_body_bytes, str):
        raw_body_bytes = raw_body_bytes.encode("utf-8")
    signed_payload = timestamp.encode("utf-8") + b"." + raw_body_bytes

    tried = []
    for key_bytes in _candidate_secret_keys(signing_secret):
        expected = hmac.new(key_bytes, signed_payload, hashlib.sha256).hexdigest()
        tried.append(expected)
        for sig in signatures:
            if hmac.compare_digest(expected, sig):
                return True, "ok"

    body_sha = hashlib.sha256(raw_body_bytes).hexdigest()
    head_hex = raw_body_bytes[:32].hex()
    tail_hex = raw_body_bytes[-32:].hex() if len(raw_body_bytes) >= 32 else raw_body_bytes.hex()
    logger.warning(
        "Sublime webhook: signature mismatch. "
        f"timestamp={timestamp} body_bytes={len(raw_body_bytes)} "
        f"body_sha256={body_sha} body_head_hex={head_hex} body_tail_hex={tail_hex} "
        f"received={[s[:8] + '...' for s in signatures]} "
        f"computed={[e[:8] + '...' for e in tried]} "
        f"candidate_count={len(tried)}"
    )
    return False, "signature mismatch"


def _extract_email(value):
    """Sublime email fields can be a plain string or {email: {email: '...'}}."""
    if not value:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        inner = value.get("email")
        if isinstance(inner, str):
            return inner
        if isinstance(inner, dict):
            return inner.get("email", "") or ""
    return ""


def _lookup_container_id_by_sdi(rest_base_url, soar_headers, sdi, label, asset_id, logger):
    """Find an existing container with this SDI / label / asset and return its id.

    Used to merge a follow-up webhook (same canonical_id) into the existing
    container instead of failing on SOAR's per-asset+label SDI uniqueness rule.
    Returns None if no matching container exists.
    """
    try:
        params = {
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
            timeout=15,
        )
        if resp.status_code != 200:
            logger.warning(f"Sublime webhook: container lookup by SDI failed: HTTP {resp.status_code} {resp.text[:200]}")
            return None
        rows = resp.json().get("data") or []
        if rows and isinstance(rows, list):
            return rows[0].get("id")
    except Exception as e:
        logger.warning(f"Sublime webhook: container lookup by SDI exception: {e!s}")
    return None


def _create_error_container(
    rest_base_url, soar_headers, *, reason, raw_body, payload, cfg_label, cfg_sensitivity, logger, message_id=None, extra=None
):
    """Create a SOAR container that records a webhook failure.

    Tags it `error` so it can be filtered out of normal triage, sets severity
    high so it shows up in admin dashboards, and attaches the offending payload
    + reason as a JSON vault file for debugging.
    """
    import json as _json
    import time as _time

    ident = f"sublime-webhook-error-{int(_time.time() * 1000)}-{message_id or 'event'}"
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
            timeout=30,
        )
        c_json = c_resp.json() if c_resp.content else {}
        container_id = c_json.get("id")
        if not (c_resp.status_code in (200, 201) and container_id):
            logger.warning(f"Sublime webhook: error container create failed: HTTP {c_resp.status_code} {c_json}")
            return None
    except Exception as e:
        logger.warning(f"Sublime webhook: error container create exception: {e!s}")
        return None

    try:
        body_text = raw_body.decode("utf-8", errors="replace") if isinstance(raw_body, (bytes, bytearray)) else (raw_body or "")
        debug_doc = {
            "reason": reason,
            "message_id": message_id,
            "parsed_payload": payload,
            "raw_body": body_text,
        }
        if extra:
            debug_doc["extra"] = extra
        debug_bytes = _json.dumps(debug_doc, indent=2, default=str).encode("utf-8")
        debug_b64 = base64.b64encode(debug_bytes).decode("utf-8")
        requests.post(
            f"{rest_base_url}container_attachment",
            headers=soar_headers,
            json={
                "container_id": container_id,
                "file_name": f"sublime-webhook-error-{int(_time.time())}.json",
                "file_content": debug_b64,
                "metadata": {"contains": ["vault id"]},
            },
            verify=False,
            timeout=30,
        )
    except Exception as e:
        logger.warning(f"Sublime webhook: error debug attachment exception: {e!s}")

    try:
        status_resp = requests.post(
            f"{rest_base_url}container/{container_id}",
            headers=soar_headers,
            json={"status": "error"},
            verify=False,
            timeout=15,
        )
        if status_resp.status_code not in (200, 201):
            logger.warning(
                f"Sublime webhook: could not set container status to 'error': HTTP {status_resp.status_code} {status_resp.text[:200]}"
            )
    except Exception as e:
        logger.warning(f"Sublime webhook: could not set container status to 'error': {e!s}")

    return container_id


def _build_artifact_from_webhook_message(data, event, container_id):
    """Build a SOAR artifact dict from a Sublime webhook event `data` block.

    Payloads `data` contains the full MDM: data.message has compact
    IDs, while data.sender, data.recipients, data.subject, data.mailbox, etc.
    carry the full details. The raw webhook event (`event`) is preserved on
    the artifact as `raw_data` so downstream playbooks can replay the full
    Sublime payload.
    """
    if not isinstance(data, dict):
        data = {}

    message = data.get("message") or {}
    if not isinstance(message, dict):
        message = {}

    # Subject can be a string or {subject, base, is_forward, is_reply}
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
    sender_email = _extract_email(sender)
    sender_display = sender.get("display_name", "") if isinstance(sender, dict) else ""
    sender_domain = ""
    if isinstance(sender, dict):
        inner = sender.get("email")
        if isinstance(inner, dict):
            sender_domain = inner.get("domain", {}).get("domain", "") if isinstance(inner.get("domain"), dict) else ""

    recipients = data.get("recipients") or {}
    to_list = recipients.get("to") if isinstance(recipients, dict) else None
    cc_list = recipients.get("cc") if isinstance(recipients, dict) else None
    bcc_list = recipients.get("bcc") if isinstance(recipients, dict) else None
    to_emails = [_extract_email(r) for r in (to_list or []) if r]
    cc_emails = [_extract_email(r) for r in (cc_list or []) if r]
    bcc_emails = [_extract_email(r) for r in (bcc_list or []) if r]
    recipient_count = len([e for e in to_emails + cc_emails + bcc_emails if e])

    reply_to_list = data.get("reply_to") or []
    reply_to_emails = [_extract_email(r) for r in (reply_to_list or []) if r] if isinstance(reply_to_list, list) else []

    mailbox_full = data.get("mailbox") or {}
    mailbox_email = _extract_email(mailbox_full) if isinstance(mailbox_full, dict) else ""
    mailbox_ref = message.get("mailbox") or {}

    external = data.get("external") or {}
    message_type = data.get("message_type") or {}

    # Attack score (verdict, numeric score, signal breakdown)
    attack_score_verdict = data.get("attack_score_verdict", "")
    attack_score = data.get("attack_score")
    graymail_score = data.get("graymail_score")
    top_signals = data.get("attack_score_top_signals") or []
    signal_categories = [s.get("category", "") for s in top_signals if isinstance(s, dict) and s.get("category")]
    signal_names = [s.get("name", "") for s in top_signals if isinstance(s, dict) and s.get("name")]

    # Rules & actions
    flagged_rules = data.get("flagged_rules") or []
    triggered_actions = data.get("triggered_actions") or []
    rule_names = [r.get("name", "") for r in flagged_rules if isinstance(r, dict)]
    rule_ids = [r.get("id", "") for r in flagged_rules if isinstance(r, dict)]
    rule_severities = [r.get("severity", "") for r in flagged_rules if isinstance(r, dict) and r.get("severity")]
    rule_tags = sorted({t for r in flagged_rules if isinstance(r, dict) for t in (r.get("tags") or []) if t})
    action_types = [a.get("type", "") for a in triggered_actions if isinstance(a, dict)]
    action_names = [a.get("name", "") for a in triggered_actions if isinstance(a, dict) and a.get("name")]

    # Headers & authentication summary
    headers = data.get("headers") or {}
    if not isinstance(headers, dict):
        headers = {}
    header_message_id = headers.get("message_id", "") or ""
    header_date = headers.get("date", "") or ""
    header_in_reply_to = headers.get("in_reply_to", "") or ""
    header_references = headers.get("references", "") or ""
    auth_summary = headers.get("auth_summary") or {}
    spf_result = (auth_summary.get("spf") or {}).get("pass") if isinstance(auth_summary.get("spf"), dict) else None
    dkim_result = (auth_summary.get("dkim") or {}).get("pass") if isinstance(auth_summary.get("dkim"), dict) else None
    dmarc_result = (auth_summary.get("dmarc") or {}).get("pass") if isinstance(auth_summary.get("dmarc"), dict) else None

    # Attachments
    attachments = data.get("attachments") or []
    if not isinstance(attachments, list):
        attachments = []
    attachment_names = [a.get("file_name", "") for a in attachments if isinstance(a, dict) and a.get("file_name")]
    attachment_hashes = [a.get("md5", "") for a in attachments if isinstance(a, dict) and a.get("md5")]

    # Links/URLs in the body
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
        "externalMessageId": message.get("external_id", "") or external.get("message_id", ""),
        "messageSourceId": message.get("message_source_id", ""),
        "rfc822MessageId": header_message_id,
        "mailboxId": mailbox_ref.get("id", "") if isinstance(mailbox_ref, dict) else "",
        "mailboxExternalId": mailbox_ref.get("external_id", "") if isinstance(mailbox_ref, dict) else "",
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
        "isInbound": bool(message_type.get("inbound")) if isinstance(message_type, dict) else None,
        "isOutbound": bool(message_type.get("outbound")) if isinstance(message_type, dict) else None,
        "isInternal": bool(message_type.get("internal")) if isinstance(message_type, dict) else None,
        "attackScoreVerdict": attack_score_verdict,
        "attackScore": attack_score if isinstance(attack_score, (int, float)) else None,
        "graymailScore": graymail_score if isinstance(graymail_score, (int, float)) else None,
        "attackScoreTopSignals": ", ".join(signal_categories),
        "attackScoreTopSignalNames": ", ".join(signal_names),
        "landedInSpam": bool(message.get("landed_in_spam")) if message.get("landed_in_spam") is not None else None,
        "flaggedRules": ", ".join(rule_names),
        "flaggedRuleIds": ", ".join(rule_ids),
        "flaggedRuleSeverities": ", ".join(rule_severities),
        "flaggedRuleTags": ", ".join(rule_tags),
        "triggeredActionTypes": ", ".join(action_types),
        "triggeredActionNames": ", ".join(action_names),
        "attachmentCount": len(attachments) or None,
        "attachmentFileNames": ", ".join(attachment_names),
        "attachmentMd5Hashes": ", ".join(attachment_hashes),
        "linkCount": len(link_urls) or None,
        "linkUrls": ", ".join(link_urls[:50]),
        "eventType": event.get("type", ""),
        "eventId": event.get("id", ""),
        "eventCreatedAt": event.get("created_at", ""),
    }
    cef = {k: v for k, v in cef.items() if v not in (None, "", False) or v is True}

    name = subject or (rule_names[0] if rule_names else f"Sublime message {message.get('id', 'unknown')}")

    return {
        "name": name,
        "label": "flagged message",
        "container_id": container_id,
        "source_data_identifier": message.get("id", "") or event.get("id", ""),
        "cef": cef,
        "cef_types": {
            "messageId": ["message id"],
            "canonicalId": ["message group id"],
            "rfc822MessageId": ["email message id"],
            "senderEmail": ["email"],
            "senderDomain": ["domain"],
            "fromEmail": ["email"],
            "replyToEmails": ["email"],
            "mailboxEmail": ["email"],
            "toRecipients": ["email"],
            "ccRecipients": ["email"],
            "bccRecipients": ["email"],
            "attachmentMd5Hashes": ["md5"],
            "linkUrls": ["url"],
        },
        "data": data,
        "raw_data": event,
        "run_automation": True,
    }


def handle_request(request, path_parts):
    """REST handler for inbound Sublime Security webhook Actions.

    Parses the Sublime webhook event, verifies the X-Sublime-Signature if a
    signing secret is configured on the asset, then creates a container +
    artifact for the flagged message.
    """
    import json as _json
    import logging

    try:
        from django.http import HttpResponse, JsonResponse
    except ImportError:  # pragma: no cover
        HttpResponse = None
        JsonResponse = None

    try:
        from phantom_common.install_info import get_rest_base_url

        rest_base_url = get_rest_base_url()
    except Exception:
        rest_base_url = "https://127.0.0.1/rest/"

    logger = logging.getLogger(__name__)

    def _respond(status_code, body):
        if JsonResponse is not None:
            return JsonResponse(body, status=status_code)
        return _json.dumps(body)

    auth_token = None
    try:
        auth_token = request.META.get("HTTP_PH_AUTH_TOKEN")
    except Exception:
        auth_token = None
    if not auth_token:
        try:
            auth_token = request.headers.get("ph-auth-token")
        except Exception:
            auth_token = None
    if not auth_token:
        return _respond(401, {"error": 'Missing "ph-auth-token" header'})

    soar_headers = {"ph-auth-token": auth_token}

    cfg_label = "events"
    cfg_severity = "medium"
    cfg_sensitivity = "amber"
    signing_secret = None
    signature_tolerance = 300
    fetch_eml = False
    sublime_base_url = ""
    sublime_api_key = ""
    sublime_verify_cert = True
    sdi_strategy = "canonical_id"
    asset_id = None
    try:
        asset_name = path_parts[0] if path_parts else None
        if asset_name:
            asset_resp = requests.get(
                f"{rest_base_url}asset",
                headers=soar_headers,
                params={"_filter_name": f'"{asset_name}"'},
                verify=False,
                timeout=10,
            )
            asset_cfg = {}
            if asset_resp.status_code == 200:
                asset_json = asset_resp.json()
                data = asset_json.get("data") or []
                if data and isinstance(data, list):
                    asset_record = data[0] or {}
                    asset_cfg = asset_record.get("configuration") or {}
                    asset_id = asset_record.get("id")
            if isinstance(asset_cfg, dict):
                cfg_label = asset_cfg.get("webhook_container_label") or cfg_label
                cfg_severity = asset_cfg.get("webhook_container_severity") or cfg_severity
                cfg_sensitivity = asset_cfg.get("webhook_container_sensitivity") or cfg_sensitivity
                signing_secret = asset_cfg.get("webhook_signing_secret") or None
                if asset_cfg.get("webhook_signature_tolerance_seconds") is not None:
                    try:
                        signature_tolerance = int(asset_cfg["webhook_signature_tolerance_seconds"])
                    except (TypeError, ValueError):
                        pass
                fetch_eml = bool(asset_cfg.get("webhook_fetch_eml"))
                sublime_api_key = asset_cfg.get("api_key") or ""
                sublime_verify_cert = bool(asset_cfg.get("verify_server_cert", True))
                region = asset_cfg.get("region", "NA-East")
                if region == "Custom":
                    sublime_base_url = (asset_cfg.get("base_url") or "").rstrip("/")
                else:
                    sublime_base_url = BASE_URLS.get(region, BASE_URLS["NA-East"])
                sdi_strategy = (asset_cfg.get("webhook_container_sdi_strategy") or "canonical_id").lower()
    except Exception as e:
        logger.warning(f"Sublime webhook: failed to load asset config: {e!s}")

    if request.method != "POST":
        return _respond(405, {"error": "Method Not Allowed. Use POST."})

    raw_body = request.body if isinstance(request.body, (bytes, bytearray)) else (request.body or "").encode("utf-8")

    if signing_secret:
        sig_header = None
        try:
            sig_header = request.META.get("HTTP_X_SUBLIME_SIGNATURE")
        except Exception:
            sig_header = None
        if not sig_header:
            try:
                sig_header = request.headers.get("X-Sublime-Signature")
            except Exception:
                sig_header = None
        ok, reason = _verify_sublime_signature(sig_header, raw_body, signing_secret, signature_tolerance)
        if not ok:
            return _respond(401, {"error": f"signature verification failed: {reason}"})

    try:
        payload = _json.loads(raw_body.decode("utf-8")) if raw_body else {}
    except Exception as e:
        _create_error_container(
            rest_base_url,
            soar_headers,
            reason=f"Invalid JSON: {e!s}",
            raw_body=raw_body,
            payload=None,
            cfg_label=cfg_label,
            cfg_sensitivity=cfg_sensitivity,
            logger=logger,
        )
        return _respond(400, {"error": f"Invalid JSON: {e!s}"})

    if not isinstance(payload, dict):
        _create_error_container(
            rest_base_url,
            soar_headers,
            reason="Payload must be a JSON object",
            raw_body=raw_body,
            payload=payload,
            cfg_label=cfg_label,
            cfg_sensitivity=cfg_sensitivity,
            logger=logger,
        )
        return _respond(400, {"error": "Payload must be a JSON object"})

    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    data_blocks = []

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

    severity_rank = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    def _derive_severity(rules):
        if str(cfg_severity).lower() != "use alert severity":
            return cfg_severity

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

    def _derive_subject(d):
        sf = d.get("subject") if isinstance(d, dict) else None
        if isinstance(sf, dict):
            return sf.get("subject") or sf.get("base") or ""
        return sf or ""

    results = []
    errors = []

    for block in data_blocks:
        if not isinstance(block, dict):
            block = {}
        message = block.get("message") if isinstance(block.get("message"), dict) else {}
        flagged_rules = block.get("flagged_rules") or []
        if not isinstance(flagged_rules, list):
            flagged_rules = []

        message_id = message.get("id") or block.get("id") or event_id or "unknown"
        canonical_id = message.get("canonical_id") or block.get("canonical_id") or message_id

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

        # SDI strategy: canonical_id groups same-group messages into one
        # container (default), message_id makes one container per message,
        # event_message_id is always unique (no dedup at all).
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
            "tags": [t for r in flagged_rules if isinstance(r, dict) for t in (r.get("tags") or [])],
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
                timeout=30,
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
                existing_id = c_json.get("existing_container_id") if isinstance(c_json, dict) else None
                if not existing_id:
                    existing_id = _lookup_container_id_by_sdi(
                        rest_base_url,
                        soar_headers,
                        container_sdi,
                        cfg_label,
                        asset_id,
                        logger,
                    )
                if existing_id:
                    container_id = existing_id
                    merged_into_existing = True
                else:
                    reason = f"container dedup but lookup failed: HTTP {c_resp.status_code} {c_json}"
                    err_cid = _create_error_container(
                        rest_base_url,
                        soar_headers,
                        reason=reason,
                        raw_body=raw_body,
                        payload=payload,
                        cfg_label=cfg_label,
                        cfg_sensitivity=cfg_sensitivity,
                        logger=logger,
                        message_id=message_id,
                        extra={"failed_container": container},
                    )
                    errors.append({"message_id": message_id, "error": reason, "error_container_id": err_cid})
                    continue
            elif not (c_resp.status_code in (200, 201) and container_id):
                reason = f"container create failed: HTTP {c_resp.status_code} {c_json}"
                err_cid = _create_error_container(
                    rest_base_url,
                    soar_headers,
                    reason=reason,
                    raw_body=raw_body,
                    payload=payload,
                    cfg_label=cfg_label,
                    cfg_sensitivity=cfg_sensitivity,
                    logger=logger,
                    message_id=message_id,
                    extra={"failed_container": container},
                )
                errors.append({"message_id": message_id, "error": reason, "error_container_id": err_cid})
                continue
        except Exception as e:
            reason = f"container create exception: {e!s}"
            err_cid = _create_error_container(
                rest_base_url,
                soar_headers,
                reason=reason,
                raw_body=raw_body,
                payload=payload,
                cfg_label=cfg_label,
                cfg_sensitivity=cfg_sensitivity,
                logger=logger,
                message_id=message_id,
                extra={"failed_container": container},
            )
            errors.append({"message_id": message_id, "error": reason, "error_container_id": err_cid})
            continue

        try:
            artifact = _build_artifact_from_webhook_message(block, payload, container_id)
        except Exception as e:
            reason = f"artifact build exception: {e!s}"
            err_cid = _create_error_container(
                rest_base_url,
                soar_headers,
                reason=reason,
                raw_body=raw_body,
                payload=payload,
                cfg_label=cfg_label,
                cfg_sensitivity=cfg_sensitivity,
                logger=logger,
                message_id=message_id,
            )
            errors.append({"message_id": message_id, "container_id": container_id, "error": reason, "error_container_id": err_cid})
            continue

        try:
            a_resp = requests.post(
                f"{rest_base_url}artifact",
                headers=soar_headers,
                json=artifact,
                verify=False,
                timeout=30,
            )
            a_json = a_resp.json() if a_resp.content else {}
            if a_resp.status_code not in (200, 201) or not a_json.get("id"):
                reason = f"artifact create failed: HTTP {a_resp.status_code} {a_json}"
                err_cid = _create_error_container(
                    rest_base_url,
                    soar_headers,
                    reason=reason,
                    raw_body=raw_body,
                    payload=payload,
                    cfg_label=cfg_label,
                    cfg_sensitivity=cfg_sensitivity,
                    logger=logger,
                    message_id=message_id,
                    extra={"failed_artifact": artifact},
                )
                errors.append({"message_id": message_id, "container_id": container_id, "error": reason, "error_container_id": err_cid})
                continue
        except Exception as e:
            reason = f"artifact create exception: {e!s}"
            err_cid = _create_error_container(
                rest_base_url,
                soar_headers,
                reason=reason,
                raw_body=raw_body,
                payload=payload,
                cfg_label=cfg_label,
                cfg_sensitivity=cfg_sensitivity,
                logger=logger,
                message_id=message_id,
                extra={"failed_artifact": artifact},
            )
            errors.append({"message_id": message_id, "container_id": container_id, "error": reason, "error_container_id": err_cid})
            continue

        eml_vault_id = None
        if fetch_eml and sublime_base_url and sublime_api_key and message_id and message_id != "unknown":
            try:
                eml_url = f"{sublime_base_url}/v0/messages/{message_id}/eml"
                eml_resp = requests.get(
                    eml_url,
                    headers={"Authorization": f"Bearer {sublime_api_key}", "Accept": "*/*"},
                    verify=sublime_verify_cert,
                    timeout=60,
                )
                if eml_resp.status_code == 200 and eml_resp.content:
                    eml_b64 = base64.b64encode(eml_resp.content).decode("utf-8")
                    file_name = f"message_{message_id}.eml"
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
                        timeout=60,
                    )
                    if va_resp.status_code in (200, 201):
                        va_json = va_resp.json() if va_resp.content else {}
                        eml_vault_id = va_json.get("vault_id") or va_json.get("hash") or va_json.get("id")
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
                                timeout=30,
                            )
                    else:
                        logger.warning(
                            f"Sublime webhook: vault upload failed for message {message_id}: HTTP {va_resp.status_code} {va_resp.text[:200]}"
                        )
                else:
                    logger.warning(f"Sublime webhook: EML fetch failed for message {message_id}: HTTP {eml_resp.status_code}")
            except Exception as e:
                logger.warning(f"Sublime webhook: EML fetch/upload exception for message {message_id}: {e!s}")

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

    response_body = {
        "status": "success" if not errors else ("partial_success" if results else "error"),
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
        status_code = 207  # Multi-Status: some messages succeeded, some failed
    else:
        status_code = 200

    return _respond(status_code, response_body)


if __name__ == "__main__":
    import sys

    import pudb

    pudb.set_trace()

    connector = SublimeSecurityConnector()
    connector.print_progress_message = True

    sys.exit(0)
