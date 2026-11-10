# File: client.py
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

"""HTTP client for the Sublime Security Platform API."""

from __future__ import annotations

from typing import Any

import requests
from soar_sdk.exceptions import ActionFailure, AssetMisconfiguration
from soar_sdk.logging import getLogger

from .consts import BASE_URLS, DEFAULT_TIMEOUT, RAW_TIMEOUT

logger = getLogger()


def format_server_error(status_code: int, payload: Any) -> str:
    """Turn a Sublime error body into a single action message.

    The API returns ``{"error": {"type": "...", "message": "..."}}``. Surface the
    message text instead of the raw object.
    """
    detail = "Unknown error"
    if isinstance(payload, dict):
        err = payload.get("error", payload.get("message"))
        if isinstance(err, dict):
            detail = str(err.get("message") or err.get("type") or err)
        elif err:
            detail = str(err)
    elif isinstance(payload, str) and payload:
        detail = payload[:200]
    return f"Error from server. Status Code: {status_code}. Error: {detail}"


class SublimeClient:
    """Thin requests wrapper with auth, timeouts, and ActionFailure mapping."""

    def __init__(self, asset: Any) -> None:
        region = getattr(asset, "region", None) or "NA-East"
        if region == "Custom":
            base_url = (getattr(asset, "base_url", None) or "").rstrip("/")
            if not base_url:
                raise AssetMisconfiguration(
                    "Custom region selected but no base URL provided"
                )
        else:
            base_url = BASE_URLS.get(region, BASE_URLS["NA-East"])

        api_key = getattr(asset, "api_key", None)
        if not api_key:
            raise AssetMisconfiguration("API key is required")

        verify = getattr(asset, "verify_server_cert", True)
        if verify is None:
            verify = True

        self.base_url = base_url.rstrip("/")
        self.verify = bool(verify)
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def request(
        self,
        method: str,
        endpoint: str,
        *,
        params: dict[str, Any] | None = None,
        json_data: Any | None = None,
        data: Any | None = None,
        headers: dict[str, str] | None = None,
        timeout: tuple[float, float] | float | None = None,
        return_status_code: bool = False,
        raw: bool = False,
        accept: str | None = None,
    ) -> Any:
        """Perform an HTTP request against the Sublime API.

        Does not log response bodies or headers. On timeout raises ActionFailure.
        When return_status_code is True, returns (result, status_code) and does not
        raise on non-2xx (caller decides). Otherwise non-2xx raises ActionFailure.
        """
        url = f"{self.base_url}{endpoint}"
        request_headers = dict(self.headers)
        if accept:
            request_headers["Accept"] = accept
        if headers:
            request_headers.update(headers)
        if timeout is None:
            timeout = RAW_TIMEOUT if raw else DEFAULT_TIMEOUT

        status_code: int | None = None
        try:
            logger.debug("Making REST call to: %s", url)
            response = requests.request(
                method.upper(),
                url,
                json=json_data,
                data=data,
                headers=request_headers,
                params=params,
                verify=self.verify,
                timeout=timeout,
            )
            status_code = response.status_code
            logger.debug(
                "REST response status=%s body_bytes=%s",
                response.status_code,
                len(response.content or b""),
            )
            request_id = response.headers.get("X-Request-Id") or response.headers.get(
                "Request-Id"
            )
            if request_id:
                logger.debug("REST request_id=%s", request_id)

            if raw:
                if 200 <= response.status_code < 300:
                    result = (
                        response.content,
                        response.headers.get("Content-Type", ""),
                    )
                    return (result, status_code) if return_status_code else result
                error_message = (
                    f"Error from server. Status Code: {response.status_code}"
                )
                if return_status_code:
                    return (None, status_code)
                raise ActionFailure(error_message)

            if 200 <= response.status_code < 300:
                if response.status_code == 204 or not response.text:
                    result: Any = {}
                else:
                    try:
                        result = response.json()
                    except ValueError:
                        result = response.text
                return (result, status_code) if return_status_code else result

            if response.text:
                try:
                    error_message = format_server_error(
                        response.status_code, response.json()
                    )
                except ValueError:
                    # Avoid dumping large/unknown bodies into action messages
                    error_message = format_server_error(
                        response.status_code, response.text[:200]
                    )
            else:
                error_message = format_server_error(response.status_code, {})
            if return_status_code:
                return (None, status_code)
            raise ActionFailure(error_message)

        except ActionFailure:
            raise
        except requests.exceptions.Timeout as e:
            raise ActionFailure(f"Request timed out: {e!s}") from e
        except requests.exceptions.ConnectionError as e:
            raise ActionFailure(f"Connection error: {e!s}") from e
        except Exception as e:
            raise ActionFailure(f"Error making REST call: {e!s}") from e

    def get(self, endpoint: str, **kwargs: Any) -> Any:
        return self.request("GET", endpoint, **kwargs)

    def post(self, endpoint: str, **kwargs: Any) -> Any:
        return self.request("POST", endpoint, **kwargs)

    def put(self, endpoint: str, **kwargs: Any) -> Any:
        return self.request("PUT", endpoint, **kwargs)

    def patch(self, endpoint: str, **kwargs: Any) -> Any:
        return self.request("PATCH", endpoint, **kwargs)

    def delete(self, endpoint: str, **kwargs: Any) -> Any:
        return self.request("DELETE", endpoint, **kwargs)

    def get_raw(self, endpoint: str, **kwargs: Any) -> tuple[bytes, str]:
        return self.request("GET", endpoint, raw=True, accept="*/*", **kwargs)
