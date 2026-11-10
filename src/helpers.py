# File: helpers.py
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

"""Shared helpers for Sublime Security SOAR actions and webhooks."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import time
import urllib.parse
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError
from soar_sdk.abstract import SOARClient
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger

from .consts import DEFAULT_LIMIT, MAX_LIMIT

logger = getLogger()

T = TypeVar("T", bound=BaseModel)


def safe_id(value: Any) -> str:
    """URL-encode a path-segment identifier so it cannot alter the request path."""
    return urllib.parse.quote(str(value), safe="")


def safe_filename(file_name: str | None, default: str = "attachment") -> str:
    """Sanitize a filename for vault temp writes (no path traversal)."""
    safe_name = os.path.basename(file_name or "")
    safe_name = "".join(c for c in safe_name if c.isprintable()).strip() or default
    return safe_name


def clamp_limit(limit: Any, maximum: int | None = None) -> int:
    if maximum is None:
        maximum = MAX_LIMIT
    if limit is None:
        return DEFAULT_LIMIT
    return min(int(limit), maximum)


def parse_comma_list(value: Any) -> list[str]:
    if not value:
        return []
    return [v.strip() for v in str(value).split(",") if v.strip()]


def decode_base64_strict(data: str) -> bytes:
    """Strict base64 decode (rejects non-alphabet characters)."""
    try:
        return base64.b64decode(data, validate=True)
    except Exception as e:
        raise ActionFailure(f"Error decoding base64 data: {e!s}") from e


def get_vault_bytes(soar: SOARClient, vault_id: str) -> bytes:
    """Read vault file bytes; vault failures raise ActionFailure."""
    try:
        attachments = soar.vault.get_attachment(vault_id=vault_id)
    except Exception as e:
        raise ActionFailure(f"Could not find vault file: {e!s}") from e
    if not attachments:
        raise ActionFailure("No vault file found for the provided Vault ID")
    attachment = attachments[0]
    path = getattr(attachment, "path", None)
    if not path:
        raise ActionFailure("Could not determine file path from vault")
    try:
        with open(path, "rb") as f:
            return f.read()
    except Exception as e:
        raise ActionFailure(f"Error reading vault file: {e!s}") from e


def get_file_bytes(
    soar: SOARClient,
    vault_id: str | None = None,
    base64_data: str | None = None,
    *,
    strict_base64: bool = True,
) -> bytes:
    """Retrieve file data from a Vault ID or base64 string."""
    if vault_id:
        return get_vault_bytes(soar, vault_id)
    if base64_data:
        if strict_base64:
            return decode_base64_strict(base64_data)
        try:
            return base64.b64decode(base64_data)
        except Exception as e:
            raise ActionFailure(f"Error decoding base64 data: {e!s}") from e
    raise ActionFailure("Either vault_id or base64_data must be provided")


def get_file_as_base64(
    soar: SOARClient,
    vault_id: str | None = None,
    base64_data: str | None = None,
    *,
    strict_base64: bool = True,
) -> str:
    """Return base64 string from vault_id or base64_data param."""
    if vault_id:
        file_bytes = get_vault_bytes(soar, vault_id)
        return base64.b64encode(file_bytes).decode("utf-8")
    if base64_data:
        if strict_base64:
            # Validate round-trip without altering padding semantics for upstream APIs
            decode_base64_strict(base64_data)
        return base64_data
    raise ActionFailure("Either vault_id or base64_data must be provided")


def save_to_vault(
    soar: SOARClient,
    data_bytes: bytes,
    file_name: str,
    container_id: int | None = None,
) -> str:
    """Save bytes to the SOAR vault. Vault failures raise ActionFailure."""
    safe_name = safe_filename(file_name)
    if container_id is None:
        try:
            container_id = soar.get_executing_container_id()
        except Exception as e:
            raise ActionFailure(f"Failed to resolve container for vault save: {e!s}") from e
    try:
        vault_id = soar.vault.create_attachment(
            container_id=container_id,
            file_content=data_bytes,
            file_name=safe_name,
        )
    except Exception as e:
        raise ActionFailure(f"Failed to save '{safe_name}' to vault: {e!s}") from e
    if not vault_id:
        raise ActionFailure(f"Failed to save '{safe_name}' to vault: empty vault id")
    return vault_id


def iter_image_bytes(data: Any):
    """Yield image byte blobs from a Sublime image response."""
    if not data:
        return
    if isinstance(data, (bytes, bytearray)):
        yield bytes(data)
        return
    if isinstance(data, str):
        try:
            yield base64.b64decode(data)
        except Exception as e:
            logger.debug("Failed to base64-decode image data: %s", e)
        return
    if isinstance(data, list):
        if not data:
            return
        if all(isinstance(el, (list, tuple)) for el in data):
            for el in data:
                try:
                    yield bytes(el)
                except Exception as e:
                    logger.debug("Failed to convert image list: %s", e)
        elif all(isinstance(el, str) for el in data):
            for el in data:
                try:
                    yield base64.b64decode(el)
                except Exception as e:
                    logger.debug("Failed to base64-decode image entry: %s", e)
        else:
            try:
                yield bytes(data)
            except Exception as e:
                logger.debug("Failed to convert image list: %s", e)


def build_review_body(params: Any, *, include_ids: bool = True) -> dict[str, Any]:
    """Build the standard review request body for message group actions."""
    body: dict[str, Any] = {}
    if include_ids:
        ids = getattr(params, "message_group_ids", None)
        body["message_group_ids"] = parse_comma_list(ids)
    classification = getattr(params, "classification", None)
    if classification:
        body["classification"] = classification
    report_label = getattr(params, "report_label", None)
    if report_label:
        body["report_label"] = report_label
    review_comment = getattr(params, "review_comment", None)
    if review_comment:
        body["review_comment"] = review_comment
    return body


def _default_for_annotation(annotation: Any) -> Any:
    origin = getattr(annotation, "__origin__", None)
    args = getattr(annotation, "__args__", ())
    if origin is list:
        return []
    if origin is dict:
        return {}
    # Optional[X] / X | None
    if origin is type(None):
        return None
    non_none = [a for a in args if a is not type(None)]
    if type(None) in args and non_none:
        return None
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return coerce_output(annotation, {})
    if annotation is str:
        return ""
    if annotation is bool:
        return False
    if annotation is int:
        return 0
    if annotation is float:
        return 0.0
    return None


def coerce_output(model_cls: type[T], data: Any) -> T:
    """Coerce a loosely-shaped API dict into an ActionOutput / BaseModel.

    Missing required fields are filled with empty defaults so strict ActionOutput
    schemas still validate for partial API payloads.
    """
    if data is None:
        data = {}
    if isinstance(data, model_cls):
        return data
    if not isinstance(data, dict):
        data = {"value": data}

    payload = dict(data)
    for name, field in model_cls.model_fields.items():
        key = name
        if key not in payload and field.alias and field.alias in payload:
            continue
        if key not in payload:
            # Prefer None for optional fields; ActionOutput fills those itself.
            annotation = field.annotation
            try:
                # Heuristic: if optional, skip (ActionOutput fills None)
                args = getattr(annotation, "__args__", ())
                if type(None) in args:
                    continue
            except Exception:
                pass
            default = _default_for_annotation(annotation)
            if default is not None or (
                isinstance(annotation, type) and annotation in (str, bool, int, float)
            ):
                payload[key] = default

        # Recurse into nested models when value is a dict
        value = payload.get(key)
        annotation = field.annotation
        args = [a for a in getattr(annotation, "__args__", ()) if a is not type(None)]
        nested_cls = None
        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
            nested_cls = annotation
        elif args and isinstance(args[0], type) and issubclass(args[0], BaseModel):
            if getattr(annotation, "__origin__", None) is list and isinstance(
                value, list
            ):
                payload[key] = [coerce_output(args[0], item) for item in value]
                continue
            nested_cls = args[0]
        if nested_cls is not None and isinstance(value, dict):
            payload[key] = coerce_output(nested_cls, value)

    try:
        return model_cls.model_validate(payload)
    except ValidationError:
        # Last resort: construct without full validation where possible
        try:
            return model_cls.model_construct(**payload)
        except Exception as e:
            raise ActionFailure(
                f"Failed to coerce API response into {model_cls.__name__}: {e!s}"
            ) from e


def coerce_many(model_cls: type[T], items: list[Any] | None) -> list[T]:
    return [coerce_output(model_cls, item) for item in (items or [])]


# ---------------------------------------------------------------------------
# Webhook signature helpers
# ---------------------------------------------------------------------------


def candidate_secret_keys(signing_secret: Any):
    """Yield HMAC key candidates for a configured Sublime signing secret."""
    if signing_secret is None:
        return
    if isinstance(signing_secret, (bytes, bytearray)):
        yield bytes(signing_secret)
        return

    s = str(signing_secret).strip()
    if not s:
        return

    raw = s.encode("utf-8")
    yield raw
    seen = {raw}

    if all(c in "0123456789abcdefABCDEF" for c in s) and len(s) % 2 == 0:
        try:
            hex_bytes = bytes.fromhex(s)
        except ValueError:
            hex_bytes = None
        if hex_bytes and hex_bytes not in seen:
            seen.add(hex_bytes)
            yield hex_bytes

    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        for padded in (s, s + "=" * (-len(s) % 4)):
            try:
                decoded = decoder(padded)
            except Exception:
                continue
            if decoded and decoded not in seen:
                seen.add(decoded)
                yield decoded


def verify_sublime_signature(
    header_value: str | None,
    raw_body_bytes: bytes,
    signing_secret: Any,
    tolerance_seconds: float | int | None,
) -> tuple[bool, str]:
    """Verify the X-Sublime-Signature header. Returns (ok, reason).

    Does not log raw webhook body bytes.
    """
    if not header_value:
        return False, "missing X-Sublime-Signature header"
    if not signing_secret:
        return False, "no signing secret configured"

    timestamp = None
    signatures: list[str] = []
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

    tried: list[str] = []
    for key_bytes in candidate_secret_keys(signing_secret):
        expected = hmac.new(key_bytes, signed_payload, hashlib.sha256).hexdigest()
        tried.append(expected)
        for sig in signatures:
            if hmac.compare_digest(expected, sig):
                return True, "ok"

    body_sha = hashlib.sha256(raw_body_bytes).hexdigest()
    logger.warning(
        "Sublime webhook: signature mismatch. "
        "timestamp=%s body_bytes=%s body_sha256=%s "
        "received=%s computed=%s candidate_count=%s",
        timestamp,
        len(raw_body_bytes),
        body_sha,
        [s[:8] + "..." for s in signatures],
        [e[:8] + "..." for e in tried],
        len(tried),
    )
    return False, "signature mismatch"


def extract_email(value: Any) -> str:
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


def header_get(headers: dict[str, str], name: str) -> str | None:
    """Case-insensitive header lookup."""
    if not headers:
        return None
    lower = name.lower()
    for k, v in headers.items():
        if k.lower() == lower:
            return v
    return None
