"""Contract tests for action request bodies and output coercion."""

import base64
import json

import pytest
from soar_sdk.exceptions import ActionFailure

from src import app as app_mod
from src import impl
from src.client import format_server_error
from src.helpers import coerce_output


class Soar:
    def __init__(self) -> None:
        self.message = ""
        self.summary = None

    def set_message(self, message: str) -> None:
        self.message = message

    def set_summary(self, summary) -> None:
        self.summary = summary


class StubClient:
    def __init__(self, gets=None, posts=None, puts=None) -> None:
        self.gets = gets or {}
        self.posts = posts or {}
        self.puts = puts or {}
        self.calls: list[tuple] = []

    def get(self, endpoint, params=None, **kwargs):
        self.calls.append(("GET", endpoint, params, kwargs))
        body = self.gets[endpoint]
        return body(params) if callable(body) else body

    def post(self, endpoint, json_data=None, **kwargs):
        self.calls.append(("POST", endpoint, json_data))
        body = self.posts.get(endpoint, {})
        return body(json_data) if callable(body) else body

    def put(self, endpoint, json_data=None, **kwargs):
        self.calls.append(("PUT", endpoint, json_data))
        body = self.puts.get(endpoint, json_data)
        return body(json_data) if callable(body) else body


def _patch_client(monkeypatch, client: StubClient) -> None:
    monkeypatch.setattr(impl, "_client", lambda asset: client)


def test_list_message_groups_defaults_required_filters(monkeypatch):
    client = StubClient(gets={"/v0/message-groups": {"message_groups": []}})
    _patch_client(monkeypatch, client)
    impl.list_message_groups(
        app_mod.ListMessageGroupsParams(),
        Soar(),
        object(),
        app_mod.ListMessageGroupsOutput,
    )
    params = client.calls[0][2]
    assert params["flagged"] is True
    assert "created_at__gte" in params
    assert "canonical_id__is" not in params


def test_list_message_groups_keeps_explicit_canonical_filter(monkeypatch):
    client = StubClient(gets={"/v0/message-groups": {"message_groups": []}})
    _patch_client(monkeypatch, client)
    impl.list_message_groups(
        app_mod.ListMessageGroupsParams(canonical_id="abc", flagged=False),
        Soar(),
        object(),
        app_mod.ListMessageGroupsOutput,
    )
    params = client.calls[0][2]
    assert params["canonical_id__is"] == ["abc"]
    assert params["flagged"] is False
    assert "created_at__gte" not in params


def test_list_user_reports_defaults_window(monkeypatch):
    client = StubClient(gets={"/v0/user-reports": {"user_reports": []}})
    _patch_client(monkeypatch, client)
    impl.list_user_reports(
        app_mod.ListUserReportsParams(),
        Soar(),
        object(),
        app_mod.ListUserReportsOutput,
    )
    assert "reported_at[gte]" in client.calls[0][2]


def test_search_message_groups_requires_a_term():
    with pytest.raises(ActionFailure, match="search term"):
        impl.search_message_groups(
            app_mod.SearchMessageGroupsParams(),
            Soar(),
            object(),
            app_mod.SearchMessageGroupsOutput,
        )


def test_siem_summary_uses_timestamp_filters_and_flattens_fields(monkeypatch):
    client = StubClient(
        gets={
            "/v0/message-groups/siem-summary": {
                "message_groups": [
                    {
                        "id": "grp",
                        "attack_score_verdict": "graymail",
                        "subjects": {"values": ["Hello"], "total": 1},
                        "senders": {"values": ["a@example.invalid"], "total": 1},
                        "message_count": 2,
                    }
                ],
                "cursor": "next",
                "total": {"count": 4, "truncated": False},
                "truncated": False,
            }
        }
    )
    _patch_client(monkeypatch, client)
    soar = Soar()
    rows = impl.get_message_groups_siem_summary(
        app_mod.GetMessageGroupsSiemSummaryParams(created_at_gte="2026-11-01T00:00:00Z"),
        soar,
        object(),
        app_mod.GetMessageGroupsSiemSummaryOutput,
        summary_cls=app_mod.GetMessageGroupsSiemSummarySummary,
    )
    params = client.calls[0][2]
    assert params["timestamp__gte"] == "2026-11-01T00:00:00Z"
    assert "created_at__gte" not in params
    assert "offset" not in params
    assert params["type"] == "flagged"
    assert rows[0].subjects == "Hello"
    assert rows[0].attack_score_verdict == "graymail"
    assert soar.summary.cursor == "next"
    assert soar.summary.total == 4


def test_list_dlp_release_requests_reads_results(monkeypatch):
    client = StubClient(
        gets={"/v0/dlp/release-requests": {"results": [{"id": "rel-1", "status": "pending"}]}}
    )
    _patch_client(monkeypatch, client)
    rows = impl.list_dlp_release_requests(
        app_mod.ListDlpReleaseRequestsParams(),
        Soar(),
        object(),
        app_mod.ListDlpReleaseRequestsOutput,
    )
    assert len(rows) == 1
    assert rows[0].id == "rel-1"
    assert rows[0].status == "pending"


def test_update_rule_preserves_omitted_name_and_source(monkeypatch):
    current = {
        "id": "rule-1",
        "name": "Existing",
        "source": 'type.inbound\nand sender.email.domain.root_domain == "example.invalid"',
        "severity": "low",
        "description": "old",
        "active": False,
        "tags": ["keep"],
        "created_at": "2026-01-01T00:00:00Z",
    }
    client = StubClient(
        gets={"/v0/rules/rule-1": current},
        puts={"/v0/rules/rule-1": lambda body: body},
    )
    _patch_client(monkeypatch, client)
    impl.update_rule(
        app_mod.UpdateRuleParams(rule_id="rule-1", description="patched"),
        Soar(),
        object(),
        app_mod.UpdateRuleOutput,
    )
    body = client.calls[1][2]
    assert body["name"] == "Existing"
    assert "example.invalid" in body["source"]
    assert body["description"] == "patched"
    assert body["tags"] == ["keep"]
    assert "created_at" not in body
    assert "id" not in body


def test_analyze_raw_message_defaults_to_active_rules(monkeypatch):
    client = StubClient(posts={"/v0/messages/analyze": {"rule_results": [], "query_results": []}})
    _patch_client(monkeypatch, client)
    impl.analyze_raw_message(
        app_mod.AnalyzeRawMessageParams(
            base64_data=base64.b64encode(b"hello").decode(),
            run_active_detection_rules=False,
            run_all_detection_rules=False,
            run_all_insights=False,
        ),
        Soar(),
        object(),
        app_mod.AnalyzeRawMessageOutput,
    )
    assert client.calls[0][2]["run_active_detection_rules"] is True


def test_rule_history_dict_is_json_string():
    output = coerce_output(
        app_mod.ListRuleHistoryOutput,
        {"history": {"rule-1": {"rule": {"id": "rule-1", "name": "n"}}}},
    )
    parsed = json.loads(output.history)
    assert parsed["rule-1"]["rule"]["id"] == "rule-1"


def test_format_server_error_uses_nested_message():
    text = format_server_error(
        400,
        {"error": {"type": "invalid_input", "message": "Name contains invalid characters"}},
    )
    assert text == "Error from server. Status Code: 400. Error: Name contains invalid characters"
