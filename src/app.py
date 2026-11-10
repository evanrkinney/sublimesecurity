from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.app import App
from soar_sdk.asset import AssetField, BaseAsset, FieldCategory
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params
from soar_sdk.webhooks.models import WebhookRequest, WebhookResponse

from . import impl
from .webhook_handler import handle_sublime_webhook

logger = getLogger()


class Asset(BaseAsset):
    region: str = AssetField(
        description="Sublime Security region",
        default="NA-East",
        value_list=[
            "NA-East",
            "NA-West",
            "Canada",
            "UK (London)",
            "Europe (Dublin)",
            "Australia",
            "Custom",
        ],
        category=FieldCategory.CONNECTIVITY,
    )
    base_url: str | None = AssetField(
        description="Custom base URL (used only when region is Custom)",
        category=FieldCategory.CONNECTIVITY,
    )
    api_key: str = AssetField(
        description="API key for Sublime Security",
        sensitive=True,
        category=FieldCategory.CONNECTIVITY,
    )
    verify_server_cert: bool | None = AssetField(
        description="Verify server certificate",
        default=True,
        category=FieldCategory.CONNECTIVITY,
    )
    webhook_container_label: str | None = AssetField(
        description="SOAR label for inbound webhook containers",
        default="events",
        category=FieldCategory.INGEST,
    )
    webhook_container_severity: str | None = AssetField(
        description="Severity for webhook containers; see README for 'use alert severity'",
        default="medium",
        value_list=["low", "medium", "high", "use alert severity"],
        category=FieldCategory.INGEST,
    )
    webhook_container_sensitivity: str | None = AssetField(
        description="TLP sensitivity for inbound webhook containers",
        default="amber",
        value_list=["white", "green", "amber", "red"],
        category=FieldCategory.INGEST,
    )
    webhook_signing_secret: str | None = AssetField(
        description="Sublime webhook signing secret (see README)",
        sensitive=True,
        category=FieldCategory.INGEST,
    )
    webhook_signature_tolerance_seconds: float | None = AssetField(
        description="Reject signatures older than this many seconds",
        default=300.0,
        category=FieldCategory.INGEST,
    )
    webhook_fetch_eml: bool | None = AssetField(
        description="Fetch each flagged message's EML into container vault",
        default=False,
        category=FieldCategory.INGEST,
    )
    webhook_container_sdi_strategy: str | None = AssetField(
        description="How webhook containers are deduplicated (see README)",
        default="canonical_id",
        value_list=["canonical_id", "message_id", "event_message_id"],
        category=FieldCategory.INGEST,
    )


class VaultIdSummary(ActionOutput):
    vault_id: str | None = None


class ScreenshotVaultSummary(ActionOutput):
    screenshot_vault_id: str | None = None
    analyzed: bool | None = None
    disposition: str | None = None
    confidence: str | None = None
    brand_name: str | None = None
    effective_url: str | None = None


app = App(
    name="sublimesecurity",
    app_type="information",
    logo="logo.svg",
    logo_dark="logo_dark.svg",
    product_vendor="Sublime Security",
    product_name="Sublime Platform",
    publisher="Splunk SOAR Community",
    appid="e58b1480-1a76-59ea-8004-92df9a9291b8",
    fips_compliant=True,
    encrypt_cache_state=True,
    encrypt_ingest_state=True,
    asset_cls=Asset,
).enable_webhooks(
    default_requires_auth=True,
    default_allowed_headers=[
        "Authorization",
        "ph-auth-token",
        "X-Sublime-Signature",
    ],
    default_ip_allowlist=[
        "66.22.9.207/32",
        "66.22.9.208/32",
        "66.22.9.209/32",
    ],
)


@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    return impl.test_connectivity(soar, asset)


class UploadBinaryParams(Params):
    vault_id: str | None = Param(
        description="Vault ID of the file to upload", cef_types=["vault id"]
    )
    base64_data: str | None = Param(
        description="Base64 encoded contents of the file (alternative to vault_id)"
    )
    file_name: str = Param(description="Name of the file")


class UploadBinaryOutput(ActionOutput):
    task_id: str


@app.action(
    description="Upload a binary to be binexploded. Results expire after 1 hour. Max original file size 37 MB",
    action_type="investigate",
    read_only=False,
)
def upload_binary(
    params: UploadBinaryParams, soar: SOARClient, asset: Asset
) -> UploadBinaryOutput:
    return impl.upload_binary(params, soar, asset, UploadBinaryOutput)


class GetBinexplodeResultsParams(Params):
    task_id: str = Param(description="Task ID returned from upload binary action")


class HashOutput(ActionOutput):
    md5: str = OutputField(cef_types=["md5"])
    sha1: str = OutputField(cef_types=["sha1"])
    sha256: str = OutputField(cef_types=["sha256"])


class ScanOutput(ActionOutput):
    hash: HashOutput


class GetBinexplodeResultsOutput(ActionOutput):
    file_name: str
    file_extension: str
    depth: float
    size: float
    source: str
    node_id: str
    parent_node_id: str
    scan: ScanOutput


@app.action(
    description="Get results of a binexplode scan by task ID", action_type="investigate"
)
def get_binexplode_results(
    params: GetBinexplodeResultsParams, soar: SOARClient, asset: Asset
) -> GetBinexplodeResultsOutput:
    return impl.get_binexplode_results(params, soar, asset, GetBinexplodeResultsOutput)


class AnalyzeLinkParams(Params):
    url: str = Param(description="URL to analyze", primary=True, cef_types=["url"])
    no_logo_detect: bool | None = Param(
        description="Skip logo detection during analysis", default=False
    )


class BrandOutput(ActionOutput):
    name: str


class CredphishOutput(ActionOutput):
    disposition: str
    confidence: str
    brand: BrandOutput
    contains_login: bool
    contains_captcha: bool


class DomainOutput(ActionOutput):
    domain: str = OutputField(cef_types=["domain"])


class EffectiveUrlOutput(ActionOutput):
    url: str = OutputField(cef_types=["url"])
    domain: DomainOutput


class OriginalUrlOutput(ActionOutput):
    url: str = OutputField(cef_types=["url"])


class ScreenshotOutput(ActionOutput):
    raw: str


class AnalyzeLinkOutput(ActionOutput):
    analyzed: bool
    credphish: CredphishOutput
    effective_url: EffectiveUrlOutput
    original_url: OriginalUrlOutput
    content_type: str
    page_status_code: float
    retrieved: bool
    screenshot: ScreenshotOutput


@app.action(
    description="Analyze a provided URL using Sublime Security ml.link_analysis for credential phishing detection",
    action_type="investigate",
    summary_type=ScreenshotVaultSummary,
)
def analyze_link(
    params: AnalyzeLinkParams, soar: SOARClient, asset: Asset
) -> AnalyzeLinkOutput:
    return impl.analyze_link(
        params, soar, asset, AnalyzeLinkOutput, summary_cls=ScreenshotVaultSummary
    )


class ListAuditEventsParams(Params):
    start_time: str | None = Param(
        description="Inclusive start datetime filter (ISO 8601 UTC)"
    )
    end_time: str | None = Param(
        description="Exclusive end datetime filter (ISO 8601 UTC)"
    )
    event_type: str | None = Param(description="Filter by event type")
    user_ids: str | None = Param(description="Comma-separated user IDs to filter by")
    limit: float | None = Param(
        description="Maximum number of events to return (max: 500)", default=100
    )
    offset: float | None = Param(
        description="Zero-based offset for pagination", default=0
    )


class CreatedByOutput(ActionOutput):
    email_address: str = OutputField(cef_types=["email"])


class RequestOutput(ActionOutput):
    method: str
    path: str
    ip: str = OutputField(cef_types=["ip"])


class DataOutput(ActionOutput):
    request: RequestOutput


class ListAuditEventsOutput(ActionOutput):
    id: str = OutputField(cef_types=["event id"])
    type: str
    created_at: str
    created_by: CreatedByOutput
    data: DataOutput


@app.action(
    description="List events in the Sublime Security audit log",
    action_type="investigate",
)
def list_audit_events(
    params: ListAuditEventsParams, soar: SOARClient, asset: Asset
) -> ListAuditEventsOutput:
    return impl.list_audit_events(params, soar, asset, ListAuditEventsOutput)


class ListAuditEventTypesOutput(ActionOutput):
    name: str
    type: str


@app.action(
    description="List all available event types for the audit log",
    action_type="investigate",
)
def list_audit_event_types(
    params: Params, soar: SOARClient, asset: Asset
) -> ListAuditEventTypesOutput:
    return impl.list_audit_event_types(params, soar, asset, ListAuditEventTypesOutput)


class GetAuditEventParams(Params):
    event_id: str = Param(
        description="UUID of the audit event", primary=True, cef_types=["event id"]
    )


class CreatedByOutput(ActionOutput):
    email_address: str = OutputField(cef_types=["email"])


class RequestOutput(ActionOutput):
    method: str
    path: str
    ip: str = OutputField(cef_types=["ip"])


class DataOutput(ActionOutput):
    request: RequestOutput


class GetAuditEventOutput(ActionOutput):
    id: str = OutputField(cef_types=["event id"])
    type: str
    created_at: str
    created_by: CreatedByOutput
    data: DataOutput


@app.action(
    description="Retrieve a single event from the audit log", action_type="investigate"
)
def get_audit_event(
    params: GetAuditEventParams, soar: SOARClient, asset: Asset
) -> GetAuditEventOutput:
    return impl.get_audit_event(params, soar, asset, GetAuditEventOutput)


class StartHuntJobParams(Params):
    source: str = Param(description="MQL source query")
    range_start_time: str = Param(
        description="Start time for hunt range (ISO 8601 UTC)"
    )
    range_end_time: str = Param(description="End time for hunt range (ISO 8601 UTC)")
    name: str | None = Param(description="Name for the hunt job")
    private: bool | None = Param(
        description="Make hunt visible only to admins", default=False
    )
    triage_flagged: bool | None = Param(
        description="Pre-filter to flagged messages (OR'd with other triage filters)"
    )
    triage_reported: bool | None = Param(
        description="Pre-filter to user-reported messages (OR'd with other triage filters)"
    )
    triage_email_bomb: bool | None = Param(
        description="Pre-filter to messages in an email bomb (OR'd with other triage filters)"
    )
    triage_dlp_rule_matched: bool | None = Param(
        description="Pre-filter to messages that matched a DLP rule (OR'd with other triage filters)"
    )


class StartHuntJobOutput(ActionOutput):
    hunt_job_id: str


@app.action(
    description="Start a hunt job using MQL source",
    action_type="investigate",
    read_only=False,
)
def start_hunt_job(
    params: StartHuntJobParams, soar: SOARClient, asset: Asset
) -> StartHuntJobOutput:
    return impl.start_hunt_job(params, soar, asset, StartHuntJobOutput)


class GetHuntJobParams(Params):
    hunt_job_id: str = Param(description="Hunt job ID", primary=True)


class GetHuntJobOutput(ActionOutput):
    id: str
    status: str
    source: str
    range_start_time: str
    range_end_time: str
    error: str
    results_truncated: bool


@app.action(description="Get the status of a hunt job", action_type="investigate")
def get_hunt_job(
    params: GetHuntJobParams, soar: SOARClient, asset: Asset
) -> GetHuntJobOutput:
    return impl.get_hunt_job(params, soar, asset, GetHuntJobOutput)


class GetHuntJobResultsParams(Params):
    hunt_job_id: str = Param(description="Hunt job ID", primary=True)
    limit: float | None = Param(
        description="Maximum number of results (max: 500)", default=100
    )
    offset: float | None = Param(
        description="Zero-based offset for pagination", default=0
    )


class GetHuntJobResultsOutput(ActionOutput):
    id: str
    review_status: str
    classification: str


@app.action(
    description="Get the results of a completed hunt job", action_type="investigate"
)
def get_hunt_job_results(
    params: GetHuntJobResultsParams, soar: SOARClient, asset: Asset
) -> GetHuntJobResultsOutput:
    return impl.get_hunt_job_results(params, soar, asset, GetHuntJobResultsOutput)


class ListListsParams(Params):
    name: str | None = Param(description="Filter by list name")
    entry_type: str | None = Param(
        description="Filter by list entry type (e.g. string, user_group, provider_org_unit). If omitted, lists of all entry types are returned"
    )


class ListListsOutput(ActionOutput):
    id: str = OutputField(cef_types=["list id"])
    name: str
    description: str
    entry_type: str
    editable: bool
    created_at: str
    updated_at: str


@app.action(description="Retrieve all lists", action_type="investigate")
def list_lists(
    params: ListListsParams, soar: SOARClient, asset: Asset
) -> ListListsOutput:
    return impl.list_lists(params, soar, asset, ListListsOutput)


class CreateListParams(Params):
    name: str = Param(description="Name of the list")
    description: str = Param(description="Description of the list")


class CreateListOutput(ActionOutput):
    id: str = OutputField(cef_types=["list id"])
    name: str
    description: str


@app.action(description="Create a new list", action_type="generic", read_only=False)
def create_list(
    params: CreateListParams, soar: SOARClient, asset: Asset
) -> CreateListOutput:
    return impl.create_list(params, soar, asset, CreateListOutput)


class DeleteListParams(Params):
    list_id: str = Param(
        description="UUID of the list to delete", primary=True, cef_types=["list id"]
    )


@app.action(description="Delete a list by ID", action_type="generic", read_only=False)
def delete_list(
    params: DeleteListParams, soar: SOARClient, asset: Asset
) -> ActionOutput:
    return impl.delete_list(params, soar, asset)


class GetListParams(Params):
    list_id: str = Param(
        description="UUID of the list", primary=True, cef_types=["list id"]
    )


class GetListOutput(ActionOutput):
    id: str = OutputField(cef_types=["list id"])
    name: str
    description: str
    entry_type: str
    editable: bool
    created_at: str
    updated_at: str


@app.action(description="Get a single list by ID", action_type="investigate")
def get_list(params: GetListParams, soar: SOARClient, asset: Asset) -> GetListOutput:
    return impl.get_list(params, soar, asset, GetListOutput)


class PatchListParams(Params):
    list_id: str = Param(
        description="UUID of the list", primary=True, cef_types=["list id"]
    )
    description: str = Param(description="New description for the list")


class PatchListOutput(ActionOutput):
    id: str = OutputField(cef_types=["list id"])
    name: str
    description: str


@app.action(
    description="Patch a list's description", action_type="generic", read_only=False
)
def patch_list(
    params: PatchListParams, soar: SOARClient, asset: Asset
) -> PatchListOutput:
    return impl.patch_list(params, soar, asset, PatchListOutput)


class GetListEntriesParams(Params):
    list_id: str = Param(
        description="UUID of the list", primary=True, cef_types=["list id"]
    )
    save_to_vault: bool | None = Param(
        description="Save the list entries to the vault as a CSV file", default=False
    )
    csv_file_name: str | None = Param(
        description="Optional file name for the CSV (default: list_<list_id>_entries.csv)"
    )


class GetListEntriesOutput(ActionOutput):
    entry: str


@app.action(
    description="Get all entries in a list, optionally saving them to the vault as a CSV file",
    action_type="investigate",
    summary_type=VaultIdSummary,
)
def get_list_entries(
    params: GetListEntriesParams, soar: SOARClient, asset: Asset
) -> GetListEntriesOutput:
    return impl.get_list_entries(
        params, soar, asset, GetListEntriesOutput, summary_cls=VaultIdSummary
    )


class SetListEntriesParams(Params):
    list_id: str = Param(
        description="UUID of the list", primary=True, cef_types=["list id"]
    )
    entries: str | None = Param(
        description="Comma-separated list of entries (alternative to vault_id)"
    )
    vault_id: str | None = Param(
        description="Vault ID of a CSV file containing entries (one per row, or comma-separated)",
        cef_types=["vault id"],
    )


@app.action(
    description="Replace all entries in a list. Provide entries as a comma-separated string OR a vault CSV file ID",
    action_type="generic",
    read_only=False,
)
def set_list_entries(
    params: SetListEntriesParams, soar: SOARClient, asset: Asset
) -> ActionOutput:
    return impl.set_list_entries(params, soar, asset)


class DeleteListEntryParams(Params):
    list_id: str = Param(
        description="UUID of the list", primary=True, cef_types=["list id"]
    )
    entry: str = Param(description="The entry string to delete (max 2000 chars)")


@app.action(
    description="Delete a single entry from a list",
    action_type="generic",
    read_only=False,
)
def delete_list_entry(
    params: DeleteListEntryParams, soar: SOARClient, asset: Asset
) -> ActionOutput:
    return impl.delete_list_entry(params, soar, asset)


class GetListEntryParams(Params):
    list_id: str = Param(
        description="UUID of the list", primary=True, cef_types=["list id"]
    )
    entry: str = Param(
        description="Entry string OR comma-separated list of entries to look up (max 2000 chars each)"
    )


class GetListEntryOutput(ActionOutput):
    entry: str
    found: bool


@app.action(
    description="Check if a single entry or multiple entries exist in a list",
    action_type="investigate",
)
def get_list_entry(
    params: GetListEntryParams, soar: SOARClient, asset: Asset
) -> GetListEntryOutput:
    return impl.get_list_entry(params, soar, asset, GetListEntryOutput)


class AddListEntryParams(Params):
    list_id: str = Param(
        description="UUID of the list", primary=True, cef_types=["list id"]
    )
    entry: str = Param(description="The entry string to add (max 2000 chars)")


@app.action(
    description="Add a single entry to a list", action_type="generic", read_only=False
)
def add_list_entry(
    params: AddListEntryParams, soar: SOARClient, asset: Asset
) -> ActionOutput:
    return impl.add_list_entry(params, soar, asset)


class ProcessRawMessageParams(Params):
    vault_id: str | None = Param(
        description="Vault ID of the EML file", cef_types=["vault id"]
    )
    base64_data: str | None = Param(
        description="Base64 encoded EML (alternative to vault_id)"
    )
    mailbox_email_address: str = Param(
        description="Mailbox email address", cef_types=["email"]
    )
    message_source_id: str = Param(description="Message source UUID")
    create_mailbox: bool | None = Param(
        description="Create mailbox if it does not exist", default=False
    )
    analyze_async: bool | None = Param(
        description="Run analysis and finish ingestion async. flagged_rules will be empty on response",
        default=False,
    )
    canonical_id: str | None = Param(
        description="Known canonical (message group) ID (64 chars)"
    )
    external_message_id: str | None = Param(
        description="ID of the message according to the external source"
    )
    external_thread_id: str | None = Param(
        description="ID of the thread according to the external source"
    )
    external_created_at: str | None = Param(
        description="Timestamp the message was created per external source (ISO 8601)"
    )
    folder: str | None = Param(description="The mailbox folder the message is in")
    labels: str | None = Param(
        description="Comma-separated labels applied by the mailbox"
    )
    route_type: str | None = Param(description="Directional route type of the message")
    message_type: str | None = Param(
        description="Message type override",
        value_list=["inbound", "internal", "outbound"],
    )


class ProcessRawMessageOutput(ActionOutput):
    canonical_id: str
    message_id: str = OutputField(cef_types=["message id"])
    raw_message_id: str
    flagged_rules: str


@app.action(
    description="Process a raw EML message through Sublime Security live flow",
    action_type="investigate",
    read_only=False,
)
def process_raw_message(
    params: ProcessRawMessageParams, soar: SOARClient, asset: Asset
) -> ProcessRawMessageOutput:
    return impl.process_raw_message(params, soar, asset, ProcessRawMessageOutput)


class ListMailboxesParams(Params):
    active: bool | None = Param(
        description="Filter for effectively active mailboxes (marked active with a live subscription)"
    )
    marked_active: bool | None = Param(description="Filter for mailboxes marked active")
    search: str | None = Param(
        description="Search across mailbox names and email addresses"
    )
    email_addresses: str | None = Param(
        description="Comma-delimited email addresses to return", cef_types=["email"]
    )
    mailbox_types: str | None = Param(
        description="Comma-delimited mailbox types to filter by"
    )
    sub_error_types: str | None = Param(
        description="Comma-delimited subscription error types to filter by"
    )
    message_source_id: str | None = Param(
        description="ID of the message source the mailboxes belong to"
    )
    limit: float | None = Param(
        description="Maximum number of results (max: 500)", default=100
    )
    offset: float | None = Param(
        description="Zero-based offset for pagination", default=0
    )


class ListMailboxesOutput(ActionOutput):
    id: str
    email_address: str = OutputField(cef_types=["email"])
    active: bool
    subscription_error_status: str


@app.action(description="List connected mailboxes", action_type="investigate")
def list_mailboxes(
    params: ListMailboxesParams, soar: SOARClient, asset: Asset
) -> ListMailboxesOutput:
    return impl.list_mailboxes(params, soar, asset, ListMailboxesOutput)


class ListMessageGroupsParams(Params):
    start_time: str | None = Param(
        description="Start time filter (ISO 8601 UTC), maps to created_at__gte"
    )
    end_time: str | None = Param(
        description="End time filter (ISO 8601 UTC), maps to created_at__lt"
    )
    flagged: bool | None = Param(description="Filter by flagged status")
    reviewed: bool | None = Param(description="Filter by reviewed status")
    user_reported: bool | None = Param(
        description="Filter to groups with at least one reported message"
    )
    attack_surface_reduction: bool | None = Param(
        description="Filter to groups with flagged 'Attack surface reduction' tag"
    )
    sender_email: str | None = Param(
        description="Filter by sender email (comma-separated list)", cef_types=["email"]
    )
    sender_domain: str | None = Param(
        description="Filter by sender domain (comma-separated)"
    )
    sender_display_name: str | None = Param(
        description="Filter by sender display name (comma-separated)"
    )
    mailbox_email: str | None = Param(
        description="Filter by mailbox email (comma-separated)", cef_types=["email"]
    )
    recipient_email: str | None = Param(
        description="Filter by recipient email (comma-separated)", cef_types=["email"]
    )
    subject: str | None = Param(description="Filter by subject (comma-separated)")
    canonical_id: str | None = Param(
        description="Filter by canonical ID (comma-separated)"
    )
    attachment_name: str | None = Param(
        description="Filter by attachment name (comma-separated)"
    )
    attachment_sha256: str | None = Param(
        description="Filter by attachment SHA256 (comma-separated)",
        cef_types=["sha256"],
    )
    attack_score_verdict: str | None = Param(
        description="Filter by attack score verdict (comma-separated: unknown, likely_benign, suspicious, malicious, graymail, spam)"
    )
    flagged_rule_id: str | None = Param(
        description="Filter by flagged rule ID (comma-separated)"
    )
    flagged_rule_severity: str | None = Param(
        description="Filter by flagged rule severity (comma-separated: informational, low, medium, high, critical)"
    )
    historically_flagged_rule_id: str | None = Param(
        description="Filter by historically flagged rule ID (comma-separated)"
    )
    historically_flagged_rule_severity: str | None = Param(
        description="Filter by historically flagged rule severity (comma-separated)"
    )
    reported_as_phish_by: str | None = Param(
        description="Filter by reporter (comma-separated)"
    )
    spam_status: str | None = Param(
        description="Filter by spam status (comma-separated: spam, not_spam, mixed)"
    )
    vendor_id: str | None = Param(description="Filter by vendor ID (comma-separated)")
    first_message_reported_at_gte: str | None = Param(
        description="Only groups with a message first reported at or after this time (ISO 8601 UTC)"
    )
    limit: float | None = Param(
        description="Maximum number of results (max: 500)", default=100
    )
    offset: float | None = Param(
        description="Zero-based offset for pagination", default=0
    )


class ListMessageGroupsOutput(ActionOutput):
    id: str = OutputField(cef_types=["message group id"])
    review_status: str
    classification: str
    state: str


@app.action(
    description="List message groups with optional filters", action_type="investigate"
)
def list_message_groups(
    params: ListMessageGroupsParams, soar: SOARClient, asset: Asset
) -> ListMessageGroupsOutput:
    return impl.list_message_groups(params, soar, asset, ListMessageGroupsOutput)


class DismissMessageGroupsParams(Params):
    message_group_ids: str = Param(
        description="Comma-separated list of message group IDs"
    )
    classification: str | None = Param(
        description="Classification for dismissed groups",
        value_list=[
            "malicious",
            "benign",
            "unwanted",
            "simulation",
            "graymail",
            "spam",
            "violation",
            "non-violation",
        ],
    )
    report_label: str | None = Param(
        description="Label to apply to messages being reviewed",
        value_list=[
            "spam",
            "phishing",
            "false_positive",
            "false_negative",
            "phishing_simulation",
            "graymail",
            "violation",
            "non-violation",
        ],
    )
    review_comment: str | None = Param(description="Optional review comment")


@app.action(
    description="Dismiss multiple message groups",
    action_type="correct",
    read_only=False,
)
def dismiss_message_groups(
    params: DismissMessageGroupsParams, soar: SOARClient, asset: Asset
) -> ActionOutput:
    return impl.dismiss_message_groups(params, soar, asset)


class QuarantineMessageGroupsParams(Params):
    message_group_ids: str = Param(
        description="Comma-separated list of message group IDs"
    )
    classification: str | None = Param(
        description="Classification",
        value_list=[
            "malicious",
            "benign",
            "unwanted",
            "simulation",
            "graymail",
            "spam",
            "violation",
            "non-violation",
        ],
    )
    report_label: str | None = Param(
        description="Label to apply to messages being reviewed",
        value_list=[
            "spam",
            "phishing",
            "false_positive",
            "false_negative",
            "phishing_simulation",
            "graymail",
            "violation",
            "non-violation",
        ],
    )
    review_comment: str | None = Param(description="Optional review comment")


class QuarantineMessageGroupsOutput(ActionOutput):
    task_id: str


@app.action(
    description="Quarantine multiple message groups",
    action_type="correct",
    read_only=False,
)
def quarantine_message_groups(
    params: QuarantineMessageGroupsParams, soar: SOARClient, asset: Asset
) -> QuarantineMessageGroupsOutput:
    return impl.quarantine_message_groups(params, soar, asset, QuarantineMessageGroupsOutput)


class GraymailMessageGroupsParams(Params):
    message_group_ids: str = Param(
        description="Comma-separated list of message group IDs"
    )
    classification: str | None = Param(
        description="Classification",
        value_list=[
            "malicious",
            "benign",
            "unwanted",
            "simulation",
            "graymail",
            "spam",
            "violation",
            "non-violation",
        ],
    )
    report_label: str | None = Param(
        description="Label to apply to messages being reviewed",
        value_list=[
            "spam",
            "phishing",
            "false_positive",
            "false_negative",
            "phishing_simulation",
            "graymail",
            "violation",
            "non-violation",
        ],
    )
    review_comment: str | None = Param(description="Optional review comment")


class GraymailMessageGroupsOutput(ActionOutput):
    task_id: str


@app.action(
    description="Move multiple message groups to graymail",
    action_type="correct",
    read_only=False,
)
def graymail_message_groups(
    params: GraymailMessageGroupsParams, soar: SOARClient, asset: Asset
) -> GraymailMessageGroupsOutput:
    return impl.graymail_message_groups(params, soar, asset, GraymailMessageGroupsOutput)


class RestoreMessageGroupsParams(Params):
    message_group_ids: str = Param(
        description="Comma-separated list of message group IDs"
    )
    classification: str | None = Param(
        description="Classification",
        value_list=[
            "malicious",
            "benign",
            "unwanted",
            "simulation",
            "graymail",
            "spam",
            "violation",
            "non-violation",
        ],
    )
    report_label: str | None = Param(
        description="Label to apply to messages being reviewed",
        value_list=[
            "spam",
            "phishing",
            "false_positive",
            "false_negative",
            "phishing_simulation",
            "graymail",
            "violation",
            "non-violation",
        ],
    )
    review_comment: str | None = Param(description="Optional review comment")


class RestoreMessageGroupsOutput(ActionOutput):
    task_id: str


@app.action(
    description="Restore multiple message groups",
    action_type="correct",
    read_only=False,
)
def restore_message_groups(
    params: RestoreMessageGroupsParams, soar: SOARClient, asset: Asset
) -> RestoreMessageGroupsOutput:
    return impl.restore_message_groups(params, soar, asset, RestoreMessageGroupsOutput)


class ReviewMessageGroupsParams(Params):
    message_group_ids: str = Param(
        description="Comma-separated list of message group IDs"
    )
    classification: str = Param(
        description="Review classification",
        value_list=[
            "malicious",
            "benign",
            "simulation",
            "graymail",
            "spam",
            "skip",
            "violation",
            "non-violation",
        ],
    )
    action: str | None = Param(
        description="Action to take on the message groups",
        value_list=[
            "restore",
            "warning_banner",
            "quarantine",
            "trash",
            "move_to_spam",
            "move_to_graymail",
            "delete_calendar_events",
        ],
    )
    review_comment: str | None = Param(description="Optional review comment")
    share_with_sublime: bool | None = Param(
        description="Share with Sublime for community detection", default=False
    )


class ReviewMessageGroupsOutput(ActionOutput):
    task_id: str
    actions: str


@app.action(
    description="Review message groups with classification and optional action",
    action_type="correct",
    read_only=False,
)
def review_message_groups(
    params: ReviewMessageGroupsParams, soar: SOARClient, asset: Asset
) -> ReviewMessageGroupsOutput:
    return impl.review_message_groups(params, soar, asset, ReviewMessageGroupsOutput)


class SearchMessageGroupsParams(Params):
    any: str | None = Param(
        description="Search all fields (not compatible with other fields)"
    )
    sender: str | None = Param(
        description="Search in From field (wildcard)", cef_types=["email"]
    )
    to: str | None = Param(
        description="Search in To/CC/Bcc fields (wildcard)", cef_types=["email"]
    )
    mailbox: str | None = Param(
        description="Search mailbox by email (wildcard)", cef_types=["email"]
    )
    subject: str | None = Param(description="Search subject (wildcard)")
    message_id: str | None = Param(description="Search Message-ID header (wildcard)")
    type: str | None = Param(description="Search by message type")
    states: str | None = Param(description="Comma-separated list of message states")
    file_name: str | None = Param(description="Search attachment filename (wildcard)")
    attachment_md5: str | None = Param(
        description="Attachment MD5 (32 chars)", cef_types=["md5"]
    )
    attachment_sha1: str | None = Param(
        description="Attachment SHA1 (40 chars)", cef_types=["sha1"]
    )
    attachment_sha256: str | None = Param(
        description="Attachment SHA256 (64 chars)", cef_types=["sha256"]
    )
    start_time: str | None = Param(
        description="Start time filter (ISO 8601 UTC), maps to created_at[gte]"
    )
    end_time: str | None = Param(
        description="End time filter (ISO 8601 UTC), maps to created_at[lt]"
    )
    first_reported_as_phish_at_gte: str | None = Param(
        description="Groups reported at or after this time (ISO 8601 UTC)"
    )
    first_reported_as_phish_at_lt: str | None = Param(
        description="Groups reported before this time (ISO 8601 UTC)"
    )
    limit: float | None = Param(
        description="Maximum number of results (max: 500)", default=100
    )
    offset: float | None = Param(
        description="Zero-based offset for pagination", default=0
    )


class SearchMessageGroupsOutput(ActionOutput):
    id: str = OutputField(cef_types=["message group id"])
    review_status: str
    classification: str
    state: str


@app.action(
    description="Search message groups across multiple fields",
    action_type="investigate",
)
def search_message_groups(
    params: SearchMessageGroupsParams, soar: SOARClient, asset: Asset
) -> SearchMessageGroupsOutput:
    return impl.search_message_groups(params, soar, asset, SearchMessageGroupsOutput)


class TrashMessageGroupsParams(Params):
    message_group_ids: str = Param(
        description="Comma-separated list of message group IDs"
    )
    classification: str | None = Param(
        description="Classification",
        value_list=[
            "malicious",
            "benign",
            "unwanted",
            "simulation",
            "graymail",
            "spam",
            "violation",
            "non-violation",
        ],
    )
    report_label: str | None = Param(
        description="Label to apply to messages being reviewed",
        value_list=[
            "spam",
            "phishing",
            "false_positive",
            "false_negative",
            "phishing_simulation",
            "graymail",
            "violation",
            "non-violation",
        ],
    )
    review_comment: str | None = Param(description="Optional review comment")


class TrashMessageGroupsOutput(ActionOutput):
    task_id: str


@app.action(
    description="Trash multiple message groups", action_type="correct", read_only=False
)
def trash_message_groups(
    params: TrashMessageGroupsParams, soar: SOARClient, asset: Asset
) -> TrashMessageGroupsOutput:
    return impl.trash_message_groups(params, soar, asset, TrashMessageGroupsOutput)


class GetMessageGroupParams(Params):
    message_group_id: str = Param(
        description="Canonical ID of the message group",
        primary=True,
        cef_types=["message group id"],
    )


class GetMessageGroupOutput(ActionOutput):
    id: str = OutputField(cef_types=["message group id"])
    review_status: str
    classification: str
    state: str
    flagged_rules: str
    messages: str
    user_reports: str


@app.action(
    description="Get a single message group by canonical ID", action_type="investigate"
)
def get_message_group(
    params: GetMessageGroupParams, soar: SOARClient, asset: Asset
) -> GetMessageGroupOutput:
    return impl.get_message_group(params, soar, asset, GetMessageGroupOutput)


class DismissMessageGroupParams(Params):
    message_group_id: str = Param(
        description="Canonical ID of the message group",
        primary=True,
        cef_types=["message group id"],
    )
    classification: str | None = Param(
        description="Classification",
        value_list=[
            "malicious",
            "benign",
            "unwanted",
            "simulation",
            "graymail",
            "spam",
            "violation",
            "non-violation",
        ],
    )
    review_comment: str | None = Param(description="Optional review comment")


@app.action(
    description="Dismiss a single message group", action_type="correct", read_only=False
)
def dismiss_message_group(
    params: DismissMessageGroupParams, soar: SOARClient, asset: Asset
) -> ActionOutput:
    return impl.dismiss_message_group(params, soar, asset)


class QuarantineMessageGroupParams(Params):
    message_group_id: str = Param(
        description="Canonical ID of the message group",
        primary=True,
        cef_types=["message group id"],
    )
    classification: str | None = Param(
        description="Classification",
        value_list=[
            "malicious",
            "benign",
            "unwanted",
            "simulation",
            "graymail",
            "spam",
            "violation",
            "non-violation",
        ],
    )
    review_comment: str | None = Param(description="Optional review comment")


class QuarantineMessageGroupOutput(ActionOutput):
    task_id: str


@app.action(
    description="Quarantine a single message group",
    action_type="correct",
    read_only=False,
)
def quarantine_message_group(
    params: QuarantineMessageGroupParams, soar: SOARClient, asset: Asset
) -> QuarantineMessageGroupOutput:
    return impl.quarantine_message_group(params, soar, asset, QuarantineMessageGroupOutput)


class RestoreMessageGroupParams(Params):
    message_group_id: str = Param(
        description="Canonical ID of the message group",
        primary=True,
        cef_types=["message group id"],
    )
    classification: str | None = Param(
        description="Classification",
        value_list=[
            "malicious",
            "benign",
            "unwanted",
            "simulation",
            "graymail",
            "spam",
            "violation",
            "non-violation",
        ],
    )
    review_comment: str | None = Param(description="Optional review comment")


class RestoreMessageGroupOutput(ActionOutput):
    task_id: str


@app.action(
    description="Restore a single message group", action_type="correct", read_only=False
)
def restore_message_group(
    params: RestoreMessageGroupParams, soar: SOARClient, asset: Asset
) -> RestoreMessageGroupOutput:
    return impl.restore_message_group(params, soar, asset, RestoreMessageGroupOutput)


class ShareWithSublimeParams(Params):
    message_group_id: str = Param(
        description="Canonical ID of the message group",
        primary=True,
        cef_types=["message group id"],
    )
    report_label: str | None = Param(
        description="Report label",
        value_list=["spam", "phishing", "false_positive", "violation", "non-violation"],
    )
    review_comment: str | None = Param(description="Optional review comment")


class ShareWithSublimeOutput(ActionOutput):
    task_id: str


@app.action(
    description="Share a message group with Sublime for community detection",
    action_type="generic",
    read_only=False,
)
def share_with_sublime(
    params: ShareWithSublimeParams, soar: SOARClient, asset: Asset
) -> ShareWithSublimeOutput:
    return impl.share_with_sublime(params, soar, asset, ShareWithSublimeOutput)


class TrashMessageGroupParams(Params):
    message_group_id: str = Param(
        description="Canonical ID of the message group",
        primary=True,
        cef_types=["message group id"],
    )
    classification: str | None = Param(
        description="Classification",
        value_list=[
            "malicious",
            "benign",
            "unwanted",
            "simulation",
            "graymail",
            "spam",
            "violation",
            "non-violation",
        ],
    )
    review_comment: str | None = Param(description="Optional review comment")


class TrashMessageGroupOutput(ActionOutput):
    task_id: str


@app.action(
    description="Trash a single message group", action_type="correct", read_only=False
)
def trash_message_group(
    params: TrashMessageGroupParams, soar: SOARClient, asset: Asset
) -> TrashMessageGroupOutput:
    return impl.trash_message_group(params, soar, asset, TrashMessageGroupOutput)


class AnalyzeRawMessageParams(Params):
    vault_id: str | None = Param(
        description="Vault ID of the EML file", cef_types=["vault id"]
    )
    base64_data: str | None = Param(
        description="Base64 encoded EML (alternative to vault_id)"
    )
    run_active_detection_rules: bool | None = Param(
        description="Run all active detection rules", default=False
    )
    run_all_detection_rules: bool | None = Param(
        description="Run all detection rules including inactive", default=False
    )
    run_all_insights: bool | None = Param(
        description="Run all insight queries", default=False
    )


class AnalyzeRawMessageOutput(ActionOutput):
    rule_results: str
    query_results: str


@app.action(
    description="Analyze a raw EML message against rules and queries",
    action_type="investigate",
)
def analyze_raw_message(
    params: AnalyzeRawMessageParams, soar: SOARClient, asset: Asset
) -> AnalyzeRawMessageOutput:
    return impl.analyze_raw_message(params, soar, asset, AnalyzeRawMessageOutput)


class RenderAttachmentImageParams(Params):
    vault_id: str | None = Param(
        description="Vault ID of the attachment file", cef_types=["vault id"]
    )
    base64_data: str | None = Param(
        description="Base64 encoded raw attachment bytes (alternative to vault_id)"
    )
    file_type: str | None = Param(description="File type hint for rendering")


class RenderAttachmentImageOutput(ActionOutput):
    hash: str


@app.action(
    description="Render image for attachment from raw base64 encoded bytes",
    action_type="investigate",
    summary_type=ScreenshotVaultSummary,
)
def render_attachment_image(
    params: RenderAttachmentImageParams, soar: SOARClient, asset: Asset
) -> RenderAttachmentImageOutput:
    return impl.render_attachment_image(
        params, soar, asset, RenderAttachmentImageOutput, summary_cls=ScreenshotVaultSummary
    )


class GetAttackScoreRawParams(Params):
    vault_id: str | None = Param(
        description="Vault ID of the EML file", cef_types=["vault id"]
    )
    base64_data: str | None = Param(
        description="Base64 encoded EML (alternative to vault_id)"
    )


class GetAttackScoreRawOutput(ActionOutput):
    score: float
    graymail_score: float
    verdict: str
    top_signals: str


@app.action(
    description="Evaluate attack score for a raw message", action_type="investigate"
)
def get_attack_score_raw(
    params: GetAttackScoreRawParams, soar: SOARClient, asset: Asset
) -> GetAttackScoreRawOutput:
    return impl.get_attack_score_raw(params, soar, asset, GetAttackScoreRawOutput)


class CreateMessageParams(Params):
    vault_id: str | None = Param(
        description="Vault ID of the EML file", cef_types=["vault id"]
    )
    base64_data: str | None = Param(
        description="Base64 encoded EML (alternative to vault_id)"
    )
    mailbox_email_address: str | None = Param(
        description="Mailbox email address", cef_types=["email"]
    )
    canonical_id: str | None = Param(
        description="Canonical ID of the message, if known"
    )
    external_message_id: str | None = Param(
        description="ID of the message according to the external source"
    )
    external_thread_id: str | None = Param(
        description="ID of the thread according to the external source"
    )
    external_created_at: str | None = Param(
        description="Timestamp the message was created per external source (ISO 8601)"
    )
    folder: str | None = Param(description="The mailbox folder the message is in")
    labels: str | None = Param(
        description="Comma-separated labels applied by the mailbox"
    )
    route_type: str | None = Param(description="Directional route type of the message")
    message_type: str | None = Param(
        description="Message type override",
        value_list=["inbound", "internal", "outbound"],
    )


class PreviewOutput(ActionOutput):
    subject: str
    sender_email_address: str = OutputField(cef_types=["email"])


class CreateMessageOutput(ActionOutput):
    id: str = OutputField(cef_types=["message id"])
    canonical_id: str
    preview: PreviewOutput


@app.action(
    description="Create a new message from a raw EML",
    action_type="generic",
    read_only=False,
)
def create_message(
    params: CreateMessageParams, soar: SOARClient, asset: Asset
) -> CreateMessageOutput:
    return impl.create_message(params, soar, asset, CreateMessageOutput)


class GetActionStateParams(Params):
    message_group_id: str = Param(
        description="Canonical group ID", primary=True, cef_types=["message group id"]
    )
    limit: float | None = Param(
        description="Maximum number of results (max: 50)", default=10
    )
    offset: float | None = Param(
        description="Zero-based offset for pagination", default=0
    )


class GetActionStateOutput(ActionOutput):
    id: str
    action_type: str
    change: str
    created_at: str
    attempts: float
    total: float


@app.action(
    description="Retrieve the state of manual actions for a canonical group",
    action_type="investigate",
)
def get_action_state(
    params: GetActionStateParams, soar: SOARClient, asset: Asset
) -> GetActionStateOutput:
    return impl.get_action_state(params, soar, asset, GetActionStateOutput)


class GetMessageParams(Params):
    message_id: str = Param(
        description="UUID of the message", primary=True, cef_types=["message id"]
    )


class SenderOutput(ActionOutput):
    email: str = OutputField(cef_types=["email"])
    display_name: str


class MailboxOutput(ActionOutput):
    email: str = OutputField(cef_types=["email"])


class GetMessageOutput(ActionOutput):
    id: str = OutputField(cef_types=["message id"])
    canonical_id: str
    subject: str
    sender: SenderOutput
    created_at: str
    mailbox: MailboxOutput
    recipients: str


@app.action(description="Retrieve a message by ID", action_type="investigate")
def get_message(
    params: GetMessageParams, soar: SOARClient, asset: Asset
) -> GetMessageOutput:
    return impl.get_message(params, soar, asset, GetMessageOutput)


class ActionMessageParams(Params):
    message_id: str = Param(
        description="UUID of the message", primary=True, cef_types=["message id"]
    )
    action: str | None = Param(
        description="Action to perform",
        value_list=[
            "restore",
            "warning_banner",
            "quarantine",
            "trash",
            "move_to_spam",
            "move_to_graymail",
            "delete_calendar_events",
        ],
    )
    share_with_sublime: bool | None = Param(
        description="Share with Sublime", default=False
    )


class ActionMessageOutput(ActionOutput):
    task_id: str


@app.action(
    description="Perform an action on an individual message",
    action_type="correct",
    read_only=False,
)
def action_message(
    params: ActionMessageParams, soar: SOARClient, asset: Asset
) -> ActionMessageOutput:
    return impl.action_message(params, soar, asset, ActionMessageOutput)


class AnalyzeMessageByIdParams(Params):
    message_id: str = Param(
        description="UUID of the message", primary=True, cef_types=["message id"]
    )
    run_active_detection_rules: bool | None = Param(
        description="Run all active detection rules", default=False
    )
    run_all_detection_rules: bool | None = Param(
        description="Run all detection rules including inactive", default=False
    )
    run_all_insights: bool | None = Param(
        description="Run all insight queries", default=False
    )


class AnalyzeMessageByIdOutput(ActionOutput):
    rule_results: str
    query_results: str


@app.action(
    description="Analyze an existing message by its ID against rules and queries",
    action_type="investigate",
)
def analyze_message_by_id(
    params: AnalyzeMessageByIdParams, soar: SOARClient, asset: Asset
) -> AnalyzeMessageByIdOutput:
    return impl.analyze_message_by_id(params, soar, asset, AnalyzeMessageByIdOutput)


class GetAsaReportParams(Params):
    message_id: str = Param(
        description="UUID of the message", primary=True, cef_types=["message id"]
    )


class GetAsaReportOutput(ActionOutput):
    verdict: str
    summary: str
    full_explanation: str
    attack_type: str
    tactics_and_techniques: str


@app.action(
    description="Retrieve ASA (Attack Surface Assessment) report for a message",
    action_type="investigate",
)
def get_asa_report(
    params: GetAsaReportParams, soar: SOARClient, asset: Asset
) -> GetAsaReportOutput:
    return impl.get_asa_report(params, soar, asset, GetAsaReportOutput)


class GetAsaVerdictParams(Params):
    message_id: str = Param(
        description="UUID of the message", primary=True, cef_types=["message id"]
    )


class GetAsaVerdictOutput(ActionOutput):
    verdict: str


@app.action(
    description="Retrieve ASA verdict for a message (malicious, spam, graymail, likely_benign, benign, unknown)",
    action_type="investigate",
)
def get_asa_verdict(
    params: GetAsaVerdictParams, soar: SOARClient, asset: Asset
) -> GetAsaVerdictOutput:
    return impl.get_asa_verdict(params, soar, asset, GetAsaVerdictOutput)


class GetAttachmentImageParams(Params):
    message_id: str = Param(
        description="UUID of the message", primary=True, cef_types=["message id"]
    )
    attachment_hash: str = Param(
        description="MD5 hash of the attachment", cef_types=["md5"]
    )


class GetAttachmentImageOutput(ActionOutput):
    hash: str = OutputField(cef_types=["md5"])


@app.action(
    description="Retrieve image of a PDF attachment by MD5 hash",
    action_type="investigate",
    summary_type=ScreenshotVaultSummary,
)
def get_attachment_image(
    params: GetAttachmentImageParams, soar: SOARClient, asset: Asset
) -> GetAttachmentImageOutput:
    return impl.get_attachment_image(
        params, soar, asset, GetAttachmentImageOutput, summary_cls=ScreenshotVaultSummary
    )


class GetAttackScoreParams(Params):
    message_id: str = Param(
        description="UUID of the message", primary=True, cef_types=["message id"]
    )


class GetAttackScoreOutput(ActionOutput):
    score: float
    graymail_score: float
    verdict: str
    top_signals: str


@app.action(
    description="Evaluate attack score against an existing message",
    action_type="investigate",
)
def get_attack_score(
    params: GetAttackScoreParams, soar: SOARClient, asset: Asset
) -> GetAttackScoreOutput:
    return impl.get_attack_score(params, soar, asset, GetAttackScoreOutput)


class GetMessageImageParams(Params):
    message_id: str = Param(
        description="UUID of the message", primary=True, cef_types=["message id"]
    )


class GetMessageImageOutput(ActionOutput):
    mime_type: str
    is_empty_body: bool


@app.action(
    description="Retrieve rendered image of a message", action_type="investigate",
    summary_type=ScreenshotVaultSummary,
)
def get_message_image(
    params: GetMessageImageParams, soar: SOARClient, asset: Asset
) -> GetMessageImageOutput:
    return impl.get_message_image(
        params, soar, asset, GetMessageImageOutput, summary_cls=ScreenshotVaultSummary
    )


class GetMessageEmlParams(Params):
    message_id: str = Param(
        description="UUID of the message", primary=True, cef_types=["message id"]
    )


@app.action(
    description="Retrieve raw EML content of a message", action_type="investigate",
    summary_type=VaultIdSummary,
)
def get_message_eml(
    params: GetMessageEmlParams, soar: SOARClient, asset: Asset
) -> ActionOutput:
    return impl.get_message_eml(
        params, soar, asset, summary_cls=VaultIdSummary
    )


class GetMessageImageLinkParams(Params):
    message_id: str = Param(
        description="UUID of the message", primary=True, cef_types=["message id"]
    )
    link_duration_seconds: float | None = Param(
        description="Duration the link is valid in seconds (default 900, max 604800 = 7 days)"
    )
    platform_link: bool | None = Param(
        description="If true, link is presigned against Sublime; if false, may be a direct S3 link"
    )


class GetMessageImageLinkOutput(ActionOutput):
    url: str = OutputField(cef_types=["url"])
    expires_in: float


@app.action(
    description="Retrieve a temporary link to the image of a message",
    action_type="investigate",
)
def get_message_image_link(
    params: GetMessageImageLinkParams, soar: SOARClient, asset: Asset
) -> GetMessageImageLinkOutput:
    return impl.get_message_image_link(params, soar, asset, GetMessageImageLinkOutput)


class SetAccessJustificationParams(Params):
    message_id: str = Param(
        description="UUID of the message", primary=True, cef_types=["message id"]
    )
    justification: str = Param(description="Justification text")


@app.action(
    description="Set access justification for a message",
    action_type="generic",
    read_only=False,
)
def set_access_justification(
    params: SetAccessJustificationParams, soar: SOARClient, asset: Asset
) -> ActionOutput:
    return impl.set_access_justification(params, soar, asset)


class GetMessageDataModelParams(Params):
    message_id: str = Param(
        description="UUID of the message", primary=True, cef_types=["message id"]
    )


class EmailOutput(ActionOutput):
    email: str = OutputField(cef_types=["email"])


class SenderOutput(ActionOutput):
    email: EmailOutput


class SubjectOutput(ActionOutput):
    subject: str


class MetaOutput(ActionOutput):
    canonical_id: str
    id: str


class GetMessageDataModelOutput(ActionOutput):
    sender: SenderOutput
    subject: SubjectOutput
    meta: MetaOutput


@app.action(
    description="Retrieve the message's Message Data Model (MDM)",
    action_type="investigate",
)
def get_message_data_model(
    params: GetMessageDataModelParams, soar: SOARClient, asset: Asset
) -> GetMessageDataModelOutput:
    return impl.get_message_data_model(params, soar, asset, GetMessageDataModelOutput)


class RestoreMessageParams(Params):
    message_id: str = Param(
        description="UUID of the message", primary=True, cef_types=["message id"]
    )


class RestoreMessageOutput(ActionOutput):
    task_id: str


@app.action(
    description="Restore a previously trashed message",
    action_type="correct",
    read_only=False,
)
def restore_message(
    params: RestoreMessageParams, soar: SOARClient, asset: Asset
) -> RestoreMessageOutput:
    return impl.restore_message(params, soar, asset, RestoreMessageOutput)


class TrashMessageParams(Params):
    message_id: str = Param(
        description="UUID of the message", primary=True, cef_types=["message id"]
    )


class TrashMessageOutput(ActionOutput):
    task_id: str


@app.action(
    description="Trash an individual message", action_type="correct", read_only=False
)
def trash_message(
    params: TrashMessageParams, soar: SOARClient, asset: Asset
) -> TrashMessageOutput:
    return impl.trash_message(params, soar, asset, TrashMessageOutput)


class ListRulesParams(Params):
    search: str | None = Param(
        description="Case-insensitive substring match across rule name, description, and MQL source"
    )
    in_feed: bool | None = Param(
        description="Restrict to rules that are explicitly in or not in a feed"
    )
    limit: float | None = Param(
        description="Maximum number of results (max: 500)", default=50
    )
    offset: float | None = Param(
        description="Zero-based offset for pagination", default=0
    )


class ListRulesOutput(ActionOutput):
    id: str = OutputField(cef_types=["rule id"])
    name: str
    severity: str
    active: bool
    description: str
    source: str
    tags: str
    created_at: str
    updated_at: str


@app.action(description="List all rules in the organization", action_type="investigate")
def list_rules(
    params: ListRulesParams, soar: SOARClient, asset: Asset
) -> ListRulesOutput:
    return impl.list_rules(params, soar, asset, ListRulesOutput)


class CreateRuleParams(Params):
    name: str = Param(description="Rule name")
    source: str = Param(description="MQL rule source")
    type: str | None = Param(
        description="Rule type",
        default="detection",
        value_list=["detection", "dlp", "triage"],
    )
    severity: str | None = Param(
        description="Rule severity",
        value_list=["informational", "low", "medium", "high", "critical"],
    )
    description: str | None = Param(description="Rule description")
    active: bool | None = Param(description="Activate rule immediately", default=False)
    label: str | None = Param(description="Rule label")
    maturity: str | None = Param(description="Rule maturity")
    tags: str | None = Param(description="Comma-separated tags")
    user_provided_tags: str | None = Param(
        description="Comma-separated user-provided tags"
    )
    attack_types: str | None = Param(description="Comma-separated attack types")
    detection_methods: str | None = Param(
        description="Comma-separated detection technologies"
    )
    tactics_and_techniques: str | None = Param(
        description="Comma-separated tactics and techniques"
    )
    false_positives: str | None = Param(
        description="Comma-separated descriptions of known false positives"
    )
    references: str | None = Param(description="Comma-separated URL references")
    action_ids: str | None = Param(
        description="Comma-separated IDs of actions to run when the rule triggers"
    )
    authors: str | None = Param(
        description='Rule authors as JSON array (e.g. [{"name":"Jane","twitter":"@jane"}])'
    )
    auto_review_classification: str | None = Param(
        description="Classification for auto-reviewed messages",
        value_list=[
            "malicious",
            "benign",
            "spam",
            "graymail",
            "simulation",
            "unwanted",
        ],
    )
    auto_review_auto_share: bool | None = Param(
        description="Whether auto-reviewed messages will be shared"
    )
    triage_abuse_reports: bool | None = Param(
        description="(Triage) run for reported messages"
    )
    triage_flagged_messages: bool | None = Param(
        description="(Triage) run for flagged messages"
    )
    triage_classification_changes: bool | None = Param(
        description="(Triage) run when classification changes"
    )
    triage_dlp_rule_matched: bool | None = Param(
        description="(Triage) run for messages matching a DLP rule"
    )
    run_triage_on_excluded_messages: bool | None = Param(
        description="(Triage) run even on globally-excluded messages"
    )


class CreateRuleOutput(ActionOutput):
    id: str = OutputField(cef_types=["rule id"])
    name: str
    severity: str
    active: bool


@app.action(
    description="Create a new detection, DLP, or triage rule",
    action_type="generic",
    read_only=False,
)
def create_rule(
    params: CreateRuleParams, soar: SOARClient, asset: Asset
) -> CreateRuleOutput:
    return impl.create_rule(params, soar, asset, CreateRuleOutput)


class ListRuleHistoryParams(Params):
    start_time: str = Param(
        description="Classification start time (ISO 8601 UTC, required)"
    )
    end_time: str = Param(
        description="Classification end time (ISO 8601 UTC, required)"
    )
    active: bool | None = Param(description="Restrict to rules that are active")
    in_feed: bool | None = Param(description="Restrict to rules that are in a feed")
    type: str | None = Param(
        description="Comma-separated rule types (detection, triage, dlp)"
    )
    count: float | None = Param(description="Number of results to return")
    offset: float | None = Param(description="Offset from the first result")


class ListRuleHistoryOutput(ActionOutput):
    history: str


@app.action(
    description="List history for rules across the organization",
    action_type="investigate",
)
def list_rule_history(
    params: ListRuleHistoryParams, soar: SOARClient, asset: Asset
) -> ListRuleHistoryOutput:
    return impl.list_rule_history(params, soar, asset, ListRuleHistoryOutput)


class ValidateRuleParams(Params):
    name: str = Param(description="Rule name")
    source: str = Param(description="MQL rule source")


class ValidateRuleOutput(ActionOutput):
    validation_error: str
    is_org_dependent: bool
    functions: str
    list: str


@app.action(
    description="Validate rule MQL syntax without creating", action_type="investigate"
)
def validate_rule(
    params: ValidateRuleParams, soar: SOARClient, asset: Asset
) -> ValidateRuleOutput:
    return impl.validate_rule(params, soar, asset, ValidateRuleOutput)


class DeleteRuleParams(Params):
    rule_id: str = Param(
        description="UUID of the rule", primary=True, cef_types=["rule id"]
    )


@app.action(description="Delete a rule by ID", action_type="generic", read_only=False)
def delete_rule(
    params: DeleteRuleParams, soar: SOARClient, asset: Asset
) -> ActionOutput:
    return impl.delete_rule(params, soar, asset)


class GetRuleParams(Params):
    rule_id: str = Param(
        description="UUID of the rule", primary=True, cef_types=["rule id"]
    )


class GetRuleOutput(ActionOutput):
    id: str = OutputField(cef_types=["rule id"])
    name: str
    severity: str
    active: bool
    source: str
    description: str
    tags: str


@app.action(description="Retrieve a rule by ID", action_type="investigate")
def get_rule(params: GetRuleParams, soar: SOARClient, asset: Asset) -> GetRuleOutput:
    return impl.get_rule(params, soar, asset, GetRuleOutput)


class UpdateRuleParams(Params):
    rule_id: str = Param(
        description="UUID of the rule", primary=True, cef_types=["rule id"]
    )
    name: str | None = Param(description="New rule name")
    source: str | None = Param(description="New MQL source")
    severity: str | None = Param(
        description="New severity",
        value_list=["informational", "low", "medium", "high", "critical"],
    )
    description: str | None = Param(description="New description")
    label: str | None = Param(description="Rule label")
    maturity: str | None = Param(description="Rule maturity")
    tags: str | None = Param(description="Comma-separated tags")
    user_provided_tags: str | None = Param(
        description="Comma-separated user-provided tags"
    )
    attack_types: str | None = Param(description="Comma-separated attack types")
    detection_methods: str | None = Param(
        description="Comma-separated detection technologies"
    )
    tactics_and_techniques: str | None = Param(
        description="Comma-separated tactics and techniques"
    )
    false_positives: str | None = Param(
        description="Comma-separated descriptions of known false positives"
    )
    references: str | None = Param(description="Comma-separated URL references")
    action_ids: str | None = Param(
        description="Comma-separated IDs of actions to run when the rule triggers"
    )
    authors: str | None = Param(
        description='Rule authors as JSON array (e.g. [{"name":"Jane","twitter":"@jane"}])'
    )
    auto_review_classification: str | None = Param(
        description="Classification for auto-reviewed messages",
        value_list=[
            "malicious",
            "benign",
            "spam",
            "graymail",
            "simulation",
            "unwanted",
        ],
    )
    auto_review_auto_share: bool | None = Param(
        description="Whether auto-reviewed messages will be shared"
    )
    triage_abuse_reports: bool | None = Param(
        description="(Triage) run for reported messages"
    )
    triage_flagged_messages: bool | None = Param(
        description="(Triage) run for flagged messages"
    )
    triage_classification_changes: bool | None = Param(
        description="(Triage) run when classification changes"
    )
    triage_dlp_rule_matched: bool | None = Param(
        description="(Triage) run for messages matching a DLP rule"
    )
    run_triage_on_excluded_messages: bool | None = Param(
        description="(Triage) run even on globally-excluded messages"
    )


class UpdateRuleOutput(ActionOutput):
    id: str = OutputField(cef_types=["rule id"])
    name: str
    severity: str
    active: bool


@app.action(
    description="Update an existing rule", action_type="generic", read_only=False
)
def update_rule(
    params: UpdateRuleParams, soar: SOARClient, asset: Asset
) -> UpdateRuleOutput:
    return impl.update_rule(params, soar, asset, UpdateRuleOutput)


class ActivateRuleParams(Params):
    rule_id: str = Param(
        description="UUID of the rule", primary=True, cef_types=["rule id"]
    )


class ActivateRuleOutput(ActionOutput):
    id: str = OutputField(cef_types=["rule id"])
    name: str
    active: bool


@app.action(description="Activate a rule", action_type="generic", read_only=False)
def activate_rule(
    params: ActivateRuleParams, soar: SOARClient, asset: Asset
) -> ActivateRuleOutput:
    return impl.activate_rule(params, soar, asset, ActivateRuleOutput)


class DeactivateRuleParams(Params):
    rule_id: str = Param(
        description="UUID of the rule", primary=True, cef_types=["rule id"]
    )


class DeactivateRuleOutput(ActionOutput):
    id: str = OutputField(cef_types=["rule id"])
    name: str
    active: bool


@app.action(description="Deactivate a rule", action_type="generic", read_only=False)
def deactivate_rule(
    params: DeactivateRuleParams, soar: SOARClient, asset: Asset
) -> DeactivateRuleOutput:
    return impl.deactivate_rule(params, soar, asset, DeactivateRuleOutput)


class GetRuleHistoryParams(Params):
    rule_id: str = Param(
        description="UUID of the rule", primary=True, cef_types=["rule id"]
    )
    start_time: str | None = Param(
        description="Classification start time (ISO 8601 UTC)"
    )
    end_time: str | None = Param(description="Classification end time (ISO 8601 UTC)")
    use_rule_last_updated_as_created_at: bool | None = Param(
        description="Filter to classifications made since the rule was last updated"
    )


class RuleOutput(ActionOutput):
    id: str = OutputField(cef_types=["rule id"])
    name: str


class FlaggedMessageGroupsReportOutput(ActionOutput):
    total: float


class GetRuleHistoryOutput(ActionOutput):
    rule: RuleOutput
    flagged_message_groups_report: FlaggedMessageGroupsReportOutput


@app.action(
    description="Retrieve history of a specific rule", action_type="investigate"
)
def get_rule_history(
    params: GetRuleHistoryParams, soar: SOARClient, asset: Asset
) -> GetRuleHistoryOutput:
    return impl.get_rule_history(params, soar, asset, GetRuleHistoryOutput)


class GetTaskParams(Params):
    task_id: str = Param(description="UUID of the task", primary=True)


class GetTaskOutput(ActionOutput):
    id: str
    state: str
    created_at: str
    error: str


@app.action(description="Retrieve task status by ID", action_type="investigate")
def get_task(params: GetTaskParams, soar: SOARClient, asset: Asset) -> GetTaskOutput:
    return impl.get_task(params, soar, asset, GetTaskOutput)


class ListUserReportsParams(Params):
    start_time: str | None = Param(description="Start time filter (ISO 8601 UTC)")
    end_time: str | None = Param(description="End time filter (ISO 8601 UTC)")
    limit: float | None = Param(
        description="Maximum number of results (max: 500)", default=100
    )


class ListUserReportsOutput(ActionOutput):
    reporter: str
    channel: str
    reported_at: str
    reported_message_canonical_id: str


@app.action(
    description="List user-submitted phishing reports", action_type="investigate"
)
def list_user_reports(
    params: ListUserReportsParams, soar: SOARClient, asset: Asset
) -> ListUserReportsOutput:
    return impl.list_user_reports(params, soar, asset, ListUserReportsOutput)


class AssignRoleParams(Params):
    email_address: str = Param(
        description="Email address of the user", primary=True, cef_types=["email"]
    )
    role_title: str = Param(description="Role title to assign")


@app.action(
    description="Assign a role to a user", action_type="generic", read_only=False
)
def assign_role(
    params: AssignRoleParams, soar: SOARClient, asset: Asset
) -> ActionOutput:
    return impl.assign_role(params, soar, asset)


class ListScimResourceTypesOutput(ActionOutput):
    id: str
    name: str
    endpoint: str
    description: str


@app.action(description="List SCIM resource types", action_type="investigate")
def list_scim_resource_types(
    params: Params, soar: SOARClient, asset: Asset
) -> ListScimResourceTypesOutput:
    return impl.list_scim_resource_types(params, soar, asset, ListScimResourceTypesOutput)


class GetScimResourceTypeParams(Params):
    resource_type_id: str = Param(description="Resource type ID", primary=True)


class GetScimResourceTypeOutput(ActionOutput):
    id: str
    name: str
    endpoint: str
    schema_: str = OutputField(alias="schema")


@app.action(description="Get a single SCIM resource type", action_type="investigate")
def get_scim_resource_type(
    params: GetScimResourceTypeParams, soar: SOARClient, asset: Asset
) -> GetScimResourceTypeOutput:
    return impl.get_scim_resource_type(params, soar, asset, GetScimResourceTypeOutput)


class ListScimUsersParams(Params):
    count: float | None = Param(
        description="Maximum number of results (max: 1000)", default=100
    )
    start_index: float | None = Param(
        description="1-based start index for pagination", default=1
    )
    filter: str | None = Param(description="SCIM filter expression")


class NameOutput(ActionOutput):
    givenName: str
    familyName: str


class ListScimUsersOutput(ActionOutput):
    id: str
    userName: str = OutputField(cef_types=["email"])
    name: NameOutput
    active: bool


@app.action(description="List SCIM provisioned users", action_type="investigate")
def list_scim_users(
    params: ListScimUsersParams, soar: SOARClient, asset: Asset
) -> ListScimUsersOutput:
    return impl.list_scim_users(params, soar, asset, ListScimUsersOutput)


class CreateScimUserParams(Params):
    user_name: str = Param(
        description="Username (typically email)", primary=True, cef_types=["email"]
    )
    given_name: str = Param(description="First name")
    family_name: str = Param(description="Last name")
    email: str = Param(description="Email address", cef_types=["email"])
    active: bool | None = Param(description="Set user as active", default=True)


class CreateScimUserOutput(ActionOutput):
    id: str
    userName: str = OutputField(cef_types=["email"])
    active: bool


@app.action(
    description="Create a user via SCIM", action_type="generic", read_only=False
)
def create_scim_user(
    params: CreateScimUserParams, soar: SOARClient, asset: Asset
) -> CreateScimUserOutput:
    return impl.create_scim_user(params, soar, asset, CreateScimUserOutput)


class GetScimUserParams(Params):
    user_id: str = Param(description="Sublime user ID", primary=True)


class NameOutput(ActionOutput):
    givenName: str
    familyName: str


class GetScimUserOutput(ActionOutput):
    id: str
    userName: str = OutputField(cef_types=["email"])
    name: NameOutput
    active: bool


@app.action(description="Get a SCIM user by ID", action_type="investigate")
def get_scim_user(
    params: GetScimUserParams, soar: SOARClient, asset: Asset
) -> GetScimUserOutput:
    return impl.get_scim_user(params, soar, asset, GetScimUserOutput)


class DeleteScimUserParams(Params):
    user_id: str = Param(description="Sublime user ID", primary=True)


@app.action(
    description="Delete a SCIM user by ID", action_type="generic", read_only=False
)
def delete_scim_user(
    params: DeleteScimUserParams, soar: SOARClient, asset: Asset
) -> ActionOutput:
    return impl.delete_scim_user(params, soar, asset)


class UpdateScimUserParams(Params):
    user_id: str = Param(description="Sublime user ID", primary=True)
    user_name: str = Param(description="Username", cef_types=["email"])
    given_name: str = Param(description="First name")
    family_name: str = Param(description="Last name")
    email: str = Param(description="Email address", cef_types=["email"])
    active: bool | None = Param(description="Set user as active", default=True)


class UpdateScimUserOutput(ActionOutput):
    id: str
    userName: str = OutputField(cef_types=["email"])
    active: bool


@app.action(
    description="Full update of a SCIM user (PUT)",
    action_type="generic",
    read_only=False,
)
def update_scim_user(
    params: UpdateScimUserParams, soar: SOARClient, asset: Asset
) -> UpdateScimUserOutput:
    return impl.update_scim_user(params, soar, asset, UpdateScimUserOutput)


class PatchScimUserParams(Params):
    user_id: str = Param(description="Sublime user ID", primary=True)
    operations_json: str = Param(
        description='JSON array of SCIM PATCH operations, e.g. [{"op":"replace","path":"active","value":false}]'
    )


class PatchScimUserOutput(ActionOutput):
    id: str
    userName: str = OutputField(cef_types=["email"])
    active: bool


@app.action(
    description="Partial update of a SCIM user (PATCH)",
    action_type="generic",
    read_only=False,
)
def patch_scim_user(
    params: PatchScimUserParams, soar: SOARClient, asset: Asset
) -> PatchScimUserOutput:
    return impl.patch_scim_user(params, soar, asset, PatchScimUserOutput)


class ValidateScimAuthOutput(ActionOutput):
    user_email: str = OutputField(cef_types=["email"])


@app.action(
    description="Validate SCIM-specific authentication", action_type="investigate"
)
def validate_scim_auth(
    params: Params, soar: SOARClient, asset: Asset
) -> ValidateScimAuthOutput:
    return impl.validate_scim_auth(params, soar, asset, ValidateScimAuthOutput)


class ListScimSchemasOutput(ActionOutput):
    id: str
    name: str
    description: str


@app.action(description="List SCIM schemas", action_type="investigate")
def list_scim_schemas(
    params: Params, soar: SOARClient, asset: Asset
) -> ListScimSchemasOutput:
    return impl.list_scim_schemas(params, soar, asset, ListScimSchemasOutput)


class GetScimSchemaParams(Params):
    schema_id: str = Param(
        description="Schema ID (e.g. urn:ietf:params:scim:schemas:core:2.0:User)",
        primary=True,
    )


class GetScimSchemaOutput(ActionOutput):
    id: str
    name: str
    description: str
    attributes: str


@app.action(description="Get a single SCIM schema by ID", action_type="investigate")
def get_scim_schema(
    params: GetScimSchemaParams, soar: SOARClient, asset: Asset
) -> GetScimSchemaOutput:
    return impl.get_scim_schema(params, soar, asset, GetScimSchemaOutput)


class PatchOutput(ActionOutput):
    supported: bool


class BulkOutput(ActionOutput):
    supported: bool


class FilterOutput(ActionOutput):
    supported: bool


class SortOutput(ActionOutput):
    supported: bool


class ChangepasswordOutput(ActionOutput):
    supported: bool


class EtagOutput(ActionOutput):
    supported: bool


class GetScimServiceProviderConfigOutput(ActionOutput):
    patch: PatchOutput
    bulk: BulkOutput
    filter: FilterOutput
    sort: SortOutput
    changePassword: ChangepasswordOutput
    etag: EtagOutput


@app.action(
    description="Get SCIM service provider configuration", action_type="investigate"
)
def get_scim_service_provider_config(
    params: Params, soar: SOARClient, asset: Asset
) -> GetScimServiceProviderConfigOutput:
    return impl.get_scim_service_provider_config(params, soar, asset, GetScimServiceProviderConfigOutput)


class ListChildOrganizationsParams(Params):
    active: bool | None = Param(
        description="Filter by active status (omit for all)"
    )
    limit: float | None = Param(
        description="Maximum number of organizations to return (max: 500)", default=50
    )
    offset: float | None = Param(
        description="Zero-based offset for pagination", default=0
    )
    max_depth: float | None = Param(
        description="Hierarchy depth to descend (1 = direct children)"
    )
    parent_org_id: str | None = Param(
        description="Restrict results to descendants of this organization ID"
    )
    search: str | None = Param(
        description="Case-insensitive substring filter on organization name"
    )


class ListChildOrganizationsOutput(ActionOutput):
    id: str | None = None
    name: str | None = None
    active: bool | None = None


@app.action(
    description="List child organizations under the calling organization",
    action_type="investigate",
)
def list_child_organizations(
    params: ListChildOrganizationsParams, soar: SOARClient, asset: Asset
) -> list[ListChildOrganizationsOutput]:
    return impl.list_child_organizations(
        params, soar, asset, ListChildOrganizationsOutput
    )


class CreateChildOrganizationParams(Params):
    name: str = Param(description="Display name for the child organization")
    licenses_json: str | None = Param(
        description="Optional JSON array/object of licenses to provision"
    )


class CreateChildOrganizationOutput(ActionOutput):
    id: str | None = None
    name: str | None = None


@app.action(
    description="Create a child organization under the calling organization",
    action_type="generic",
    read_only=False,
)
def create_child_organization(
    params: CreateChildOrganizationParams, soar: SOARClient, asset: Asset
) -> CreateChildOrganizationOutput:
    return impl.create_child_organization(
        params, soar, asset, CreateChildOrganizationOutput
    )


class PatchChildOrganizationParams(Params):
    organization_id: str = Param(description="Child organization ID", primary=True)
    name: str | None = Param(description="Updated display name")
    delegation_json: str | None = Param(
        description="Optional JSON object of delegation settings to merge into the patch body"
    )


class PatchChildOrganizationOutput(ActionOutput):
    id: str | None = None
    name: str | None = None


@app.action(
    description="Update a child organization's name and/or delegation settings",
    action_type="generic",
    read_only=False,
)
def patch_child_organization(
    params: PatchChildOrganizationParams, soar: SOARClient, asset: Asset
) -> PatchChildOrganizationOutput:
    return impl.patch_child_organization(
        params, soar, asset, PatchChildOrganizationOutput
    )


class PatchChildOrganizationLicensingParams(Params):
    organization_id: str = Param(description="Child organization ID", primary=True)
    licensing_json: str = Param(
        description="JSON body for the desired license transition"
    )


class PatchChildOrganizationLicensingOutput(ActionOutput):
    id: str | None = None


@app.action(
    description="Apply a license transition to a child organization",
    action_type="generic",
    read_only=False,
)
def patch_child_organization_licensing(
    params: PatchChildOrganizationLicensingParams, soar: SOARClient, asset: Asset
) -> PatchChildOrganizationLicensingOutput:
    return impl.patch_child_organization_licensing(
        params, soar, asset, PatchChildOrganizationLicensingOutput
    )


class BulkPatchChildOrganizationLicensingParams(Params):
    bulk_licensing_json: str = Param(
        description="JSON body for bulk license transitions (up to 200 orgs)"
    )


class BulkPatchChildOrganizationLicensingOutput(ActionOutput):
    results: list[str] | None = None


@app.action(
    description="Bulk update licensing for up to 200 child organizations",
    action_type="generic",
    read_only=False,
)
def bulk_patch_child_organization_licensing(
    params: BulkPatchChildOrganizationLicensingParams, soar: SOARClient, asset: Asset
) -> BulkPatchChildOrganizationLicensingOutput:
    return impl.bulk_patch_child_organization_licensing(
        params, soar, asset, BulkPatchChildOrganizationLicensingOutput
    )


@app.webhook("webhook", allowed_methods=["POST"])
def sublime_webhook(
    request: WebhookRequest[Asset], soar: SOARClient
) -> WebhookResponse:
    return handle_sublime_webhook(request, soar)


if __name__ == "__main__":
    app.cli()
