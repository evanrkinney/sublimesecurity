# Sublime Security

Built with the [Splunk SOAR SDK](https://phantomcyber.github.io/splunk-soar-sdk/api_reference.html).

Publisher: Splunk SOAR Community <br>
Connector Version: 1.1.0 <br>
Product Vendor: Sublime Security <br>
Product Name: Sublime Platform <br>
Minimum Product Version: 6.4.0

Integrates with the Sublime Security Platform API to perform email security operations including binexplode analysis, link analysis, audit log management, hunt jobs, list management, message group actions, message analysis, rule management, SCIM user provisioning, and more

### Configuration variables

This table lists the configuration variables required to operate Sublime Security. These variables are specified when configuring a Sublime Platform asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**region** | required | string | Sublime Security region |
**base_url** | optional | string | Custom base URL (used only when region is Custom) |
**api_key** | required | password | API key for Sublime Security |
**verify_server_cert** | optional | boolean | Verify server certificate |
**webhook_container_label** | optional | string | SOAR label for inbound webhook containers |
**webhook_container_severity** | optional | string | Severity for webhook containers; see README for 'use alert severity' |
**webhook_container_sensitivity** | optional | string | TLP sensitivity for inbound webhook containers |
**webhook_signing_secret** | optional | password | Sublime webhook signing secret (see README) |
**webhook_signature_tolerance_seconds** | optional | numeric | Reject signatures older than this many seconds |
**webhook_fetch_eml** | optional | boolean | Fetch each flagged message's EML into container vault |
**webhook_container_sdi_strategy** | optional | string | How webhook containers are deduplicated (see README) |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied credentials <br>
[upload binary](#action-upload-binary) - Upload a binary to be binexploded. Results expire after 1 hour. Max original file size 37 MB <br>
[get binexplode results](#action-get-binexplode-results) - Get results of a binexplode scan by task ID <br>
[analyze link](#action-analyze-link) - Analyze a provided URL using Sublime Security ml.link_analysis for credential phishing detection <br>
[list audit events](#action-list-audit-events) - List events in the Sublime Security audit log <br>
[list audit event types](#action-list-audit-event-types) - List all available event types for the audit log <br>
[get audit event](#action-get-audit-event) - Retrieve a single event from the audit log <br>
[start hunt job](#action-start-hunt-job) - Start a hunt job using MQL source <br>
[get hunt job](#action-get-hunt-job) - Get the status of a hunt job <br>
[get hunt job results](#action-get-hunt-job-results) - Get the results of a completed hunt job <br>
[list lists](#action-list-lists) - Retrieve all lists <br>
[create list](#action-create-list) - Create a new list <br>
[delete list](#action-delete-list) - Delete a list by ID <br>
[get list](#action-get-list) - Get a single list by ID <br>
[patch list](#action-patch-list) - Patch a list's description <br>
[get list entries](#action-get-list-entries) - Get all entries in a list, optionally saving them to the vault as a CSV file <br>
[set list entries](#action-set-list-entries) - Replace all entries in a list. Provide entries as a comma-separated string OR a vault CSV file ID <br>
[delete list entry](#action-delete-list-entry) - Delete a single entry from a list <br>
[get list entry](#action-get-list-entry) - Check if a single entry or multiple entries exist in a list <br>
[add list entry](#action-add-list-entry) - Add a single entry to a list <br>
[process raw message](#action-process-raw-message) - Process a raw EML message through Sublime Security live flow <br>
[list mailboxes](#action-list-mailboxes) - List connected mailboxes <br>
[list message groups](#action-list-message-groups) - List message groups. With no canonical id, defaults to flagged groups from the last 7 days <br>
[dismiss message groups](#action-dismiss-message-groups) - Dismiss multiple message groups <br>
[quarantine message groups](#action-quarantine-message-groups) - Quarantine multiple message groups <br>
[graymail message groups](#action-graymail-message-groups) - Move multiple message groups to graymail <br>
[restore message groups](#action-restore-message-groups) - Restore multiple message groups <br>
[review message groups](#action-review-message-groups) - Review message groups with classification and optional action <br>
[search message groups](#action-search-message-groups) - Search message groups. At least one search field, state, hash, or time bound is required <br>
[trash message groups](#action-trash-message-groups) - Trash multiple message groups <br>
[get message group](#action-get-message-group) - Get a single message group by canonical ID <br>
[dismiss message group](#action-dismiss-message-group) - Dismiss a single message group <br>
[quarantine message group](#action-quarantine-message-group) - Quarantine a single message group <br>
[restore message group](#action-restore-message-group) - Restore a single message group <br>
[share with sublime](#action-share-with-sublime) - Share a message group with Sublime for community detection <br>
[trash message group](#action-trash-message-group) - Trash a single message group <br>
[analyze raw message](#action-analyze-raw-message) - Analyze a raw EML message against rules and queries. Runs active detection rules when no run flag is set <br>
[render attachment image](#action-render-attachment-image) - Render image for attachment from raw base64 encoded bytes <br>
[get attack score raw](#action-get-attack-score-raw) - Evaluate attack score for a raw message <br>
[create message](#action-create-message) - Create a new message from a raw EML <br>
[get action state](#action-get-action-state) - Retrieve the state of manual actions for a canonical group <br>
[get message](#action-get-message) - Retrieve a message by ID <br>
[action message](#action-action-message) - Perform an action on an individual message <br>
[analyze message by id](#action-analyze-message-by-id) - Analyze an existing message by its ID against rules and queries. Runs active detection rules when no run flag is set <br>
[get asa report](#action-get-asa-report) - Retrieve ASA (Attack Surface Assessment) report for a message <br>
[get asa verdict](#action-get-asa-verdict) - Retrieve ASA verdict for a message (malicious, spam, graymail, likely_benign, benign, unknown) <br>
[get attachment image](#action-get-attachment-image) - Retrieve image of a PDF attachment by MD5 hash <br>
[get attack score](#action-get-attack-score) - Evaluate attack score against an existing message <br>
[get message image](#action-get-message-image) - Retrieve rendered image of a message <br>
[get message eml](#action-get-message-eml) - Retrieve raw EML content of a message <br>
[get message image link](#action-get-message-image-link) - Retrieve a temporary link to the image of a message <br>
[set access justification](#action-set-access-justification) - Set access justification for a message <br>
[get message data model](#action-get-message-data-model) - Retrieve the message's Message Data Model (MDM) <br>
[restore message](#action-restore-message) - Restore a previously trashed message <br>
[trash message](#action-trash-message) - Trash an individual message <br>
[list rules](#action-list-rules) - List all rules in the organization <br>
[create rule](#action-create-rule) - Create a new detection, DLP, or triage rule <br>
[list rule history](#action-list-rule-history) - List history for rules across the organization <br>
[validate rule](#action-validate-rule) - Validate rule MQL syntax without creating <br>
[delete rule](#action-delete-rule) - Delete a rule by ID <br>
[get rule](#action-get-rule) - Retrieve a rule by ID <br>
[update rule](#action-update-rule) - Update an existing rule. Omitted fields are kept from the current rule <br>
[activate rule](#action-activate-rule) - Activate a rule <br>
[deactivate rule](#action-deactivate-rule) - Deactivate a rule <br>
[get rule history](#action-get-rule-history) - Retrieve history of a specific rule <br>
[get task](#action-get-task) - Retrieve task status by ID <br>
[list user reports](#action-list-user-reports) - List user-submitted phishing reports. Defaults to the last 30 days when no time bound is set <br>
[assign role](#action-assign-role) - Assign a role to a user <br>
[list scim resource types](#action-list-scim-resource-types) - List SCIM resource types <br>
[get scim resource type](#action-get-scim-resource-type) - Get a single SCIM resource type <br>
[list scim users](#action-list-scim-users) - List SCIM provisioned users <br>
[create scim user](#action-create-scim-user) - Create a user via SCIM <br>
[get scim user](#action-get-scim-user) - Get a SCIM user by ID <br>
[delete scim user](#action-delete-scim-user) - Delete a SCIM user by ID <br>
[update scim user](#action-update-scim-user) - Full update of a SCIM user (PUT) <br>
[patch scim user](#action-patch-scim-user) - Partial update of a SCIM user (PATCH) <br>
[validate scim auth](#action-validate-scim-auth) - Validate SCIM-specific authentication <br>
[list scim schemas](#action-list-scim-schemas) - List SCIM schemas <br>
[get scim schema](#action-get-scim-schema) - Get a single SCIM schema by ID <br>
[get scim service provider config](#action-get-scim-service-provider-config) - Get SCIM service provider configuration

## action: 'test connectivity'

Validate the asset configuration for connectivity using supplied credentials

Type: **test** <br>
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'upload binary'

Upload a binary to be binexploded. Results expire after 1 hour. Max original file size 37 MB

Type: **investigate** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault_id** | optional | Vault ID of the file to upload | string | `vault id` |
**base64_data** | optional | Base64 encoded contents of the file (alternative to vault_id) | string | |
**file_name** | required | Name of the file | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.message | string | | |
action_result.summary.task_id | string | | |
action_result.data.\*.task_id | string | | |
action_result.parameter.vault_id | string | `vault id` | |
action_result.parameter.file_name | string | | |
action_result.parameter.base64_data | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'get binexplode results'

Get results of a binexplode scan by task ID

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**task_id** | required | Task ID returned from upload binary action | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.message | string | | |
action_result.summary.total_results | numeric | | |
action_result.summary.task_state | string | | |
action_result.data.\*.file_name | string | | |
action_result.data.\*.file_extension | string | | |
action_result.data.\*.depth | numeric | | |
action_result.data.\*.size | numeric | | |
action_result.data.\*.source | string | | |
action_result.data.\*.node_id | string | | |
action_result.data.\*.parent_node_id | string | | |
action_result.data.\*.scan.hash.md5 | string | `md5` | |
action_result.data.\*.scan.hash.sha1 | string | `sha1` | |
action_result.data.\*.scan.hash.sha256 | string | `sha256` | |
action_result.parameter.task_id | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'analyze link'

Analyze a provided URL using Sublime Security ml.link_analysis for credential phishing detection

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** | required | URL to analyze | string | `url` |
**no_logo_detect** | optional | Skip logo detection during analysis | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.message | string | | |
action_result.summary.screenshot_vault_id | string | `vault id` | |
action_result.summary.disposition | string | | benign phishing unknown |
action_result.summary.confidence | string | | |
action_result.summary.brand_name | string | | |
action_result.summary.analyzed | boolean | | |
action_result.data.\*.analyzed | boolean | | |
action_result.data.\*.credphish.disposition | string | | |
action_result.data.\*.credphish.confidence | string | | |
action_result.data.\*.credphish.brand.name | string | | |
action_result.data.\*.credphish.contains_login | boolean | | |
action_result.data.\*.credphish.contains_captcha | boolean | | |
action_result.data.\*.effective_url.url | string | `url` | |
action_result.data.\*.original_url.url | string | `url` | |
action_result.data.\*.effective_url.domain.domain | string | `domain` | |
action_result.data.\*.content_type | string | | |
action_result.data.\*.page_status_code | numeric | | |
action_result.data.\*.retrieved | boolean | | |
action_result.data.\*.screenshot.raw | string | | |
action_result.parameter.url | string | `url` | |
action_result.parameter.no_logo_detect | boolean | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'list audit events'

List events in the Sublime Security audit log

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start_time** | optional | Inclusive start datetime filter (ISO 8601 UTC) | string | |
**end_time** | optional | Exclusive end datetime filter (ISO 8601 UTC) | string | |
**event_type** | optional | Filter by event type | string | |
**user_ids** | optional | Comma-separated user IDs to filter by | string | |
**limit** | optional | Maximum number of events to return (max: 500) | numeric | |
**offset** | optional | Zero-based offset for pagination | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.total_events | numeric | | |
action_result.summary.events_returned | numeric | | |
action_result.data.\*.id | string | `event id` | |
action_result.data.\*.type | string | | |
action_result.data.\*.created_at | string | | |
action_result.data.\*.created_by.email_address | string | `email` | |
action_result.data.\*.data.request.method | string | | |
action_result.data.\*.data.request.path | string | | |
action_result.data.\*.data.request.ip | string | `ip` | |
action_result.parameter.start_time | string | | |
action_result.parameter.end_time | string | | |
action_result.parameter.event_type | string | | |
action_result.parameter.user_ids | string | | |
action_result.parameter.limit | numeric | | |
action_result.parameter.offset | numeric | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'list audit event types'

List all available event types for the audit log

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.total_event_types | numeric | | |
action_result.data.\*.name | string | | |
action_result.data.\*.type | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'get audit event'

Retrieve a single event from the audit log

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**event_id** | required | UUID of the audit event | string | `event id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.data.\*.id | string | `event id` | |
action_result.data.\*.type | string | | |
action_result.data.\*.created_at | string | | |
action_result.data.\*.created_by.email_address | string | `email` | |
action_result.data.\*.data.request.method | string | | |
action_result.data.\*.data.request.path | string | | |
action_result.data.\*.data.request.ip | string | `ip` | |
action_result.parameter.event_id | string | `event id` | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'start hunt job'

Start a hunt job using MQL source

Type: **investigate** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**source** | required | MQL source query | string | |
**range_start_time** | required | Start time for hunt range (ISO 8601 UTC) | string | |
**range_end_time** | required | End time for hunt range (ISO 8601 UTC) | string | |
**name** | optional | Name for the hunt job | string | |
**private** | optional | Make hunt visible only to admins | boolean | |
**triage_flagged** | optional | Pre-filter to flagged messages (OR'd with other triage filters) | boolean | |
**triage_reported** | optional | Pre-filter to user-reported messages (OR'd with other triage filters) | boolean | |
**triage_email_bomb** | optional | Pre-filter to messages in an email bomb (OR'd with other triage filters) | boolean | |
**triage_dlp_rule_matched** | optional | Pre-filter to messages that matched a DLP rule (OR'd with other triage filters) | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.hunt_job_id | string | | |
action_result.data.\*.hunt_job_id | string | | |
action_result.parameter.source | string | | |
action_result.parameter.range_start_time | string | | |
action_result.parameter.range_end_time | string | | |
action_result.parameter.name | string | | |
action_result.parameter.private | boolean | | |
action_result.parameter.triage_flagged | boolean | | |
action_result.parameter.triage_reported | boolean | | |
action_result.parameter.triage_email_bomb | boolean | | |
action_result.parameter.triage_dlp_rule_matched | boolean | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'get hunt job'

Get the status of a hunt job

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hunt_job_id** | required | Hunt job ID | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.hunt_status | string | | |
action_result.data.\*.id | string | | |
action_result.data.\*.status | string | | |
action_result.data.\*.source | string | | |
action_result.data.\*.range_start_time | string | | |
action_result.data.\*.range_end_time | string | | |
action_result.data.\*.error | string | | |
action_result.data.\*.results_truncated | boolean | | |
action_result.parameter.hunt_job_id | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'get hunt job results'

Get the results of a completed hunt job

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hunt_job_id** | required | Hunt job ID | string | |
**limit** | optional | Maximum number of results (max: 500) | numeric | |
**offset** | optional | Zero-based offset for pagination | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.total_group_count | numeric | | |
action_result.summary.groups_returned | numeric | | |
action_result.data.\*.id | string | | |
action_result.data.\*.review_status | string | | |
action_result.data.\*.classification | string | | |
action_result.parameter.hunt_job_id | string | | |
action_result.parameter.limit | numeric | | |
action_result.parameter.offset | numeric | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'list lists'

Retrieve all lists

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** | optional | Filter by list name | string | |
**entry_type** | optional | Filter by list entry type (e.g. string, user_group, provider_org_unit). If omitted, lists of all entry types are returned | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.total_lists | numeric | | |
action_result.data.\*.id | string | `list id` | |
action_result.data.\*.name | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.entry_type | string | | |
action_result.data.\*.editable | boolean | | |
action_result.data.\*.created_at | string | | |
action_result.data.\*.updated_at | string | | |
action_result.parameter.name | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |
action_result.parameter.entry_type | string | | |

## action: 'create list'

Create a new list

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** | required | Name of the list | string | |
**description** | required | Description of the list | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.list_id | string | `list id` | |
action_result.data.\*.id | string | `list id` | |
action_result.data.\*.name | string | | |
action_result.data.\*.description | string | | |
action_result.parameter.name | string | | |
action_result.parameter.description | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'delete list'

Delete a list by ID

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**list_id** | required | UUID of the list to delete | string | `list id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.parameter.list_id | string | `list id` | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'get list'

Get a single list by ID

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**list_id** | required | UUID of the list | string | `list id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.data.\*.id | string | `list id` | |
action_result.data.\*.name | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.entry_type | string | | |
action_result.data.\*.editable | boolean | | |
action_result.data.\*.created_at | string | | |
action_result.data.\*.updated_at | string | | |
action_result.parameter.list_id | string | `list id` | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'patch list'

Patch a list's description

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**list_id** | required | UUID of the list | string | `list id` |
**description** | required | New description for the list | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.data.\*.id | string | `list id` | |
action_result.data.\*.name | string | | |
action_result.data.\*.description | string | | |
action_result.parameter.list_id | string | `list id` | |
action_result.parameter.description | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'get list entries'

Get all entries in a list, optionally saving them to the vault as a CSV file

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**list_id** | required | UUID of the list | string | `list id` |
**save_to_vault** | optional | Save the list entries to the vault as a CSV file | boolean | |
**csv_file_name** | optional | Optional file name for the CSV (default: list\_\<list_id>\_entries.csv) | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.total_entries | numeric | | |
action_result.summary.vault_id | string | `vault id` | |
action_result.data.\*.entry | string | | |
action_result.parameter.list_id | string | `list id` | |
action_result.parameter.save_to_vault | boolean | | |
action_result.parameter.csv_file_name | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'set list entries'

Replace all entries in a list. Provide entries as a comma-separated string OR a vault CSV file ID

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**list_id** | required | UUID of the list | string | `list id` |
**entries** | optional | Comma-separated list of entries (alternative to vault_id) | string | |
**vault_id** | optional | Vault ID of a CSV file containing entries (one per row, or comma-separated) | string | `vault id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.entries_set | numeric | | |
action_result.parameter.list_id | string | `list id` | |
action_result.parameter.entries | string | | |
action_result.parameter.vault_id | string | `vault id` | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'delete list entry'

Delete a single entry from a list

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**list_id** | required | UUID of the list | string | `list id` |
**entry** | required | The entry string to delete (max 2000 chars) | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.parameter.list_id | string | `list id` | |
action_result.parameter.entry | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'get list entry'

Check if a single entry or multiple entries exist in a list

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**list_id** | required | UUID of the list | string | `list id` |
**entry** | required | Entry string OR comma-separated list of entries to look up (max 2000 chars each) | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.total_checked | numeric | | |
action_result.summary.total_found | numeric | | |
action_result.data.\*.entry | string | | |
action_result.data.\*.found | boolean | | |
action_result.parameter.list_id | string | `list id` | |
action_result.parameter.entry | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'add list entry'

Add a single entry to a list

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**list_id** | required | UUID of the list | string | `list id` |
**entry** | required | The entry string to add (max 2000 chars) | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.parameter.list_id | string | `list id` | |
action_result.parameter.entry | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'process raw message'

Process a raw EML message through Sublime Security live flow

Type: **investigate** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault_id** | optional | Vault ID of the EML file | string | `vault id` |
**base64_data** | optional | Base64 encoded EML (alternative to vault_id) | string | |
**mailbox_email_address** | required | Mailbox email address | string | `email` |
**message_source_id** | required | Message source UUID | string | |
**create_mailbox** | optional | Create mailbox if it does not exist | boolean | |
**analyze_async** | optional | Run analysis and finish ingestion async. flagged_rules will be empty on response | boolean | |
**canonical_id** | optional | Known canonical (message group) ID (64 chars) | string | |
**external_message_id** | optional | ID of the message according to the external source | string | |
**external_thread_id** | optional | ID of the thread according to the external source | string | |
**external_created_at** | optional | Timestamp the message was created per external source (ISO 8601) | string | |
**folder** | optional | The mailbox folder the message is in | string | |
**labels** | optional | Comma-separated labels applied by the mailbox | string | |
**route_type** | optional | Directional route type of the message | string | |
**message_type** | optional | Message type override | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.message_id | string | | |
action_result.summary.flagged_rules_count | numeric | | |
action_result.data.\*.canonical_id | string | | |
action_result.data.\*.message_id | string | `message id` | |
action_result.data.\*.raw_message_id | string | | |
action_result.data.\*.flagged_rules | string | | |
action_result.parameter.vault_id | string | `vault id` | |
action_result.parameter.base64_data | string | | |
action_result.parameter.mailbox_email_address | string | `email` | |
action_result.parameter.message_source_id | string | | |
action_result.parameter.create_mailbox | boolean | | |
action_result.parameter.analyze_async | boolean | | |
action_result.parameter.canonical_id | string | | |
action_result.parameter.external_message_id | string | | |
action_result.parameter.external_thread_id | string | | |
action_result.parameter.external_created_at | string | | |
action_result.parameter.folder | string | | |
action_result.parameter.labels | string | | |
action_result.parameter.route_type | string | | |
action_result.parameter.message_type | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'list mailboxes'

List connected mailboxes

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**active** | optional | Filter for effectively active mailboxes (marked active with a live subscription) | boolean | |
**marked_active** | optional | Filter for mailboxes marked active | boolean | |
**search** | optional | Search across mailbox names and email addresses | string | |
**email_addresses** | optional | Comma-delimited email addresses to return | string | `email` |
**mailbox_types** | optional | Comma-delimited mailbox types to filter by | string | |
**sub_error_types** | optional | Comma-delimited subscription error types to filter by | string | |
**message_source_id** | optional | ID of the message source the mailboxes belong to | string | |
**limit** | optional | Maximum number of results (max: 500) | numeric | |
**offset** | optional | Zero-based offset for pagination | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.total_mailboxes | numeric | | |
action_result.summary.active_mailboxes | numeric | | |
action_result.data.\*.id | string | | |
action_result.data.\*.email_address | string | `email` | |
action_result.data.\*.active | boolean | | |
action_result.data.\*.subscription_error_status | string | | |
action_result.parameter.active | boolean | | |
action_result.parameter.marked_active | boolean | | |
action_result.parameter.search | string | | |
action_result.parameter.email_addresses | string | `email` | |
action_result.parameter.mailbox_types | string | | |
action_result.parameter.sub_error_types | string | | |
action_result.parameter.message_source_id | string | | |
action_result.parameter.limit | numeric | | |
action_result.parameter.offset | numeric | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'list message groups'

List message groups. With no canonical id, defaults to flagged groups from the last 7 days

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start_time** | optional | Start time filter (ISO 8601 UTC), maps to created_at\_\_gte. Defaults to the last 7 days when no canonical id or report-time bound is set | string | |
**end_time** | optional | End time filter (ISO 8601 UTC), maps to created_at\_\_lt | string | |
**flagged** | optional | Filter by flagged status. Defaults to true when no canonical id is set and user_reported is not true | boolean | |
**reviewed** | optional | Filter by reviewed status | boolean | |
**user_reported** | optional | Filter to groups with at least one reported message | boolean | |
**attack_surface_reduction** | optional | Filter to groups with flagged 'Attack surface reduction' tag | boolean | |
**sender_email** | optional | Filter by sender email (comma-separated list) | string | `email` |
**sender_domain** | optional | Filter by sender domain (comma-separated) | string | |
**sender_display_name** | optional | Filter by sender display name (comma-separated) | string | |
**mailbox_email** | optional | Filter by mailbox email (comma-separated) | string | `email` |
**recipient_email** | optional | Filter by recipient email (comma-separated) | string | `email` |
**subject** | optional | Filter by subject (comma-separated) | string | |
**canonical_id** | optional | Filter by canonical ID (comma-separated) | string | |
**attachment_name** | optional | Filter by attachment name (comma-separated) | string | |
**attachment_sha256** | optional | Filter by attachment SHA256 (comma-separated) | string | `sha256` |
**attack_score_verdict** | optional | Filter by attack score verdict (comma-separated: unknown, likely_benign, suspicious, malicious, graymail, spam) | string | |
**flagged_rule_id** | optional | Filter by flagged rule ID (comma-separated) | string | |
**flagged_rule_severity** | optional | Filter by flagged rule severity (comma-separated: informational, low, medium, high, critical) | string | |
**historically_flagged_rule_id** | optional | Filter by historically flagged rule ID (comma-separated) | string | |
**historically_flagged_rule_severity** | optional | Filter by historically flagged rule severity (comma-separated) | string | |
**reported_as_phish_by** | optional | Filter by reporter (comma-separated) | string | |
**spam_status** | optional | Filter by spam status (comma-separated: spam, not_spam, mixed) | string | |
**vendor_id** | optional | Filter by vendor ID (comma-separated) | string | |
**first_message_reported_at_gte** | optional | Only groups with a message first reported at or after this time (ISO 8601 UTC) | string | |
**limit** | optional | Maximum number of results (max: 500) | numeric | |
**offset** | optional | Zero-based offset for pagination | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.total_groups | numeric | | |
action_result.summary.groups_returned | numeric | | |
action_result.data.\*.id | string | `message group id` | |
action_result.data.\*.review_status | string | | |
action_result.data.\*.classification | string | | |
action_result.data.\*.state | string | | |
action_result.parameter.start_time | string | | |
action_result.parameter.end_time | string | | |
action_result.parameter.flagged | boolean | | |
action_result.parameter.reviewed | boolean | | |
action_result.parameter.user_reported | boolean | | |
action_result.parameter.attack_surface_reduction | boolean | | |
action_result.parameter.sender_email | string | `email` | |
action_result.parameter.sender_domain | string | | |
action_result.parameter.sender_display_name | string | | |
action_result.parameter.mailbox_email | string | `email` | |
action_result.parameter.recipient_email | string | `email` | |
action_result.parameter.subject | string | | |
action_result.parameter.canonical_id | string | | |
action_result.parameter.attachment_name | string | | |
action_result.parameter.attachment_sha256 | string | `sha256` | |
action_result.parameter.attack_score_verdict | string | | |
action_result.parameter.flagged_rule_id | string | | |
action_result.parameter.flagged_rule_severity | string | | |
action_result.parameter.historically_flagged_rule_id | string | | |
action_result.parameter.historically_flagged_rule_severity | string | | |
action_result.parameter.reported_as_phish_by | string | | |
action_result.parameter.spam_status | string | | |
action_result.parameter.vendor_id | string | | |
action_result.parameter.first_message_reported_at_gte | string | | |
action_result.parameter.limit | numeric | | |
action_result.parameter.offset | numeric | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'dismiss message groups'

Dismiss multiple message groups

Type: **correct** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**message_group_ids** | required | Comma-separated list of message group IDs | string | |
**classification** | optional | Classification for dismissed groups | string | |
**report_label** | optional | Label to apply to messages being reviewed | string | |
**review_comment** | optional | Optional review comment | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.parameter.message_group_ids | string | | |
action_result.parameter.classification | string | | |
action_result.parameter.report_label | string | | |
action_result.parameter.review_comment | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'quarantine message groups'

Quarantine multiple message groups

Type: **correct** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**message_group_ids** | required | Comma-separated list of message group IDs | string | |
**classification** | optional | Classification | string | |
**report_label** | optional | Label to apply to messages being reviewed | string | |
**review_comment** | optional | Optional review comment | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.task_id | string | | |
action_result.data.\*.task_id | string | | |
action_result.parameter.message_group_ids | string | | |
action_result.parameter.classification | string | | |
action_result.parameter.report_label | string | | |
action_result.parameter.review_comment | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'graymail message groups'

Move multiple message groups to graymail

Type: **correct** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**message_group_ids** | required | Comma-separated list of message group IDs | string | |
**classification** | optional | Classification | string | |
**report_label** | optional | Label to apply to messages being reviewed | string | |
**review_comment** | optional | Optional review comment | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.task_id | string | | |
action_result.data.\*.task_id | string | | |
action_result.parameter.message_group_ids | string | | |
action_result.parameter.classification | string | | |
action_result.parameter.report_label | string | | |
action_result.parameter.review_comment | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'restore message groups'

Restore multiple message groups

Type: **correct** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**message_group_ids** | required | Comma-separated list of message group IDs | string | |
**classification** | optional | Classification | string | |
**report_label** | optional | Label to apply to messages being reviewed | string | |
**review_comment** | optional | Optional review comment | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.task_id | string | | |
action_result.data.\*.task_id | string | | |
action_result.parameter.message_group_ids | string | | |
action_result.parameter.classification | string | | |
action_result.parameter.report_label | string | | |
action_result.parameter.review_comment | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'review message groups'

Review message groups with classification and optional action

Type: **correct** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**message_group_ids** | required | Comma-separated list of message group IDs | string | |
**classification** | required | Review classification | string | |
**action** | optional | Action to take on the message groups | string | |
**review_comment** | optional | Optional review comment | string | |
**share_with_sublime** | optional | Share with Sublime for community detection | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.task_id | string | | |
action_result.data.\*.task_id | string | | |
action_result.data.\*.actions | string | | |
action_result.parameter.message_group_ids | string | | |
action_result.parameter.classification | string | | |
action_result.parameter.action | string | | |
action_result.parameter.review_comment | string | | |
action_result.parameter.share_with_sublime | boolean | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'search message groups'

Search message groups. At least one search field, state, hash, or time bound is required

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**any** | optional | Search all fields (not compatible with other fields) | string | |
**sender** | optional | Search in From field (wildcard) | string | `email` |
**to** | optional | Search in To/CC/Bcc fields (wildcard) | string | `email` |
**mailbox** | optional | Search mailbox by email (wildcard) | string | `email` |
**subject** | optional | Search subject (wildcard) | string | |
**message_id** | optional | Search Message-ID header (wildcard) | string | |
**type** | optional | Search by message type | string | |
**states** | optional | Comma-separated list of message states | string | |
**file_name** | optional | Search attachment filename (wildcard) | string | |
**attachment_md5** | optional | Attachment MD5 (32 chars) | string | `md5` |
**attachment_sha1** | optional | Attachment SHA1 (40 chars) | string | `sha1` |
**attachment_sha256** | optional | Attachment SHA256 (64 chars) | string | `sha256` |
**start_time** | optional | Start time filter (ISO 8601 UTC), maps to created_at[gte] | string | |
**end_time** | optional | End time filter (ISO 8601 UTC), maps to created_at[lt] | string | |
**first_reported_as_phish_at_gte** | optional | Groups reported at or after this time (ISO 8601 UTC) | string | |
**first_reported_as_phish_at_lt** | optional | Groups reported before this time (ISO 8601 UTC) | string | |
**limit** | optional | Maximum number of results (max: 500) | numeric | |
**offset** | optional | Zero-based offset for pagination | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.total_groups | numeric | | |
action_result.summary.groups_returned | numeric | | |
action_result.data.\*.id | string | `message group id` | |
action_result.data.\*.review_status | string | | |
action_result.data.\*.classification | string | | |
action_result.data.\*.state | string | | |
action_result.parameter.any | string | | |
action_result.parameter.sender | string | `email` | |
action_result.parameter.to | string | `email` | |
action_result.parameter.mailbox | string | `email` | |
action_result.parameter.subject | string | | |
action_result.parameter.message_id | string | | |
action_result.parameter.type | string | | |
action_result.parameter.states | string | | |
action_result.parameter.file_name | string | | |
action_result.parameter.attachment_md5 | string | `md5` | |
action_result.parameter.attachment_sha1 | string | `sha1` | |
action_result.parameter.attachment_sha256 | string | `sha256` | |
action_result.parameter.start_time | string | | |
action_result.parameter.end_time | string | | |
action_result.parameter.first_reported_as_phish_at_gte | string | | |
action_result.parameter.first_reported_as_phish_at_lt | string | | |
action_result.parameter.limit | numeric | | |
action_result.parameter.offset | numeric | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'trash message groups'

Trash multiple message groups

Type: **correct** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**message_group_ids** | required | Comma-separated list of message group IDs | string | |
**classification** | optional | Classification | string | |
**report_label** | optional | Label to apply to messages being reviewed | string | |
**review_comment** | optional | Optional review comment | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.task_id | string | | |
action_result.data.\*.task_id | string | | |
action_result.parameter.message_group_ids | string | | |
action_result.parameter.classification | string | | |
action_result.parameter.report_label | string | | |
action_result.parameter.review_comment | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'get message group'

Get a single message group by canonical ID

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**message_group_id** | required | Canonical ID of the message group | string | `message group id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.data.\*.id | string | `message group id` | |
action_result.data.\*.review_status | string | | |
action_result.data.\*.classification | string | | |
action_result.data.\*.state | string | | |
action_result.data.\*.flagged_rules | string | | |
action_result.data.\*.messages | string | | |
action_result.data.\*.user_reports | string | | |
action_result.parameter.message_group_id | string | `message group id` | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'dismiss message group'

Dismiss a single message group

Type: **correct** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**message_group_id** | required | Canonical ID of the message group | string | `message group id` |
**classification** | optional | Classification | string | |
**review_comment** | optional | Optional review comment | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.parameter.message_group_id | string | `message group id` | |
action_result.parameter.classification | string | | |
action_result.parameter.review_comment | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'quarantine message group'

Quarantine a single message group

Type: **correct** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**message_group_id** | required | Canonical ID of the message group | string | `message group id` |
**classification** | optional | Classification | string | |
**review_comment** | optional | Optional review comment | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.task_id | string | | |
action_result.data.\*.task_id | string | | |
action_result.parameter.message_group_id | string | `message group id` | |
action_result.parameter.classification | string | | |
action_result.parameter.review_comment | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'restore message group'

Restore a single message group

Type: **correct** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**message_group_id** | required | Canonical ID of the message group | string | `message group id` |
**classification** | optional | Classification | string | |
**review_comment** | optional | Optional review comment | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.task_id | string | | |
action_result.data.\*.task_id | string | | |
action_result.parameter.message_group_id | string | `message group id` | |
action_result.parameter.classification | string | | |
action_result.parameter.review_comment | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'share with sublime'

Share a message group with Sublime for community detection

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**message_group_id** | required | Canonical ID of the message group | string | `message group id` |
**report_label** | optional | Report label | string | |
**review_comment** | optional | Optional review comment | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.task_id | string | | |
action_result.data.\*.task_id | string | | |
action_result.parameter.message_group_id | string | `message group id` | |
action_result.parameter.report_label | string | | |
action_result.parameter.review_comment | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'trash message group'

Trash a single message group

Type: **correct** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**message_group_id** | required | Canonical ID of the message group | string | `message group id` |
**classification** | optional | Classification | string | |
**review_comment** | optional | Optional review comment | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.task_id | string | | |
action_result.data.\*.task_id | string | | |
action_result.parameter.message_group_id | string | `message group id` | |
action_result.parameter.classification | string | | |
action_result.parameter.review_comment | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'analyze raw message'

Analyze a raw EML message against rules and queries. Runs active detection rules when no run flag is set

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault_id** | optional | Vault ID of the EML file | string | `vault id` |
**base64_data** | optional | Base64 encoded EML (alternative to vault_id) | string | |
**run_active_detection_rules** | optional | Run all active detection rules. Used when no other run flag is set | boolean | |
**run_all_detection_rules** | optional | Run all detection rules including inactive | boolean | |
**run_all_insights** | optional | Run all insight queries | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.matched_rules | numeric | | |
action_result.summary.total_rules_evaluated | numeric | | |
action_result.data.\*.rule_results | string | | |
action_result.data.\*.query_results | string | | |
action_result.parameter.vault_id | string | `vault id` | |
action_result.parameter.base64_data | string | | |
action_result.parameter.run_active_detection_rules | boolean | | |
action_result.parameter.run_all_detection_rules | boolean | | |
action_result.parameter.run_all_insights | boolean | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'render attachment image'

Render image for attachment from raw base64 encoded bytes

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault_id** | optional | Vault ID of the attachment file | string | `vault id` |
**base64_data** | optional | Base64 encoded raw attachment bytes (alternative to vault_id) | string | |
**file_type** | optional | File type hint for rendering, such as pdf. Image types such as png are rejected | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.screenshot_vault_id | string | `vault id` | |
action_result.data.\*.hash | string | | |
action_result.parameter.vault_id | string | `vault id` | |
action_result.parameter.base64_data | string | | |
action_result.parameter.file_type | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'get attack score raw'

Evaluate attack score for a raw message

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault_id** | optional | Vault ID of the EML file | string | `vault id` |
**base64_data** | optional | Base64 encoded EML (alternative to vault_id) | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.verdict | string | | |
action_result.summary.score | numeric | | |
action_result.data.\*.score | numeric | | |
action_result.data.\*.graymail_score | numeric | | |
action_result.data.\*.verdict | string | | |
action_result.data.\*.top_signals | string | | |
action_result.parameter.vault_id | string | `vault id` | |
action_result.parameter.base64_data | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'create message'

Create a new message from a raw EML

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault_id** | optional | Vault ID of the EML file | string | `vault id` |
**base64_data** | optional | Base64 encoded EML (alternative to vault_id) | string | |
**mailbox_email_address** | optional | Mailbox email address | string | `email` |
**canonical_id** | optional | Canonical ID of the message, if known | string | |
**external_message_id** | optional | ID of the message according to the external source | string | |
**external_thread_id** | optional | ID of the thread according to the external source | string | |
**external_created_at** | optional | Timestamp the message was created per external source (ISO 8601) | string | |
**folder** | optional | The mailbox folder the message is in | string | |
**labels** | optional | Comma-separated labels applied by the mailbox | string | |
**route_type** | optional | Directional route type of the message | string | |
**message_type** | optional | Message type override | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.message_id | string | `message id` | |
action_result.data.\*.id | string | `message id` | |
action_result.data.\*.canonical_id | string | | |
action_result.data.\*.preview.subject | string | | |
action_result.data.\*.preview.sender_email_address | string | `email` | |
action_result.parameter.vault_id | string | `vault id` | |
action_result.parameter.base64_data | string | | |
action_result.parameter.mailbox_email_address | string | `email` | |
action_result.parameter.canonical_id | string | | |
action_result.parameter.external_message_id | string | | |
action_result.parameter.external_thread_id | string | | |
action_result.parameter.external_created_at | string | | |
action_result.parameter.folder | string | | |
action_result.parameter.labels | string | | |
action_result.parameter.route_type | string | | |
action_result.parameter.message_type | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'get action state'

Retrieve the state of manual actions for a canonical group

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**message_group_id** | required | Canonical group ID | string | `message group id` |
**limit** | optional | Maximum number of results (max: 50) | numeric | |
**offset** | optional | Zero-based offset for pagination | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.data.\*.id | string | | |
action_result.data.\*.action_type | string | | |
action_result.data.\*.change | string | | |
action_result.data.\*.created_at | string | | |
action_result.data.\*.attempts | numeric | | |
action_result.data.\*.total | numeric | | |
action_result.parameter.message_group_id | string | `message group id` | |
action_result.parameter.limit | numeric | | |
action_result.parameter.offset | numeric | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'get message'

Retrieve a message by ID

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**message_id** | required | UUID of the message | string | `message id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.data.\*.id | string | `message id` | |
action_result.data.\*.canonical_id | string | | |
action_result.data.\*.subject | string | | |
action_result.data.\*.sender.email | string | `email` | |
action_result.data.\*.sender.display_name | string | | |
action_result.data.\*.created_at | string | | |
action_result.data.\*.mailbox.email | string | `email` | |
action_result.data.\*.recipients | string | | |
action_result.parameter.message_id | string | `message id` | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'action message'

Perform an action on an individual message

Type: **correct** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**message_id** | required | UUID of the message | string | `message id` |
**action** | optional | Action to perform | string | |
**share_with_sublime** | optional | Share with Sublime | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.task_id | string | | |
action_result.data.\*.task_id | string | | |
action_result.parameter.message_id | string | `message id` | |
action_result.parameter.action | string | | |
action_result.parameter.share_with_sublime | boolean | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'analyze message by id'

Analyze an existing message by its ID against rules and queries. Runs active detection rules when no run flag is set

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**message_id** | required | UUID of the message | string | `message id` |
**run_active_detection_rules** | optional | Run all active detection rules. Used when no other run flag is set | boolean | |
**run_all_detection_rules** | optional | Run all detection rules including inactive | boolean | |
**run_all_insights** | optional | Run all insight queries | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.matched_rules | numeric | | |
action_result.summary.total_rules_evaluated | numeric | | |
action_result.data.\*.rule_results | string | | |
action_result.data.\*.query_results | string | | |
action_result.parameter.message_id | string | `message id` | |
action_result.parameter.run_active_detection_rules | boolean | | |
action_result.parameter.run_all_detection_rules | boolean | | |
action_result.parameter.run_all_insights | boolean | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'get asa report'

Retrieve ASA (Attack Surface Assessment) report for a message

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**message_id** | required | UUID of the message | string | `message id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.verdict | string | | |
action_result.data.\*.verdict | string | | |
action_result.data.\*.summary | string | | |
action_result.data.\*.full_explanation | string | | |
action_result.data.\*.attack_type | string | | |
action_result.data.\*.tactics_and_techniques | string | | |
action_result.parameter.message_id | string | `message id` | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'get asa verdict'

Retrieve ASA verdict for a message (malicious, spam, graymail, likely_benign, benign, unknown)

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**message_id** | required | UUID of the message | string | `message id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.verdict | string | | |
action_result.data.\*.verdict | string | | |
action_result.parameter.message_id | string | `message id` | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'get attachment image'

Retrieve image of a PDF attachment by MD5 hash

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**message_id** | required | UUID of the message | string | `message id` |
**attachment_hash** | required | MD5 hash of the attachment | string | `md5` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.screenshot_vault_id | string | `vault id` | |
action_result.data.\*.hash | string | `md5` | |
action_result.parameter.message_id | string | `message id` | |
action_result.parameter.attachment_hash | string | `md5` | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'get attack score'

Evaluate attack score against an existing message

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**message_id** | required | UUID of the message | string | `message id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.verdict | string | | |
action_result.summary.score | numeric | | |
action_result.data.\*.score | numeric | | |
action_result.data.\*.graymail_score | numeric | | |
action_result.data.\*.verdict | string | | |
action_result.data.\*.top_signals | string | | |
action_result.parameter.message_id | string | `message id` | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'get message image'

Retrieve rendered image of a message

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**message_id** | required | UUID of the message | string | `message id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.screenshot_vault_id | string | `vault id` | |
action_result.data.\*.mime_type | string | | |
action_result.data.\*.is_empty_body | boolean | | |
action_result.parameter.message_id | string | `message id` | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'get message eml'

Retrieve raw EML content of a message

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**message_id** | required | UUID of the message | string | `message id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.vault_id | string | `vault id` | |
action_result.parameter.message_id | string | `message id` | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'get message image link'

Retrieve a temporary link to the image of a message

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**message_id** | required | UUID of the message | string | `message id` |
**link_duration_seconds** | optional | Duration the link is valid in seconds (default 900, max 604800 = 7 days) | numeric | |
**platform_link** | optional | If true, link is presigned against Sublime; if false, may be a direct S3 link | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.data.\*.url | string | `url` | |
action_result.data.\*.expires_in | numeric | | |
action_result.parameter.message_id | string | `message id` | |
action_result.parameter.link_duration_seconds | numeric | | |
action_result.parameter.platform_link | boolean | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'set access justification'

Set access justification for a message

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**message_id** | required | UUID of the message | string | `message id` |
**justification** | required | Justification text | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.parameter.message_id | string | `message id` | |
action_result.parameter.justification | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'get message data model'

Retrieve the message's Message Data Model (MDM)

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**message_id** | required | UUID of the message | string | `message id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.data.\*.sender.email.email | string | `email` | |
action_result.data.\*.subject.subject | string | | |
action_result.data.\*.\_meta.canonical_id | string | | |
action_result.data.\*.\_meta.id | string | | |
action_result.parameter.message_id | string | `message id` | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'restore message'

Restore a previously trashed message

Type: **correct** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**message_id** | required | UUID of the message | string | `message id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.task_id | string | | |
action_result.data.\*.task_id | string | | |
action_result.parameter.message_id | string | `message id` | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'trash message'

Trash an individual message

Type: **correct** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**message_id** | required | UUID of the message | string | `message id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.task_id | string | | |
action_result.data.\*.task_id | string | | |
action_result.parameter.message_id | string | `message id` | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'list rules'

List all rules in the organization

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**search** | optional | Case-insensitive substring match across rule name, description, and MQL source | string | |
**in_feed** | optional | Restrict to rules that are explicitly in or not in a feed | boolean | |
**limit** | optional | Maximum number of results (max: 500) | numeric | |
**offset** | optional | Zero-based offset for pagination | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.total_rules | numeric | | |
action_result.summary.rules_returned | numeric | | |
action_result.data.\*.id | string | `rule id` | |
action_result.data.\*.name | string | | |
action_result.data.\*.severity | string | | |
action_result.data.\*.active | boolean | | |
action_result.data.\*.description | string | | |
action_result.data.\*.source | string | | |
action_result.data.\*.tags | string | | |
action_result.data.\*.created_at | string | | |
action_result.data.\*.updated_at | string | | |
action_result.parameter.search | string | | |
action_result.parameter.in_feed | boolean | | |
action_result.parameter.limit | numeric | | |
action_result.parameter.offset | numeric | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'create rule'

Create a new detection, DLP, or triage rule

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** | required | Rule name | string | |
**source** | required | MQL rule source | string | |
**type** | optional | Rule type | string | |
**severity** | optional | Rule severity | string | |
**description** | optional | Rule description | string | |
**active** | optional | Activate rule immediately | boolean | |
**label** | optional | Rule label | string | |
**maturity** | optional | Rule maturity | string | |
**tags** | optional | Comma-separated tags | string | |
**user_provided_tags** | optional | Comma-separated user-provided tags | string | |
**attack_types** | optional | Comma-separated attack types | string | |
**detection_methods** | optional | Comma-separated detection technologies | string | |
**tactics_and_techniques** | optional | Comma-separated tactics and techniques | string | |
**false_positives** | optional | Comma-separated descriptions of known false positives | string | |
**references** | optional | Comma-separated URL references | string | |
**action_ids** | optional | Comma-separated IDs of actions to run when the rule triggers | string | |
**authors** | optional | Rule authors as JSON array (e.g. [{"name":"Jane","twitter":"@jane"}]) | string | |
**auto_review_classification** | optional | Classification for auto-reviewed messages | string | |
**auto_review_auto_share** | optional | Whether auto-reviewed messages will be shared | boolean | |
**triage_abuse_reports** | optional | (Triage) run for reported messages | boolean | |
**triage_flagged_messages** | optional | (Triage) run for flagged messages | boolean | |
**triage_classification_changes** | optional | (Triage) run when classification changes | boolean | |
**triage_dlp_rule_matched** | optional | (Triage) run for messages matching a DLP rule | boolean | |
**run_triage_on_excluded_messages** | optional | (Triage) run even on globally-excluded messages | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.rule_id | string | `rule id` | |
action_result.data.\*.id | string | `rule id` | |
action_result.data.\*.name | string | | |
action_result.data.\*.severity | string | | |
action_result.data.\*.active | boolean | | |
action_result.parameter.name | string | | |
action_result.parameter.source | string | | |
action_result.parameter.type | string | | |
action_result.parameter.severity | string | | |
action_result.parameter.description | string | | |
action_result.parameter.active | boolean | | |
action_result.parameter.label | string | | |
action_result.parameter.maturity | string | | |
action_result.parameter.tags | string | | |
action_result.parameter.user_provided_tags | string | | |
action_result.parameter.attack_types | string | | |
action_result.parameter.detection_methods | string | | |
action_result.parameter.tactics_and_techniques | string | | |
action_result.parameter.false_positives | string | | |
action_result.parameter.references | string | | |
action_result.parameter.action_ids | string | | |
action_result.parameter.authors | string | | |
action_result.parameter.auto_review_classification | string | | |
action_result.parameter.auto_review_auto_share | boolean | | |
action_result.parameter.triage_abuse_reports | boolean | | |
action_result.parameter.triage_flagged_messages | boolean | | |
action_result.parameter.triage_classification_changes | boolean | | |
action_result.parameter.triage_dlp_rule_matched | boolean | | |
action_result.parameter.run_triage_on_excluded_messages | boolean | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'list rule history'

List history for rules across the organization

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start_time** | required | Classification start time (ISO 8601 UTC, required) | string | |
**end_time** | required | Classification end time (ISO 8601 UTC, required) | string | |
**active** | optional | Restrict to rules that are active | boolean | |
**in_feed** | optional | Restrict to rules that are in a feed | boolean | |
**type** | optional | Comma-separated rule types (detection, triage, dlp) | string | |
**count** | optional | Number of results to return | numeric | |
**offset** | optional | Offset from the first result | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.data.\*.history | string | | |
action_result.parameter.start_time | string | | |
action_result.parameter.end_time | string | | |
action_result.parameter.active | boolean | | |
action_result.parameter.in_feed | boolean | | |
action_result.parameter.type | string | | |
action_result.parameter.count | numeric | | |
action_result.parameter.offset | numeric | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'validate rule'

Validate rule MQL syntax without creating

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** | required | Rule name | string | |
**source** | required | MQL rule source | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.data.\*.validation_error | string | | |
action_result.data.\*.is_org_dependent | boolean | | |
action_result.data.\*.functions | string | | |
action_result.data.\*.list | string | | |
action_result.parameter.name | string | | |
action_result.parameter.source | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'delete rule'

Delete a rule by ID

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**rule_id** | required | UUID of the rule | string | `rule id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.parameter.rule_id | string | `rule id` | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'get rule'

Retrieve a rule by ID

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**rule_id** | required | UUID of the rule | string | `rule id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.data.\*.id | string | `rule id` | |
action_result.data.\*.name | string | | |
action_result.data.\*.severity | string | | |
action_result.data.\*.active | boolean | | |
action_result.data.\*.source | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.tags | string | | |
action_result.parameter.rule_id | string | `rule id` | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'update rule'

Update an existing rule. Omitted fields are kept from the current rule

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**rule_id** | required | UUID of the rule | string | `rule id` |
**name** | optional | New rule name | string | |
**source** | optional | New MQL source | string | |
**severity** | optional | New severity | string | |
**description** | optional | New description | string | |
**label** | optional | Rule label | string | |
**maturity** | optional | Rule maturity | string | |
**tags** | optional | Comma-separated tags | string | |
**user_provided_tags** | optional | Comma-separated user-provided tags | string | |
**attack_types** | optional | Comma-separated attack types | string | |
**detection_methods** | optional | Comma-separated detection technologies | string | |
**tactics_and_techniques** | optional | Comma-separated tactics and techniques | string | |
**false_positives** | optional | Comma-separated descriptions of known false positives | string | |
**references** | optional | Comma-separated URL references | string | |
**action_ids** | optional | Comma-separated IDs of actions to run when the rule triggers | string | |
**authors** | optional | Rule authors as JSON array (e.g. [{"name":"Jane","twitter":"@jane"}]) | string | |
**auto_review_classification** | optional | Classification for auto-reviewed messages | string | |
**auto_review_auto_share** | optional | Whether auto-reviewed messages will be shared | boolean | |
**triage_abuse_reports** | optional | (Triage) run for reported messages | boolean | |
**triage_flagged_messages** | optional | (Triage) run for flagged messages | boolean | |
**triage_classification_changes** | optional | (Triage) run when classification changes | boolean | |
**triage_dlp_rule_matched** | optional | (Triage) run for messages matching a DLP rule | boolean | |
**run_triage_on_excluded_messages** | optional | (Triage) run even on globally-excluded messages | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.data.\*.id | string | `rule id` | |
action_result.data.\*.name | string | | |
action_result.data.\*.severity | string | | |
action_result.data.\*.active | boolean | | |
action_result.parameter.rule_id | string | `rule id` | |
action_result.parameter.name | string | | |
action_result.parameter.source | string | | |
action_result.parameter.severity | string | | |
action_result.parameter.description | string | | |
action_result.parameter.label | string | | |
action_result.parameter.maturity | string | | |
action_result.parameter.tags | string | | |
action_result.parameter.user_provided_tags | string | | |
action_result.parameter.attack_types | string | | |
action_result.parameter.detection_methods | string | | |
action_result.parameter.tactics_and_techniques | string | | |
action_result.parameter.false_positives | string | | |
action_result.parameter.references | string | | |
action_result.parameter.action_ids | string | | |
action_result.parameter.authors | string | | |
action_result.parameter.auto_review_classification | string | | |
action_result.parameter.auto_review_auto_share | boolean | | |
action_result.parameter.triage_abuse_reports | boolean | | |
action_result.parameter.triage_flagged_messages | boolean | | |
action_result.parameter.triage_classification_changes | boolean | | |
action_result.parameter.triage_dlp_rule_matched | boolean | | |
action_result.parameter.run_triage_on_excluded_messages | boolean | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'activate rule'

Activate a rule

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**rule_id** | required | UUID of the rule | string | `rule id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.data.\*.id | string | `rule id` | |
action_result.data.\*.name | string | | |
action_result.data.\*.active | boolean | | |
action_result.parameter.rule_id | string | `rule id` | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'deactivate rule'

Deactivate a rule

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**rule_id** | required | UUID of the rule | string | `rule id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.data.\*.id | string | `rule id` | |
action_result.data.\*.name | string | | |
action_result.data.\*.active | boolean | | |
action_result.parameter.rule_id | string | `rule id` | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'get rule history'

Retrieve history of a specific rule

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**rule_id** | required | UUID of the rule | string | `rule id` |
**start_time** | optional | Classification start time (ISO 8601 UTC) | string | |
**end_time** | optional | Classification end time (ISO 8601 UTC) | string | |
**use_rule_last_updated_as_created_at** | optional | Filter to classifications made since the rule was last updated | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.data.\*.rule.id | string | `rule id` | |
action_result.data.\*.rule.name | string | | |
action_result.data.\*.flagged_message_groups_report.total | numeric | | |
action_result.parameter.rule_id | string | `rule id` | |
action_result.parameter.start_time | string | | |
action_result.parameter.end_time | string | | |
action_result.parameter.use_rule_last_updated_as_created_at | boolean | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'get task'

Retrieve task status by ID

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**task_id** | required | UUID of the task | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.task_state | string | | |
action_result.data.\*.id | string | | |
action_result.data.\*.state | string | | |
action_result.data.\*.created_at | string | | |
action_result.data.\*.error | string | | |
action_result.parameter.task_id | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'list user reports'

List user-submitted phishing reports. Defaults to the last 30 days when no time bound is set

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start_time** | optional | Start time filter (ISO 8601 UTC). Defaults to the last 30 days when end_time is also empty | string | |
**end_time** | optional | End time filter (ISO 8601 UTC) | string | |
**limit** | optional | Maximum number of results (max: 500) | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.total_reports | numeric | | |
action_result.data.\*.reporter | string | | |
action_result.data.\*.channel | string | | |
action_result.data.\*.reported_at | string | | |
action_result.data.\*.reported_message_canonical_id | string | | |
action_result.parameter.start_time | string | | |
action_result.parameter.end_time | string | | |
action_result.parameter.limit | numeric | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'assign role'

Assign a role to a user

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email_address** | required | Email address of the user | string | `email` |
**role_title** | required | Role title to assign | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.parameter.email_address | string | `email` | |
action_result.parameter.role_title | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'list scim resource types'

List SCIM resource types

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.total_resource_types | numeric | | |
action_result.data.\*.id | string | | |
action_result.data.\*.name | string | | |
action_result.data.\*.endpoint | string | | |
action_result.data.\*.description | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'get scim resource type'

Get a single SCIM resource type

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**resource_type_id** | required | Resource type ID | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.data.\*.id | string | | |
action_result.data.\*.name | string | | |
action_result.data.\*.endpoint | string | | |
action_result.data.\*.schema | string | | |
action_result.parameter.resource_type_id | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'list scim users'

List SCIM provisioned users

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**count** | optional | Maximum number of results (max: 1000) | numeric | |
**start_index** | optional | 1-based start index for pagination | numeric | |
**filter** | optional | SCIM filter expression | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.total_results | numeric | | |
action_result.data.\*.id | string | | |
action_result.data.\*.userName | string | `email` | |
action_result.data.\*.name.givenName | string | | |
action_result.data.\*.name.familyName | string | | |
action_result.data.\*.active | boolean | | |
action_result.parameter.count | numeric | | |
action_result.parameter.start_index | numeric | | |
action_result.parameter.filter | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'create scim user'

Create a user via SCIM

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_name** | required | Username (typically email) | string | `email` |
**given_name** | required | First name | string | |
**family_name** | required | Last name | string | |
**email** | required | Email address | string | `email` |
**active** | optional | Set user as active | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.user_id | string | | |
action_result.data.\*.id | string | | |
action_result.data.\*.userName | string | `email` | |
action_result.data.\*.active | boolean | | |
action_result.parameter.user_name | string | `email` | |
action_result.parameter.given_name | string | | |
action_result.parameter.family_name | string | | |
action_result.parameter.email | string | `email` | |
action_result.parameter.active | boolean | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'get scim user'

Get a SCIM user by ID

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** | required | Sublime user ID | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.data.\*.id | string | | |
action_result.data.\*.userName | string | `email` | |
action_result.data.\*.name.givenName | string | | |
action_result.data.\*.name.familyName | string | | |
action_result.data.\*.active | boolean | | |
action_result.parameter.user_id | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'delete scim user'

Delete a SCIM user by ID

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** | required | Sublime user ID | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.parameter.user_id | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'update scim user'

Full update of a SCIM user (PUT)

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** | required | Sublime user ID | string | |
**user_name** | required | Username | string | `email` |
**given_name** | required | First name | string | |
**family_name** | required | Last name | string | |
**email** | required | Email address | string | `email` |
**active** | optional | Set user as active | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.data.\*.id | string | | |
action_result.data.\*.userName | string | `email` | |
action_result.data.\*.active | boolean | | |
action_result.parameter.user_id | string | | |
action_result.parameter.user_name | string | `email` | |
action_result.parameter.given_name | string | | |
action_result.parameter.family_name | string | | |
action_result.parameter.email | string | `email` | |
action_result.parameter.active | boolean | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'patch scim user'

Partial update of a SCIM user (PATCH)

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** | required | Sublime user ID | string | |
**operations_json** | required | JSON array of SCIM PATCH operations, e.g. [{"op":"replace","path":"active","value":false}] | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.data.\*.id | string | | |
action_result.data.\*.userName | string | `email` | |
action_result.data.\*.active | boolean | | |
action_result.parameter.user_id | string | | |
action_result.parameter.operations_json | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'validate scim auth'

Validate SCIM-specific authentication

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.data.\*.user_email | string | `email` | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'list scim schemas'

List SCIM schemas

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.summary.total_schemas | numeric | | |
action_result.data.\*.id | string | | |
action_result.data.\*.name | string | | |
action_result.data.\*.description | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'get scim schema'

Get a single SCIM schema by ID

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**schema_id** | required | Schema ID (e.g. urn:ietf:params:scim:schemas:core:2.0:User) | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.data.\*.id | string | | |
action_result.data.\*.name | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.attributes | string | | |
action_result.parameter.schema_id | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'get scim service provider config'

Get SCIM service provider configuration

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.message | string | | |
action_result.data.\*.patch.supported | boolean | | |
action_result.data.\*.bulk.supported | boolean | | |
action_result.data.\*.filter.supported | boolean | | |
action_result.data.\*.sort.supported | boolean | | |
action_result.data.\*.changePassword.supported | boolean | | |
action_result.data.\*.etag.supported | boolean | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2026 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
