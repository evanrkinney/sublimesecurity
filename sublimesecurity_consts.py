# File: sublimesecurity_consts.py
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

# BinExplode
BINEXPLODE_SCAN_ENDPOINT = "/v0/binexplode/scan"
BINEXPLODE_SCAN_RESULT_ENDPOINT = "/v0/binexplode/scan/{id}"

# Enrichment
LINK_ANALYSIS_ENDPOINT = "/v0/enrichment/link_analysis/evaluate"

# Audit Log
AUDIT_EVENTS_ENDPOINT = "/v0/audit-log/events"
AUDIT_EVENT_TYPES_ENDPOINT = "/v0/audit-log/events/types"
AUDIT_EVENT_ENDPOINT = "/v0/audit-log/events/{id}"

# Hunt Jobs
HUNT_JOBS_ENDPOINT = "/v0/hunt-jobs"
HUNT_JOB_ENDPOINT = "/v0/hunt-jobs/{id}"
HUNT_JOB_RESULTS_ENDPOINT = "/v0/hunt-jobs/{id}/results"

# Lists
LISTS_ENDPOINT = "/v0/lists"
LIST_ENDPOINT = "/v0/lists/{id}"
LIST_ENTRIES_ENDPOINT = "/v0/lists/{id}/entries"
LIST_ENTRY_ENDPOINT = "/v0/lists/{id}/entries/entry"

# Messages - Live Flow
RAW_MESSAGE_ANALYZE_ENDPOINT = "/v0/live-flow/raw-messages/analyze"

# Mailboxes
MAILBOXES_ENDPOINT = "/v0/mailboxes"

# Message Groups
MESSAGE_GROUPS_ENDPOINT = "/v0/message-groups"
MESSAGE_GROUPS_DISMISS_ENDPOINT = "/v0/message-groups/dismiss"
MESSAGE_GROUPS_QUARANTINE_ENDPOINT = "/v0/message-groups/quarantine"
MESSAGE_GROUPS_GRAYMAIL_ENDPOINT = "/v0/message-groups/move-to-graymail"
MESSAGE_GROUPS_RESTORE_ENDPOINT = "/v0/message-groups/restore"
MESSAGE_GROUPS_REVIEW_ENDPOINT = "/v0/message-groups/review"
MESSAGE_GROUPS_SEARCH_ENDPOINT = "/v0/message-groups/search"
MESSAGE_GROUPS_TRASH_ENDPOINT = "/v0/message-groups/trash"
MESSAGE_GROUP_ENDPOINT = "/v0/message-groups/{id}"
MESSAGE_GROUP_DISMISS_ENDPOINT = "/v0/message-groups/{id}/dismiss"
MESSAGE_GROUP_QUARANTINE_ENDPOINT = "/v0/message-groups/{id}/quarantine"
MESSAGE_GROUP_RESTORE_ENDPOINT = "/v0/message-groups/{id}/restore"
MESSAGE_GROUP_SHARE_ENDPOINT = "/v0/message-groups/{id}/share-with-sublime"
MESSAGE_GROUP_TRASH_ENDPOINT = "/v0/message-groups/{id}/trash"

# Messages
MESSAGES_CREATE_ENDPOINT = "/v0/messages/create"
MESSAGES_ANALYZE_ENDPOINT = "/v0/messages/analyze"
MESSAGES_ATTACK_SCORE_ENDPOINT = "/v0/messages/attack_score"
MESSAGES_ATTACHMENT_IMAGE_RAW_ENDPOINT = "/v0/messages/attachment/image"
MESSAGE_ENDPOINT = "/v0/messages/{id}"
MESSAGE_ACTIONS_ENDPOINT = "/v0/messages/{id}/actions"
MESSAGE_ANALYZE_BY_ID_ENDPOINT = "/v0/messages/{id}/analyze"
MESSAGE_ASA_REPORT_ENDPOINT = "/v0/messages/{id}/asa_report"
MESSAGE_ASA_VERDICT_ENDPOINT = "/v0/messages/{id}/asa_verdict"
MESSAGE_ATTACHMENT_IMAGE_ENDPOINT = "/v0/messages/{id}/attachment/{hash}/image"
MESSAGE_ATTACK_SCORE_ENDPOINT = "/v0/messages/{id}/attack_score"
MESSAGE_IMAGE_ENDPOINT = "/v0/messages/{id}/image"
MESSAGE_EML_ENDPOINT = "/v0/messages/{id}/eml"
MESSAGE_IMAGE_LINK_ENDPOINT = "/v0/messages/{id}/image_link"
MESSAGE_JUSTIFICATION_ENDPOINT = "/v0/messages/{id}/justification"
MESSAGE_MDM_ENDPOINT = "/v0/messages/{id}/message_data_model"
MESSAGE_RESTORE_ENDPOINT = "/v0/messages/{id}/restore"
MESSAGE_TRASH_ENDPOINT = "/v0/messages/{id}/trash"
MESSAGE_GROUP_ACTION_STATE_ENDPOINT = "/v0/messages/groups/{id}/action-state"

# Rules
RULES_ENDPOINT = "/v0/rules"
RULES_VALIDATE_ENDPOINT = "/v0/rules/validate"
RULES_HISTORY_ENDPOINT = "/v0/rules/rule-history"
RULE_ENDPOINT = "/v0/rules/{id}"
RULE_ACTIVATE_ENDPOINT = "/v0/rules/{id}/activate"
RULE_DEACTIVATE_ENDPOINT = "/v0/rules/{id}/deactivate"
RULE_HISTORY_ENDPOINT = "/v0/rules/{id}/rule-history"

# Tasks
TASK_ENDPOINT = "/v0/tasks/{id}"

# User Reports
USER_REPORTS_ENDPOINT = "/v0/user-reports"

# Users/Roles
ASSIGN_ROLE_ENDPOINT = "/v0/roles/assign"

# SCIM
SCIM_RESOURCE_TYPES_ENDPOINT = "/v0/scim/ResourceTypes"
SCIM_RESOURCE_TYPE_ENDPOINT = "/v0/scim/ResourceTypes/{id}"
SCIM_USERS_ENDPOINT = "/v0/scim/Users"
SCIM_USER_ENDPOINT = "/v0/scim/Users/{id}"
SCIM_VALIDATE_AUTH_ENDPOINT = "/v0/scim/validate_auth"
SCIM_SCHEMAS_ENDPOINT = "/v0/scim/Schemas"
SCIM_SCHEMA_ENDPOINT = "/v0/scim/Schemas/{id}"
SCIM_SERVICE_PROVIDER_CONFIG_ENDPOINT = "/v0/scim/ServiceProviderConfig"

DEFAULT_LIMIT = 100
MAX_LIMIT = 500
SCIM_DEFAULT_COUNT = 100
SCIM_MAX_COUNT = 1000

# (connect, read) timeouts, in seconds
DEFAULT_TIMEOUT = (10, 30)
RAW_TIMEOUT = (10, 60)

BINEXPLODE_MAX_FILE_SIZE_BYTES = 37 * 1024 * 1024

BASE_URLS = {
    "NA-East": "https://platform.sublime.security",
    "NA-West": "https://na-west.platform.sublime.security",
    "Canada": "https://ca.platform.sublime.security",
    "UK (London)": "https://uk.platform.sublime.security",
    "Europe (Dublin)": "https://eu.platform.sublime.security",
    "Australia": "https://au.platform.sublime.security",
}

SUCC_CONNECTIVITY_TEST = "Test Connectivity Passed"
ERR_CONNECTIVITY_TEST = "Test Connectivity Failed"
