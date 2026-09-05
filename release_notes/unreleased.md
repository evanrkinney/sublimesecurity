**Unreleased**
* Added connect/read timeouts to all REST calls; timeouts and connection errors now return a clear error instead of hanging
* Fixed actions that save results to the Vault (Analyze Link, Get List Entries, Render Attachment Image, Get Attachment Image, Get Message Image, Get Message EML) to fail with a clear error when the Vault save itself fails, instead of reporting success
* Removed logging of full API response bodies/headers and raw webhook body bytes from debug data; only status code, body length, and a controlled digest are logged now
* Fixed Get List Entry to only treat a confirmed HTTP 404 as "entry not found"; other errors (auth, server, connectivity) now fail the action instead of being reported as false negatives
* List Lists no longer hardcodes `entry_type=string`; added an optional `entry_type` parameter so lists of other entry types are no longer silently excluded
* Upload Binary is no longer marked read-only (it creates a remote scan), and now validates and enforces the documented 37 MB size limit for both Vault-backed and Base64 input
* Sanitized filenames used when writing to the Vault temp directory to prevent path traversal
* URL-encoded all identifiers (task/event/hunt/list/message/rule/attachment/SCIM IDs) interpolated into REST request paths
* Test Connectivity now calls a low-privilege mailbox-listing endpoint instead of the admin-only audit log endpoint
* Marked `webhook_signing_secret` as a password-type configuration field
* Declared the `screenshot_vault_id` output for Analyze Link to match its actual behavior
* Fixed the inbound webhook handler to reject requests when it cannot resolve the asset's signing secret, instead of silently accepting them as unsigned; reduced internal SOAR REST call timeouts inside the webhook handler; removed a dead import
* Removed unused constants from `sublimesecurity_consts.py`
