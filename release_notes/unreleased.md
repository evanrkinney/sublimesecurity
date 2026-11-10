**Unreleased**
- List message groups defaults to flagged groups from the last 7 days when no canonical id or time bound is provided, matching the API's required filters
- List user reports defaults to the last 30 days when no time bound is provided
- Search message groups fails with a clear message when no search term is provided
- Analyze raw message and analyze message by id run active detection rules when every run flag is off
- Update rule keeps the current name, source, and other omitted fields instead of sending an empty replacement
- SIEM summary filters with timestamp bounds and cursor, and returns the summary fields the API sends
- List DLP release requests reads the `results` array
- API errors surface the server message text
- String outputs JSON-encode list and object payloads so fields such as rule history keep their data
