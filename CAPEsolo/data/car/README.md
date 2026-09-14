# Windows CAR in P32319

Upstream snapshot: https://github.com/mitre-attack/car/tree/1b922fe1527d956e222a99473472e594f10f610b

`windows_catalog.json` inventories all 99 analytics whose platform list contains
Windows in this snapshot (102 total upstream analytics). All 99 original YAML
files are retained with SHA-256, source URL and upstream ATT&CK metadata.

55 analytics have selected runtime variants in `tools/car_runtime_specs.py`.
These are explicit P3 adaptations, not wholesale execution of Splunk, EQL,
PowerShell or pseudocode from upstream. Runtime consumes JSON and never executes
recorded command lines. Its normal input is sample-scoped canonical P3 API events,
not an automatic adapter for every Windows Event Log channel. Test Sysmon records
exercise the event interface independently; they do not establish that the live
P3 collector supplies every corresponding Sysmon field.

44 analytics have a deferred reason: historical/multi-host context, decoded
SMB/RPC, a Windows Security/System adapter, or pending semantic implementation.
Even an implemented variant can be not evaluable when a sensor/field is absent.
Fixed C:\Windows path patterns are deliberately retained for selected upstream
variants; other system roots are outside those variants' tested scope.

CAR findings remain candidate/context evidence and add no risk score. Native,
Sigma and CAR agreement on the same event is not independent acquisition.
Broad monitors (cmd, rundll32, Office children, discovery tools) may match benign
activity. Specific operation mappings narrow ambiguous upstream ATT&CK lists.

`catalog.json` and `native_audit.json` retain the P32318 native detector review;
`windows_catalog.json` and `validation/P32319_VALIDATION.json` describe the new
runtime. The native audit is a traceability review, not MITRE certification.

Validation: 55 manually specified synthetic positive/near-miss/missing-field
contracts; independently captured positive events for 13 analytic IDs. See
`docs/P32319_CAR_MATRIX.md` and fixture manifests for exact coverage and hashes.
Source YAML and new runtime adaptations are distributed with LICENSE.txt and
NOTICE.txt. No upstream update occurs during analysis.
