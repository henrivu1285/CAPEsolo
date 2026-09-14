# Bundled SigmaHQ rule pack

`sigmahq_windows_p3.json.gz` is a deterministic intermediate representation
compiled from supported Windows logsource rules (with or without ATT&CK tags) in
<https://github.com/SigmaHQ/sigma> at commit
`272daf82bf77fb0bb97f1f0c4d82bc61154772e1`.

The source YAML is parsed with pySigma 1.5.0 by
`tools/build_sigma_pack.py`. CAPEsolo evaluates the compiled representation
with `CAPEsolo/capelib/sigma_runtime.py`; pySigma and YAML are not required at
analysis time.

The pack retains the upstream rule ID, title, status, severity, authors,
references, false-positive context, ATT&CK tags, source path, and source
SHA-256. Sigma-derived material is licensed under Detection Rule License 1.1. The included upstream
SIGMAHQ_LICENSE notice links to its full license terms.

P32319: 2,410 Windows source rules; 1,845 compiled, including 185 without
ATT&CK tags. The other 565 use unsupported logsource categories. A compiled
rule is not necessarily evaluable in a run: the report lists missing sensor,
missing field, no events, evaluated no match and matched separately. Untagged
findings are retained without inventing an ATT&CK mapping. Missing values are
unknown (including inside negation), not automatically false.

The snapshot is pinned for reproducibility, not claimed to be the latest
upstream release. No upstream update runs during malware analysis.
