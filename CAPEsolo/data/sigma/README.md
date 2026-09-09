# Bundled SigmaHQ rule pack

`sigmahq_windows_p3.json.gz` is a deterministic intermediate representation
compiled from ATT&CK-tagged Windows rules in
<https://github.com/SigmaHQ/sigma> at commit
`272daf82bf77fb0bb97f1f0c4d82bc61154772e1`.

The source YAML is parsed with pySigma 1.5.0 by
`tools/build_sigma_pack.py`. CAPEsolo evaluates the compiled representation
with `CAPEsolo/capelib/sigma_runtime.py`; pySigma and YAML are not required at
analysis time.

The pack retains the upstream rule ID, title, status, severity, authors,
references, false-positive context, ATT&CK tags, source path, and source
SHA-256. Sigma-derived material is licensed under the included Detection Rule
License 1.1.
