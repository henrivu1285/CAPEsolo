# CAPEsolo + Frida P3.2.3.16 — SigmaHQ delta patch

P3.2.3.16 adds a conservative SigmaHQ evaluation layer to the existing P3
evidence-first ATT&CK mapper.  It does not replace CAPEMON, Frida, Sysmon,
PCAP correlation, or the deterministic state machines.

## What changed

- Bundles 1,660 ATT&CK-tagged Windows rules compiled from SigmaHQ commit
  `272daf82bf77fb0bb97f1f0c4d82bc61154772e1`.
- Uses pySigma 1.5.0 at build time to parse Sigma YAML and compile conditions
  into a deterministic, compressed P3 intermediate representation.
- Does not require pySigma or PyYAML on the malware-analysis Windows guest.
- Normalizes P3 process, registry, file, image-load, process-access,
  remote-thread, named-pipe, tracked network, and tracked DNS evidence into
  Sigma field schemas.
- Rejects a rule when its log source or required fields are not supported.
- Requires at least one positive populated field match; a rule cannot match
  merely because an exclusion field is absent.
- Keeps a Sigma-only ATT&CK result at `candidate` and excludes it from the
  0–100 threat score.
- Preserves native `observed`/`attempted` mappings and records Sigma as an
  independent corroborating source when both engines support the same result.
- Adds rule commit, coverage, matches, false-positive context, matched fields,
  and ATT&CK candidates to JSON and standalone HTML reports.
- Corrects the detector coverage description: Sysmon EID 10, Sysmon EID
  12–14, and PowerShell EID 4104 are optional sensors, not default P3 inputs.

## Detection flow

1. CAPEMON, Frida, Sysmon and the Ubuntu PCAP agent collect raw evidence.
2. P3 provenance filtering produces the canonical clean behavior view.
3. Native semantic detectors and state machines decide whether an ATT&CK
   technique is `observed`, `attempted`, `candidate`, or
   `insufficient_evidence`.
4. The Sigma runtime evaluates only rules compatible with the available P3
   log sources and field schemas.
5. Results are merged by ATT&CK ID. Sigma may corroborate a native result, but
   Sigma alone cannot promote it above `candidate`.
6. Threat scoring ignores Sigma-only candidates. JSON and HTML retain them for
   hunting and analyst review.

## Install

Stop CAPEsolo, extract this ZIP over the root of the existing P3.2.3.15 source
tree, and allow files to be replaced.  This patch does not change the Ubuntu
PCAP agent, so no Ubuntu update or service restart is required.

Use the same Python environment that runs CAPEsolo:

```powershell
$Python = 'C:\Users\tan\AppData\Local\Python\pythoncore-3.12-64\python.exe'
& $Python tools\p3_selftest.py
Get-Content .\CAPEsolo\version.txt
```

Expected result:

```text
PASS all=87
0.5.31-p32316
```

Jinja2 and MarkupSafe must already be installed for HTML reporting, as in the
normal CAPEsolo requirements.  There is no new run-time Python dependency for
Sigma evaluation.

## Historical report replay

The supplied replay utility never executes malware. It reprocesses report
artifacts and verifies the Sigma promotion and scoring invariants:

```powershell
& $Python tools\p32316_replay_sigma_reports.py C:\path\to\corpus `
  --output C:\path\to\sigma_replay.json
```

The validation shipped with this patch replayed eight earlier P3 reports:

| Sample | Sigma rules matched | Result |
|---|---:|---|
| BlackEnergy 2.1 | 0 | No compatible rule hit; native P3 mappings retained |
| Dyre | 1 | T1547.001 corroborated |
| Ardamax Keylogger | 1 | T1547.001 corroborated |
| Kido/Conficker | 0 | No compatible rule hit; native P3 mappings retained |
| Nivdort | 0 | No compatible rule hit; native P3 mappings retained |
| PlugX | 0 | No compatible rule hit; native P3 mappings retained |
| Poweliks | 5 | T1059.001, T1218.011 and T1547.001 corroborated; T1055 retained as Sigma-only candidate |
| ZeusVM | 0 | No compatible rule hit; native P3 mappings retained |

All eight passed: no Sigma-only result became `observed` or `attempted`, and
removing Sigma-only candidates did not change any threat score. A zero match
means that no bundled rule matched the evidence available in that run; it does
not mean the sample is benign or that the ATT&CK technique is absent.

## Optional rule-pack rebuild

Rule rebuilding is a build-host operation, not a guest operation. Checkout the
same SigmaHQ commit, install `pySigma==1.5.0`, then run:

```bash
python tools/build_sigma_pack.py /path/to/sigma \
  CAPEsolo/data/sigma/sigmahq_windows_p3.json.gz
```

The builder writes deterministic gzip output (`mtime=0`). The bundled source
paths and SHA-256 values allow every compiled rule to be audited against the
pinned repository revision.

## Limits that must remain visible

- The executable Sigma layer currently targets Windows Enterprise telemetry.
  Mobile and ICS remain catalog-only until suitable Android/iOS/industrial
  sensors and normalizers exist.
- Rule count is not detector coverage. A rule is evaluated only when P3 can
  provide its log source and every referenced field.
- Sigma matches describe suspicious log patterns and can have legitimate
  false positives. Native P3 state machines remain authoritative for
  `observed` behavior.
- P3 still does not identify a malware family from Sigma rules alone.
- A missing event under incomplete behavior/network collection is not evidence
  that the malware did not use a technique.

SigmaHQ-derived data in `CAPEsolo/data/sigma/` is distributed under the
included Detection Rule License 1.1 (`SIGMAHQ_LICENSE`).
