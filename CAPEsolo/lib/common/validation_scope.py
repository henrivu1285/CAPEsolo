"""Exact opt-in PowerShell script identity for the P3 validation runner."""
import ntpath


def matches_validation_script(name, command_line, expected):
    if str(name or "").lower() not in {"powershell.exe", "pwsh.exe"} or not expected:
        return False
    expected = ntpath.normcase(ntpath.normpath(str(expected)))
    if not ntpath.isabs(expected) or not expected.endswith(".ps1"):
        return False
    args = list(command_line or [])
    positions = [i for i, arg in enumerate(args) if str(arg).lower() == "-file"]
    return len(positions) == 1 and positions[0] + 1 < len(args) and ntpath.normcase(
        ntpath.normpath(str(args[positions[0] + 1]).strip('"'))) == expected
