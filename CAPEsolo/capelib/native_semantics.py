"""Conservative structured Windows telemetry predicates shared by P3 analytics.

No input command is executed. These helpers interpret recorded evidence only.
"""
from __future__ import annotations
import ntpath
import re

PROCESS_CREATE = frozenset({"createprocessa", "createprocessw", "createprocessinternalw", "ntcreateuserprocess", "shellexecutea", "shellexecutew", "shellexecuteexa", "shellexecuteexw", "winexec"})
REGISTRY_SET = frozenset({"regsetvalueexw", "regsetvalueexa", "regsetvaluew", "regsetvaluea", "ntsetvaluekey"})
REMOTE_WRITE = frozenset({"ntwritevirtualmemory", "writeprocessmemory"})
REMOTE_START = frozenset({"createremotethread", "createremotethreadex", "ntcreatethreadex", "rtlcreateuserthread"})

def argument(args, *names):
    lower = {str(k).lower(): v for k, v in args.items()}
    return next((lower[n.lower()] for n in names if n.lower() in lower), None)

def integer(value):
    if value is None or isinstance(value, bool):
        return None
    try:
        text = str(value).strip()
        return int(text, 16 if text.lower().startswith('0x') else 10)
    except (ValueError, TypeError):
        return None

def path(value):
    text = str(value or '').strip().strip('"').replace('/', '\\')
    return ntpath.normcase(ntpath.normpath(text)) if text else ''

def basename(value):
    return ntpath.basename(path(value))

def success(call):
    # CAPEMON serializes Boolean status. Missing status is not successful evidence.
    status = call.get('status')
    return (status is True or (type(status) is int and status == 1)) and str(call.get('return', '')).lower() not in {'0xffffffff', '0xffffffffffffffff', '-1', 'false', 'error'}

def command_tokens(value):
    # Windows path/argument tokenizer for detection, never an execution parser.
    # Preserve backslashes and quoted arguments, reject unmatched quotes.
    value = str(value or '').strip()
    if value.count('"') % 2:
        return []
    return [m.group(1) if m.group(1) is not None else m.group(2) for m in re.finditer(r'"([^"\r\n]*)"|([^\s"]+)', value)]

def executed_image(args):
    explicit = argument(args, 'ApplicationName', 'ImagePathName', 'ImagePath', 'FilePath', 'File', 'lpFile')
    if explicit:
        return path(explicit)
    tokens = command_tokens(argument(args, 'CommandLine', 'lpCommandLine'))
    return path(tokens[0]) if tokens else ''

def executed_basename(args):
    name = basename(executed_image(args))
    # Windows resolves extensionless executable names through CreateProcess.
    return name + '.exe' if name and '.' not in name else name

def command_args(args):
    tokens = command_tokens(argument(args, 'CommandLine', 'lpCommandLine'))
    if tokens:
        return [x.lower() for x in tokens[1:]]
    return [x.lower() for x in command_tokens(argument(args, 'Parameters', 'lpParameters'))]

def registry_path(args):
    return path(argument(args, 'FullName', 'RegistryPath', 'KeyName', 'ObjectName'))

def run_key_write(api, args):
    if api.lower() not in REGISTRY_SET:
        return None
    full = registry_path(args)
    # A Run value may be part of FullName; boundaries exclude RunMRU/RunOnceEx.
    if not re.search(r'^(?:hkey_local_machine|hkey_current_user|hklm|hkcu|hkey_users\\s-[0-9-]+|\\registry\\machine|\\registry\\user\\s-[0-9-]+)\\software\\(?:wow6432node\\)?microsoft\\windows\\currentversion\\(?:run|runonce)(?:\\[^\\]+)?$', full):
        return None
    value = argument(args, 'Buffer', 'Data', 'ValueData')
    if value is None or not str(value).strip():
        return None  # Clearing a value does not establish persistence.
    return str(argument(args, "FullName", "RegistryPath", "KeyName", "ObjectName")), str(value)

def service_image_write(api, args):
    if api.lower() not in REGISTRY_SET:
        return False
    full = registry_path(args)
    value_name = str(argument(args, 'ValueName') or '').lower()
    if value_name == 'imagepath' and not full.endswith('\\imagepath'):
        full += '\\imagepath'
    return bool(re.search(r'\\system\\(?:currentcontrolset|controlset\d{3})\\services\\[^\\]+\\imagepath$', full)
                and argument(args, 'Buffer', 'Data', 'ValueData'))

class ProcessTargets:
    """Bind a handle lifetime to an explicit target PID and optional process name."""
    def __init__(self):
        self.handles = {}
        self.generations = {}

    def observe(self, pid, api, args, call):
        pid = integer(pid)
        handle = integer(argument(args, 'ProcessHandle', 'hProcess', 'TargetProcessHandle'))
        if api in {'ntclose', 'closehandle'} and success(call):
            closed = integer(argument(args, 'Handle', 'hObject', 'ProcessHandle'))
            self.handles.pop((pid, closed), None)
        target_pid = integer(argument(args, 'TargetProcessId', 'ProcessIdentifier', 'ProcessId'))
        key = (pid, handle)
        if api in {'ntopenprocess', 'openprocess'} and success(call):
            self.handles.pop(key, None)
            self.generations[key] = self.generations.get(key, 0) + 1
            if pid and target_pid and handle not in {None, 0, -1, 0xffffffff, 0xffffffffffffffff}:
                self.handles[key] = (target_pid, basename(argument(args, 'ProcessName', 'TargetProcessName')), self.generations[key])
        bound = self.handles.get(key)
        if bound and target_pid is not None and target_pid != bound[0]:
            return None  # Contradictory metadata, fail closed.
        if bound:
            target_pid, name, generation = bound
            correlation = f'pid:{target_pid}:handle:{handle}:generation:{generation}'
        else:
            name = basename(argument(args, 'ProcessName', 'TargetProcessName'))
            correlation = f'pid:{target_pid}'
        if not pid or not target_pid or pid == target_pid:
            return None
        return {'key': correlation, 'pid': target_pid, 'name': name}
