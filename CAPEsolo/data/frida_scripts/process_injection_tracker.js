/*
 * process_injection_tracker_p31_hotfix.js
 *
 * P2.1 Hybrid fallback/enrichment telemetry for CAPEsolo + Frida.
 * Observe-only: this script never changes API arguments, return values,
 * registers, target memory, or thread context.
 *
 * Preferred sensor: Sysmon Event ID 8, consumed by lib/common/sysmon_bridge.py.
 * Frida remains useful for memory/APC/context signals that Sysmon EID 8 does not
 * represent directly. When the Sysmon bridge is unavailable, mode=frida_fallback
 * additionally enables CreateRemoteThread/NtCreateThreadEx-family hooks.
 */

'use strict';

const main = Process.mainModule;
const runtime = {
    role: 'root',
    enabled: false,
    includePrivateExecCallers: true,
    mode: 'off',              // off | hybrid | frida_fallback
    sysmonBridgeActive: false
};

const installed = {
    memory: false,
    context: false,
    remoteThread: false
};

function sendEvent(hook, action, details, extra) {
    const payload = Object.assign({
        hook: hook,
        action: action,
        details: details,
        pid: Process.id,
        main: main.name,
        role: runtime.role,
        arch: Process.arch
    }, extra || {});
    send(payload);
}

function isFrameworkOrSystemPath(path) {
    const p = String(path || '').toLowerCase();
    return (
        p.indexOf('frida') !== -1 ||
        p.indexOf('capesolo') !== -1 ||
        p.indexOf('capemon') !== -1 ||
        p.indexOf('\\windows\\') !== -1
    );
}

function addressInMain(address) {
    if (!address || address.isNull()) return false;
    return (
        address.compare(main.base) >= 0 &&
        address.compare(main.base.add(main.size)) < 0
    );
}

function callerIsTrackedCode(returnAddress) {
    if (!returnAddress || returnAddress.isNull()) return false;

    // For root/child processes the main image belongs to the analysis. For an
    // injected pre-existing host (for example explorer.exe), its original main
    // image is not automatically treated as malware-owned.
    if (runtime.role !== 'injected' && addressInMain(returnAddress)) {
        return true;
    }

    try {
        const mod = Process.findModuleByAddress(returnAddress);
        if (mod !== null) {
            const path = String(mod.path || mod.name || '');
            if (isFrameworkOrSystemPath(path)) return false;
            if (runtime.role === 'injected' && mod.base.equals(main.base)) {
                return false;
            }
            return runtime.includePrivateExecCallers;
        }
    } catch (_) {}

    if (!runtime.includePrivateExecCallers) return false;

    try {
        const range = Process.findRangeByAddress(returnAddress);
        if (range === null || range.protection.indexOf('x') === -1) {
            return false;
        }
        if (range.file && range.file.path && isFrameworkOrSystemPath(range.file.path)) {
            return false;
        }
        return true;
    } catch (_) {
        return false;
    }
}

function findExport(moduleName, exportName) {
    const mod = Process.findModuleByName(moduleName);
    if (mod === null) return null;
    try { return mod.findExportByName(exportName); }
    catch (_) { return null; }
}

let getProcessId = null;
let getProcessIdOfThread = null;

(function initPidResolvers() {
    const p1 = findExport('kernel32.dll', 'GetProcessId');
    if (p1 !== null) {
        try { getProcessId = new NativeFunction(p1, 'uint32', ['pointer']); }
        catch (_) {}
    }

    const p2 = findExport('kernel32.dll', 'GetProcessIdOfThread');
    if (p2 !== null) {
        try { getProcessIdOfThread = new NativeFunction(p2, 'uint32', ['pointer']); }
        catch (_) {}
    }
})();

function pidFromProcessHandle(handle) {
    if (getProcessId === null || !handle || handle.isNull()) return 0;
    try { return getProcessId(handle) >>> 0; }
    catch (_) { return 0; }
}

function pidFromThreadHandle(handle) {
    if (getProcessIdOfThread === null || !handle || handle.isNull()) return 0;
    try { return getProcessIdOfThread(handle) >>> 0; }
    catch (_) { return 0; }
}

function categoryEnabled(category) {
    if (!runtime.enabled || runtime.mode === 'off') return false;
    if (category === 'remote_thread') {
        return runtime.mode === 'frida_fallback';
    }
    return true;
}

const recentHints = Object.create(null);
function emitHint(targetPid, reason, strength, category, family, caller) {
    if (!categoryEnabled(category)) return;
    targetPid = Number(targetPid) >>> 0;
    if (targetPid === 0 || targetPid === Process.id) return;

    const key = targetPid + '|' + family;
    const now = Date.now();
    const previous = recentHints[key] || 0;
    if (now - previous < 250) return;
    recentHints[key] = now;

    sendEvent(
        'ProcessEnrollment',
        'hint',
        'target_pid=' + targetPid +
        ' reason=' + reason +
        ' strength=' + strength +
        ' category=' + category +
        ' family=' + family +
        ' mode=' + runtime.mode +
        ' caller=' + String(caller),
        {
            sensor: 'frida',
            target_pid: targetPid,
            reason: reason,
            strength: strength,
            category: category,
            family: family,
            tracker_mode: runtime.mode,
            caller: String(caller)
        }
    );
}

function installProcessHandleHook(moduleName, apiName, processArgIndex, strength, category, family) {
    const p = findExport(moduleName, apiName);
    if (p === null) return;

    Interceptor.attach(p, {
        onEnter(args) {
            if (!categoryEnabled(category)) return;
            if (!callerIsTrackedCode(this.returnAddress)) return;
            const targetPid = pidFromProcessHandle(args[processArgIndex]);
            emitHint(targetPid, apiName, strength, category, family, this.returnAddress);
        }
    });
}

function installThreadHandleHook(moduleName, apiName, threadArgIndex, strength, category, family) {
    const p = findExport(moduleName, apiName);
    if (p === null) return;

    Interceptor.attach(p, {
        onEnter(args) {
            if (!categoryEnabled(category)) return;
            if (!callerIsTrackedCode(this.returnAddress)) return;
            const targetPid = pidFromThreadHandle(args[threadArgIndex]);
            emitHint(targetPid, apiName, strength, category, family, this.returnAddress);
        }
    });
}

function installMemoryHooks() {
    if (installed.memory) return;
    installed.memory = true;
    installProcessHandleHook('kernel32.dll', 'VirtualAllocEx', 0, 'memory', 'memory', 'remote_alloc');
    installProcessHandleHook('kernel32.dll', 'WriteProcessMemory', 0, 'memory', 'memory', 'remote_write');
    installProcessHandleHook('kernel32.dll', 'VirtualProtectEx', 0, 'memory', 'memory', 'remote_protect');
    installProcessHandleHook('ntdll.dll', 'NtAllocateVirtualMemory', 0, 'memory', 'memory', 'remote_alloc');
    installProcessHandleHook('ntdll.dll', 'NtWriteVirtualMemory', 0, 'memory', 'memory', 'remote_write');
    installProcessHandleHook('ntdll.dll', 'NtProtectVirtualMemory', 0, 'memory', 'memory', 'remote_protect');
    installProcessHandleHook('ntdll.dll', 'NtMapViewOfSection', 1, 'memory', 'memory', 'section_map');
}

function installContextHooks() {
    if (installed.context) return;
    installed.context = true;
    installThreadHandleHook('kernel32.dll', 'QueueUserAPC', 1, 'execution', 'context', 'apc');
    installThreadHandleHook('kernel32.dll', 'SetThreadContext', 0, 'execution', 'context', 'thread_context');
    installThreadHandleHook('kernel32.dll', 'Wow64SetThreadContext', 0, 'execution', 'context', 'thread_context');
    installThreadHandleHook('ntdll.dll', 'NtQueueApcThread', 0, 'execution', 'context', 'apc');
    installThreadHandleHook('ntdll.dll', 'NtQueueApcThreadEx', 0, 'execution', 'context', 'apc');
    installThreadHandleHook('ntdll.dll', 'NtSetContextThread', 0, 'execution', 'context', 'thread_context');
}

function installRemoteThreadFallbackHooks() {
    if (installed.remoteThread) return;
    installed.remoteThread = true;
    installProcessHandleHook('kernel32.dll', 'CreateRemoteThread', 0, 'execution', 'remote_thread', 'remote_thread');
    installProcessHandleHook('kernel32.dll', 'CreateRemoteThreadEx', 0, 'execution', 'remote_thread', 'remote_thread');
    installProcessHandleHook('ntdll.dll', 'NtCreateThreadEx', 3, 'execution', 'remote_thread', 'remote_thread');
    installProcessHandleHook('ntdll.dll', 'RtlCreateUserThread', 0, 'execution', 'remote_thread', 'remote_thread');
}

function ensureHooksForMode() {
    if (!runtime.enabled || runtime.mode === 'off') return;
    installMemoryHooks();
    installContextHooks();
    if (runtime.mode === 'frida_fallback') {
        installRemoteThreadFallbackHooks();
    }
}

function isInstrumentationPath(path) {
    const lower = String(path || '').toLowerCase();
    return (
        lower.indexOf('frida') !== -1 ||
        lower.indexOf('capesolo') !== -1 ||
        lower.indexOf('capemon') !== -1
    );
}

const instrumentationSeen = Object.create(null);

function emitInstrumentationInventory() {
    function emitRange(kind, base, size, path) {
        if (!base || Number(size) <= 0 || !isInstrumentationPath(path)) return;
        const key = String(base) + '|' + Number(size) + '|' + String(path).toLowerCase();
        if (instrumentationSeen[key]) return;
        instrumentationSeen[key] = true;

        sendEvent(
            kind,
            'observed',
            'base=' + base +
            ' size=0x' + Number(size).toString(16) +
            ' path=' + String(path),
            {
                module_base: String(base),
                module_size: Number(size),
                module_path: String(path)
            }
        );
    }

    try {
        Process.enumerateModules().forEach(function (m) {
            emitRange(
                'InstrumentationModule',
                m.base,
                m.size,
                String(m.path || m.name || '')
            );
        });
    } catch (e) {
        sendEvent('InstrumentationModule', 'inventory_error', e.message || String(e));
    }

    // Frida's own agent is not guaranteed to appear in enumerateModules() on
    // every architecture/build. File-backed ranges provide a second source.
    // Newer Frida builds prefer the object-form enumerateRanges API; keep a
    // string-form fallback for older builds.
    const protections = ['r--', 'r-x', 'rw-', 'rwx', '--x'];
    protections.forEach(function (protection) {
        let ranges = [];
        try {
            ranges = Process.enumerateRanges({ protection: protection, coalesce: true });
        } catch (_) {
            try { ranges = Process.enumerateRanges(protection); } catch (_) { ranges = []; }
        }
        ranges.forEach(function (r) {
            if (!r.file || !r.file.path) return;
            emitRange(
                'InstrumentationRange',
                r.base,
                r.size,
                String(r.file.path)
            );
        });
    });
}

recv('profile_config', function configure(message) {
    runtime.role = String(message.process_role || 'root');
    runtime.enabled = Boolean(message.follow_injected_targets);
    runtime.includePrivateExecCallers = Boolean(message.private_exec_callers);
    runtime.sysmonBridgeActive = Boolean(message.sysmon_bridge_active);

    const requested = String(message.injection_tracker_mode || 'hybrid').toLowerCase();
    runtime.mode = ['off', 'hybrid', 'frida_fallback'].indexOf(requested) !== -1
        ? requested
        : 'hybrid';

    ensureHooksForMode();
    emitInstrumentationInventory();
    // Repeat after the profile message returns: some Frida builds finish
    // exposing agent-backed ranges slightly after script startup. Global
    // deduplication keeps this low-noise.
    setTimeout(emitInstrumentationInventory, 250);
    setTimeout(emitInstrumentationInventory, 1000);
    sendEvent(
        'ProcessInjectionTracker',
        'ready',
        'enabled=' + runtime.enabled +
        ' role=' + runtime.role +
        ' mode=' + runtime.mode +
        ' sysmon=' + runtime.sysmonBridgeActive +
        ' private_exec=' + runtime.includePrivateExecCallers +
        ' hooks={memory:' + installed.memory +
        ',context:' + installed.context +
        ',remote_thread:' + installed.remoteThread + '}'
    );
});
