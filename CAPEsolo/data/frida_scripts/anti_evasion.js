/*
 * anti_evasion_p31_hotfix.js
 *
 * Frida 17+ compatible.
 *
 * This version keeps the v3 anti-debug hooks but improves gate validation:
 *   - derives AddressOfEntryPoint from the in-memory PE header;
 *   - applies gate_delta supplied by Python;
 *   - verifies EB FE before patching;
 *   - reports the bytes before AND after restore;
 *   - reports the computed destination of an E9 rel32 stub.
 */

'use strict';

const main = Process.mainModule;

/*
 * Runtime profile is supplied by frida_muncher P3. Safe defaults are
 * intentionally generic: no sample-specific exception bypass is enabled.
 */
const runtimeProfile = {
    name: 'generic',
    processRole: 'root',
    enableLegacyInt2A: false,
    enableExceptionDiagnostics: false,
    gateMode: 'none',
    antiAnalysisMode: 'observe',
    includePrivateExecCallers: true
};

function report(hook, action, details) {
    send({
        hook: hook,
        action: action,
        details: details,
        pid: Process.id,
        main: main.name,
        role: runtimeProfile.processRole,
        arch: Process.arch
    });
}

function findExport(moduleName, exportName) {
    const mod = Process.findModuleByName(moduleName);

    if (mod === null) {
        report(
            exportName,
            'not_installed',
            'module not loaded: ' + moduleName
        );
        return null;
    }

    return mod.findExportByName(exportName);
}

function addressInMain(address) {
    if (!address || address.isNull()) {
        return false;
    }

    const start = main.base;
    const end = main.base.add(main.size);
    return (
        address.compare(start) >= 0 &&
        address.compare(end) < 0
    );
}

/*
 * P1 caller policy.
 *
 * A packed/manual-mapped stage often executes from anonymous RX/RWX memory and
 * therefore falls outside Process.mainModule.  Treat those executable private
 * ranges as malware callers, while rejecting calls originating from normal
 * loaded DLL modules (including CAPEMON, Frida and Windows DLLs).
 */
function callerIsMalware(returnAddress) {
    if (!returnAddress || returnAddress.isNull()) {
        return false;
    }

    if (addressInMain(returnAddress)) {
        return true;
    }

    try {
        const mod = Process.findModuleByAddress(returnAddress);
        if (mod !== null) {
            const path = String(mod.path || mod.name || '').toLowerCase();
            if (
                path.indexOf('frida') !== -1 ||
                path.indexOf('capesolo') !== -1 ||
                path.indexOf('capemon') !== -1 ||
                path.indexOf('\\windows\\') !== -1 ||
                path.indexOf('\\windows\\system32\\') !== -1 ||
                path.indexOf('\\windows\\syswow64\\') !== -1
            ) {
                return false;
            }

            // A non-system module loaded into the sample process may itself be
            // a dropped/manual stage.  Extended caller tracking is intentionally
            // controlled by the same P1 profile switch.
            return runtimeProfile.includePrivateExecCallers;
        }
    } catch (_) {}

    if (!runtimeProfile.includePrivateExecCallers) {
        return false;
    }

    try {
        const range = Process.findRangeByAddress(returnAddress);
        if (range === null || range.protection.indexOf('x') === -1) {
            return false;
        }

        // Anonymous executable memory is the common unpacked/JIT-like case.
        // If Frida reports a backing file, reject obvious framework/system
        // mappings to keep this policy conservative.
        if (range.file && range.file.path) {
            const path = String(range.file.path).toLowerCase();
            if (
                path.indexOf('frida') !== -1 ||
                path.indexOf('capesolo') !== -1 ||
                path.indexOf('capemon') !== -1 ||
                path.indexOf('\\windows\\') !== -1
            ) {
                return false;
            }
        }

        return true;
    } catch (_) {
        return false;
    }
}

function antiAnalysisBypassEnabled() {
    return runtimeProfile.antiAnalysisMode === 'bypass';
}

function safeAnsi(p) {
    if (!p || p.isNull()) return '';
    try { return p.readAnsiString() || ''; }
    catch (_) { return ''; }
}

function safeUtf16(p) {
    if (!p || p.isNull()) return '';
    try { return p.readUtf16String() || ''; }
    catch (_) { return ''; }
}


/* ---------------- Anti-debug ---------------- */

(function hookIsDebuggerPresent() {
    const p = findExport(
        'kernel32.dll',
        'IsDebuggerPresent'
    );

    if (p === null) return;

    Interceptor.attach(p, {
        onEnter() {
            this.apply = callerIsMalware(this.returnAddress);
            this.caller = this.returnAddress;
        },

        onLeave(retval) {
            if (!this.apply) return;

            const original = retval.toInt32();
            if (antiAnalysisBypassEnabled()) {
                retval.replace(0);
                report(
                    'IsDebuggerPresent',
                    'bypassed',
                    'original=' + original + ' return->FALSE caller=' +
                    formatAddress(this.caller)
                );
            } else {
                report(
                    'IsDebuggerPresent',
                    'observed',
                    'return=' + original + ' caller=' +
                    formatAddress(this.caller)
                );
            }
        }
    });
})();


(function hookCheckRemoteDebuggerPresent() {
    const p = findExport(
        'kernel32.dll',
        'CheckRemoteDebuggerPresent'
    );

    if (p === null) return;

    Interceptor.attach(p, {
        onEnter(args) {
            this.apply = callerIsMalware(this.returnAddress);
            this.caller = this.returnAddress;
            this.outValue = args[1];
        },

        onLeave(retval) {
            if (!this.apply) return;

            const success = retval.toInt32() !== 0;
            let original = '<unreadable>';
            try {
                if (!this.outValue.isNull()) {
                    original = String(this.outValue.readU32());
                }
            } catch (_) {}

            if (
                antiAnalysisBypassEnabled() &&
                success &&
                !this.outValue.isNull()
            ) {
                this.outValue.writeU32(0);
                report(
                    'CheckRemoteDebuggerPresent',
                    'bypassed',
                    'original=' + original +
                    ' pbDebuggerPresent->FALSE caller=' +
                    formatAddress(this.caller)
                );
            } else {
                report(
                    'CheckRemoteDebuggerPresent',
                    'observed',
                    'success=' + success + ' debugger=' + original +
                    ' caller=' + formatAddress(this.caller)
                );
            }
        }
    });
})();


(function hookNtQueryInformationProcess() {
    const p = findExport(
        'ntdll.dll',
        'NtQueryInformationProcess'
    );

    if (p === null) return;

    Interceptor.attach(p, {
        onEnter(args) {
            this.apply = callerIsMalware(this.returnAddress);
            this.caller = this.returnAddress;
            if (!this.apply) return;

            this.infoClass = args[1].toInt32();
            this.outBuffer = args[2];
        },

        onLeave(retval) {
            if (
                !this.apply ||
                this.outBuffer.isNull() ||
                retval.toInt32() < 0
            ) {
                return;
            }

            if (
                this.infoClass !== 7 &&
                this.infoClass !== 0x1e &&
                this.infoClass !== 0x1f
            ) {
                return;
            }

            let original = '<unreadable>';
            try {
                if (this.infoClass === 0x1f) {
                    original = '0x' + this.outBuffer.readU32().toString(16);
                } else {
                    original = String(this.outBuffer.readPointer());
                }
            } catch (_) {}

            if (!antiAnalysisBypassEnabled()) {
                report(
                    'NtQueryInformationProcess',
                    'observed',
                    'class=0x' + this.infoClass.toString(16) +
                    ' value=' + original +
                    ' caller=' + formatAddress(this.caller)
                );
                return;
            }

            if (this.infoClass === 7) {
                this.outBuffer.writePointer(ptr(0));
                report(
                    'NtQueryInformationProcess',
                    'bypassed',
                    'ProcessDebugPort original=' + original + ' -> 0'
                );
            }
            else if (this.infoClass === 0x1e) {
                this.outBuffer.writePointer(ptr(0));
                report(
                    'NtQueryInformationProcess',
                    'bypassed',
                    'ProcessDebugObjectHandle original=' + original + ' -> NULL'
                );
            }
            else if (this.infoClass === 0x1f) {
                this.outBuffer.writeU32(1);
                report(
                    'NtQueryInformationProcess',
                    'bypassed',
                    'ProcessDebugFlags original=' + original + ' -> 1'
                );
            }
        }
    });
})();



/* ---------------- Basic sandbox checks ---------------- */

function installFindWindowHook(
    apiName,
    reader
) {
    const p = findExport(
        'user32.dll',
        apiName
    );

    if (p === null) return;

    Interceptor.attach(p, {
        onEnter(args) {
            this.apply = callerIsMalware(this.returnAddress);
            this.caller = this.returnAddress;
            if (!this.apply) return;

            this.a = reader(args[0]).toUpperCase();
            this.b = reader(args[1]).toUpperCase();
        },

        onLeave(retval) {
            if (!this.apply) return;

            const value = this.a + ' ' + this.b;
            const needles = [
                'OLLYDBG',
                'WINDBG',
                'X64DBG',
                'X32DBG',
                'PROCESS HACKER',
                'WIRESHARK'
            ];

            if (!needles.some(x => value.indexOf(x) !== -1)) {
                return;
            }

            const original = String(retval);
            if (antiAnalysisBypassEnabled()) {
                retval.replace(ptr(0));
                report(
                    apiName,
                    'bypassed',
                    'analysis window hidden: ' + value +
                    ' original=' + original
                );
            } else {
                report(
                    apiName,
                    'observed',
                    'analysis-window query: ' + value +
                    ' result=' + original +
                    ' caller=' + formatAddress(this.caller)
                );
            }
        }
    });
}


installFindWindowHook(
    'FindWindowA',
    safeAnsi
);

installFindWindowHook(
    'FindWindowW',
    safeUtf16
);


function installSystemInfoHook(apiName) {
    const p = findExport(
        'kernel32.dll',
        apiName
    );

    if (p === null) return;

    Interceptor.attach(p, {
        onEnter(args) {
            this.apply = callerIsMalware(this.returnAddress);
            this.caller = this.returnAddress;
            this.info = args[0];
        },

        onLeave() {
            if (!this.apply || this.info.isNull()) {
                return;
            }

            const offset = Process.pointerSize === 8 ? 32 : 20;
            let original = 0;
            try {
                original = this.info.add(offset).readU32();
            } catch (_) {
                return;
            }

            if (antiAnalysisBypassEnabled()) {
                this.info.add(offset).writeU32(8);
                report(
                    apiName,
                    'bypassed',
                    'dwNumberOfProcessors ' + original + ' -> 8'
                );
            } else {
                report(
                    apiName,
                    'observed',
                    'dwNumberOfProcessors=' + original +
                    ' caller=' + formatAddress(this.caller)
                );
            }
        }
    });
}


installSystemInfoHook(
    'GetSystemInfo'
);

installSystemInfoHook(
    'GetNativeSystemInfo'
);


/* ---------------- PE / gate ---------------- */

function peAddressOfEntryPoint() {
    const base = main.base;

    if (base.readU16() !== 0x5a4d) {
        throw new Error(
            'MZ signature missing at ' + base
        );
    }

    const eLfanew =
        base.add(0x3c).readU32();

    const nt =
        base.add(eLfanew);

    if (
        nt.readU32() !== 0x00004550
    ) {
        throw new Error(
            'PE signature missing at ' + nt
        );
    }

    const optionalHeader =
        nt.add(24);

    return optionalHeader
        .add(0x10)
        .readU32();
}


function hexToBytes(hex) {
    const clean =
        String(hex || '')
        .replace(/\s+/g, '')
        .toLowerCase();

    if (
        clean.length === 0 ||
        (clean.length & 1) !== 0 ||
        !/^[0-9a-f]+$/.test(clean)
    ) {
        throw new Error(
            'invalid hex: ' + hex
        );
    }

    const out = [];

    for (
        let i = 0;
        i < clean.length;
        i += 2
    ) {
        out.push(
            parseInt(
                clean.substr(i, 2),
                16
            )
        );
    }

    return out;
}


function readHex(address, count) {
    const raw =
        address.readByteArray(count);

    const data =
        new Uint8Array(raw);

    return Array.from(data)
        .map(
            x => x
                .toString(16)
                .padStart(2, '0')
        )
        .join('');
}


function signed32(value) {
    return value > 0x7fffffff
        ? value - 0x100000000
        : value;
}


recv(
    'release_ep',
    function releaseEntryGate(message) {
        try {
            const aoep =
                peAddressOfEntryPoint();

            const delta =
                Number(
                    message.gate_delta || 0
                );

            const gate =
                main.base
                    .add(aoep)
                    .add(delta);

            const restore =
                hexToBytes(
                    message.restore_hex
                );

            const expected =
                String(
                    message.expected_hex ||
                    ''
                ).toLowerCase();

            if (expected.length === 0) {
                throw new Error('expected_hex is required for patched_entry mode');
            }

            const before =
                readHex(
                    gate,
                    Math.max(
                        restore.length,
                        7
                    )
                );

            report(
                'EP_Gate',
                'check',
                'base=' + main.base +
                ' AoEP=0x' +
                aoep.toString(16) +
                ' delta=0x' +
                delta.toString(16) +
                ' gate=' + gate +
                ' bytes=' + before
            );

            if (
                before.substr(
                    0,
                    expected.length
                ) !== expected
            ) {
                report(
                    'EP_Gate',
                    'refused',
                    'expected=' +
                    expected +
                    ' found=' +
                    before +
                    ' at ' +
                    gate
                );
                return;
            }

            if (
                !Memory.protect(
                    gate,
                    restore.length,
                    'rwx'
                )
            ) {
                throw new Error(
                    'Memory.protect failed at ' +
                    gate
                );
            }

            gate.writeByteArray(
                restore
            );

            Memory.protect(
                gate,
                restore.length,
                'r-x'
            );

            const after =
                readHex(
                    gate,
                    7
                );

            let jumpInfo = '';

            /*
             * Generic E9 rel32 gate sanity check. If a profile restores an E9
             * instruction, report its computed destination without changing the
             * execution context.
             */
            if (
                gate.readU8() === 0xe9
            ) {
                const rawRel =
                    gate
                    .add(1)
                    .readU32();

                const rel =
                    signed32(rawRel);

                const destination =
                    gate
                        .add(5)
                        .add(rel);

                jumpInfo =
                    ' jmp_target=' +
                    destination;
            }

            report(
                'EP_Gate',
                'released',
                'after=' +
                after +
                jumpInfo
            );
        }
        catch (e) {
            report(
                'EP_Gate',
                'exception',
                e.stack ||
                e.message ||
                String(e)
            );
        }
    }
);




/* ---------------- Generic low-noise crash diagnostics ---------------- */

/*
 * Keep selective profile-controlled INT 2Ah recovery, while keeping generic
 * diagnostics low-noise in three ways:
 *
 *  1) FUZZY backtraces only.  This avoids asking the accurate Windows
 *     unwinder/debug-symbol path to do heavy work inside the malware.
 *  2) Duplicate exception rate-limiting.  A fault loop will not flood the
 *     sandbox with hundreds of send()/backtrace operations.
 *  3) For the first occurrence of a fault, capture x86 registers, code bytes,
 *     stack bytes, and inspect whether EIP is sitting inside a valid PE header.
 *
 * No generic access violation is bypassed.
 * No staged PE entry point is forced.
 */

function formatAddress(p) {
    try {
        const m = Process.findModuleByAddress(p);
        if (m !== null) {
            return p + ' (' + m.name + '+0x' +
                p.sub(m.base).toString(16) + ')';
        }
    } catch (_) {}

    return String(p);
}

function captureBacktrace(context) {
    try {
        return Thread.backtrace(
            context,
            Backtracer.FUZZY
        ).slice(0, 16).map(formatAddress).join(' <- ');
    } catch (e) {
        return 'backtrace unavailable: ' +
            (e.message || String(e));
    }
}

function safeReadHex(address, count) {
    try {
        if (!address || address.isNull()) {
            return '<null>';
        }

        return readHex(address, count);
    } catch (e) {
        return '<unreadable:' +
            (e.message || String(e)) +
            '>';
    }
}

function contextProgramCounter(ctx, fallback) {
    try {
        if (ctx.pc !== undefined) return ctx.pc;
        if (ctx.rip !== undefined) return ctx.rip;
        if (ctx.eip !== undefined) return ctx.eip;
    } catch (_) {}
    return fallback;
}

function contextStackPointer(ctx) {
    try {
        if (ctx.sp !== undefined) return ctx.sp;
        if (ctx.rsp !== undefined) return ctx.rsp;
        if (ctx.esp !== undefined) return ctx.esp;
    } catch (_) {}
    return ptr(0);
}

function contextRegisters(ctx) {
    let names;

    if (Process.arch === 'x64') {
        names = [
            'rax', 'rbx', 'rcx', 'rdx',
            'rsi', 'rdi', 'rsp', 'rbp',
            'r8', 'r9', 'r10', 'r11',
            'r12', 'r13', 'r14', 'r15',
            'rip', 'pc', 'eflags'
        ];
    } else if (Process.arch === 'ia32') {
        names = [
            'eax', 'ebx', 'ecx', 'edx',
            'esi', 'edi', 'esp', 'ebp',
            'eip', 'pc', 'eflags',
            'cs', 'ss', 'ds', 'es', 'fs', 'gs'
        ];
    } else {
        names = [
            'pc', 'sp', 'fp', 'lr',
            'x0', 'x1', 'x2', 'x3',
            'r0', 'r1', 'r2', 'r3'
        ];
    }

    const parts = [];
    names.forEach(function(name) {
        try {
            if (ctx[name] !== undefined) {
                parts.push(name + '=' + ctx[name]);
            }
        } catch (_) {}
    });

    return parts.join(' ');
}


/*
 * Inspect the native memory range containing an address.  If the range begins
 * with an MZ/PE header, extract only the fields useful for diagnosing a
 * manually-mapped/unpacked image.
 */
function inspectPeRange(address) {
    try {
        const range = Process.findRangeByAddress(address);

        if (range === null) {
            return null;
        }

        const base = range.base;

        if (base.readU16() !== 0x5a4d) {
            return null;
        }

        const eLfanew = base.add(0x3c).readU32();

        // Refuse implausible header offsets.
        if (eLfanew < 0x40 || eLfanew > 0x1000) {
            return null;
        }

        const nt = base.add(eLfanew);

        if (nt.readU32() !== 0x00004550) {
            return null;
        }

        const fileHeader = nt.add(4);
        const characteristics = fileHeader.add(18).readU16();
        const optionalHeader = nt.add(24);
        const magic = optionalHeader.readU16();

        if (magic !== 0x10b && magic !== 0x20b) {
            return null;
        }

        const aoep = optionalHeader.add(0x10).readU32();
        const sizeOfImage = optionalHeader.add(0x38).readU32();

        let preferredBase;

        if (magic === 0x10b) {
            preferredBase = ptr(optionalHeader.add(0x1c).readU32());
        } else {
            preferredBase = optionalHeader.add(0x18).readPointer();
        }

        const dataDirectory =
            optionalHeader.add(magic === 0x10b ? 0x60 : 0x70);

        const relocDirectory = dataDirectory.add(5 * 8);
        const relocRva = relocDirectory.readU32();
        const relocSize = relocDirectory.add(4).readU32();

        return {
            base: base,
            rangeSize: range.size,
            protection: range.protection,
            pcOffset: address.sub(base),
            aoep: aoep,
            runtimeEntry: base.add(aoep),
            preferredBase: preferredBase,
            sizeOfImage: sizeOfImage,
            characteristics: characteristics,
            relocRva: relocRva,
            relocSize: relocSize,
            headerBytes: safeReadHex(base, 32)
        };
    } catch (_) {
        return null;
    }
}

function peInfoToString(pe) {
    if (pe === null) {
        return '';
    }

    return (
        ' pe_base=' + pe.base +
        ' pc_off=0x' + pe.pcOffset.toString(16) +
        ' preferred_base=' + pe.preferredBase +
        ' aoep=0x' + pe.aoep.toString(16) +
        ' runtime_ep=' + pe.runtimeEntry +
        ' size_image=0x' + pe.sizeOfImage.toString(16) +
        ' characteristics=0x' + pe.characteristics.toString(16) +
        ' reloc_rva=0x' + pe.relocRva.toString(16) +
        ' reloc_size=0x' + pe.relocSize.toString(16) +
        ' protection=' + pe.protection +
        ' header=' + pe.headerBytes
    );
}

/* Duplicate exception counters. */
const exceptionCounts = Object.create(null);

function exceptionKey(details, pc) {
    let operation = '';
    let memAddress = '';

    try {
        if (details.memory) {
            operation = details.memory.operation || '';
            memAddress = String(details.memory.address || '');
        }
    } catch (_) {}

    return [
        details.type,
        String(pc),
        operation,
        memAddress
    ].join('|');
}

function shouldReportDuplicate(count) {
    return (
        count <= 3 ||
        count === 10 ||
        count === 25 ||
        count === 50 ||
        count === 100 ||
        count === 250
    );
}

let exceptionHandlerInstalled = false;

function handleProcessException(details) {
    const ctx = details.context;
    const pc = contextProgramCounter(ctx, details.address);

    /*
     * Profile-controlled legacy recovery: skip only an actual CD 2A
     * instruction attributed to malware code. Generic profile leaves this off.
     */
    try {
        if (
            runtimeProfile.enableLegacyInt2A &&
            Process.arch === 'ia32' &&
            callerIsMalware(pc)
        ) {
            const b0 = pc.readU8();
            const b1 = pc.add(1).readU8();

            if (b0 === 0xcd && b1 === 0x2a) {
                const next = pc.add(2);

                report(
                    'Legacy_INT2A',
                    'bypassed',
                    'pc=' + formatAddress(pc) +
                    ' type=' + details.type +
                    ' next=' + formatAddress(next) +
                    ' ' + contextRegisters(ctx)
                );

                ctx.pc = next;

                try {
                    ctx.eip = next;
                } catch (_) {}

                return true;
            }
        }
    } catch (e) {
        report(
            'Legacy_INT2A',
            'handler_error',
            e.stack || e.message || String(e)
        );
    }

    /*
     * Legacy INT2A recovery may require the handler, but generic crash
     * diagnostics are independently opt-in.  With diagnostics disabled we do
     * not inspect, count, symbolize, or report unrelated exceptions.
     */
    if (!runtimeProfile.enableExceptionDiagnostics) {
        return false;
    }

    let operation = '';
    let memAddress = '';

    try {
        if (details.memory) {
            operation = details.memory.operation || '';
            memAddress = String(details.memory.address || '');
        }
    } catch (_) {}

    const key = exceptionKey(details, pc);
    const count = (exceptionCounts[key] || 0) + 1;
    exceptionCounts[key] = count;

    /*
     * First occurrence gets the complete forensic snapshot.
     * Selected duplicate counts get only a short progress message.
     */
    if (count === 1) {
        const pe = inspectPeRange(pc);

        report(
            'Exception',
            'first',
            'type=' + details.type +
            ' pc=' + formatAddress(pc) +
            ' operation=' + operation +
            ' memory=' + memAddress +
            ' code=' + safeReadHex(pc, 24) +
            ' stack=' + safeReadHex(contextStackPointer(ctx), 96) +
            ' regs={' + contextRegisters(ctx) + '}' +
            peInfoToString(pe) +
            ' bt=' + captureBacktrace(ctx)
        );

    } else if (shouldReportDuplicate(count)) {
        report(
            'Exception',
            'duplicate',
            'count=' + count +
            ' type=' + details.type +
            ' pc=' + pc +
            ' operation=' + operation +
            ' memory=' + memAddress +
            ' regs={' + contextRegisters(ctx) + '}'
        );
    }

    /*
     * Every non-INT2A exception is still delivered to the original program /
     * Windows. Diagnostics never invent a new execution path.
     */
    return false;
}

function installExceptionDiagnostics() {
    if (exceptionHandlerInstalled) {
        return;
    }

    const required = (
        runtimeProfile.enableExceptionDiagnostics ||
        runtimeProfile.enableLegacyInt2A
    );

    if (!required) {
        report(
            'CrashDiagnostics',
            'disabled',
            'profile=' + runtimeProfile.name +
            ' role=' + runtimeProfile.processRole
        );
        return;
    }

    try {
        Process.setExceptionHandler(handleProcessException);
        exceptionHandlerInstalled = true;
        report(
            'CrashDiagnostics',
            'ready',
            'profile=' + runtimeProfile.name +
            ' role=' + runtimeProfile.processRole +
            ' diagnostics=' + runtimeProfile.enableExceptionDiagnostics +
            ' legacy_int2a=' + runtimeProfile.enableLegacyInt2A
        );
    } catch (e) {
        report(
            'CrashDiagnostics',
            'install_failed',
            e.stack || e.message || String(e)
        );
    }
}


(function hookNtSetInformationProcessDiagnostic() {
    const p = findExport(
        'ntdll.dll',
        'NtSetInformationProcess'
    );

    if (p === null) return;

    Interceptor.attach(p, {
        onEnter(args) {
            this.apply = callerIsMalware(this.returnAddress);
            this.infoClass = args[1].toInt32();
            this.info = args[2];
            this.infoLength = args[3].toUInt32();

            if (!this.apply || this.infoClass !== 63) {
                return;
            }

            let raw = '';

            try {
                const n = Math.min(
                    this.infoLength,
                    32
                );

                if (!this.info.isNull() && n > 0) {
                    raw = safeReadHex(
                        this.info,
                        n
                    );
                }
            } catch (_) {}

            report(
                'NtSetInformationProcess',
                'diagnostic',
                'class=63' +
                ' len=' + this.infoLength +
                ' data=' + raw +
                ' caller=' + formatAddress(this.returnAddress) +
                ' bt=' + captureBacktrace(this.context)
            );
        },

        onLeave(retval) {
            if (this.apply && this.infoClass === 63) {
                report(
                    'NtSetInformationProcess',
                    'diagnostic_return',
                    'class=63 status=' + retval
                );
            }
        }
    });
})();


(function hookNtTerminateProcessDiagnostic() {
    const p = findExport(
        'ntdll.dll',
        'NtTerminateProcess'
    );

    if (p === null) return;

    Interceptor.attach(p, {
        onEnter(args) {
            if (!callerIsMalware(this.returnAddress)) {
                return;
            }

            const handle = args[0];
            const status = args[1].toInt32();

            report(
                'NtTerminateProcess',
                'diagnostic',
                'handle=' + handle +
                ' status=0x' +
                (status >>> 0).toString(16) +
                ' caller=' + formatAddress(this.returnAddress) +
                ' regs={' + contextRegisters(this.context) + '}' +
                ' bt=' + captureBacktrace(this.context)
            );
        }
    });
})();


/*
 * Python sends profile_config after script.load().  FridaHooks=ready is
 * intentionally delayed until configuration arrives, so generic mode cannot
 * accidentally inherit sample-specific behavior.
 */
recv(
    'profile_config',
    function configureRuntimeProfile(message) {
        runtimeProfile.name = String(message.profile || 'generic');
        runtimeProfile.processRole = String(message.process_role || 'root');
        runtimeProfile.enableLegacyInt2A = Boolean(message.enable_legacy_int2a);
        runtimeProfile.enableExceptionDiagnostics = Boolean(
            message.enable_exception_diagnostics
        );
        runtimeProfile.gateMode = String(message.gate_mode || 'none');
        runtimeProfile.antiAnalysisMode = String(
            message.anti_analysis_mode || 'observe'
        ).toLowerCase();
        runtimeProfile.includePrivateExecCallers = Boolean(
            message.private_exec_callers
        );

        if (
            runtimeProfile.antiAnalysisMode !== 'observe' &&
            runtimeProfile.antiAnalysisMode !== 'bypass'
        ) {
            runtimeProfile.antiAnalysisMode = 'observe';
        }

        installExceptionDiagnostics();

        report(
            'Profile',
            'configured',
            'name=' + runtimeProfile.name +
            ' role=' + runtimeProfile.processRole +
            ' arch=' + Process.arch +
            ' anti_analysis=' + runtimeProfile.antiAnalysisMode +
            ' private_exec=' + runtimeProfile.includePrivateExecCallers +
            ' exception_diagnostics=' + runtimeProfile.enableExceptionDiagnostics +
            ' legacy_int2a=' + runtimeProfile.enableLegacyInt2A +
            ' gate_mode=' + runtimeProfile.gateMode
        );

        report(
            'FridaHooks',
            'ready',
            'anti_evasion_p3235 loaded; profile=' + runtimeProfile.name +
            ' role=' + runtimeProfile.processRole +
            ' arch=' + Process.arch +
            ' main=' + main.name +
            ' base=' + main.base
        );
    }
);
