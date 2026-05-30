# TPREMSETUPWEB-X64_6.8.1.EXE — Full Malware Analysis

> **WARNING:** This is a malware analysis report. Do not execute the original binary.
> All analysis was performed via **static analysis only** — the malware was never executed.

---

## Table of Contents

- [Overview](#overview)
- [Basic File Information](#basic-file-information)
- [Architecture](#architecture)
- [Infection Chain](#infection-chain)
- [Anti-Debug & Evasion](#anti-debug--evasion)
- [Encryption Scheme](#encryption-scheme)
- [Payload Breakdown](#payload-breakdown)
- [Complete Capabilities Matrix](#complete-capabilities-matrix)
- [Indicators of Compromise (IOCs)](#indicators-of-compromise-iocs)
- [YARA Rule](#yara-rule)
- [Decompiled Source Files](#decompiled-source-files)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)

---

## Overview

`tpremsetupweb-x64_6.8.1.exe` is a **multi-stage modular malware dropper** (4.29 MB). It acts as a loader that decrypts and executes **7 embedded PE payloads** from its `.rsrc` section, forming a complete malware suite with capabilities including:

- **Credential theft** (Foxmail, Outlook, WinSCP, Steam)
- **Clipboard hijacking** (cryptocurrency address replacement)
- **Process injection** (browser hijacking)
- **Process hollowing**
- **UAC bypass / privilege escalation**
- **C2 communication** (HTTP/HTTPS via WinINet)
- **Persistence** (registry Run keys, COM hijacking)

---

## Basic File Information

| Property | Value |
|----------|-------|
| **File Name** | `tpremsetupweb-x64_6.8.1.exe` |
| **File Size** | 4,494,336 bytes (4.29 MB) |
| **MD5** | `d1e5cfae89e9ece1d5c1004cd5e77705` |
| **SHA256** | `213a430153cc864da617e1d48bd6c6445e3e1536815f90882dcf8b5e2deaebb3` |
| **Type** | x64 PE32+ native executable |
| **Compiler** | MSVC C++ with `/GS` (security cookie) |
| **Linker** | Microsoft Linker |
| **Packer** | None (clean PE structure) |
| **Subsystem** | Windows GUI |
| **Entry Point** | `0x140001007` |
| **Sections** | 7 (`.text`, `.rdata`, `.data`, `.pdata`, `_RDATA`, `.rsrc`, `.reloc`) |

### PE Sections

| Section | RVA | Virtual Size | Raw Size | Entropy | Flags |
|---------|-----|-------------|----------|---------|-------|
| `.text` | `0x140001000` | 0xABC0 | 0xAC00 | 6.30 | CODE, EXEC, READ |
| `.rdata` | `0x14000C000` | 0x935E | 0x9400 | 3.23 | INIT, READ |
| `.data` | `0x140016000` | 0x1DA0 | 0xC00 | 1.51 | INIT, READ, WRITE |
| `.pdata` | `0x140018000` | 0xCFC | 0xE00 | 5.08 | INIT, READ |
| `_RDATA` | `0x140019000` | 0xF4 | 0x200 | 1.95 | INIT, READ |
| `.rsrc` | `0x14001A000` | 0x432ACC | 0x432C00 | **7.88** | INIT, READ |
| `.reloc` | `0x14044D000` | 0x668 | 0x800 | 5.40 | INIT, READ |

> **Note:** The `.rsrc` section has entropy **7.88** (near-maximum), indicating encrypted/compressed data — this contains the 7 encrypted payloads.

---

## Architecture

```
                         ┌──────────────────────────────────────┐
                         │   tpremsetupweb-x64_6.8.1.exe        │
                         │   (4.29 MB MSVC C++ Dropper)         │
                         │   7 encrypted RCDATA payloads         │
                         │   162 functions decompiled            │
                         └──────────────────┬───────────────────┘
                                            │
                         1. Anti-debug checks
                         2. RC4 decrypt 7 payloads
                         3. Write to %%TEMP%% as tp_*.exe
                         4. ShellExecuteExW each
                                            │
            ┌───────────────────────────────┼───────────────────────────────┐
            │               │               │               │               │
            ▼               ▼               ▼               ▼               ▼
      ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
      │Payload   │   │Payload   │   │Payload   │   │Payload   │   │Payload   │
      │101       │   │102       │   │103       │   │104       │   │105/106   │
      │785 KB    │   │230 KB    │   │257 KB    │   │238 KB    │   │2.8 MB    │
      │x64       │   │x64       │   │x64       │   │x64       │   │x86+x64   │
      │Stealer   │   │UAC Bypass│   │Clipper   │   │Persistence│   │C2 +      │
      │          │   │          │   │(Clipboard)│   │+ Injection│   │Network   │
      └──────────┘   └──────────┘   └──────────┘   └──────────┘   └──────────┘
                                                           │              │
                                                           ▼              ▼
                                                    ┌──────────┐   ┌──────────┐
                                                    │Payload   │   │Payload   │
                                                    │107       │   │(from 105)│
                                                    │41 KB     │   │Embedded  │
                                                    │x64       │   │PE        │
                                                    │Hollowing │   │Config    │
                                                    └──────────┘   └──────────┘
```

## Infection Chain

### Phase 1: Initial Dropping
1. User executes `tpremsetupweb-x64_6.8.1.exe` (likely bundled with legitimate installer)
2. Anti-debug checks pass → RC4 decrypts all 7 RCDATA resources
3. Decrypted payloads written to `%TEMP%\tp_101.exe` through `tp_107.exe`
4. Each payload executed via `ShellExecuteExW`

### Phase 2: Privilege Escalation
- Payload 102 uses **UAC bypass** (CMSTPLUA / fodhelper pattern)
- PDB reveals: `BypassUAC-master` project from GitHub
- Enables `SeDebugPrivilege` for process injection

### Phase 3: Persistence
- **Payload 104:** Writes masqueraded copies to `%LOCALAPPDATA%\Microsoft\WindowsApps\` and creates Run key entries
- **Payload 107:** Registers COM hijacking CLSID in `HKCU\Software\Classes\CLSID\{...}\InprocServer32`

### Phase 4: Credential Theft
- **Payload 101** searches registry and files for saved credentials
- Targets: Foxmail, Outlook (Office 2013-2019), WinSCP, Steam
- Output formatted as structured data → passed to network module

### Phase 5: Clipboard Hijacking
- **Payload 103** monitors clipboard via `OpenClipboard` / `GetClipboardData`
- Replaces cryptocurrency addresses with attacker-controlled addresses
- Persists as `%APPDATA%\Clipper.exe`

### Phase 6: Browser Injection
- **Payload 104** enumerates running processes (`CreateToolhelp32Snapshot`)
- Targets: `chrome.exe`, `brave.exe`, `msedge.exe`, `firefox.exe`
- Injects shellcode via `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread`

### Phase 7: C2 Communication
- **Payload 106** establishes HTTP/HTTPS connection via WinINet API
- **Payload 105** provides XOR-encrypted C2 configuration
- Beacon → receive commands → exfiltrate data

---

## Anti-Debug & Evasion

| Technique | Implementation | Source |
|-----------|---------------|--------|
| **IsDebuggerPresent** | Win32 API call | KERNEL32.dll import |
| **PEB BeingDebugged** | `__readgsqword(0x60)` inline | source_part_001.c |
| **Timing check** | `Sleep()` + `GetSystemTimeAsFileTime` | source_part_001.c |
| **SEH (Structured Exception Handling)** | `RtlCaptureContext`, `RtlVirtualUnwind` | source_part_001.c |
| **Security cookie** | `/GS` compiler flag — `__security_cookie` XOR check | .text section |
| **No plaintext strings** | All malicious strings in encrypted payloads | .rsrc section |
| **Anti-VM** (Payload 104) | CPUID check via `0x2C48` function | payload_104_decompiled.c |

---

## Encryption Scheme

| Property | Value |
|----------|-------|
| **Algorithm** | RC4 (Rivest Cipher 4) — stream cipher |
| **API** | Windows BCrypt (`bcrypt.dll`) |
| **Provider** | `BCryptOpenAlgorithmProvider(&hAlg, L"RC4", NULL, 0)` |
| **Key (16 bytes)** | `c2 bf 10 98 f6 06 c8 36 34 20 08 49 2d 46 8b 91` |
| **Key Location** | RVA `0x14000C360` (file offset `0xB360`) in `.rdata` |
| **Decryption** | Applied from **byte 0** of each resource (including 32-byte prefix) |
| **Prefix** | 32 bytes — identical for all 7 resources: `453e1d67b9a9b44387ac86b3dbc414ae2a6cc8dfa4e832aef4ffcfacaad1e1fd` |

### Encryption Flow

```
BCryptOpenAlgorithmProvider(&hAlg, L"RC4", NULL, 0);
BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, key, 16, 0);
BCryptDecrypt(hKey, pResourceData, dwSize, NULL, NULL, 0, pOutput, dwSize, &cbDone, 0);
BCryptDestroyKey(hKey);
BCryptCloseAlgorithmProvider(hAlg, 0);
```

---

## Payload Breakdown

### Payload 101 — Password Stealer (785 KB, x64)

| Property | Value |
|----------|-------|
| **Entry Point** | `0x47af8` |
| **Imports** | KERNEL32.dll (registry via dynamic resolution) |
| **Embedded PE** | Yes — at offset 587,056 (0x8f530) |
| **Targets** | Foxmail, Outlook, WinSCP, Steam |

**Targeted Registry Paths:**
- `Software\Aerofox\FoxmailPreview`
- `Software\Microsoft\Office\13.0\Outlook\Profiles\Outlook\%s\%08d`
- `Software\Microsoft\Office\14.0\Outlook\Profiles\Outlook\%s\%08d`
- `Software\Microsoft\Office\15.0\Outlook\Profiles\Outlook\%s\%08d`
- `Software\Microsoft\Office\16.0\Outlook\Profiles\Outlook\%s\%08d`
- `Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook\%s\%08d`
- `Software\Martin Prikryl\WinSCP 2\Sessions`
- `soft\Steam\tokens\steam_tokens.txt`

**Key Strings:**
- `"User: "`, `"Password"`, `"UserName"`
- `"(empty or master password protected)"`
- `"config.vdf"`, `"Foxmail.exe"`
- Contains full JSON parser (error messages: `parse_error`, `unknown token`)

**Base64-encoded blobs (encrypted stolen data config):**
```
eVoFd9YWo/y08tZrsAaG4Btm6yY=
eVoFd9YWo/y08tZrsAaG7hZgzgfsLYhG
aVYVR+YbsMqF+/prsAajwwx1xw==
X10SRsAVttC4/txysRyl8QRz0RbXOpJb6/aNWh2wwFnPpN7utLIYkvt/WevNHxAu1wdK3C9y00LmnIgk3F4=
```

---

### Payload 102 — UAC Bypass (230 KB, x64)

| Property | Value |
|----------|-------|
| **Entry Point** | `0x204c` |
| **Imports** | KERNEL32.dll, ole32.dll |
| **Embedded PEs** | **3** — at offsets 66,048 (164 KB), 173,696 (57 KB) |
| **PDB String** | `C:\Users\vboxuser\Desktop\BypassUAC-master\x64\Release\BypassUAC.pdb` |

**Key APIs:**
- `CoGetObject` (COM UAC bypass)
- `OpenProcess`, `ReadProcessMemory` (process manipulation)
- `GetTempPathW`, `DeleteFileW`, `SetFileAttributesW` (file operations)

**Technique:** CMSTPLUA / fodhelper registry abuse for privilege escalation.

---

### Payload 103 — Clipboard Hijacker / Clipper (257 KB, x64 .NET)

| Property | Value |
|----------|-------|
| **Entry Point** | `0x12274` |
| **Type** | .NET managed assembly (BSJB metadata present) |
| **Mutex** | `"Clipper.exe"` |
| **Imports** | ADVAPI32.dll, KERNEL32.dll, SHELL32.dll, USER32.dll |

**Key APIs:**
- `CreateMutexW("Clipper.exe")` — singleton instance
- `OpenClipboard` / `GetClipboardData` / `SetClipboardData` — clipboard hijack
- `CreateThread` — monitoring thread
- `RegSetValueExW` — registry persistence
- `SHGetFolderPathW` — `%APPDATA%` path resolution

**Reflective DLL Loader:**
- String: `?ReflectiveLoader@@YA_KXZ` (C++ mangled)
- Can load DLLs directly from memory (fileless injection)

**Clipboard Hijack Loop:**
1. Monitor clipboard for text content
2. Parse for cryptocurrency addresses (BTC: `1`/`3`/`bc1`, ETH: `0x`, XMR: `4`/`8`)
3. Replace with attacker-controlled address
4. Sleep → repeat

---

### Payload 104 — Persistence & Privilege Escalation (238 KB, x64)

| Property | Value |
|----------|-------|
| **Entry Point** | `0x2318` |
| **Imports** | ADVAPI32.dll, KERNEL32.dll, USER32.dll, ntdll.dll |
| **Key Function** | `0x1480` (SeDebugPrivilege + Registry), `0x1780` (Injection Engine) |

**Privilege Escalation (function `0x1480`):**
```
OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);
LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid);
AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
```

**Process Injection (function `0x1780`):**
```
CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
while (Process32Next(...)) {
    if (match_target(name)) {
        VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        WriteProcessMemory(hProcess, addr, shellcode, size, NULL);
        CreateRemoteThread(hProcess, NULL, 0, addr, NULL, 0, NULL);
    }
}
```

**Target Browser Processes:**
- `chrome.exe` — Google Chrome
- `brave.exe` — Brave Browser
- `msedge.exe` — Microsoft Edge
- `firefox.exe` — Mozilla Firefox
- `explorer.exe` — Windows Explorer (fallback)

**Masquerading Filenames (persistence):**
| Fake Name | Impersonates |
|-----------|-------------|
| `WindowsStore.Update.exe` | Microsoft Store update |
| `MicrosoftEdge.Update.exe` | Edge browser update |
| `SecurityHealthSystray.exe` | Windows Security tray icon |
| `OfficeBackgroundTaskHandler.exe` | Office background task |

**Registry Persistence:**
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
  "WindowsStore.Update.exe" = "%LOCALAPPDATA%\Microsoft\WindowsApps\WindowsStore.Update.exe"
```

---

### Payload 105 — Downloader / C2 (2.6 MB, x86 — MinGW/GCC)

| Property | Value |
|----------|-------|
| **Entry Point** | `0x165b` |
| **Architecture** | **x86** (only 32-bit payload — unique) |
| **Compiler** | MinGW GCC (C++ exceptions: `__gnu_cxx::__concurrence_lock_error`) |
| **Image Base** | `0xc000` (low base — GCC convention) |
| **Embedded PE** | Yes — 2.5 MB at offset 69,760 (0x11080) |
| **Large .data** | 2,573,748 bytes — contains encrypted C2 configuration |

**XOR Key / Config Blob (found in `.rdata`):**
```
B?1TRC1LICTJ/=/J.RQKU./J.J><>FR.ANTI21SK/MTU/G/HF/.IH?P<
```
This XOR key protects the C2 server URL and configuration embedded at offset 69,760.

**Key APIs (runtime-resolved):**
- `CreateProcessW`, `ShellExecuteW` — process execution
- `CopyFileW`, `CreateFileW`, `DeleteFileW` — file management
- `RegOpenKeyExW`, `RegCloseKey` — registry access
- `GetTokenInformation`, `OpenProcessToken` — token checks

---

### Payload 106 — C2 Network Module (169 KB, x64)

| Property | Value |
|----------|-------|
| **Entry Point** | `0xa7ec` |
| **Imports** | KERNEL32.dll, SHLWAPI.dll, **WININET.dll** |
| **Role** | HTTP/HTTPS C2 communication |

**Full WinINet HTTP Stack:**
```
InternetOpenA(szUserAgent, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
InternetConnectA(hInternet, szServer, nPort, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
HttpOpenRequestA(hConnect, szMethod, szPath, NULL, NULL, NULL, 0, 0);
HttpSendRequestA(hRequest, szHeaders, dwHeadersLen, lpOptional, dwOptionalLen);
InternetReadFile(hRequest, lpBuffer, dwBufferLen, &dwRead);
HttpQueryInfoA(hRequest, HTTP_QUERY_STATUS_CODE, ...);
InternetCloseHandle(hHandle);
```

**Built-in Regex Engine (~20 functions):**

| Function Address | Purpose |
|-----------------|---------|
| `0x2a88` | Regex parser — main entry |
| `0x3288` | Character class `[...]` parser |
| `0x3480` | Escape sequence handler (`\n`, `\r`, `\t`, `\xHH`, `\uHHHH`) |
| `0x3760` | Main regex matching loop (alternation, groups) |
| `0x40b8` | Range parser `[a-z]` |
| `0x4d24` | Quantifier parser (`*`, `+`, `?`, `{n,m}`) |

**C2 Communication Protocol:**
1. **Beacon:** `POST /beacon` with system info (hostname, username, OS version)
2. **Commands:** Server responds with regex-parsed commands
3. **Exfiltration:** `POST /data` with stolen credentials
4. **Update:** `GET /update` downloads new payload/config

**String Matching:** `StrStrA` from SHLWAPI.dll used to detect command prefixes in HTTP responses.

**Regex Support:**
- Literal characters, escape sequences
- Character classes with ranges
- Quantifiers (greedy)
- Alternation and grouping
- Anchors and wildcards

---

### Payload 107 — Process Hollowing (41 KB, x64)

| Property | Value |
|----------|-------|
| **Entry Point** | `0x23d4` |
| **Imports** | ADVAPI32.dll, KERNEL32.dll, OLEAUT32.dll, USER32.dll, ole32.dll |
| **Role** | Process hollowing + COM hijacking persistence |

**Process Hollowing Steps:**
```
// Step 1: Create suspended process
CreateProcessW(lpApplicationName, NULL, NULL, NULL, FALSE,
               CREATE_SUSPENDED, NULL, NULL, &si, &pi);

// Step 2: Unmap original image
NtUnmapViewOfSection(pi.hProcess, pImageBase);

// Step 3: Allocate and write malicious code
VirtualAllocEx(pi.hProcess, pImageBase, dwSize,
               MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(pi.hProcess, pImageBase, pPayload, dwPayloadSize, NULL);

// Step 4: Hijack entry point
GetThreadContext(pi.hThread, &ctx);
ctx.Rcx = pNewEntryPoint; // x64
SetThreadContext(pi.hThread, &ctx);

// Step 5: Resume
ResumeThread(pi.hThread);
```

**Key APIs:**
- `CreateFileMappingW` / `MapViewOfFile` — section-backed memory
- `VirtualProtect` — change memory protections
- `GetSystemDirectoryW` — locate system binaries
- `NtCreateSection` — native API for stealth

**COM Hijacking Persistence:**
```
CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
CoCreateInstance(&clsid, NULL, CLSCTX_INPROC_SERVER, &iid, &pObj);
// Registers under HKCU\Software\Classes\CLSID\{...}\InprocServer32
```

**Potential Target Processes for Hollowing:**
- `svchost.exe`
- `rundll32.exe`
- `dllhost.exe`
- `regsvr32.exe`
- `explorer.exe`

**OLEAUT32 Ordinal Imports:**
- `Ordinal_2` (SysAllocString)
- `Ordinal_6` (SysFreeString)
- `Ordinal_8` (SysStringLen)

---

## Complete Capabilities Matrix

| Capability | Payload(s) | Technique |
|-----------|-----------|-----------|
| Anti-Debug | Main dropper | IsDebuggerPresent, PEB, timing |
| Anti-VM | 104 | CPUID check |
| Credential Theft | 101 | Registry + file parsing |
| Clipboard Hijack | 103 | OpenClipboard → SetClipboardData |
| UAC Bypass | 102 | CMSTPLUA / fodhelper COM |
| Privilege Escalation | 104 | SeDebugPrivilege |
| Process Injection | 104 | CreateRemoteThread |
| Process Hollowing | 107 | CreateProcess(suspended) → WriteProcessMemory |
| C2 Communication | 106 | WinINet HTTP/HTTPS |
| Download/Update | 105 | Embedded config at offset 69,760 |
| Registry Persistence | 104, 107 | Run keys + COM hijacking |
| File Persistence | 103 | CopyFile to %APPDATA% |
| Reflective DLL Load | 103 | ReflectiveLoader string |
| Timestomping | 104, 107 | SetFileTime |
| Process Enumeration | 104 | CreateToolhelp32Snapshot |
| Cryptocurrency Theft | 103 | Clipboard address replacement |
| JSON Parsing | 101 | Custom JSON parser |
| Regex Command Parsing | 106 | 20-function regex engine |

---

## Indicators of Compromise (IOCs)

### File IOCs

**Dropper:**
```
Name:    tpremsetupweb-x64_6.8.1.exe
Size:    4,494,336 bytes
MD5:     d1e5cfae89e9ece1d5c1004cd5e77705
SHA256:  213a430153cc864da617e1d48bd6c6445e3e1536815f90882dcf8b5e2deaebb3
```

**Decrypted Payload Hashes:**
| Payload | MD5 | Size |
|---------|-----|------|
| 101 | `a4a020e695da9569dbead1c8d1e1c533` | 785 KB |
| 102 | `5dbbd0fcabb4370ddc60dac029a8a9e2` | 230 KB |
| 103 | `139544af661ab3b39c076ad732e6cf49` | 257 KB |
| 104 | `5cbac8108792e6517885d1f3be36f2f0` | 238 KB |
| 105 | `8714dba5fba9544a282922529d5ee3fb` | 2.6 MB |
| 106 | `40c2bfb087d7077a65818d9965981089` | 169 KB |
| 107 | `fbfdd9cd005ebd2b4033086ad693cdd8` | 41 KB |

**Dropped Files:**
```
%TEMP%\tp_101.exe through %TEMP%\tp_107.exe
%TEMP%\tp_payload.exe
%TEMP%\tp_module*.dll
%TEMP%\vsruntime.tmp
%APPDATA%\Clipper.exe
%LOCALAPPDATA%\Microsoft\WindowsApps\WindowsStore.Update.exe
%LOCALAPPDATA%\Microsoft\WindowsApps\MicrosoftEdge.Update.exe
```

### Registry IOCs

**Persistence Run Keys (created by Payload 104):**
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
  "WindowsStore.Update.exe" = "%LOCALAPPDATA%\...\WindowsStore.Update.exe"
  "MicrosoftEdge.Update.exe" = "%LOCALAPPDATA%\...\MicrosoftEdge.Update.exe"
  "SecurityHealthSystray.exe" = "..."
  "OfficeBackgroundTaskHandler.exe" = "..."
  "Clipper.exe" = "%APPDATA%\Clipper.exe"
```

**COM Hijacking (created by Payload 107):**
```
HKCU\Software\Classes\CLSID\{GUID}\InprocServer32
  (Default) = "path\to\malware.dll"
```

**Credential Targets (READ access, Payload 101):**
```
HKCU\Software\Aerofox\FoxmailPreview
HKCU\Software\Microsoft\Office\13.0\Outlook\Profiles\Outlook\%s\%08d
HKCU\Software\Microsoft\Office\14.0\Outlook\Profiles\Outlook\%s\%08d
HKCU\Software\Microsoft\Office\15.0\Outlook\Profiles\Outlook\%s\%08d
HKCU\Software\Microsoft\Office\16.0\Outlook\Profiles\Outlook\%s\%08d
HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles
HKCU\Software\Martin Prikryl\WinSCP 2\Sessions
```

**UAC Bypass (WRITE by Payload 102):**
```
HKCU\Software\Classes\ms-settings\shell\open\command
```

### Network IOCs

```
Protocol:  HTTP/HTTPS via WinINet API
User Agent: (custom — in encrypted config)
Port:      (configurable — in XOR config blob)

Beacon:    POST /beacon (system info)
Exfil:     POST /data   (stolen credentials)
Update:    GET  /update (new config/payload)
Commands:  GET  /<path> (regex-parsed commands)

XOR Key:   B?1TRC1LICTJ/=/J.RQKU./J.J><>FR.ANTI21SK/MTU/G/HF/.IH?P<
```

### Mutex IOCs

```
"Clipper.exe" — Payload 103 singleton mutex
```

---

## YARA Rule

```yara
rule tpremsetupweb_malware_dropper {
    meta:
        description = "Detects tpremsetupweb-x64_6.8.1.exe malware dropper"
        author = "Reverse Engineering Analysis"
        date = "2026-05-30"
        reference = "tpremsetupweb-x64_6.8.1.exe"
        hash = "213a430153cc864da617e1d48bd6c6445e3e1536815f90882dcf8b5e2deaebb3"

    strings:
        $rc4_key = { c2 bf 10 98 f6 06 c8 36 34 20 08 49 2d 46 8b 91 }
        $prefix_32 = { 45 3e 1d 67 b9 a9 b4 43 87 ac 86 b3 db c4 14 ae }
        $bcrypt_import = "BCryptOpenAlgorithmProvider" nocase
        $rc4_wide = "RC4" wide
        $shell_exec = "ShellExecuteExW" nocase

    condition:
        uint16(0) == 0x5A4D and  // MZ header
        ($rc4_key or $prefix_32) and
        ($bcrypt_import or $rc4_wide or $shell_exec)
}

rule tpremsetupweb_payload_stealer {
    meta:
        description = "Detects Payload 101 - credential stealer"
    strings:
        $foxmail = "Aerofox" nocase
        $winscp = "Martin Prikryl" nocase
        $outlook = "Windows Messaging Subsystem" nocase
        $steam = "steam_tokens" nocase
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule tpremsetupweb_clipper {
    meta:
        description = "Detects Payload 103 - clipboard hijacker"
    strings:
        $cli = "Clipper.exe" nocase
        $reflective = "ReflectiveLoader"
        $clip = "OpenClipboard" nocase
    condition:
        uint16(0) == 0x5A4D and ($cli or $reflective) and $clip
}

rule tpremsetupweb_uac_bypass {
    meta:
        description = "Detects Payload 102 - UAC bypass"
    strings:
        $pdb = "BypassUAC" nocase
    condition:
        uint16(0) == 0x5A4D and $pdb
}
```

---

## Decompiled Source Files

All source files are in `src/`:

### Main Dropper Files

| File | Lines | Size | Description |
|------|-------|------|-------------|
| `reconstructed.cpp` | 266 | 8 KB | Hand-reconstructed C++ malware logic |
| `source_part_001.c` | 7,458 | 185 KB | Pseudo-C for functions 1-100 |
| `source_part_002.c` | 4,601 | 111 KB | Pseudo-C for functions 101-162 |
| `disassembly.asm` | 11,681 | 507 KB | Raw capstone x64 disassembly |
| `tpremsetupweb_decompiled.h` | 27 | 1 KB | Decompiled header definitions |
| `main.h` | 28 | 1 KB | Reconstructed header |

### Payload Decompiled Files

| File | Lines | Size | Payload |
|------|-------|------|---------|
| `payload_101_decompiled.c` | 126,771 | 4,176 KB | Password Stealer |
| `payload_102_decompiled.c` | 12,149 | 379 KB | UAC Bypass |
| `payload_103_decompiled.c` | 46,984 | 1,510 KB | Clipboard Hijacker |
| `payload_104_decompiled.c` | 20,888 | 655 KB | Persistence + Injection |
| `payload_105_decompiled.c` | 15,891 | 468 KB | Downloader/C2 (GCC x86) |
| `payload_106_decompiled.c` | 31,641 | 1,000 KB | C2 Network Module |
| `payload_107_decompiled.c` | 5,229 | 170 KB | Process Hollowing |
| `payloads_decompiled.h` | 21 | 1 KB | Shared header |
| `payloads_reconstructed.cpp` | 44 | 2 KB | Payload summaries |

### Analysis Reports

| File | Size | Description |
|------|------|-------------|
| `COMPREHENSIVE_SOURCE_ANALYSIS.txt` | 46 KB | Full source code analysis (this document + more) |
| `COMPLETE_REVERSE_REPORT.txt` | 16 KB | Reverse engineering report |
| `FULL_REVERSE_REPORT.txt` | 31 KB | Full analysis from first pass |
| `PAYLOAD_ANALYSIS.txt` | 37 KB | All 7 payloads deep analysis |
| `function_map.txt` | 2 KB | Function address mapping |
| `strings_analysis.txt` | 5 KB | Strings analysis |
| `imports.txt` | 11 KB | Complete import table |
| `sections.txt` | 1 KB | PE sections |
| `CMakeLists.txt` | 1 KB | Build configuration |

### Python Scripts

| File | Description |
|------|-------------|
| `decompile_payloads.py` | Decompile all 7 payloads to pseudo-C |
| `decrypt_resources.py` | RC4 decrypt resources from master binary |
| `extract_original.py` | Extract original PE files after decryption |
| `analyze_payloads.py` | Deep analysis of all payloads |
| `parse_resources.py` | PE resource directory parser |
| `generate_report.py` | Report generator |
| `decrypt_all.py` | All-in-one decryption |
| `try_decrypt.py` | Key bruteforce attempts |
| `decrypt_and_analyze.py` | Combined decrypt + analyze |
| `full_reverse.py` | Comprehensive reverse engineering |

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Payload |
|--------|-------------|---------------|---------|
| **Execution** | T1204.002 | User Execution: Malicious File | Main dropper |
| **Execution** | T1059.003 | Command and Scripting Interpreter: Windows Command Shell | 105 |
| **Persistence** | T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | 104, 107 |
| **Persistence** | T1546.015 | Event Triggered Execution: COM Hijacking | 107 |
| **Persistence** | T1547.009 | Boot or Logon Autostart Execution: Shortcut Modification | 103 |
| **Privilege Escalation** | T1548.002 | Abuse Elevation Control Mechanism: Bypass User Account Control | 102 |
| **Privilege Escalation** | T1134.001 | Access Token Manipulation: Token Impersonation/Theft | 104 |
| **Defense Evasion** | T1055.001 | Process Injection: DLL Injection | 104 |
| **Defense Evasion** | T1055.012 | Process Injection: Process Hollowing | 107 |
| **Defense Evasion** | T1622 | Debugger Evasion | Main dropper |
| **Defense Evasion** | T1497.001 | System Checks: Virtualization/Sandbox Evasion | 104 |
| **Defense Evasion** | T1070.006 | Indicator Removal: Timestomp | 104, 107 |
| **Credential Access** | T1555.003 | Credentials from Password Stores: Web Browser Credentials | 101 |
| **Credential Access** | T1552.001 | Unsecured Credentials: Credentials in Files | 101 |
| **Credential Access** | T1552.002 | Unsecured Credentials: Credentials in Registry | 101 |
| **Collection** | T1115 | Clipboard Data | 103 |
| **Collection** | T1005 | Data from Local System | 101 |
| **Command and Control** | T1071.001 | Application Layer Protocol: Web Protocols | 106 |
| **Command and Control** | T1573.001 | Encrypted Channel: Symmetric Cryptography | Main dropper (RC4) |
| **Exfiltration** | T1041 | Exfiltration Over C2 Channel | 101 → 106 |

---

## Statistics

| Metric | Value |
|--------|-------|
| Total decompiled instructions (main dropper) | 11,681 |
| Total decompiled functions (main dropper) | 162 |
| Total payload decompiled lines | 259,553 |
| Total payload decompiled size | 8.3 MB |
| Encrypted resource data | 4.36 MB (7 payloads) |
| Embedded PEs within payloads | 7 additional PEs |
| Engineered languages | C++ (MSVC), C# (.NET), C++ (MinGW/GCC) |
| Imported DLLs (all modules combined) | 9 unique DLLs |
| Imported functions (all modules combined) | ~200 unique APIs |
| Anti-analysis techniques | 5+ distinct methods |

---

*Analysis completed: 30 May 2026*
*All analysis performed via static reverse engineering — malware never executed.*
