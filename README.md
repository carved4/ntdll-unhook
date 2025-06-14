# Go NTDLL Unhooking

## Overview

This project is a demonstration in Go of unhooking `ntdll.dll` at runtime. It programmatically removes in-memory API hooks that may have been placed by security software.

## Technique

The program implements the "Known Dlls" unhooking technique:

1.  The base address of the currently loaded (and potentially hooked) `ntdll.dll` is found by parsing the Process Environment Block (PEB).
2.  A handle to a clean, on-disk version of `ntdll.dll` is obtained by opening the `\KnownDlls\ntdll.dll` section object.
3.  This clean section is mapped into the process memory.
4.  The `.text` section, which contains the executable code, is located in both the hooked and clean versions of the DLL.
5.  The memory protections of the hooked `.text` section are changed to be writable.
6.  The bytes from the clean `.text` section are copied over the hooked one, effectively removing the hooks.
7.  The original memory protections are restored.

## Relevance to Malware Development

This technique is a cornerstone of defense evasion. Endpoint Detection and Response (EDR) and antivirus solutions place user-land hooks on `ntdll.dll` functions to monitor for malicious activity. By removing these hooks, a payload can execute sensitive API calls (e.g., for process injection, credential theft, or file manipulation) without being detected by the monitoring agent. This allows malware to operate stealthily.

## Usage

```bash
go build cmd/main.go
./cmd.exe
```

## Disclaimer

This code is intended for educational and research purposes only. 