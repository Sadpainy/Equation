# Equation.cpp

## What This Is

A complete, modular post‑exploitation framework. It implements persistence, plugin loading, encrypted C2 communication, and payload execution across multiple Windows subsystems.

This is not a proof‑of‑concept. It is not a simulation. Every component — from the anti‑analysis checks to the AES‑256‑GCM channel to the physical memory interface — is fully implemented and functional.

It compiles. It runs. It does what it says.

## What This Is Not

This is not derived from any leaked, reverse‑engineered, or proprietary source. All code was written from scratch based solely on public documentation and long‑established operating system interfaces.

No classified material, government‑owned code, or intelligence agency work product was used in the creation of this file.

## Capabilities

- Runtime plugin architecture with dynamic load/unload
- Multiple persistence mechanisms: Run keys, Services, WMI, Task Scheduler, IFEO
- Environmental awareness: anti‑debug, anti‑VM, anti‑sandbox, anti‑AV, anti‑dump
- AES‑256‑GCM encrypted C2 over HTTPS and DNS
- Physical memory access via kernel driver (IOCTL‑based)
- MSR and control register read/write
- Firmware‑level persistence via MBR and UEFI manipulation
- Payload execution engine supporting multiple payload types

## Supported Environment

- Microsoft Windows (x86/x64)
- Requires administrative privileges for certain operations
- Windows SDK and WDK for build

## Build
cl /O2 /Oi /GL /GS- /sdl- /MT /EHsc- /GR- /DYNAMICBASE:NO /NXCOMPAT eqdrug.cpp ws2_32.lib advapi32.lib user32.lib bcrypt.lib winhttp.lib wbemuuid.lib taskschd.lib ole32.lib oleaut32.lib shell32.lib

## Copyright

Copyright © 2026 Sadpainy.

This work is an independent, original implementation. All rights reserved.

## Disclaimer

This software is provided as‑is. The author makes no warranties regarding its functionality, accuracy, or suitability for any purpose.

The user assumes full responsibility for any use, deployment, or consequences arising from this software.

Compliance with all applicable laws, including but not limited to export control, sanctions, and criminal statutes, is solely the responsibility of the user.

## License

AGPL‑3.0. See the `LICENSE` file.
