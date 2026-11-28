# nMRTD

Reads **electronic passports and ID cards** (ICAO Doc 9303 eMRTDs) with contactless PC/SC readers, in .NET.

## Overview

**nMRTD** is a C# port of [JMRTD](https://jmrtd.org/), the reference Java implementation of the MRTD standards. It
opens a secure channel with the chip of a biometric passport or electronic ID card, reads its data groups, and checks
that the data is genuine and that the chip is not a copy.

> **Status:** an early-stage port. The protocols and the data model are covered by an automated test suite, but the
> library has been tried on only a few real documents. Validate it for your own use case.

## Features

* **Access control**: **BAC** keyed from the MRZ, and **PACE** keyed from the MRZ or the **CAN** (Generic, Integrated
  and Chip Authentication Mapping; DH and ECDH; 3DES and AES).
* **Secure messaging** with 3DES and AES on every command after access control.
* **Extended Access Control**: **Chip Authentication** and **Terminal Authentication** (BSI TR-03110), with Card
  Verifiable certificates.
* **Active Authentication**, to prove that the chip is not a copy.
* **Passive Authentication**: the data group hashes and the EF.SOD signature (CMS), with RSA, RSASSA-PSS and ECDSA.
* **Data groups**: EF.COM, EF.SOD, EF.CardAccess, EF.CardSecurity and DG1 to DG16 (MRZ, face, fingerprints, iris,
  personal and document details, security infos).
* **Biometrics**: ISO/IEC 19794 and ISO/IEC 39794 face, finger and iris records, in CBEFF structures.
* **Safe on malformed chip data**: invalid lengths and structures are rejected with exceptions, instead of exhausting
  memory.
* **Cross-platform smart card access** through PC/SC: WinSCard on Windows, PC/SC-lite on Linux and macOS.
* **Targets**: `.NET 10`, `.NET 8`, `.NET 6`, `.NET Framework 4.7.2` and `.NET Framework 4.6.2`.
* **AOT ready**: works in Native AOT applications on .NET 8 and 10, and supports trimming on .NET 6 and later.

## Documentation

The [README on GitHub](https://github.com/spallaro/nMRTD#readme) has code examples for BAC and PACE, the command-line
tool and the documents tested so far. [DOCUMENTATION.md](https://github.com/spallaro/nMRTD/blob/main/DOCUMENTATION.md)
describes the architecture and the protocols, and the
[release notes](https://github.com/spallaro/nMRTD/blob/main/RELEASENOTES.md) say which JMRTD and SCUBA code each
version is based on.

## License

nMRTD is a derivative work of JMRTD, by the JMRTD team, to whom all credit for the original design belongs; it is not
affiliated with or endorsed by the JMRTD project. Like JMRTD, it is distributed under the
[GNU Lesser General Public License v3](https://github.com/spallaro/nMRTD/blob/main/LICENSE).
