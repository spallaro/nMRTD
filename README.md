# nMRTD

[![NuGet version](https://img.shields.io/nuget/v/nMRTD.svg)](https://www.nuget.org/packages/nMRTD/)
[![Target Framework](https://img.shields.io/badge/.NET-6%20|%208%20|%2010-white)](https://dotnet.microsoft.com/platform/support/policy/dotnet-core)
[![Native AOT](https://img.shields.io/badge/.NET%20AOT-8%20|%2010-white)](https://learn.microsoft.com/dotnet/core/deploying/native-aot/)
[![License: LGPL v3](https://img.shields.io/badge/License-LGPL%20v3-white.svg)](https://opensource.org/license/lgpl-3-0)

> **Status:** THIS IS AN EARLY-STAGE PORT: the core protocol stack (BAC, PACE, EAC, Active/Passive Authentication) and the LDS/biometric data model are implemented and covered by an automated test suite (the ported JMRTD tests, unit tests and end-to-end tests against a simulated chip), but the library has been exercised against only a few real-world documents (see [Tested documents](#tested-documents)). Treat it as a foundation to build on and validate for your own use case, not as a production-hardened SDK yet.

> **Please note:** this project is AI-assisted.

**nMRTD** is a .NET 6/8/10 library for reading electronic Machine Readable Travel Documents (eMRTDs) — biometric passports, electronic ID cards, and similar ICAO-compliant documents — over NFC/contactless smart card readers, implementing the [ICAO Doc 9303](https://www.icao.int/publications/doc-series/doc-9303) specification.

It is a from-scratch **C# port of [JMRTD](https://jmrtd.org/)**, the reference Java implementation of the MRTD standards, targeting **.NET 6/8/10**, **Native AOT** (.NET 8 and 10), and cross-platform smart card access (Windows, Linux, macOS) via PC/SC.

## Contents

- [Features](#features)
- [Installation](#installation)
- [Quick start](#quick-start)
  - [Reading a document with BAC](#reading-a-document-with-bac)
  - [Authenticating with PACE, via MRZ or CAN](#authenticating-with-pace-via-mrz-or-can)
- [Documentation](#documentation)
- [Command-line tool (nMRTD.Cli)](#command-line-tool-nmrtdcli)
- [Tested documents](#tested-documents)
- [Tests](#tests)
- [License](#license)

## Features

- **Smart card access layer** — a `CardService` abstraction (command/response APDUs, file system, TLV utilities) with a cross-platform PC/SC implementation (`PCSC` / `PCSC.Iso7816`) working over WinSCard on Windows and PC/SC-lite on Linux/macOS.
- **Access-control and secure-messaging protocols**:
  - **BAC** (Basic Access Control), keyed from the MRZ.
  - **PACE** (Password Authenticated Connection Establishment), keyed either from the **MRZ** or from the document's **CAN** (Card Access Number).
  - **EAC** (Extended Access Control): Chip Authentication and Terminal Authentication (BSI TR-03110), including Card Verifiable (CV) certificate parsing/building.
  - **Active Authentication**.
  - **Secure Messaging** (DESede and AES) wrapping every subsequent APDU exchange.
- **LDS (Logical Data Structure) parsing** — EF.COM, EF.SOD, and data groups DG1 through DG16 (MRZ, facial/fingerprint/iris images, additional personal/document details, security infos, and more), plus **Passive Authentication**: verifying each data group's hash and the EF.SOD's CMS/PKCS#7 signature.
- **Biometric data models** for both **ISO/IEC 19794** (face/finger/iris, the common case) and the newer **ISO/IEC 39794** standard, wrapped per **CBEFF** (ISO/IEC 7816-11).
- **Native AOT and trimming friendly**, with no reflection-based dispatch or serialization — built to publish as a self-contained native executable on any of the supported platforms.

## Installation

Add the package to your .NET project:

```bash
dotnet add package nMRTD
```

or reference it directly in your `.csproj`:

```xml
<ItemGroup>
  <PackageReference Include="nMRTD" />
</ItemGroup>
```

nMRTD targets **.NET 6/8/10** and depends on the following transitive dependencies:
- [`BouncyCastle.Cryptography`](https://www.nuget.org/packages/BouncyCastle.Cryptography) (crypto/ASN.1)
- [`PCSC`](https://www.nuget.org/packages/PCSC)
- [`PCSC.Iso7816`](https://www.nuget.org/packages/PCSC.Iso7816) (smart card access)

## Quick start

### Reading a document with BAC

```csharp
using nMRTD;
using nMRTD.Lds.Icao;
using nMRTD.SmartCards;

// Connect to the first available PC/SC reader.
var cardService = new PcscCardService();
var passportService = new PassportService(
    cardService,
    PassportService.NormalMaxTransceiveLength,
    PassportService.DefaultMaxBlocksize,
    isSfiEnabled: true,
    shouldCheckMac: true);

passportService.Open();

// Authenticate with Basic Access Control, keyed from the printed MRZ.
var bacKey = new BacKey(
    documentNumber: "L898902C3",
    dateOfBirth: "740812",   // yyMMdd
    dateOfExpiry: "120415"); // yyMMdd

passportService.SendSelectApplet(false);
passportService.DoBAC(bacKey);

// Read and parse EF.DG1 (the MRZ).
using Stream dg1Stream = passportService.GetInputStream(PassportService.EF_DG1);
var dg1 = new DG1File(dg1Stream);
Console.WriteLine($"Document number: {dg1.GetMRZInfo().GetDocumentNumber()}");

// Read and parse EF.DG2 (the facial image).
using Stream dg2Stream = passportService.GetInputStream(PassportService.EF_DG2);
var dg2 = new DG2File(dg2Stream);

passportService.Close();
```

### Authenticating with PACE, via MRZ or CAN

Most current documents advertise PACE support in `EF.CardAccess`; prefer it over BAC when available:

```csharp
using nMRTD;
using nMRTD.Lds;
using nMRTD.SmartCards;

using Stream cardAccessStream = passportService.GetInputStream(PassportService.EF_CARD_ACCESS);
var cardAccessFile = new CardAccessFile(cardAccessStream);
PACEInfo paceInfo = cardAccessFile.GetSecurityInfos().OfType<PACEInfo>().First();

var parameterId = paceInfo.GetParameterId()!;
object staticParameters = PACEInfo.ToParameterSpec(parameterId);

// Option A -- derive the PACE key from the MRZ, same details as for BAC:
IAccessKeySpec paceKey = PaceKeySpec.CreateMrzKey(
    new BacKey("L898902C3", "740812", "120415"));

// Option B -- derive the PACE key from the Card Access Number printed on the
// document instead. A CAN can *only* be used for PACE, never for BAC.
// IAccessKeySpec paceKey = PaceKeySpec.CreateCanKey("500540");

passportService.DoPace(paceKey, paceInfo.GetObjectIdentifier(), staticParameters, parameterId);
passportService.SendSelectApplet(true);

// From here on, read DG1/DG2/... exactly as in the BAC example above.
```

For a complete, runnable example covering reader selection, PACE-with-BAC-fallback, DG1/DG2 parsing, full Passive Authentication (EF.SOD hash and signature verification) and Chip Authentication, see the [command-line tool](#command-line-tool-nmrtdcli) and its source, [`nMRTD.Cli/Program.cs`](https://github.com/spallaro/nMRTD/blob/main/nMRTD.Cli/Program.cs).

## Documentation

[DOCUMENTATION.md](DOCUMENTATION.md) is the technical documentation: the architecture (card service,
file system, secure messaging, `PassportService` API), the access control protocols (BAC, PACE, Chip
and Terminal Authentication, Active Authentication), the LDS data groups and the biometric data
model, Passive Authentication, and Native AOT and trimming.

## Command-line tool (nMRTD.Cli)

The repository includes `nMRTD.Cli`, a console application that reads a document end to end with
nMRTD, through a **contactless (NFC) PC/SC reader**. It is a sample and a test tool: it is not part of
the NuGet package. It authenticates with PACE (falling back to BAC), reads the data groups and saves
the images, and runs Passive Authentication (optionally checking the Document Signer against trusted
CSCA certificates), Chip Authentication and Active Authentication. It exits with code 4 when a
security check fails, and can write its results as JSON.

```bash
dotnet run --project nMRTD.Cli -f net10.0 -- --can 123456 --out ./out
dotnet run --project nMRTD.Cli -f net10.0 -- --doc L898902C3 --dob 740812 --doe 120415 --csca ./csca --json > result.json
```

**[CLI.md](CLI.md)** documents the options, each step, the exit codes, the JSON output, Native AOT
publishing and troubleshooting.

> **Personal data:** the output, the JSON, the `--verbose` trace and the saved images contain the
> holder's personal data and photo. Do not share them unredacted.

## Tested documents

Results of reading real documents with `nMRTD.Cli` (nMRTD 0.8.0-alpha, Windows, REINER SCT
cyberJack RFID basis reader), as a JIT build and as a Native AOT executable.

| Document | BAC | PACE | Passive Authentication | Chip Authentication | Active Authentication | LDS |
|---|---|---|---|---|---|---|
| Italian identity card (CIE 3.0) | ✅ MRZ | ✅ CAN; DH, Generic Mapping, 3DES (`id-PACE-DH-GM-3DES-CBC-CBC`) | ✅ SHA-512 hashes; RSASSA-PSS SHA-512 signature | ✅ DH 2048-bit, 3DES (`id-CA-DH-3DES-CBC-CBC`) | n.a. | 1.8 |
| Italian passport | ✅ MRZ | n.a. | ✅ SHA-1 hashes; SHA1withRSA signature | ✅ DH 1024-bit, 3DES (`id-CA-DH-3DES-CBC-CBC`) | n.a. | 1.7 |

These two documents do not cover:

- PACE and Chip Authentication with elliptic curves or AES;
- Active Authentication (neither document has DG15);
- Terminal Authentication, which needs terminal certificates issued by a national document
  verifier to read the fingerprints (DG3).

Passive Authentication here checks the document signature with the signer certificate stored in
EF.SOD; these results predate `--csca`, so that certificate was not validated against the issuing
country's CSCA.

> ***Please help extend this table.*** *If you read another document with `nMRTD.Cli` (another country,
> another document type, or the same document with a different access method), please
> [open an issue](https://github.com/spallaro/nMRTD/issues) with the document type and issuing
> country, the reader and operating system, and the BAC, PACE, Passive, Chip and Active
> Authentication lines of the output, including any error. Leave out names, document numbers, dates,
> photos and hex dumps: the protocol and algorithm lines are all that is needed.*

## Tests

```
dotnet test nMRTD.sln
dotnet test nMRTD.sln --collect:"XPlat Code Coverage"
```

The tests run on all three target frameworks. With `--collect`, coverlet writes a
`coverage.opencover.xml` for each framework under `nMRTD.Tests/TestResults/` (the format is set in
[`nMRTD.Tests/coverage.runsettings`](https://github.com/spallaro/nMRTD/blob/main/nMRTD.Tests/coverage.runsettings)).

## License

nMRTD is a derivative work: a from-scratch C# port of [**JMRTD**](https://jmrtd.org/), originally written in Java by [**the JMRTD team**](https://jmrtd.org/about.shtml). All credit for the original design, protocol implementation, and years of ICAO 9303 domain expertise belongs to them; this project would not exist without their work. nMRTD is not affiliated with or endorsed by the JMRTD project.

Like its upstream, nMRTD is distributed under the terms of the **GNU Lesser General Public License v3 (LGPL-3.0)**. See the [`LICENSE`](https://github.com/spallaro/nMRTD/blob/main/LICENSE) file for the full license text.
