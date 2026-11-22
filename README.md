# nMRTD

[![NuGet version](https://img.shields.io/nuget/v/nMRTD.svg)](https://www.nuget.org/packages/nMRTD/)
<picture><img alt="Target Framework" src="https://img.shields.io/badge/.NET-6%20|%208%20|%2010-white"></picture>
<picture><img alt="Native AOT" src="https://img.shields.io/badge/.NET%20AOT-8%20|%2010-white"></picture>
[![License: LGPL v3](https://img.shields.io/badge/License-LGPL%20v3-white.svg)](https://opensource.org/license/lgpl-3-0)

> **Status:** THIS IS AN EARLY-STAGE PORT: the core protocol stack (BAC, PACE, EAC, Active/Passive Authentication) and the LDS/biometric data model are implemented and build cleanly, but the library has not yet been exercised against a broad range of real-world documents and its automated test suite is still small. Treat it as a foundation to build on and validate for your own use case, not as a production-hardened SDK yet.

> **Please note:** this project is AI-assisted.

**nMRTD** is a .NET 6/8/10 library for reading electronic Machine Readable Travel Documents (eMRTDs) — biometric passports, electronic ID cards, and similar ICAO-compliant documents — over NFC/contactless smart card readers, implementing the [ICAO Doc 9303](https://www.icao.int/publications/doc-series/doc-9303) specification.

It is a from-scratch **C# port of [JMRTD](https://jmrtd.org/)**, the reference Java implementation of the MRTD standards, targeting **.NET 6/8/10**, **Native AOT** (.NET 8 and 10), and cross-platform smart card access (Windows, Linux, macOS) via PC/SC.

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

## Command-line tool (nMRTD.Cli)

The repository includes `nMRTD.Cli`, a console application that reads a document end to end with
nMRTD. It is a sample and a test tool: it is not part of the NuGet package. It needs a
**contactless (NFC) PC/SC reader**; contact-only smart card readers and phones are not supported.

For each document it:

1. opens the reader and authenticates with **PACE** (using EF.CardAccess), falling back to **BAC**
   when the document does not support PACE (or uses BAC directly with `--bac`);
2. reads every standard data group except DG3 and DG4 (fingerprints and iris need Terminal
   Authentication), printing a summary and a hex dump of each, and saves the images (DG2, DG5–DG7);
3. performs **Passive Authentication**: checks each data group hash against EF.SOD and verifies the
   EF.SOD signature (RSA, RSASSA-PSS, ECDSA) with the document signer certificate it contains;
4. performs **Chip Authentication** when DG14 offers it, and checks it by reading EF.COM with the new
   session keys.

Run it from the repository root:

```bash
# List the PC/SC readers
dotnet run --project nMRTD.Cli -f net10.0 -- --list-readers

# Card Access Number (PACE only)
dotnet run --project nMRTD.Cli -f net10.0 -- --can 123456 --out ./out

# MRZ access key: document number (without check digit), date of birth and date of expiry (yyMMdd)
dotnet run --project nMRTD.Cli -f net10.0 -- --doc L898902C3 --dob 740812 --doe 120415 --out ./out

# Same, skipping PACE and using BAC
dotnet run --project nMRTD.Cli -f net10.0 -- --doc L898902C3 --dob 740812 --doe 120415 --bac --out ./out
```

| Option | Meaning |
|---|---|
| `--can <CAN>` | Card Access Number (PACE only; cannot be used for BAC) |
| `--doc <number>` `--dob <yyMMdd>` `--doe <yyMMdd>` | MRZ access key; `--can` and the MRZ options are alternatives |
| `--bac` | Skip PACE and use BAC with the MRZ access key |
| `--reader <name>` | PC/SC reader to use (default: the first one found) |
| `--out <dir>` | Folder for the extracted images (default: the current folder) |
| `--verbose` | Print the APDU exchanges and protocol steps to stderr |
| `--list-readers` | List the PC/SC readers and exit |
| `-h`, `--help` | Show the help |

Without `--can` or the MRZ options, the tool asks which access key to use. The exit code is `0` on
success, `1` for invalid arguments (or a CAN on a document without PACE) and `2` for a card
communication error.

> **Personal data:** the output, the `--verbose` trace and the images saved to `--out` contain the
> holder's personal data and photo. Use `--out` to write the images outside the repository, and do not
> share the output or traces unredacted.

The tool also publishes as a Native AOT executable for `net8.0` and `net10.0`:

```bash
dotnet publish nMRTD.Cli -c Release -f net10.0 -r win-x64
```

## Tested documents

Results of reading real documents with `nMRTD.Cli` (nMRTD 0.8.0-alpha, Windows, REINER SCT
cyberJack RFID basis reader), as a JIT build and as a Native AOT executable.

| Document | BAC | PACE | Passive Authentication | Chip Authentication | LDS |
|---|---|---|---|---|---|
| Italian identity card (CIE 3.0) | ✅ MRZ | ✅ CAN; DH, Generic Mapping, 3DES (`id-PACE-DH-GM-3DES-CBC-CBC`) | ✅ SHA-512 hashes; RSASSA-PSS SHA-512 signature | ✅ DH 2048-bit, 3DES (`id-CA-DH-3DES-CBC-CBC`) | 1.8 |
| Italian passport | ✅ MRZ | n.a. | ✅ SHA-1 hashes; SHA1withRSA signature | ✅ DH 1024-bit, 3DES (`id-CA-DH-3DES-CBC-CBC`) | 1.7 |

These two documents do not cover:

- PACE and Chip Authentication with elliptic curves or AES;
- Active Authentication (neither document has DG15);
- Terminal Authentication, which needs terminal certificates issued by a national document
  verifier to read the fingerprints (DG3).

Passive Authentication here checks the document signature with the signer certificate stored in
EF.SOD; it does not validate that certificate against the issuing country's CSCA.

> ***Please help extend this table.*** *If you read another document with `nMRTD.Cli` (another country,
> another document type, or the same document with a different access method), please
> [open an issue](https://github.com/spallaro/nMRTD/issues) with the document type and issuing
> country, the reader and operating system, and the BAC, PACE, Passive Authentication and Chip
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
