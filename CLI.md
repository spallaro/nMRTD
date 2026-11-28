# nMRTD.Cli — Command-line tool

`nMRTD.Cli` reads an electronic travel document (ePassport, electronic ID card) end to end with the
nMRTD library: it authenticates, reads the data groups, and runs every check the library supports
(Passive, Chip and Active Authentication, and optionally the Document Signer against trusted CSCAs).
It is both a test tool and a way to verify documents, and its result is meant to be read by people and
by programs (text, JSON or XML, and an exit code for each problem). It is **not** part of the NuGet
package.

## Contents

- [Requirements](#requirements)
- [Running it](#running-it)
- [Options](#options)
- [What it does](#what-it-does)
  - [1. Access control: PACE or BAC](#1-access-control-pace-or-bac)
  - [2. Data groups](#2-data-groups)
  - [3. Passive Authentication](#3-passive-authentication)
  - [4. Document Signer against trusted CSCAs (--csca)](#4-document-signer-against-trusted-cscas---csca)
  - [5. Chip Authentication](#5-chip-authentication)
  - [6. Active Authentication](#6-active-authentication)
  - [7. Failed checks](#7-failed-checks)
- [Exit codes](#exit-codes)
- [Output](#output)
  - [Text](#text)
  - [JSON (--output-json)](#json---output-json)
  - [XML (--output-xml)](#xml---output-xml)
  - [Fields](#fields)
  - [Data group information (--include-information)](#data-group-information---include-information)
  - [Raw data groups (--include-raw)](#raw-data-groups---include-raw)
- [Sharing a result (--share)](#sharing-a-result---share)
- [Verbose mode (--verbose)](#verbose-mode---verbose)
- [Personal data](#personal-data)
- [Native AOT](#native-aot)
- [Troubleshooting](#troubleshooting)
- [Code layout](#code-layout)

## Requirements

- A **contactless (NFC) PC/SC reader**. Contact-only smart card readers and phones are not supported.
- On Windows the PC/SC service is built in; on Linux and macOS install PC/SC-lite (`pcscd`).
- The .NET SDK (6, 8 or 10) to run it from source, or a Native AOT build (see [Native AOT](#native-aot)).

## Running it

From the repository root:

```bash
# List the PC/SC readers
dotnet run --project nMRTD.Cli -f net10.0 -- --list-readers

# Card Access Number (PACE)
dotnet run --project nMRTD.Cli -f net10.0 -- --can 123456

# MRZ access key: document number (without check digit), date of birth and date of expiry (yyMMdd)
dotnet run --project nMRTD.Cli -f net10.0 -- --doc L898902C3 --dob 740812 --doe 120415

# Same, with BAC only
dotnet run --project nMRTD.Cli -f net10.0 -- --doc L898902C3 --dob 740812 --doe 120415 --bac

# Check the Document Signer against trusted CSCA certificates, with the result as JSON
dotnet run --project nMRTD.Cli -f net10.0 -- --can 123456 --csca ./csca --output-json > result.json

# Everything the document holds, parsed, images included, as XML
dotnet run --project nMRTD.Cli -f net10.0 -- --can 123456 --include-information --output-xml > result.xml

# A result without personal data, to share
dotnet run --project nMRTD.Cli -f net10.0 -- --can 123456 --include-information --share --output-json
```

`dotnet run` may print build messages to stdout; to capture the result alone, run the built executable
(`nMRTD.Cli/bin/...`) or a [Native AOT](#native-aot) build.

The result is written in UTF-8. In Windows PowerShell 5.1, `>` re-encodes the output (as UTF-16, and
characters outside ASCII through the console code page); to keep the bytes, redirect in `cmd`
(`cmd /c "nMRTD.Cli.exe --can 123456 --output-json > result.json"`) or use PowerShell 7.

The access key is always given on the command line: the tool never prompts.

## Options

| Option | Meaning |
|---|---|
| `--can <CAN>` | Card Access Number: the access key for PACE. It cannot be used for BAC. |
| `--doc <number>` | Document number, without the check digit (MRZ access key). |
| `--dob <yyMMdd>` | Date of birth of the holder (MRZ access key). |
| `--doe <yyMMdd>` | Date of expiry of the document (MRZ access key). |
| `--pace` | Use PACE only: fail if the document does not offer it. |
| `--bac` | Use BAC only, even if the document offers PACE. Needs the MRZ access key. |
| `--reader <name>` | PC/SC reader to use (default: the first one found). |
| `--list-readers` | List the PC/SC readers and exit. |
| `--csca <path>` | Trusted CSCA certificates: a `.cer`, `.crt`, `.der` or `.pem` file (DER or PEM, one or more certificates), an ICAO master list (`.ml`), or a folder of them. |
| `--skip-passive-authentication` | Do not read EF.SOD: no data group hash and no signature is checked. |
| `--output-json` | Write the result as JSON. |
| `--output-xml` | Write the result as XML. |
| `--include-information` | Add the parsed information of each data group, images in Base64. |
| `--include-raw` | Add each data group's bytes in Base64. |
| `--share` | Leave out everything that identifies the holder or the document, to share the result. |
| `--verbose` | Print the progress and the APDU exchanges to stderr. |
| `-h`, `--help` | Show the help. |

Without `--output-json` or `--output-xml` the result is human readable text.

- `--can` and the MRZ options (`--doc`, `--dob`, `--doe`) are alternatives; the three MRZ options go
  together.
- Without `--pace` or `--bac`, the tool uses PACE and falls back to BAC when the document has no PACE
  (see [Access control](#1-access-control-pace-or-bac)).
- These combinations are rejected (exit code `-1`): `--output-json` with `--output-xml`, `--pace` with
  `--bac`, `--bac` with `--can`, `--can` with an MRZ option, `--share` with `--include-raw` (the raw data
  groups hold all the personal data), `--skip-passive-authentication` with `--csca` (the Document Signer
  certificate is in EF.SOD).
- `--help` and `--list-readers` need no access key; any other run without one ends with exit code `-2`.

## What it does

### 1. Access control: PACE or BAC

The tool reads the card's ATR, then EF.CardAccess. If it has a `PACEInfo`, the tool performs **PACE**
with the access key given (CAN or MRZ):

- standardized domain parameters (parameter id 0 to 31) are used directly;
- explicit domain parameters are taken from the matching `PACEDomainParameterInfo` (a proprietary
  parameter id, 32 and up, or no parameter id).

| Mode | Behavior |
|---|---|
| default | PACE; when the document has no EF.CardAccess (or a malformed one) or no `PACEInfo`, or the parameters cannot be resolved, BAC with the MRZ access key. A CAN has no fallback (exit code `-20`). |
| `--pace` | PACE only: a document without PACE ends with exit code `-20`. |
| `--bac` | BAC only, straight away. |

A rejected access key ends with exit code `-21` (PACE) or `-22` (BAC).

### 2. Data groups

Every standard data group is read, except **DG3** (fingerprints) and **DG4** (iris), which need
Terminal Authentication with an inspection system certificate. For each data group the result says
whether it is present, its length and its hash check; with `--include-information` and
`--include-raw`, also its content (see [Output](#output)). A data group is not present when the chip answers its
SELECT or READ BINARY with an error status word (6A82, file not found); a read that fails otherwise
(no answer, a wrong MAC, the card removed, also in the middle of the file) ends with exit code `-30`.

### 3. Passive Authentication

The tool reads EF.SOD and checks:

1. **Data group hashes:** the hash of every data group read is compared with the hash signed in
   EF.SOD (`match` or `mismatch`). A data group without a hash in EF.SOD (`not-in-sod`) is not a
   failure: some documents have data groups that EF.SOD does not cover.
2. **Signed content:** the content of EF.SOD must match the message digest in its signed attributes.
3. **Signature:** the EF.SOD signature is verified with the Document Signer certificate stored in
   EF.SOD. RSA (PKCS #1 v1.5), RSASSA-PSS (hash, mask generation hash and salt length taken from the
   signature parameters) and ECDSA are supported.

A malformed EF.SOD (one that cannot be parsed) fails Passive Authentication: the signature is
`invalid` (exit code `-41`) with the reason in `error`, and the data group hashes are not checked.

Without `--csca` this proves that the data is unchanged and consistent with EF.SOD, but not that EF.SOD
was signed by the issuing country: anyone can produce a self-signed Document Signer certificate.

`--skip-passive-authentication` skips this step: the data group hashes are `null` and the signature is
`skipped`. Chip and Active Authentication still run, but their keys cannot be authenticated without
EF.SOD, which is then not a failure.

### 4. Document Signer against trusted CSCAs (`--csca`)

With `--csca`, the tool checks that the Document Signer certificate was issued by a Country Signing CA
(CSCA) you trust, which completes Passive Authentication (ICAO Doc 9303-12):

- **Certificates:** read from `.cer`, `.crt`, `.der` and `.pem` files (DER or PEM, one or more per
  file) and from ICAO CSCA master lists (`.ml`: CMS signed data with content type
  `id-icao-cscaMasterList`). With a folder, every file with one of these extensions is read. Files and
  master list entries that cannot be read are skipped (listed with `--verbose`). A path that does not
  exist, or from which no certificate can be read, ends with exit code `-3`.
- **Matching:** the candidates are the CSCA certificates whose subject is the Document Signer
  certificate's issuer, narrowed by the authority key identifier when both certificates have one. Each
  candidate is tried, because a country can have several CSCA keys under the same name (key rollover).
- **Verdict:** `trusted` when the certificate's signature verifies with a candidate's key (RSA,
  RSASSA-PSS or EC); `untrusted` otherwise, with the reason; `no-certificate` when EF.SOD has no
  Document Signer certificate.
- **Dates:** reported, not enforced. The result says whether the CSCA certificate was valid when the
  Document Signer certificate was issued, and whether the Document Signer certificate is valid today.
  An expired document normally has an expired Document Signer certificate.
- **Revocation:** certificate revocation lists (`.crl`, DER or PEM) in the `--csca` path are read too.
  When the Document Signer certificate is trusted, the tool looks for the CRLs whose issuer is its
  CSCA and whose signature verifies with a trusted CSCA certificate of that name (after a key rollover
  the current CRL is signed with the new key and also covers the certificates issued with the old one),
  takes the most recent one and looks up the certificate's serial number: `revoked` (exit code `-46`,
  with the revocation date and reason), `not-revoked`, `no-crl` (no CRL of that CSCA was given) or
  `crl-invalid` (the CRLs of that CSCA do not verify). A CRL covers only the certificates issued
  under its issuer's name (RFC 5280): after a CSCA name change, as the Italian CSCA's in 2020, the CRL
  of the new name gives `no-crl` for a Document Signer issued under the old one. A CRL past its next update is still used, and
  that is reported. Without any `.crl` file, revocation is `not-checked`. CRLs are not downloaded.
- **Not checked:** the signature of a master list (loading one means trusting where it came from).

Get the CSCA certificates and their CRL from the issuing country (its CSCA publication page, such as
[csca-ita.interno.gov.it](https://csca-ita.interno.gov.it/) for Italy) or from a master list published
by a document verification authority, and keep them outside the repository.

### 5. Chip Authentication

When DG14 has a `ChipAuthenticationPublicKeyInfo`, the tool performs **Chip Authentication** (BSI
TR-03110, ICAO Doc 9303-11) with the first public key and the `ChipAuthenticationInfo` with the same
key id. It then reads EF.COM, which was not read before, with the new session keys: the read succeeds
only if the chip holds the private key matching the DG14 public key. DH and ECDH keys, 3DES and AES
are supported.

### 6. Active Authentication

When DG15 is present, the tool performs **Active Authentication** (ICAO Doc 9303-11) as its last step:
it sends a random 8-byte challenge (INTERNAL AUTHENTICATE) and verifies the chip's signature with the
DG15 public key:

- **RSA:** ISO/IEC 9796-2 digital signature scheme 1, with the challenge as the non-recoverable part,
  and SHA-1 with the implicit trailer or the hash named by an explicit trailer (SHA-1, SHA-224, SHA-256,
  SHA-384, SHA-512);
- **ECDSA:** the hash named by the `ActiveAuthenticationInfo` in DG14, with a plain signature (r || s,
  BSI TR-03111). Without that info the response is reported as `unverifiable`, never as valid.

It runs last because, under secure messaging, a chip ends the session on an error status.

### 7. Failed checks

Chip and Active Authentication prove that the chip holds the private key for the DG14 or DG15 public
key. That says the chip is genuine only if the key itself is the one the issuer signed: the data group
hash must match EF.SOD and the EF.SOD signature must be valid. The result reports this as
`keyAuthenticated`.

The result lists every failed security check with its code (`failedChecks`):

| Code | Failed check |
|---|---|
| `-40` | A data group whose hash differs from EF.SOD (one entry per data group). |
| `-41` | An invalid EF.SOD signature, or EF.SOD content that does not match its signed digest. |
| `-42` | With `--csca`, a Document Signer certificate not issued by a trusted CSCA (or no certificate). |
| `-46` | With a CRL in the `--csca` path, a revoked Document Signer certificate. |
| `-43` | A failed Chip Authentication. |
| `-44` | An Active Authentication signature that does not verify. |
| `-45` | A Chip or Active Authentication that succeeded with a key not covered by a valid EF.SOD signature. |

**Not failures**, because they say nothing against the document:

- a protocol the document does not offer (no DG14 or no DG15);
- an Active Authentication that cannot be verified, or that could not be completed;
- a data group without a hash in EF.SOD;
- a Document Signer certificate that is expired, or a CSCA that was not valid when it was issued
  (reported only);
- with `--skip-passive-authentication`, keys that could not be authenticated.

## Exit codes

`0` means that the document was read and every check passed. Every problem has its own negative code:

| Code | Meaning |
|---|---|
| `0` | The document was read and no security check failed. |
| `-1` | Invalid arguments: an unknown option, a missing value, or options that cannot go together. |
| `-2` | No access key, or an incomplete MRZ access key. |
| `-3` | The `--csca` certificates could not be loaded (missing path, or no readable certificate). |
| `-10` | No PC/SC reader found, or the `--reader` name is not one of them. |
| `-11` | The card could not be connected (no card on the reader, or it was removed). |
| `-20` | PACE is not available: `--pace` or a CAN on a document without PACE. |
| `-21` | PACE failed (wrong access key, or the chip rejected it). |
| `-22` | BAC failed (wrong access key, or the chip rejected it). |
| `-30` | Card communication error while reading (card removed, chip error). |
| `-31` | Unexpected error (for example a malformed file). |
| `-40` | A data group hash does not match EF.SOD. |
| `-41` | The EF.SOD signature is invalid. |
| `-42` | The Document Signer certificate was not issued by a trusted CSCA (`--csca`). |
| `-46` | The Document Signer certificate is revoked (a CRL in the `--csca` path). |
| `-43` | Chip Authentication failed. |
| `-44` | Active Authentication failed. |
| `-45` | Chip or Active Authentication used a key not covered by a valid EF.SOD signature. |

From `-1` to `-31` the reading stopped: the result has an `error` with the reason. From `-40` to `-46`
the document was read and a check failed; when several checks fail, the exit code is the first of
`failedChecks`, in the order of this table, and the result lists all of them.

On Windows the process exit code is the negative number itself (`$LASTEXITCODE` in PowerShell,
`%ERRORLEVEL%` in cmd). On Linux and macOS exit codes are 0–255, so the shell sees `256 + code` (for
example `216` for `-40`); the result's `exitCode` field always has the negative number.

## Output

The result is written to **stdout**, always, also when reading stops early (with the reason in
`error`), so a program gets the same structure in every case. Only invalid arguments (`-1`, `-2`) are
reported on stderr instead, since the output format is not known yet. Nothing else is printed unless
`--verbose` is given.

The three formats carry the same content, built from one tree of fields: the text has a line per field,
the JSON an object, the XML an element.

### Text

The default. Example (a simulated test document read with a CAN):

```text
Environment:
  nMRTD version: 0.8.12-alpha.1
  Operating system: Microsoft Windows 10.0.26200 (X64)
  Reader: REINER SCT cyberJack RFID basis 0
ATR: 3B80800101
Document:
  Document code: P
  Issuing state: UTO
  LDS version: 1.7
  Unicode version: 4.0.0
Access protocol: PACE
PACE protocol: 0.4.0.127.0.7.2.2.4.2.2
PACE protocol name: id-PACE-ECDH-GM-AES-CBC-CMAC-128
PACE parameter ID: 13
Explicit PACE parameters: false
Data groups:
  DG1
    Length: 93
    Hash: match
  DG2
    Length: 40094
    Hash: match
  DG5: not present
  ...
  DG14
    Length: 357
    Hash: match
  DG15
    Length: 165
    Hash: match
  DG16: not present
Passive authentication:
  Signature: valid
  Digest algorithm: SHA-256
  Signature algorithm: SHA256withRSA
  Signer: C=UT,O=nMRTD tests,CN=Document Signer
  CSCA: not-checked
  Signer certificate valid now: true
Chip authentication:
  Status: succeeded
  Key authenticated: true
  Protocol: 0.4.0.127.0.7.2.2.3.2.2
  Protocol name: id-CA-ECDH-AES-CBC-CMAC-128
  Public key: EC [brainpoolP256r1]
Active authentication:
  Status: succeeded
  Key authenticated: true
  Protocol: RSA ISO/IEC 9796-2, SHA-1
  Public key: RSA [1024 bit]
Failed checks: none
Exit code: 0
```

Fields without a value are left out. A failed check reads, for example:

```text
Failed checks:
  [-40] DG2 hash does not match EF.SOD
Exit code: -40
```

### JSON (`--output-json`)

The same document:

```json
{
  "environment": {
    "nmrtdVersion": "0.8.12-alpha.1",
    "operatingSystem": "Microsoft Windows 10.0.26200 (X64)",
    "reader": "REINER SCT cyberJack RFID basis 0"
  },
  "atr": "3B80800101",
  "document": {
    "documentCode": "P",
    "issuingState": "UTO",
    "ldsVersion": "1.7",
    "unicodeVersion": "4.0.0"
  },
  "accessProtocol": "PACE",
  "paceProtocol": "0.4.0.127.0.7.2.2.4.2.2",
  "paceProtocolName": "id-PACE-ECDH-GM-AES-CBC-CMAC-128",
  "paceParameterId": 13,
  "explicitPaceParameters": false,
  "dataGroups": [
    { "number": 1, "present": true, "length": 93, "hash": "match" },
    { "number": 2, "present": true, "length": 40094, "hash": "match" },
    { "number": 5, "present": false },
    { "number": 14, "present": true, "length": 357, "hash": "match" },
    { "number": 15, "present": true, "length": 165, "hash": "match" },
    { "number": 16, "present": false }
  ],
  "passiveAuthentication": {
    "signature": "valid",
    "digestAlgorithm": "SHA-256",
    "signatureAlgorithm": "SHA256withRSA",
    "signer": "C=UT,O=nMRTD tests,CN=Document Signer",
    "error": null,
    "csca": "not-checked",
    "cscaSubject": null,
    "cscaDetail": null,
    "signerCertificateValidNow": true
  },
  "chipAuthentication": {
    "status": "succeeded",
    "keyAuthenticated": true,
    "protocol": "0.4.0.127.0.7.2.2.3.2.2",
    "protocolName": "id-CA-ECDH-AES-CBC-CMAC-128",
    "publicKey": "EC [brainpoolP256r1]",
    "error": null
  },
  "activeAuthentication": {
    "status": "succeeded",
    "keyAuthenticated": true,
    "protocol": "RSA ISO/IEC 9796-2, SHA-1",
    "publicKey": "RSA [1024 bit]",
    "error": null
  },
  "failedChecks": [],
  "exitCode": 0,
  "error": null
}
```

(`dataGroups` lists every data group the tool tried: DG1, DG2 and DG5 to DG16, shortened here; the
real output has one field per line.) The JSON has every field, `null` when it has no value. A failed
check is `{ "code": -40, "description": "DG2 hash does not match EF.SOD" }`.

### XML (`--output-xml`)

The root element is `nmrtdReport`, with an element per field. An array is an element with one child
per item, named after the array in the singular (`dataGroups` / `dataGroup`, `failedChecks` /
`failedCheck`, `faces` / `face`, `securityInfos` / `securityInfo`); fields without a value are left
out:

```xml
<?xml version="1.0" encoding="utf-8"?>
<nmrtdReport>
  <environment>
    <nmrtdVersion>0.8.12-alpha.1</nmrtdVersion>
    ...
  </environment>
  <atr>3B80800101</atr>
  ...
  <accessProtocol>PACE</accessProtocol>
  <paceProtocol>0.4.0.127.0.7.2.2.4.2.2</paceProtocol>
  <explicitPaceParameters>false</explicitPaceParameters>
  <dataGroups>
    <dataGroup>
      <number>1</number>
      <present>true</present>
      <length>93</length>
      <hash>match</hash>
    </dataGroup>
    ...
  </dataGroups>
  ...
  <failedChecks />
  <exitCode>0</exitCode>
</nmrtdReport>
```

### Fields

| Field | Values |
|---|---|
| `environment.nmrtdVersion` | The nMRTD library version |
| `environment.operatingSystem` | The operating system and the processor architecture |
| `environment.reader` | The PC/SC reader used |
| `atr` | The card's Answer To Reset in hexadecimal, or `null` if it could not be read |
| `document.documentCode`, `.issuingState` | The kind of document and the issuing state, from the MRZ (DG1) |
| `document.ldsVersion`, `.unicodeVersion` | The LDS and Unicode versions, from EF.COM (read by Chip Authentication, or on its own when the document has none) |
| `accessProtocol` | `"PACE"`, `"BAC"`, or `null` if no access protocol succeeded |
| `paceProtocol` | The PACE protocol object identifier, or `null` |
| `paceProtocolName` | Its name, for example `id-PACE-DH-GM-3DES-CBC-CBC` |
| `paceParameterId` | The PACE domain parameter id (0 to 31: standardized), or `null` |
| `explicitPaceParameters` | `true` when PACE used explicit domain parameters from EF.CardAccess; `null` when PACE was not used |
| `dataGroups[].number`, `.present` | The data group, and whether the document has it |
| `dataGroups[].length` | Its length in bytes (present data groups) |
| `dataGroups[].hash` | `"match"`, `"mismatch"`, `"not-in-sod"`, or `null` if not checked (present data groups) |
| `dataGroups[].information` | The parsed information (only with `--include-information`, see below) |
| `dataGroups[].informationError` | Why the data group could not be parsed (only with `--include-information`) |
| `dataGroups[].raw` | The data group's bytes in Base64 (only with `--include-raw`) |
| `passiveAuthentication.signature` | `"valid"`, `"invalid"`, `"error"` (for example an unsupported algorithm), `"skipped"` (`--skip-passive-authentication`), `"not-checked"` (reading stopped before) |
| `passiveAuthentication.digestAlgorithm`, `.signatureAlgorithm` | The EF.SOD algorithms |
| `passiveAuthentication.signer` | The Document Signer certificate's subject |
| `passiveAuthentication.error` | Why the signature could not be checked |
| `passiveAuthentication.csca` | `"trusted"`, `"untrusted"`, `"no-certificate"`, `"error"`, `"skipped"`, `"not-checked"` (no `--csca`) |
| `passiveAuthentication.cscaSubject` | The trusted CSCA that issued the Document Signer certificate |
| `passiveAuthentication.cscaDetail` | Why the certificate is not trusted, or a note on the CSCA's validity |
| `passiveAuthentication.revocation` | `"not-revoked"`, `"revoked"`, `"no-crl"`, `"crl-invalid"`, `"not-checked"` (no `.crl` in the `--csca` path, or the certificate is not trusted) |
| `passiveAuthentication.revocationDetail` | The CRL used (its dates) and, when revoked, the revocation date and reason |
| `passiveAuthentication.signerCertificateValidNow` | Whether the Document Signer certificate is within its validity period today |
| `chipAuthentication.status` | `"succeeded"`, `"failed"`, `"error"` (malformed DG14), `"not-available"` |
| `activeAuthentication.status` | `"succeeded"`, `"failed"` (wrong signature), `"error"` (no usable answer), `"unverifiable"`, `"not-available"` |
| `*.keyAuthenticated` | Whether the DG14 or DG15 key is covered by a valid EF.SOD signature |
| `*.protocol` | The protocol object identifier (Chip Authentication) or the signature scheme (Active Authentication) |
| `chipAuthentication.protocolName` | The Chip Authentication protocol name, for example `id-CA-DH-3DES-CBC-CBC` |
| `*.publicKey` | The chip's public key algorithm and size (DG14 or DG15), for example `DH [2048 bit]` (with `q <n> bit` when the key gives the subgroup order), `RSA [1024 bit]`, `EC [brainpoolP256r1]` |
| `*.error` | Why the protocol could not be completed |
| `failedChecks[]` | The failed security checks, `code` and `description` (see [Failed checks](#7-failed-checks)); empty when none failed |
| `exitCode` | The process exit code (see [Exit codes](#exit-codes)) |
| `error` | Why reading stopped early, or `null` |

The result never contains the access key.

### Data group information (`--include-information`)

Each data group the library can parse gets an `information` object; fields that are absent from the
document are left out. Images are in Base64 with their `mimeType` (`image/jpeg` or `image/jp2`, ready
to save as `.jpg` or `.jp2`). DG8 to DG10, DG13 and DG16 have no parser: their content is only in
`raw` with `--include-raw`.

| Data group | `information` |
|---|---|
| DG1 | `documentCode`, `issuingState`, `documentNumber`, `primaryIdentifier`, `secondaryIdentifiers` (array), `nationality`, `dateOfBirth`, `gender`, `dateOfExpiry`, `optionalData1`, `optionalData2`, `personalNumber` |
| DG2 | `faces`: one object per face image. ISO/IEC 19794-5: `format`, `mimeType`, `width`, `height`, `gender`, `eyeColor`, `hairColor`, `featureMask`, `expression`, `poseAngle` and `poseAngleUncertainty` (yaw, pitch, roll), `faceImageType`, `colorSpace`, `sourceType`, `deviceType`, `quality`, `featurePoints` (`type`, `majorCode`, `minorCode`, `x`, `y`), `image`; the numeric codes are those of the standard. ISO/IEC 39794-5: `format`, `mimeType`, `width`, `height`, and when present `faceImageKind`, `gender`, `eyeColour`, `hairColour`, `captureDateTime`, `landmarks` (count), and `image` |
| DG5, DG6, DG7 | `images` (displayed portrait, other images, signature): `mimeType`, `width`, `height`, `image` |
| DG11 | `nameOfHolder`, `otherNames`, `personalNumber`, `fullDateOfBirth`, `placeOfBirth`, `permanentAddress`, `telephone`, `profession`, `title`, `personalSummary`, `proofOfCitizenship` (`mimeType`, `image`), `otherValidTravelDocumentNumbers`, `custodyInformation` |
| DG12 | `issuingAuthority`, `dateOfIssue`, `namesOfOtherPersons`, `endorsementsAndObservations`, `taxOrExitRequirements`, `imageOfFront` and `imageOfRear` (`mimeType`, `image`), `dateAndTimeOfPersonalization`, `personalizationSystemSerialNumber` |
| DG14 | `securityInfos`: one object per security info, with `type`, `objectIdentifier`, `protocol`, and depending on the type `version`, `keyId`, `parameterId`, `publicKey` (algorithm and size), `signatureAlgorithm` |
| DG15 | `publicKey`: the Active Authentication key algorithm and size, for example `RSA [1024 bit]` |

Example (DG1 of the simulated document, JSON):

```json
{
  "number": 1,
  "present": true,
  "length": 93,
  "hash": "match",
  "information": {
    "documentCode": "P",
    "issuingState": "UTO",
    "documentNumber": "TST123456",
    "primaryIdentifier": "SPECIMEN",
    "secondaryIdentifiers": [ "TEST" ],
    "nationality": "UTO",
    "dateOfBirth": "800101",
    "gender": "Female",
    "dateOfExpiry": "351231"
  }
}
```

In the text output the same information is indented under the data group (`Document number:
TST123456`); arrays of objects, such as the faces, are numbered.

### Raw data groups (`--include-raw`)

`--include-raw` adds each present data group's bytes, as read from the chip, in Base64 in
`dataGroups[].raw`: the whole data group file (for DG2, the biometric record including the face
image), which a program can parse itself or check against EF.SOD.

## Sharing a result (`--share`)

`--share` leaves out everything that identifies the holder or the document, and keeps what is useful
to understand how the document and the tool behaved: the environment (nMRTD version, operating system,
reader), the ATR, the kind of document (`document`: document code, issuing state, LDS version), the
protocols, algorithms and key sizes, which data groups are present with their lengths and hash checks,
the outcome of every check, the failed checks and the exit code. That is all a row of the README's
*Tested documents* table needs: run the tool once with the CAN (PACE) and once with the MRZ access key
and `--bac`, both with `--share`. With `--include-information`:

| Data group | Kept |
|---|---|
| DG1 | `documentCode`, `issuingState` |
| DG2 | Per face: `format`, `mimeType`, `width`, `height`, `faceImageKind`, `faceImageType`, `colorSpace`, `sourceType`, `quality` (no image) |
| DG5, DG6, DG7 | Per image: `mimeType`, `width`, `height` (no image) |
| DG11, DG12 | `presentFields`: the names of the fields present, no values |
| DG14, DG15 | Everything (protocols and public key algorithms) |

The Document Signer and CSCA names (`signer`, `cscaSubject`, `cscaDetail`) are `null`.
`--share` cannot be combined with `--include-raw`. Errors are kept as they are: check them before
sharing, as an unusual error message could quote data from the card. `--verbose` output is not
covered by `--share`.

```json
{
  "number": 1,
  "present": true,
  "length": 93,
  "hash": "match",
  "information": {
    "documentCode": "P",
    "issuingState": "UTO"
  }
}
```

## Verbose mode (`--verbose`)

Without `--verbose` the tool prints nothing besides the result. With it, stderr gets the progress of
each step and every APDU exchange (command and response, with the status word and its meaning) and
protocol step logged by the library, color-coded: requests, successful responses, warnings and errors.
For example:

```text
Performing PACE (protocol 0.4.0.127.0.7.2.2.4.2.2)...
PACE completed; secure messaging established.
DG1: read (93 bytes).
DG2: read (40094 bytes).
DG5: not present (File not found, CAPDU = 00B0850008, RAPDU = 6A82).
...
DG1: hash matches EF.SOD (SHA-256).
EF.SOD signature is VALID (SHA256withRSA, signed by: C=UT,O=nMRTD tests,CN=Document Signer).
...
Active Authentication succeeded (RSA ISO/IEC 9796-2, SHA-1): the chip signed the challenge with the private key for the DG15 public key.
```

Since the result goes to stdout and the trace to stderr, `--output-json > result.json` still gives a
clean JSON file.

## Personal data

With `--include-information` the result contains the holder's personal data and photo, and with
`--include-raw` all of the document's content; the `--verbose` trace contains the exchanged data too
(under secure messaging, encrypted). Do not share these unredacted: use `--share` to produce a result
to share, for example to report a document in the README's *Tested documents*.

## Native AOT

The tool publishes as a Native AOT executable for `net8.0` and `net10.0`:

```bash
dotnet publish nMRTD.Cli -c Release -f net10.0 -r win-x64
```

On Windows, Native AOT needs the Visual Studio C++ build tools, and `vswhere` (in
`C:\Program Files (x86)\Microsoft Visual Studio\Installer`) on the `PATH`. The only expected warning
is IL2104 from the PCSC package. The JSON and XML outputs work in the AOT build (they are written
without reflection).

## Troubleshooting

| Symptom | Cause and remedy |
|---|---|
| Exit code `-10`, "No PC/SC reader found" | The reader is not connected or the PC/SC service is not running (`pcscd` on Linux/macOS). |
| Exit code `-10`, "Reader ... not found" | Check the name with `--list-readers` and pass it to `--reader` exactly. |
| Exit code `-11` | No card on the reader, or not in the field: place it and run again. |
| Exit code `-20` | The document has no PACE (for example older passports): use the MRZ access key without `--pace`. |
| Exit code `-21` or `-22` | Check the access key: the document number without check digit, dates as yyMMdd. |
| Exit code `-21`, "the document refused MSE:Set AT" | The document does not take this kind of access key for PACE: some passports take only the MRZ, not a CAN. |
| Exit code `-30` | The card lost the field or the session: remove the card, put it back, and run again. |
| Exit code `-40` to `-45` | A security check failed: see `failedChecks`. |
| Exit code `-3` | The `--csca` files could not be read: run with `--verbose` to see which. |
| Exit code `-46` | The Document Signer certificate is in the CSCA's CRL: see `revocationDetail`. |
| Revocation `no-crl` or `crl-invalid` | The `--csca` path has no CRL of the document's CSCA, or one signed with a key that is not among the trusted CSCA certificates: add the CRL and all the CSCA certificates (also the older ones) from the same publication. |
| Exit code `216`, `214`... on Linux/macOS | The negative code seen by the shell (`256 + code`): see [Exit codes](#exit-codes). |

## Code layout

| File | Content |
|---|---|
| `nMRTD.Cli/Program.cs` | The run: CSCA loading, reader, logging, help |
| `nMRTD.Cli/CliOptions.cs` | The options and their combinations |
| `nMRTD.Cli/ExitCodes.cs` | The exit codes |
| `nMRTD.Cli/DocumentReader.cs` | The reading flow: access control, data groups, Passive, Chip and Active Authentication |
| `nMRTD.Cli/DataGroupFields.cs` | The parsed data group information (`--include-information`) |
| `nMRTD.Cli/ReadReport.cs` | The result and the failed checks |
| `nMRTD.Cli/ReportOutput.cs` | Text, JSON and XML output, and `--share` |
| `nMRTD.Cli/CscaTrustStore.cs` | Loading CSCA certificates and checking the Document Signer certificate (`--csca`) |
| `nMRTD.Cli/ActiveAuthenticationVerifier.cs` | Verifying the Active Authentication signature |
| `nMRTD.Cli/KeyDescription.cs` | Key algorithms and sizes in the result (`DH [2048 bit]`, `RSA [1024 bit]`, `EC [brainpoolP256r1]`) |

The tests (`nMRTD.Tests/Cli`) run `DocumentReader` on a simulated chip, with Document Signer and CSCA
certificates generated at run time, and check the options, the exit codes and the three outputs.
