# nMRTD.Cli — Command-line tool

`nMRTD.Cli` reads an electronic travel document (ePassport, electronic ID card) end to end with the
nMRTD library: it authenticates, reads the data groups, and runs every check the library supports
(Passive, Chip and Active Authentication, and optionally the Document Signer against trusted CSCAs).
It is a sample application and a test tool. It is **not** part of the NuGet package.

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
  - [7. Result](#7-result)
- [Exit codes](#exit-codes)
- [JSON output (--json)](#json-output---json)
- [Verbose trace (--verbose)](#verbose-trace---verbose)
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

# Card Access Number (PACE only)
dotnet run --project nMRTD.Cli -f net10.0 -- --can 123456 --out ./out

# MRZ access key: document number (without check digit), date of birth and date of expiry (yyMMdd)
dotnet run --project nMRTD.Cli -f net10.0 -- --doc L898902C3 --dob 740812 --doe 120415 --out ./out

# Same, skipping PACE and using BAC
dotnet run --project nMRTD.Cli -f net10.0 -- --doc L898902C3 --dob 740812 --doe 120415 --bac --out ./out

# Check the Document Signer against trusted CSCA certificates, and write the results as JSON
dotnet run --project nMRTD.Cli -f net10.0 -- --can 123456 --csca ./csca --json > result.json
```

Without `--can` or the MRZ options, the tool asks which access key to use and prompts for it.

## Options

| Option | Meaning |
|---|---|
| `--can <CAN>` | Card Access Number: the access key for PACE. It cannot be used for BAC. |
| `--doc <number>` | Document number, without the check digit (MRZ access key). |
| `--dob <yyMMdd>` | Date of birth (MRZ access key). |
| `--doe <yyMMdd>` | Date of expiry (MRZ access key). |
| `--bac` | Skip PACE and use BAC with the MRZ access key, even if the document supports PACE. |
| `--reader <name>` | PC/SC reader to use (default: the first one found). |
| `--out <dir>` | Folder for the extracted images (default: the current folder). |
| `--csca <path>` | Trusted CSCA certificates: a `.cer`, `.crt`, `.der` or `.pem` file (DER or PEM, one or more certificates), an ICAO master list (`.ml`), or a folder of them. |
| `--json` | Write the results as JSON to stdout; all other output goes to stderr. |
| `--json-data` | With `--json`, add each data group's contents, in Base64, to the JSON (`dataGroups[].data`). Needs `--json`. |
| `--report-only` | Exit with 0 even when a security check fails (the results are still reported). |
| `--verbose` | Print the APDU exchanges and the protocol steps to stderr. |
| `--list-readers` | List the PC/SC readers and exit. |
| `-h`, `--help` | Show the help. |

`--can` and the MRZ options (`--doc`, `--dob`, `--doe`) are alternatives. `--bac` needs the MRZ options.

## What it does

### 1. Access control: PACE or BAC

The tool reads EF.CardAccess. If it has a `PACEInfo`, the tool performs **PACE** with the access key
given (CAN or MRZ):

- standardized domain parameters (parameter id 0 to 31) are used directly;
- explicit domain parameters are taken from the matching `PACEDomainParameterInfo` (a proprietary
  parameter id, 32 and up, or no parameter id).

When the document has no EF.CardAccess or no `PACEInfo`, or when the parameters cannot be resolved, the
tool falls back to **BAC** with the MRZ access key. With a CAN there is no fallback: a CAN is only valid
for PACE, so the tool stops with exit code 1. With `--bac` the tool goes straight to BAC.

### 2. Data groups

Every standard data group is read, except **DG3** (fingerprints) and **DG4** (iris), which need
Terminal Authentication with an inspection system certificate. For each data group the tool prints a
summary and a hex dump of its bytes, or "Not present on this document":

| Data group | Summary |
|---|---|
| DG1 | MRZ: document number, name, nationality, issuing state, dates, sex |
| DG2 | Face images, saved to `--out` as `dg2_face_<n>.jpg` or `.jp2` (ISO/IEC 19794-5 and 39794-5) |
| DG5, DG6, DG7 | Displayed portrait, other images and signature, saved to `--out` |
| DG11, DG12 | Additional personal and document details, the fields present |
| DG14 | The security infos (Chip Authentication, PACE, Terminal Authentication) |
| DG15 | The Active Authentication public key algorithm and size |
| DG8–DG10, DG13, DG16 | Hex dump only (the library has no parser for them) |

### 3. Passive Authentication

The tool reads EF.SOD and checks:

1. **Data group hashes:** the hash of every data group read is compared with the hash signed in
   EF.SOD ("hash matches EF.SOD", or "HASH MISMATCH"). A data group without a hash in EF.SOD is
   reported but is not a failure: some documents have data groups that EF.SOD does not cover.
2. **Signed content:** the content of EF.SOD must match the message digest in its signed attributes.
3. **Signature:** the EF.SOD signature is verified with the Document Signer certificate stored in
   EF.SOD. RSA (PKCS #1 v1.5), RSASSA-PSS (hash, mask generation hash and salt length taken from the
   signature parameters) and ECDSA are supported.

Without `--csca` this proves that the data is unchanged and consistent with EF.SOD, but not that EF.SOD
was signed by the issuing country: anyone can produce a self-signed Document Signer certificate. The
tool says so in its output.

### 4. Document Signer against trusted CSCAs (`--csca`)

With `--csca`, the tool checks that the Document Signer certificate was issued by a Country Signing CA
(CSCA) you trust, which completes Passive Authentication (ICAO Doc 9303-12):

- **Certificates:** read from `.cer`, `.crt`, `.der` and `.pem` files (DER or PEM, one or more per
  file) and from ICAO CSCA master lists (`.ml`: CMS signed data with content type
  `id-icao-cscaMasterList`). With a folder, every file with one of these extensions is read. Files and
  master list entries that cannot be read are skipped with a message on stderr; the number of
  certificates loaded is printed ("Loaded N trusted CSCA certificate(s)").
- **Matching:** the candidates are the CSCA certificates whose subject is the Document Signer
  certificate's issuer, narrowed by the authority key identifier when both certificates have one. Each
  candidate is tried, because a country can have several CSCA keys under the same name (key rollover).
- **Verdict:** `trusted` when the certificate's signature verifies with a candidate's key (RSA,
  RSASSA-PSS or EC); `untrusted` otherwise, with the reason; `no-certificate` when EF.SOD has no
  Document Signer certificate.
- **Dates:** reported, not enforced. The tool says whether the CSCA certificate was valid when the
  Document Signer certificate was issued, and whether the Document Signer certificate is valid today.
  An expired document normally has an expired Document Signer certificate.
- **Not checked:** the signature of a master list (loading one means trusting where it came from),
  and revocation (CRLs).

Get the CSCA certificates from the issuing country (its CSCA publication page) or from a master list
published by a document verification authority, and keep them outside the repository.

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
  BSI TR-03111). Without that info the response is reported as **unverifiable**, never as valid.

It runs last because, under secure messaging, a chip ends the session on an error status.

### 7. Result

Chip and Active Authentication prove that the chip holds the private key for the DG14 or DG15 public
key. That says the chip is genuine only if the key itself is the one the issuer signed: the data group
hash must match EF.SOD and the EF.SOD signature must be valid. The tool reports this as
`keyAuthenticated`, and warns when a protocol succeeded with a key that is not covered.

The output ends with the list of failed security checks:

```text
=== Result: no security check failed ===
```

or, for example:

```text
=== Result: 1 security check(s) FAILED ===
  - DG2 hash does not match EF.SOD
```

**Counted as failed checks:**

- a data group whose hash differs from EF.SOD;
- an invalid EF.SOD signature, or EF.SOD content that does not match its signed digest;
- with `--csca`, a Document Signer certificate not issued by a trusted CSCA (or no certificate);
- a failed Chip Authentication;
- an Active Authentication signature that does not verify;
- a Chip or Active Authentication that succeeded with a key not covered by a valid EF.SOD signature.

**Not counted**, because they say nothing against the document:

- a protocol the document does not offer (no DG14 or no DG15);
- an Active Authentication that cannot be verified, or that could not be completed;
- a data group without a hash in EF.SOD;
- a Document Signer certificate that is expired, or a CSCA that was not valid when it was issued
  (reported only).

## Exit codes

| Code | Meaning |
|---|---|
| `0` | The document was read and no security check failed (or `--report-only` was given). |
| `1` | Invalid arguments, a missing `--csca` path, or a CAN on a document without PACE. |
| `2` | Card communication error (reader not found, card removed, authentication rejected...). |
| `3` | Unexpected error (for example a malformed file). |
| `4` | The document was read, but a security check failed (see [Result](#7-result)). |

With `--report-only` the exit code only tells whether the document could be read (`0` to `3`); the
outcome of the checks is in the output and in the JSON.

## JSON output (`--json`)

With `--json`, stdout contains only a JSON object; the text output, prompts and progress go to stderr.
The JSON is also written when reading fails (with `error` set), including for invalid arguments once
they have been parsed. It never contains the access key. By default it does not contain the data group
contents either (only their length, hash check and the format of their images): add `--json-data` to
get each data group's bytes, as read from the chip, in Base64 in `dataGroups[].data`. These are the
raw data group files (for DG2, the whole biometric record including the face image), which a program
can parse itself or check against EF.SOD.

For the data groups that hold images (DG2 faces, DG5 to DG7 displayed images), `images` gives each
image's format and where it is in the data group's bytes: with `--json-data`, the image is the
`length` bytes of the decoded `data` starting at `offset`, ready to save with the extension of its
`mimeType` (`image/jpeg`: `.jpg`, `image/jp2`: `.jp2`).

Example (a simulated test document):

```json
{
  "accessProtocol": "PACE",
  "paceProtocol": "0.4.0.127.0.7.2.2.4.2.2",
  "explicitPaceParameters": false,
  "mrz": {
    "documentCode": "P",
    "documentNumber": "TST123456",
    "primaryIdentifier": "SPECIMEN",
    "secondaryIdentifier": "TEST",
    "nationality": "UTO",
    "issuingState": "UTO",
    "dateOfBirth": "800101",
    "dateOfExpiry": "351231",
    "gender": "Female"
  },
  "dataGroups": [
    { "number": 1, "present": true, "length": 93, "hash": "match" },
    {
      "number": 2, "present": true, "length": 40094, "hash": "match",
      "images": [ { "mimeType": "image/jpeg", "offset": 94, "length": 40000 } ]
    },
    { "number": 5, "present": false },
    { "number": 14, "present": true, "length": 357, "hash": "match" },
    { "number": 15, "present": true, "length": 165, "hash": "match" }
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
    "error": null
  },
  "activeAuthentication": {
    "status": "succeeded",
    "keyAuthenticated": true,
    "protocol": "RSA ISO/IEC 9796-2, SHA-1",
    "error": null
  },
  "error": null,
  "failedChecks": []
}
```

(`dataGroups` lists every data group the tool tried: DG1, DG2 and DG5 to DG16, shortened here.)

### Fields

| Field | Values |
|---|---|
| `accessProtocol` | `"PACE"`, `"BAC"`, or `null` if no access protocol succeeded |
| `paceProtocol` | The PACE protocol object identifier, or `null` |
| `explicitPaceParameters` | `true` when PACE used explicit domain parameters from EF.CardAccess |
| `mrz` | The DG1 fields, or `null` if DG1 was not read |
| `dataGroups[].hash` | `"match"`, `"mismatch"`, `"not-in-sod"`, or `null` if not checked (present data groups only) |
| `dataGroups[].images` | For data groups with images: each image's `mimeType` (for example `image/jpeg`, `image/jp2`), `offset` in the data group's bytes (`-1` if not found) and `length` |
| `dataGroups[].data` | The data group's bytes in Base64 (present data groups, only with `--json-data`) |
| `passiveAuthentication.signature` | `"valid"`, `"invalid"`, `"error"` (for example an unsupported algorithm), `"not-checked"` |
| `passiveAuthentication.csca` | `"trusted"`, `"untrusted"`, `"no-certificate"`, `"error"`, `"not-checked"` (no `--csca`) |
| `passiveAuthentication.cscaSubject` | The trusted CSCA that issued the Document Signer certificate |
| `passiveAuthentication.cscaDetail` | Why the certificate is not trusted, or a note on the CSCA's validity |
| `passiveAuthentication.signerCertificateValidNow` | Whether the Document Signer certificate is within its validity period today |
| `chipAuthentication.status` | `"succeeded"`, `"failed"`, `"error"` (malformed DG14), `"not-available"` |
| `activeAuthentication.status` | `"succeeded"`, `"failed"` (wrong signature), `"error"` (no usable answer), `"unverifiable"`, `"not-available"` |
| `*.keyAuthenticated` | Whether the DG14 or DG15 key is covered by a valid EF.SOD signature |
| `*.protocol` | The protocol object identifier (Chip Authentication) or the signature scheme (Active Authentication) |
| `error` | Why reading stopped early, or `null` |
| `failedChecks` | The failed security checks (see [Result](#7-result)); empty when none failed |

## Verbose trace (`--verbose`)

`--verbose` prints every APDU exchange (command and response, with the status word and its meaning)
and every protocol step logged by the library to stderr, color-coded: requests, successful responses,
warnings and errors.

## Personal data

The text output, the JSON, the `--verbose` trace and the images saved to `--out` contain the holder's
personal data and photo; with `--json-data` the JSON contains all of it, the face image included. Use `--out` to write the images outside the repository, and do not share the
output, the JSON or the traces unredacted. When reporting a result (see the README's *Tested
documents*), the protocol and algorithm lines are all that is needed.

## Native AOT

The tool publishes as a Native AOT executable for `net8.0` and `net10.0`:

```bash
dotnet publish nMRTD.Cli -c Release -f net10.0 -r win-x64
```

On Windows, Native AOT needs the Visual Studio C++ build tools, and `vswhere` (in
`C:\Program Files (x86)\Microsoft Visual Studio\Installer`) on the `PATH`. The only expected warning
is IL2104 from the PCSC package. The JSON output works in the AOT build (it is written without
reflection).

## Troubleshooting

| Symptom | Cause and remedy |
|---|---|
| "No PC/SC readers found" | The reader is not connected or the PC/SC service is not running (`pcscd` on Linux/macOS). |
| "The specified reader name is not recognized" | Check the name with `--list-readers` and pass it to `--reader` exactly. |
| "PACE not available ... falling back to BAC" | The document has no PACE (for example older passports): normal with the MRZ access key. |
| "a Card Access Number can only be used to perform PACE" | The document has no PACE: use the MRZ options instead of `--can`. |
| Authentication fails | Check the access key: the document number without check digit, dates as yyMMdd. |
| "No response APDU" while reading | The card lost the field or the session: remove the card, put it back, and run again. |
| Exit code 4 | A security check failed: see the list at the end of the output, or `failedChecks` in the JSON. |
| "Loaded 0 trusted CSCA certificate(s)" | The `--csca` files could not be read: see the messages on stderr. |

## Code layout

| File | Content |
|---|---|
| `nMRTD.Cli/Program.cs` | Arguments, access key prompts, logging, exit codes |
| `nMRTD.Cli/DocumentReader.cs` | The reading flow: access control, data groups, Passive, Chip and Active Authentication |
| `nMRTD.Cli/CscaTrustStore.cs` | Loading CSCA certificates and checking the Document Signer certificate (`--csca`) |
| `nMRTD.Cli/ActiveAuthenticationVerifier.cs` | Verifying the Active Authentication signature |
| `nMRTD.Cli/ReadReport.cs`, `ReadReportJson.cs` | The results and their JSON form |

The tests (`nMRTD.Tests/Cli`) run `DocumentReader` on a simulated chip, with Document Signer and CSCA
certificates generated at run time.
