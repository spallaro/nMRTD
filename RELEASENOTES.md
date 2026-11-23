# Release Notes

## Unreleased

### Fixed

- **`Util.ToSubjectPublicKeyInfo` lost the subgroup order q of DH keys.** It wrote PKCS #3 parameters
  (p, g, l) under the X9.42 `dhpublicnumber` identifier. It now writes an X9.42 key (p, g, q) when the key
  has q and a PKCS #3 `dhKeyAgreement` key otherwise, as `ChipAuthenticationPublicKeyInfo` already did
  since 0.8.3-alpha; both now share this code.
- **`Util.DeriveKey` with the cipher name `3DES`, or a cipher name in lower case, always threw.** It
  accepts these names, but the digest choice compared the names exactly (as in JMRTD) and rejected them.

## 0.8.7-alpha (2026-11-23)

### Fixed

- **An ISO/IEC 19794-5 face image with feature points never equalled a decoded copy of itself.**
  `FaceImageInfo.FeaturePoint` had no `Equals`/`GetHashCode` (as in JMRTD), so the feature points were
  compared by identity. They are now compared by value.
- **The right writer's palm** (ISO/IEC 19794-4 finger position 22) mapped to a CBEFF biometric subtype
  without the "right" bit, unlike every other right-hand position (a slip copied from JMRTD).

### Documentation

- **README:** the .NET and Native AOT badges link to the .NET support policy and to the Native AOT
  documentation. The `<picture>` wrapping of 0.8.6-alpha showed as raw HTML on nuget.org, which does
  not render HTML in package READMEs.
- **Package description** reworded: reading with contactless PC/SC readers, ISO/IEC 19794 and 39794
  biometrics, Native AOT compatible.

## 0.8.6-alpha (2026-11-23)

### Added

- **`PaceParameters.Resolve(paceInfo, securityInfos)`** finds the static domain parameters to pass to
  `DoPace` for a `PACEInfo` from EF.CardAccess: standardized parameters for parameter ids 0 to 31, or
  the explicit parameters of the matching `PACEDomainParameterInfo` for a proprietary parameter id
  (32 and up) or none (ICAO Doc 9303-11, BSI TR-03110-3). An nMRTD addition, not part of JMRTD.
- **CLI:** PACE now also works with documents whose EF.CardAccess carries explicit domain
  parameters. Before, the CLI fell back to BAC when the `PACEInfo` had no parameter id, and stopped with
  an error on a proprietary parameter id.

### Fixed

- **Equal `PADDataBlock`s and `StandardBiometricHeader`s could have different hash codes.** Their
  `GetHashCode()` hashed the PAD challenges and the header values (byte arrays) by array identity, as
  JMRTD does in Java, while `Equals` compares them by content; hash-based collections (`HashSet`,
  `Dictionary`) could then hold or miss equal blocks, including the face, finger and iris data blocks
  that contain them. The byte arrays are now hashed by content.
- **Equal `FaceImageCaptureDeviceBlock`s and DG5/DG6/DG7 files could have different hash codes** (a
  porting error, not in JMRTD): their `GetHashCode()` used the hash of a .NET `List`, which is per
  instance, while Java's `List.hashCode()` is content-based. This also affected `FaceImageDataBlock`
  and `DG2File` hash codes for ISO/IEC 39794 faces with a capture device. Lists are now hashed by
  content.
- **Explicit EC domain parameters** built in memory (rather than read from bytes) are now accepted by
  `PACEDomainParameterInfo.GetParameters()`; the parser cast the ASN.1 elements instead of converting
  them.

### Documentation

- **README:** a table of contents, a link to [DOCUMENTATION.md](DOCUMENTATION.md), an updated status
  note on testing, and the .NET and Native AOT badges no longer link to their own image.

## 0.8.5-alpha (2026-11-22)

### Fixed

- **`PACEDomainParameterInfo.GetParameters()` always threw.** It compared the PACE protocol identifier
  with the key algorithm identifiers (`ecPublicKey`, `dhpublicnumber`), which can never match, so
  explicit PACE domain parameters from EF.CardAccess could not be used. It now looks at the algorithm
  identifier of the domain parameters: explicit EC parameters become `ECDomainParameters`, and X9.42
  DH parameters (p, g, q), which were not implemented, become `DHParameters`.

## 0.8.4-alpha (2026-11-22)

### Packaging

- **Debugging support in the NuGet package.** The DLLs now embed their PDB (symbols and compiler
  flags) and Source Link information pointing at the exact GitHub commit, so a debugger can step into
  nMRTD's sources. Release builds are deterministic CI builds (normalized source paths). This clears
  the "Source Link", "Deterministic" and "Compiler Flags" warnings of NuGet Package Explorer.

## 0.8.3-alpha (2026-11-22)

### Fixed

- **DH Chip Authentication keys in DG14 kept their subgroup order q only until re-encoded.** A DH
  public key whose domain parameters include q is now written as an X9.42 `dhpublicnumber` key (RFC
  3279: p, g, q and the optional j and validation parameters), the form TR-03110 and ICAO Doc 9303-11
  refer to. Before, `ChipAuthenticationPublicKeyInfo` always wrote PKCS #3 parameters (p, g, l):
  q was dropped, so the decoded key no longer equalled the original, and a DG14 read from
  an X9.42 encoding was written back with the `dhpublicnumber` identifier but PKCS #3 parameters, which
  did not decode to the same key. DH keys without q are still written as PKCS #3 `dhKeyAgreement`.

## 0.8.2-alpha (2026-11-22)

### Changed

- **SCUBA's test countries are recognized.** `Country.GetInstance` and `Country.GetInstanceByAlpha2`
  now resolve `UTO`/`UT` (Utopia), `XBP`/`BP` and `XDV`/`DV`, like SCUBA's `TestCountry`, which JMRTD
  looks up after the ISO codes. A CV certificate reference such as `UTDVCS00001` now yields Utopia
  instead of the unknown-country placeholder, and MRZ data with `UTO` (the ICAO specimen country)
  resolves too.
- **Taiwan is named "Taiwan"**, the name SCUBA's `Country.getInstance` returns for `TWN`/`TW`.
- **`SecurityInfo.GetInstance` wraps every parse failure** as `ArgumentException("Malformed input
  stream.")`, as JMRTD does; Bouncy Castle's own `ArgumentException` used to pass through unwrapped.
  The original exception is kept as `InnerException`.

### Fixed

- **DG2, DG3 and DG4 files can be decoded on several threads at once.** Each data group shared one
  static `ISO781611Decoder` (as in JMRTD), which keeps the encoding type of the last biometric data
  block it read; two concurrent decodes of ISO 19794 and ISO 39794 files could report each other's
  encoding type. `GetDecoder()` now returns a new decoder on every call (the stateless per-tag block
  decoders are still shared).

## 0.8.1-alpha (2026-11-22)

### Fixed

- **Secure messaging was lost after the short-read fallback with short file identifiers** *(upstream
  JMRTD bug, fixed in nMRTD)*. When a card rejects a long READ BINARY with a wrong-length status,
  `DefaultFileSystem` retries with shorter reads and restores the secure messaging wrapper saved before
  the failed command. Only the file identifier path saved it (JMRTD `DefaultFileSystem.java:403`, not
  `:421`), so with short file identifiers, which `PassportService` enables by default, the wrapper
  restored after BAC or PACE was the one from before authentication (`null`) and the next READ BINARY
  was sent without secure messaging; the card then ended the session. Both paths now save it.
  Reported upstream as [JMRTD bug #92](https://sourceforge.net/p/jmrtd/bugs/92/).
- **PACE with AES over an existing secure channel kept the old send sequence counter** *(upstream
  JMRTD bug, fixed in nMRTD)*. After PACE, secure messaging restarts with the new keys and a send
  sequence counter of 0 (TR-SAC 4.6, Doc 9303-11), as the 3DES branch and Chip Authentication already
  did; the AES branch kept the previous channel's counter (JMRTD `PACEProtocol.java:338`), so PACE run
  after BAC failed on the next command. A first PACE, with no previous channel, was not affected.
  Reported upstream as [JMRTD bug #93](https://sourceforge.net/p/jmrtd/bugs/93/).

### Documentation

- **README:** a section on the command-line tool (what it does, options, examples, personal data
  warning, Native AOT publishing) and a table of the documents tested so far (Italian CIE 3.0 and
  Italian passport) with the BAC, PACE, Passive Authentication and Chip Authentication results. The
  target framework badge now shows .NET 6 | 8 | 10.

## 0.8.0-alpha (2026-11-21)

### Changed

- **Target `net6.0`, `net8.0` and `net10.0`.** `net8.0` is back (it was dropped in 0.6.0-alpha) so that
  .NET 8 and 9 apps get an AOT-compatible build: the `net8.0` and `net10.0` builds are marked
  `IsAotCompatible` and checked by the AOT and single-file analyzers, with no warnings, and the CLI
  publishes as a Native AOT executable on both. The `net6.0` build is unchanged and still covers
  .NET 6 and 7 apps. .NET 8 is out of support; the target is kept for AOT consumers. The tests run
  on all three frameworks, and the Native AOT CLI (`net8.0`) was checked on an Italian CIE 3.0.
- **Chip Authentication takes the key ID type used by DG14.** `ChipAuthenticationInfo.GetKeyId()` and
  `ChipAuthenticationPublicKeyInfo.GetKeyId()` return `Org.BouncyCastle.Math.BigInteger`, like
  `PACEInfo.GetParameterId()` and `DoPace`, but `DoEACCA` took a `System.Numerics.BigInteger`, so
  callers had to convert. `AbstractMRTDCardService`/`PassportService.DoEACCA`, `EACCAProtocol.DoCA`
  and `SendPublicKey`, `IApduLevelEacCACapable.SendMseSetAtIntAuth` and `EACCAResult.KeyId` now use
  `Org.BouncyCastle.Math.BigInteger`, and the key ID is encoded with `Util.I2os`, as in JMRTD. An
  `[Obsolete]` `DoEACCA` overload still accepts a (non-nullable) `System.Numerics.BigInteger`; code that
  passes a nullable `System.Numerics.BigInteger?` or implements `IApduLevelEacCACapable` needs updating.

### Fixed

- **"No response APDU" now keeps its cause.** When sending a READ BINARY failed (for example the
  reader stopped getting answers from the card), `ReadBinaryAPDUSender` discarded the exception, as
  JMRTD does, and only reported "No response APDU". The original exception is now its inner
  exception and part of its message. The status word stays unset, so `DefaultFileSystem` reacts to
  it as before.

### CLI

- **RSASSA-PSS EF.SOD signatures are verified**, using the hash, MGF1 hash and salt length from the
  signer info (`SODFile.GetDigestEncryptionAlgorithm()` only gives the generic "SSAwithRSA/PSS").
  Verified on an Italian CIE 3.0 (RSASSA-PSS, SHA-512).
- **Chip Authentication** runs after Passive Authentication when DG14 offers it, and is checked by
  reading EF.COM with the new session keys. Verified with DH keys on an Italian CIE 3.0 (2048 bit)
  and an Italian passport (1024 bit).
- **`--bac`** skips PACE and uses BAC with the MRZ access key.

## 0.7.1-alpha (2026-11-21)

### Fixed

- **Links in the package readme.** The README, which is also the NuGet package readme, linked to the
  CLI sample, the coverage settings and the license with paths relative to the repository, which do
  not resolve on nuget.org. They now point to the files on GitHub.

### Internal

- **More tests** (79 in total): a signed EF.SOD that reads back and whose signature verifies, with a
  tampered data group hash detected; EF.CardAccess read from a simulated card through
  `PassportService`; an extended READ BINARY response (DO'53' with a long-form length); errors in
  `CardFileInputStream`; invalid CV certificate dates; and round trips of `CardSecurityFile`, DG11
  and `DisplayedImageInfo`.

## 0.7.0-alpha (2026-11-21)

This release comes from a file-by-file review of nMRTD against JMRTD (at upstream commit
`2c08440a`) and SCUBA. The core protocols (secure messaging, BAC, PACE, EAC, AA) were confirmed
against the ICAO Doc 9303-11 worked examples; the problems below were found elsewhere, and most of
them date back to the initial port.

### Fixed

- **`DG14File` read from a document was always empty.** The stream constructor reset the set of
  security infos after the base constructor had parsed it, so no Chip Authentication, Terminal
  Authentication or Active Authentication info was ever returned.
- **CV certificate dates used the wrong encoding.** TR-03110-3 encodes the effective and expiration
  dates (tags `5F25`, `5F24`) as 6 bytes of unpacked BCD; the port used 3 bytes of packed BCD.
  Parsing any real CVCA, DV or IS certificate failed, so Terminal Authentication was unusable, and
  certificates built by `CVCertificateBuilder` were malformed. Verified with the EJBCA-generated
  certificates in the JMRTD repository: they parse, re-encode byte for byte, and the chain
  (including a link certificate) verifies. **Certificates built with nMRTD 0.6.1-alpha or earlier
  have 3-byte dates and no longer parse.**
- **A `DG12File` built from data was encoded with the DG11 tag.** `DG11File`/`DG12File` hid
  `GetTag()` instead of overriding it; JMRTD overrides it and writes `6C`. The comment and
  `DOCUMENTATION.md`, which described the wrong tag as inherited from JMRTD, are corrected.
- **`CardFileInputStream` truncated files and could read the wrong file.** When a card rejected a
  long READ BINARY, `DefaultFileSystem` lowered its read length and returned no bytes so that the
  read would be retried; the stream treated that as the end of the file. The stream also used
  whatever file was selected when it first read. It now binds to the selected file when it is
  created (path and length), re-selects it before reading if needed, retries empty reads, and runs
  select-and-read under a lock on the file system, as SCUBA does. It can now throw
  `CardServiceException` at creation if no file is selected.
- **`DG15File.GetEncoded()` threw `NullReferenceException` for RSA keys**, and a DG15 with a named EC
  curve did not re-encode to the bytes read. A DG15 read from a document now writes back the bytes it
  read; one built from a key uses BouncyCastle's `SubjectPublicKeyInfoFactory`.
- **`PaceProtocol.DoPace` with a plain `BacKey` failed** before sending any APDU (key reference 0).
  As in JMRTD, a key without a PACE key reference now uses the MRZ reference.
- **Wrapped `CardServiceException`s lost the card's status word.** `CardServiceException(message,
  cause)` now takes the status word from the cause, as SCUBA does, so the
  `CardServiceProtocolException`s thrown by PACE, BAC and EAC carry it (for example `63Cx` for a
  wrong CAN).

### Changed

- **The ISO/IEC 39794 block types are public, as in JMRTD.** A DG2, DG3 or DG4 encoded per ISO/IEC
  39794 could be read, but its images and metadata could not be reached from outside the library.
  The block types, their nested types, `FingerImagePositionCode`, `FaceImageLandmarkCoordinates`,
  `GetRepresentationBlocks()`, `GetVersionBlock()`, the build-from-parts constructors of the face
  and finger data blocks, and the decoding constructors that are public in JMRTD are now public.
  The other decoding constructors, the decoders, `ISO39794Util` and the encoding methods stay
  internal, as they are package-private in JMRTD.

### Internal

- Internal callers no longer use obsolete APIs: the BouncyCastle 2.x names (`Issuer`,
  `SignatureAlgorithm`, `SignedAttrs`, `Signature`) replace the obsolete ones, internal callers of
  the obsolete `SecurityInfo.GetDERObject()` and `PACEDomainParameterInfo.ToECDomainParameters()` go
  through internal helpers, and the explicit EC parameters parser builds `FpCurve` with order and
  cofactor.
- `AbstractImageInfo` no longer ports JMRTD's `SplittableInputStream` path, which is dead upstream
  (its setup code is commented out).
- Smaller cleanups: unambiguous and resolvable `cref`s, an explicit unsigned byte in the READ BINARY
  length parser, `new` on `DG11File.TAG_LIST_TAG`, and awaited error output in the CLI.
- **New `nMRTD.Tests` project** (xUnit, `net6.0` and `net10.0`): 65 tests for secure messaging, BAC,
  AA, PACE, MRZ, utilities, LDS round trips, CV certificates (including the EJBCA chains from the
  JMRTD repository), `CardFileInputStream` and ISO/IEC 39794, with a regression test for each fix
  above. Code coverage is collected with coverlet in OpenCover format. The library grants the test
  assembly access to its internals (`InternalsVisibleTo`) in unsigned builds only; the signed
  release build does not.

## 0.6.1-alpha (2026-11-21)

### Fixed

- **Document all parameters of the `SODFile` constructors.** Four constructors documented only some
  of their parameters (compiler warning CS1573); the descriptions follow the upstream JMRTD javadoc.

## 0.6.0-alpha (2026-11-21)

### Changed

- **Target `net6.0` and `net10.0` (instead of `net6.0` and `net8.0`).** .NET 8 reached end of
  support on November 10, 2026; .NET 10 is the current LTS release. Apps on .NET 6, 7, 8, and 9
  keep working: NuGet picks the `net6.0` build for them. Apps on .NET 10 and later get the
  `net10.0` build, which is the one marked AOT-compatible (`IsAotCompatible`, AOT and single-file
  analyzers); the CLI is published as a Native AOT executable from `net10.0`. Building nMRTD now
  requires the .NET 10 SDK (or later).

## 0.5.0-alpha (2026-11-21)

**JMRTD upstream alignment status:** nMRTD has been reviewed against upstream JMRTD up to commit
`2c08440a` ("Fixed trivial bugs and spelling errors", 2026-10-22 17:16), the latest commit on the
upstream `jmrtd-jmrtd` repository as of this review. All 15 commits after `277cd364` have been
evaluated for applicability to nMRTD. The applicable changes were verified with a throwaway
harness that ports the tests upstream added in these commits (secure messaging unwrap hardening
for 3DES and AES, BAC, PACE DH/ECDH mapping and public key validation, the PACE public key data
object, AA, TD2 MRZ, `Util`), plus the ICAO Doc 9303 Part 11 Appendix D BAC vectors.

### Security

- **Secure messaging: check the MAC before decrypting the response** *(ported from JMRTD)*.
  `SecureMessagingWrapper.Unwrap` used to decrypt DO'87/DO'85 while parsing, and only then check
  the MAC. It now parses all data objects first, checks the MAC (also failing when DO'8E is
  missing), and decrypts last. Unknown data objects are now skipped by their length (their value
  used to be parsed as further data objects), DO'8E must be the last data object, the MAC input is
  computed from the actual MAC length (8 or 16 bytes) instead of a hard-coded 8, and the MAC is
  compared in constant time (`CryptographicOperations.FixedTimeEquals`). Lengths are bounds-checked
  and long-form lengths are limited to 1 to 3 length bytes. Ported from upstream JMRTD commits
  `5329b2506a4c36f85a2acf0c7b26666622727486`, "Secure messaging: check the MAC before decrypting
  the response, ...", and (the length checks) `73c7c92f5b1ff4130d40dd433ffcce2f564ef2c7`; the tests
  of `3f79496b78be8b10baa574fbd51da9e105685e5a` (AES unwrap hardening) were used for verification.

- **BAC: verify the PICC's `EXTERNAL AUTHENTICATE` response** *(ported from JMRTD)*.
  `BACAPDUSender.SendMutualAuth` now checks the checksum M_IC on the PICC's cryptogram before
  decrypting it, and checks that the PICC returned RND.IFD (Doc 9303 Part 11, 4.3.1, step 4), both
  in constant time. The retry with Le = 0 now also null-checks its response. Ported from upstream
  JMRTD commit `f2eaee4541a67894fec824c1fcd50fc1c2091ac0`.

- **PACE with DH: validate the PICC's public values and the mapped generator** *(ported from
  JMRTD)*. The PICC's DH public values (mapping and ephemeral) are now validated as in RFC 2631,
  2.1.5 (in `[2, p - 1]` and, when q is known, in the subgroup of order q). PACE-GM
  (`MapNonceGMWithDH`) now rejects a mapped generator of 0 or 1 and keeps q in the mapped
  parameters (needed for that validation in the key agreement step). PACE-IM (`MapNonceImWithDH`)
  now requires q (with the previous fallback q = 1 the mapped generator was always 1), rejects a
  mapped generator of 1, and keeps q. PACE-GM with ECDH (`MapNonceGMWithECDH`) now throws when the
  mapped generator is the point at infinity or not a valid point (it used to be silently
  accepted). Ported from upstream JMRTD commits `242e89c4e5be8ae32c90c4a15ed0aff008655b7a`,
  `a199a6fcf967e1662084106ed4480b8a9b3a5b12`, and `73c7c92f5b1ff4130d40dd433ffcce2f564ef2c7`. The
  other half of `a199a6fc` (the PACE-IM ECDH cofactor multiplication, whose result upstream
  discarded) did not apply: nMRTD's `IcartPointEncode` already used the multiplied point.

### Fixed

- **PACE public key data object with domain parameters** *(ported from JMRTD)*.
  `PaceProtocol.EncodePublicKeyDataObject(..., isContextKnown: false)` now writes q (not the
  private value length l) in DH tag 82, and the EC base point in tag 84 as an uncompressed point
  (Doc 9303 Part 11, 9.4.1) instead of the bare concatenation of its coordinates. Unsupported keys
  and DH keys without q are rejected before anything is written. Ported from upstream JMRTD commit
  `7f476b2172c254152fe9be3dead4bc311e811062`.

- **TD2 composite check digit** *(ported from JMRTD)*. It is now computed over the fields as
  printed: a document number shorter than 9 characters is padded with fillers, and a document
  number longer than 9 characters continues in the optional data field (as TD1 already did).
  Ported from upstream JMRTD commit `bd0633f55c73bfd0fa29d5d0535399318f3ceaf6`.

- **Active Authentication: choose short or extended Le from the secure messaging pad length**
  *(ported from JMRTD)*. The largest signature that still fits a short response APDU is now 223
  bytes with AES secure messaging (231 with 3DES, as before). Ported from upstream JMRTD commit
  `bd0633f55c73bfd0fa29d5d0535399318f3ceaf6`.

- **`SELECT MF` without file identifier** *(ported from JMRTD)*. `SendSelectMf` now sends
  `00 A4 00 0C` without the `3F00` data field. Ported from upstream JMRTD commit
  `4b9bb6309f11e9d22aabf70f8f2afccd4c04e718`.

- **Biometric data fixes** *(ported from JMRTD)*. `FaceInfo` now copies only the bytes actually
  read when reconstructing a bare JPEG 2000 face image (it used to copy the whole 2048-byte buffer,
  padding the image with zeros), `FingerImageRepresentationBlock.GetMimeType()` now returns the
  MIME type of the image data format (it always returned `null`), and
  `IrisImageRepresentationBlock.ToString()` now prints the image data length (its null check was
  inverted). Ported from upstream JMRTD commit `2c08440a1df68b4b8f8d957165e580937f44e74f`.

- **Robustness** *(ported from JMRTD)*. `Util.Unpad` now throws a `CryptographicException` for
  input that is all zero bytes (it used to throw `IndexOutOfRangeException`), `Util.Os2ECPoint`
  rejects input that is not of odd length, and the random filler in an empty CBEFF data group now
  comes from `RandomNumberGenerator`. Ported from upstream JMRTD commit
  `73c7c92f5b1ff4130d40dd433ffcce2f564ef2c7`.

### Changed

- **"Tranceive" is now spelled "transceive"** *(ported from JMRTD)*. The old public names are kept
  as `[Obsolete]` aliases, as upstream did with `@Deprecated`:
  `PassportService.NormalMaxTranceiveLength`, `PassportService.ExtendedMaxTranceiveLength`,
  `PassportService.GetMaxTranceiveLength()`, and `SecureMessagingWrapper.MaxTranceiveLength`. The
  misspelled `GeImageData()` of `FingerImageRepresentationBlock` and
  `IrisImageRepresentationBlock` is now `GetImageData()`, also with an `[Obsolete]` alias.
  Constructor and method parameter names were renamed too, which only affects callers using named
  arguments. Ported from upstream JMRTD commit `2c08440a1df68b4b8f8d957165e580937f44e74f`.

### Not applicable

- `3b64745a4f834a19d79e6ec3cc21d642fa7cca76`, "Bump BC to 1.86": a Maven dependency of the Java
  BouncyCastle provider; nMRTD uses BouncyCastle.Cryptography for .NET, versioned independently.
- `20841a132e5c4d4c3abaeb30d0ab373e94ff8f2c`, "Version 0.8.9": a Maven version bump.
- `ef635cfd147458ef3552fe9e05bc012733b4c11c`, "Use spdx.org compliant license identifier": a
  `pom.xml` change; nMRTD's source files already carry `SPDX-License-Identifier: LGPL-3.0-or-later`.
- `4da6e5945da0a99aa4564d1c5b535c68159447e9`, "DG12: date and time of personalization in 24 hour
  format": `DG12File` already used `yyyyMMddHHmmss`; the `BACKey` `synchronized` removal has no
  counterpart.
- `ab97c153510a82405a26ffa5479e3e0499e31ebc`, "Try-with-resources instead of closing in finally.
  StandardCharsets instead of charset names.": Java resource handling and named charsets only;
  nMRTD already uses `using` and explicit `Encoding` instances.
- From `73c7c92f`, the locale and charset changes did not apply: nMRTD already uses
  `ToUpperInvariant()` and explicit encodings, and builds with `InvariantGlobalization`. From
  `2c08440a`, the `FaceImageCaptureDeviceSpectral2DBlock.equals` fix (boxed `Boolean` compared by
  reference) did not apply: C# compares `bool?` by value.

## 0.4.1-alpha (2026-09-01)

### Added

- **Set the NuGet package icon.** The `nMRTD` package now carries `nMRTD.png` as its icon
  (`PackageIcon`), packed alongside the existing `LICENSE` and `README.md`.

## 0.4.0-alpha (2026-09-01)

**JMRTD upstream alignment status:** nMRTD has been reviewed against upstream JMRTD up to commit
`277cd364` ("Version 0.8.8", 2026-08-26 16:53), the latest commit on the upstream `jmrtd-jmrtd`
repository as of this review. Every commit up to and including that one has been evaluated for
applicability to nMRTD.

### Internal

- **Align `Util.Pad`, `Util.Os2i`, `Util.I2os`, and `SecureMessagingWrapper.CheckMac` with upstream
  performance improvements** *(ported from JMRTD)*. No functional/behavioral change: verified via a
  randomized cross-check (1300+ cases, including zero, power-of-256 boundaries, and both
  under-and-over-sized fixed lengths) confirming the new implementations are byte-for-byte identical
  to the previous ones.
  - `Util.Pad`: precomputes the padded length and does a single `Array.Copy`, instead of appending
    to a `MemoryStream` byte-by-byte.
  - `Util.Os2i`: builds the result directly via `new BigInteger(1, bytes)`, instead of an explicit
    `Multiply`/`Add` loop over each input byte.
  - `Util.I2os(BigInteger, int)`: derives the output from `val.ToByteArray()` via `Array.Copy`,
    instead of an explicit `Mod`/`Divide` loop over each output byte.
  - `Util.I2os(BigInteger)`: sizes the output from `val.BitLength`, instead of
    `val.ToString(16).Length` (mathematically equivalent for non-negative integers, but avoids a
    string allocation).
  - `SecureMessagingWrapper.CheckMac`: feeds the send sequence counter and the padded response data
    to the MAC via two consecutive `BlockUpdate` calls, instead of concatenating them into an
    intermediate buffer first.

  Ported from upstream JMRTD commit `de36540c58bd3badacc095639c32325acb934f80`, "Prefer arraycopy
  over ByteArrayOutputStream writing and other minor perf improvements", and commit
  `e5a69adc20b8217b05859855d7ef2bac9dd86f5e`, "Use bitLength()-based sizing instead of toString(16)
  in i2os".

  Two further upstream commits in this range were reviewed and found not applicable. Commit
  `4559ee00541d3c9ce9894b5272b3b6ad4b0a4444`, "Correct logger names", only renames
  `java.util.logging` logger categories (e.g. `"org.jmrtd"` to `"org.jmrtd.cert"`); nMRTD's
  `LogSource` (`nMRTD/Logging/LogSource.cs`) is deliberately independent of any such static,
  per-class logger registry -- every log call already takes an explicit `category` string, so this
  class of bug cannot occur by construction. Commit `277cd36445d63e037498dae2463cb44bd155f897`,
  "Version 0.8.8", is only a Maven `pom.xml` version bump; nMRTD has its own independent versioning.

## 0.3.0-alpha (2026-08-26)

This release was prompted by a review of six commits pushed to the upstream
[JMRTD](https://jmrtd.org/) Java project (the reference implementation nMRTD is ported from)
between August 25 and August 26, 2026. Two of the three changes below are direct ports of
upstream bug fixes; the third addresses the same underlying issue as an upstream fix but required
a different design due to platform differences between Java's JCA and BouncyCastle.Cryptography
(see below for details). The two upstream commits about improving Java's built-in object
serialization (`readObject`/`writeObject`, `transient` fields) were reviewed but found not
applicable: nMRTD does not implement any binary object-serialization mechanism, by design.

### Fixed

- **Fix personal number check digit generation in TD3 MRZ/DG1** *(ported from JMRTD)*.
  `'<'` is now used in place of a computed `'0'` for the TD3 personal-number check digit only
  when the personal number field itself is empty, per ICAO Doc 9303 Part 4 — not whenever the
  7-3-1 weighted checksum happens to come out to 0. Ported from upstream JMRTD commit
  `c3f29f195b9e89a9aadd28c14c280e225ef8c6c8`, "Fix preference of '<' over '0' when generating
  MRZ/DG1, which should be only for empty string"
  ([Bug #85](https://sourceforge.net/p/jmrtd/bugs/85/)); nMRTD carried the same defect (and the
  same `FIXME` comment) since the initial port.

- **Fix `Equals()`/`GetHashCode()` for `ActiveAuthenticationInfo`, `PACEDomainParameterInfo`, and
  `TerminalAuthenticationInfo`** *(ported from JMRTD)*.
  Their `Equals()` overrides previously re-encoded both sides to DER and compared the encoded
  bytes; they now compare the relevant fields directly, matching the pattern already used by
  `ChipAuthenticationInfo`, `ChipAuthenticationPublicKeyInfo`, and `PACEInfo`. Ported from upstream
  JMRTD commit `fd0be4826309b4b83e2a48a51e36ad4f5ee20067`, "Improve equals(), hashCode() for
  SecurityInfo and other data classes". This is not just a style cleanup: these three types are
  stored in `HashSet<SecurityInfo>` while parsing `EF.CardAccess`, `EF.CardSecurity`, and
  `EF.DG14`, so a fragile, encoding-based equality could cause incorrect deduplication of the
  security infos advertised by the chip.

### Added

- **Add a `TerminalKeySigner` extension point for EAC Terminal Authentication (EAC-TA), to
  support terminal keys backed by an HSM or smart card** *(adapted from JMRTD)*.
  Until now, `PassportService.DoEACTA`/`DoTA` required the terminal private key to always be
  supplied as an in-memory BouncyCastle `AsymmetricKeyParameter` — a type that inherently carries
  the raw private key material. There was no way to perform EAC-TA with a terminal key that lives
  on external, non-extractable key storage (an HSM, a smart card, a PKCS#11 token). Upstream JMRTD
  addresses the equivalent problem in commits `fedf00757aab1672d60ae8dd4572975701e2ca05` and
  `f6aa31ff16a04853c0d27ecb7e9e5063afedb668`, "Fix EAC-TA with HSM backed private key"
  ([Bug #45](https://sourceforge.net/p/jmrtd/bugs/45/)), by avoiding an unnecessary extraction of
  the private key's raw scalar and adding an optional JCA `Provider` parameter so signing can be
  delegated to a provider backed by external key material. BouncyCastle.Cryptography has no
  equivalent pluggable-provider abstraction, so this fix could not be ported as-is: nMRTD closes
  the same gap with a different, .NET-idiomatic design. `DoEACTA`/`DoTA` now accept two new
  optional parameters, `TerminalKeySigner? terminalKeySigner` and `ECDomainParameters?
  terminalKeyEcDomainParameters`. When `terminalKeySigner` is supplied, it is invoked to produce
  the raw signature over the EAC-TA challenge instead of using an in-memory BouncyCastle key — for
  example, backed by .NET's own `ECDsa`/`RSA` types, which can themselves be CNG- or PKCS#11-backed
  and never export the private key. For an ECDSA terminal certificate,
  `terminalKeyEcDomainParameters` supplies the terminal key's *public* curve parameters (never the
  private scalar) so the raw ECDSA signature length can still be computed. Both parameters are
  optional and appended at the end of the existing parameter lists, so this change is fully
  backward compatible with existing callers that pass an in-memory `terminalKey`.


## 0.2.0-alpha (2026-08-23)

First released version of the porting of [JMRTD](https://jmrtd.org/).