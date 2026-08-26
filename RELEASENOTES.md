# Release Notes

## 0.3.0-alpha (2026-08-26)

### Fixed

- **Fix personal number check digit generation in TD3 MRZ/DG1.**
  `'<'` is now used in place of a computed `'0'` for the TD3 personal-number check digit only
  when the personal number field itself is empty, per ICAO Doc 9303 Part 4 — not whenever the
  7-3-1 weighted checksum happens to come out to 0. Ported from upstream jMRTD's fix for
  [Bug #85](https://sourceforge.net/p/jmrtd/bugs/85/); nMRTD carried the same defect (and the
  same `FIXME` comment) since the initial port.

- **Fix `Equals()`/`GetHashCode()` for `ActiveAuthenticationInfo`, `PACEDomainParameterInfo`, and
  `TerminalAuthenticationInfo`.**
  Their `Equals()` overrides previously re-encoded both sides to DER and compared the encoded
  bytes; they now compare the relevant fields directly, matching the pattern already used by
  `ChipAuthenticationInfo`, `ChipAuthenticationPublicKeyInfo`, and `PACEInfo`. This is not just a
  style cleanup: these three types are stored in `HashSet<SecurityInfo>` while parsing
  `EF.CardAccess`, `EF.CardSecurity`, and `EF.DG14`, so a fragile, encoding-based equality could
  cause incorrect deduplication of the security infos advertised by the chip.

### Added

- **Add a `TerminalKeySigner` extension point for EAC Terminal Authentication (EAC-TA), to
  support terminal keys backed by an HSM or smart card.**
  Until now, `PassportService.DoEACTA`/`DoTA` required the terminal private key to always be
  supplied as an in-memory BouncyCastle `AsymmetricKeyParameter` — a type that inherently carries
  the raw private key material. There was no way to perform EAC-TA with a terminal key that lives
  on external, non-extractable key storage (an HSM, a smart card, a PKCS#11 token), the way
  upstream jMRTD supports via a pluggable JCA `Provider` (see jMRTD Bug #45, "Fix EAC-TA with HSM
  backed private key"). Since BouncyCastle.Cryptography has no equivalent provider abstraction,
  nMRTD closes this gap differently: `DoEACTA`/`DoTA` now accept two new optional parameters,
  `TerminalKeySigner? terminalKeySigner` and `ECDomainParameters? terminalKeyEcDomainParameters`.
  When `terminalKeySigner` is supplied, it is invoked to produce the raw signature over the EAC-TA
  challenge instead of using an in-memory BouncyCastle key — for example, backed by .NET's own
  `ECDsa`/`RSA` types, which can themselves be CNG- or PKCS#11-backed and never export the private
  key. For an ECDSA terminal certificate, `terminalKeyEcDomainParameters` supplies the terminal
  key's *public* curve parameters (never the private scalar) so the raw ECDSA signature length can
  still be computed. Both parameters are optional and appended at the end of the existing
  parameter lists, so this change is fully backward compatible with existing callers that pass an
  in-memory `terminalKey`.
