# Release Notes

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