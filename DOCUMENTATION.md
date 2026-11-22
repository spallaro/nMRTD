# nMRTD — Technical Documentation

nMRTD is a .NET 6/8/10 library for reading ICAO Doc 9303 electronic Machine Readable Travel
Documents (ePassports, eID cards) over PC/SC-connected contactless readers. It is a
from-scratch C# port of [JMRTD](https://jmrtd.org/). This document is a deep technical
reference for consumers of the library (and for contributors extending it). It assumes
familiarity with ICAO Doc 9303 terminology (MRZ, LDS, Data Groups, EF.SOD) but explains
how each concept maps onto the library's classes and APIs.

## Table of contents

1. [Architecture & Core Concepts](#1-architecture--core-concepts)
2. [Access Control Protocols](#2-access-control-protocols)
3. [Logical Data Structure (LDS) & Data Groups](#3-logical-data-structure-lds--data-groups)
4. [Passive Authentication](#4-passive-authentication)
5. [Native AOT & Trimming Best Practices](#5-native-aot--trimming-best-practices)

---

## 1. Architecture & Core Concepts

### 1.1 Layered class hierarchy

The library is built as a chain of increasingly specialized services, each adding one
layer of behavior over the one below it:

```
CardService (abstract)                          nMRTD/SmartCards/CardService.cs
  └─ FileSystemCardService (abstract)            nMRTD/FileSystemCardService.cs
       └─ AbstractMRTDCardService (abstract)     nMRTD/AbstractMRTDCardService.cs
            └─ PassportService (concrete)        nMRTD/PassportService.cs

PcscCardService : CardService (concrete)         nMRTD/SmartCards/PcscCardService.cs
```

- **`CardService`** is the transport-agnostic contract: `Open()`, `IsOpen`, `Transmit(CommandApdu)`,
  `GetAtr()`, `IsConnectionLost(Exception)`, `Close()`, plus an APDU-listener registry
  (`AddApduListener`/`RemoveApduListener`/`ApduListeners`) used for tracing. It implements
  `IDisposable` (`Dispose()` calls `Close()`).
- **`PcscCardService`** is the concrete transport built on the `PCSC`/`PCSC.Iso7816` NuGet
  packages — the only file in the library that references those packages directly.
- **`FileSystemCardService`** adds `CardFileInputStream GetInputStream(short fid, int maxBlockSize)`
  — the file-oriented read API — to the raw APDU contract.
- **`AbstractMRTDCardService`** adds the whole MRTD protocol surface as abstract methods:
  `DoBAC`, `DoPace`, `DoEACCA`, `DoEACTA`, `DoAA`, `SendSelectApplet`, `SendSelectMf`,
  `GetWrapper()`, `GetMaxReadBinaryLength()`.
- **`PassportService`** is the concrete facade applications instantiate. It wraps an
  injected `CardService` (normally a `PcscCardService`) and implements every abstract
  method above by delegating to a family of protocol classes (`BACProtocol`,
  `PaceProtocol`, `EACCAProtocol`, `EACTAProtocol`, `AAProtocol`) that all share a single
  `SecureMessagingAPDUSender`.

### 1.2 Connecting to a PC/SC reader

`PcscCardService` (`sealed class PcscCardService : CardService`) is constructed with an
optional reader name:

```csharp
public PcscCardService(string? readerName = null);   // null = use the first reader found
public static string[] GetReaderNames();              // enumerate available PC/SC readers
```

`Open()` establishes a PC/SC context (`ContextFactory.Instance.Establish(SCardScope.System)`),
resolves the reader name (or auto-selects the first one, throwing `CardServiceException`
if none are available), and connects with `SCardShareMode.Shared` and `SCardProtocol.Any`
— both T=0 and T=1 are accepted deliberately, because many contactless readers report T=1.
Any `PCSCException` raised during connection is caught and rethrown as a
`CardServiceException`, with the partially-open connection torn down first.

`Transmit(CommandApdu)` allocates a 65538-byte receive buffer (sized for extended-length
responses — DG2 face images can be up to 65536 bytes), calls the underlying PC/SC
`Transmit`, wraps the result in a `ResponseApdu`, and raises an `ApduEvent` to any
registered listeners.

`IsConnectionLost(Exception)` walks the exception's `InnerException` chain looking for a
`PCSCException` and maps card-removal/reset/unresponsive-reader error codes to `true`, so
callers can distinguish a dropped card from a protocol error.

Note that GET RESPONSE chaining and T=0-specific quirks are deliberately *not* handled at
this transport layer — that responsibility belongs to the protocol/APDU-sender layer above
it.

### 1.3 File system abstraction

Two cooperating classes implement file access above the raw transport:

- **`IFileSystemStructured`** (`GetSelectedPath()`, `SelectFile(short fid)`,
  `ReadBinary(int offset, int length)`) is the abstraction `PassportService` programs
  against.
- **`DefaultFileSystem`** is the concrete implementation. It is constructed with an
  `IApduLevelReadBinaryCapable` sender (in practice `ReadBinaryAPDUSender`) and an
  `isSfiEnabled` flag, and translates high-level reads into low-level SELECT FILE / READ
  BINARY APDUs, caching file contents in a `FragmentBuffer` so repeated/overlapping reads
  don't re-transmit already-fetched bytes. `SelectFile(short fid)` does *not* itself send a
  SELECT command — `ReadBinary` sends it lazily only if needed. On a `SwWrongLength`
  (0x6700) response while using an extended block size, `DefaultFileSystem` transparently
  shrinks the read block size to `PassportService.DefaultMaxBlocksize` (223 bytes) and
  retries, accommodating cards that reject large READ BINARY lengths.

`PassportService` keeps **two** `DefaultFileSystem` instances: `_rootFileSystem` (used
before the MRTD applet is selected, e.g. to read `EF.CardAccess`; SFI is always disabled
here because some documents don't support SFI-addressed reads for that file) and
`_appletFileSystem` (used after `SendSelectApplet`, with `isSfiEnabled` as configured by
the caller).

**`CardFileInputStream`** (`sealed class CardFileInputStream : Stream`) is the public
read API surface: a forward-only, lazily-fetching stream over an `IFileSystemStructured`,
reading in `maxBlockSize`-sized chunks. It does not support seeking or writing
(`CanSeek == false`; `Seek`/`SetLength`/`Write` throw `NotSupportedException`); `Length` is
resolved lazily from the file system's parsed header and cached.

### 1.4 Secure Messaging pipeline

Once an access-control protocol (BAC, PACE, or EAC-CA) succeeds, all further APDU traffic
must be wrapped: encrypted and MAC-protected under session keys, per ICAO Doc 9303 /
BSI TR-03110 Secure Messaging.

- **`IApduWrapper`** — `CommandApdu Wrap(CommandApdu)`; `ResponseApdu Unwrap(ResponseApdu)`.
- **`SecureMessagingWrapper`** (abstract, implements `IApduWrapper`) holds the encryption
  key, MAC key, send-sequence counter (SSC), and a `ShouldCheckMac` flag. Concrete
  subclasses `DESedeSecureMessagingWrapper` (3DES, produced by BAC and DESede-flavored
  PACE/EAC-CA) and `AESSecureMessagingWrapper` (AES, produced by AES-flavored PACE/EAC-CA)
  supply the cipher-specific padding length, IV derivation, and SSC encoding.
  - `Wrap(CommandApdu)` increments the SSC, builds a masked-CLA header, pads and encrypts
    the command data into a DO'87 (or DO'85) object, adds a DO'97 expected-length object
    when needed, computes a retail-MAC/AES-CMAC over SSC + padded header + data object +
    DO'97 into a DO'8E object, and assembles the final command, choosing extended-length
    encoding when the payload requires it.
  - `Unwrap(ResponseApdu)` increments the SSC, decrypts DO'87/DO'85, reads the DO'99 status
    word, and — if `ShouldCheckMac` — verifies the DO'8E MAC, throwing
    `InvalidOperationException("Invalid MAC")` on mismatch.
- **`SecureMessagingAPDUSender`** is the single low-level transmit point shared by every
  protocol sender (`BACAPDUSender`, `PACEAPDUSender`, `AAAPDUSender`, `EACCAAPDUSender`,
  `EACTAAPDUSender`, `ReadBinaryAPDUSender`). Its `Transmit(IApduWrapper? wrapper,
  CommandApdu commandApdu)` wraps (if a wrapper is supplied), transmits via the underlying
  `CardService`, unwraps the response, and raises a `WrappedApduEvent` (carrying both the
  plaintext and wrapped APDUs) to listeners, plus a `Trace`-level log line pair
  (`"--> "`/`"<-- "`) via its shared `LogSource`.
- **`ReadBinaryAPDUSender`** implements `IApduLevelReadBinaryCapable` and is what
  `DefaultFileSystem` actually talks to: it builds SELECT APPLET / SELECT MF / SELECT FILE
  / READ BINARY APDUs (SFI form, offset form, and TLV-encoded-offset "long read" form),
  sends them through `SecureMessagingAPDUSender.Transmit`, and maps status words to
  `CardServiceException` (`SwFileNotFound` → "File not found",
  `SwSecurityStatusNotSatisfied`/`SwConditionsNotSatisfied`/`SwCommandNotAllowed` →
  "Access to file denied", etc.).

End-to-end read path after authentication: `CardFileInputStream` →
`DefaultFileSystem.ReadBinary` → `ReadBinaryAPDUSender.SendReadBinary` →
`SecureMessagingAPDUSender.Transmit(wrapper, …)` → `wrapper.Wrap` → `CardService.Transmit`
→ `wrapper.Unwrap`.

### 1.5 `PassportService` — public API reference

Namespace `nMRTD`, class `PassportService : AbstractMRTDCardService`.

**Constants.** PACE key references: `NoPaceKeyReference` (0x00), `MrzPaceKeyReference`
(0x01), `CanPaceKeyReference` (0x02), `PinPaceKeyReference` (0x03), `PukPaceKeyReference`
(0x04). File IDs: `EF_CARD_ACCESS` (0x011C), `EF_CARD_SECURITY` (0x011D), `EF_DG1`…`EF_DG16`
(0x0101–0x0110), `EF_SOD` (0x011D), `EF_COM` (0x011E), `EF_CVCA` (0x011C). Corresponding
short file IDs `SFI_CARD_ACCESS`…`SFI_CVCA`. Block sizes: `DefaultMaxBlocksize = 223`,
`NormalMaxTransceiveLength = 256`, `ExtendedMaxTransceiveLength = 65536`.

**Constructors:**

```csharp
public PassportService(
    CardService service,
    int maxTransceiveLengthForSecureMessaging,
    int maxBlockSize,
    bool isSfiEnabled,
    bool shouldCheckMac);

public PassportService(
    CardService service,
    int maxTransceiveLengthForPaceProtocol,
    int maxTransceiveLengthForSecureMessaging,
    int maxBlockSize,
    bool isSfiEnabled,
    bool shouldCheckMac);
```

The first constructor forwards to the second with `maxTransceiveLengthForPaceProtocol =
NormalMaxTransceiveLength`. The (primary) constructor builds one shared
`SecureMessagingAPDUSender` and all protocol senders around it, plus the two
`DefaultFileSystem` instances described in §1.3.

**Session lifecycle:**

- `void Open()` — opens the underlying `CardService`; idempotent if already open. The
  caller is responsible for calling `SendSelectApplet` afterwards.
- `bool IsOpen { get; }`
- `void SendSelectApplet(bool shouldUseSecureMessaging)` — selects the ICAO MRTD applet
  AID. Pass `true` after a successful PACE run (secure messaging already established, so
  the SELECT itself is wrapped); pass `false` to select in the clear, in which case the
  caller must follow up with `DoBAC`.
- `void SendSelectMf()` — selects the master file and clears the current secure-messaging
  wrapper on both internal file systems (used to return to an unauthenticated state, e.g.
  before re-running EAC-TA against a fresh certificate chain).
- `void Close()` — closes the underlying `CardService` and clears wrapper state.

**Access-control protocols** (all under an internal lock, mirroring the original Java
`synchronized` methods; each also updates `_wrapper` and the applet file system's wrapper
on success):

- `BACResult DoBAC(IAccessKeySpec bacKey)` — throws `ArgumentException` if `bacKey` is not
  an `IBacKeySpec`.
- `BACResult DoBAC(KeyParameter kEnc, KeyParameter kMac)` — BAC with explicit static keys.
- `PACEResult DoPace(IAccessKeySpec keySpec, string oid, object staticParameters, BigInteger? parameterId)`.
- `EACCAResult DoEACCA(BigInteger? keyId, string? oid, string? publicKeyOID, AsymmetricKeyParameter publicKey)`.
- `EACTAResult DoEACTA(CVCPrincipal? caReference, IReadOnlyList<CardVerifiableCertificate> terminalCertificates, AsymmetricKeyParameter? terminalKey, string? taAlg, EACCAResult? chipAuthenticationResult, string? documentNumber)`.
- `EACTAResult DoEACTA(CVCPrincipal? caReference, IReadOnlyList<CardVerifiableCertificate> terminalCertificates, AsymmetricKeyParameter? terminalKey, string? taAlg, EACCAResult? chipAuthenticationResult, PACEResult paceResult)`.
- `AAResult DoAA(AsymmetricKeyParameter publicKey, string? digestAlgorithm, string signatureAlgorithm, byte[] challenge)`.

**File access:**

- `CardFileInputStream GetInputStream(short fid, int maxBlockSize)` — the primary read
  entry point. Selects `_rootFileSystem` or `_appletFileSystem` depending on whether the
  applet has been selected yet, then returns a stream over the requested file.
  `[Obsolete] GetInputStream(short fid)` forwards to this using the service's configured
  `maxBlockSize`.
- `int GetMaxReadBinaryLength()` / `int GetMaxTransceiveLength()`.
- `SecureMessagingWrapper? GetWrapper()` — the currently active wrapper, if any (with a
  documented Java-parity quirk: it reconciles against the applet file system's own wrapper
  by SSC value, in case the two have drifted).

**Diagnostics:**

- `void AddApduListener(IApduListener listener)` / `RemoveApduListener` /
  `IReadOnlyCollection<IApduListener> ApduListeners` — observe every wrapped/raw APDU
  exchange.
- `void AddLogListener(ILogListener listener)` / `RemoveLogListener` /
  `IReadOnlyCollection<ILogListener> LogListeners` — observe structured log events (APDU
  trace lines plus protocol-level narration) from every protocol object in the session,
  since they all share one `LogSource`.

### 1.6 Capability interfaces

Each protocol depends on a narrow interface expressing only the low-level APDU
interactions it needs, implemented by a corresponding `XxxAPDUSender`:

| Interface | Implementor | Purpose |
|---|---|---|
| `IApduLevelBacCapable` | `BACAPDUSender` | `SendGetChallenge()`, `SendMutualAuth(...)` |
| `IApduLevelPaceCapable` | `PACEAPDUSender` | `SendMseSetAtMutualAuth(...)`, `SendGeneralAuthenticate(...)` |
| `IApduLevelEacCACapable` | `EACCAAPDUSender` | `SendMseKat`, `SendMseSetAtIntAuth`, `SendGeneralAuthenticate` |
| `IApduLevelEacTACapable` | `EACTAAPDUSender` | `SendMseSetDst`, `SendPsoExtendedLengthMode`, `SendMseSetAtExtAuth`, `SendGetChallenge`, `SendMutualAuthenticate` |
| `IApduLevelAACapable` | `AAAPDUSender` | `SendInternalAuthenticate(...)` |
| `IApduLevelReadBinaryCapable` | `ReadBinaryAPDUSender` | `SendSelectApplet`, `SendSelectMf`, `SendSelectFile`, `SendReadBinary` |

### 1.7 Access-key specifications

- `IAccessKeySpec { string GetAlgorithm(); byte[] GetKey(); }` is the root abstraction for
  anything that can be turned into a key-derivation seed (BAC or PACE).
- `IBacKeySpec : IAccessKeySpec` adds `GetDocumentNumber()`, `GetDateOfBirth()` (`yyMMdd`),
  `GetDateOfExpiry()` (`yyMMdd`).
- `BacKey : IBacKeySpec` — constructible from `DateTime`s or from `yyMMdd` strings; the
  document number is right-padded with `<` to 9 characters. `GetAlgorithm()` returns
  `"BAC"`; `GetKey()` returns `Util.ComputeKeySeed(documentNumber, dateOfBirth,
  dateOfExpiry, "SHA-1", isMrz: true)`.
- `PaceKeySpec : IAccessKeySpec` — wraps a CAN/PIN/PUK/MRZ-derived value plus a PACE key
  reference byte. Factory helpers: `CreateMrzKey(IBacKeySpec mrz)`, `CreateCanKey(string
  can)`, `CreatePinKey(string pin)`, `CreatePukKey(string puk)`.

### 1.8 Exceptions

```
Exception
└─ CardServiceException                     -- carries Sw (status word; -1 = "not set")
      ├─ AccessDeniedException  [Obsolete]   -- + AccessKey
      ├─ BacDeniedException     [Obsolete]   -- + BacKey
      └─ CardServiceProtocolException        -- + Step (int), Message includes "(step: N)"
            └─ PaceException    [Obsolete]
```

`CardServiceException` is thrown throughout the transport and file-system layers on
transceive failures, missing readers, and unexpected status words. Every current protocol
implementation (BAC/PACE/EAC/AA) throws `CardServiceProtocolException` — carrying a
numeric `Step` identifying which stage of the protocol failed — rather than the
`[Obsolete]` `AccessDeniedException`/`BacDeniedException`/`PaceException`, which are kept
only for source compatibility with older JMRTD-style call sites.

`SecureMessagingWrapper.Wrap`/`Unwrap` throw plain `InvalidOperationException` (not
`CardServiceException`) on cryptographic/format errors such as an invalid MAC.

### 1.9 Logging

`nMRTD.Logging` provides a lightweight, allocation-cheap logging seam independent of any
external logging framework:

- `LogLevel` — `Trace, Debug, Information, Warning, Error`.
- `LogEvent` — `readonly record struct LogEvent(DateTimeOffset Timestamp, LogLevel Level, string Category, string Message, Exception? Exception = null)`.
- `ILogListener { void Log(LogEvent logEvent); }`.
- `DelegateLogListener` — adapts an `Action<LogEvent>` lambda to `ILogListener`, avoiding
  the need for a dedicated listener class.
- `LogSource` — the dispatcher: `AddListener`/`RemoveListener`/`Listeners`, plus
  convenience wrappers `Trace`, `Debug`, `Info`, `Warn`, `Error(category, message,
  exception = null)`. A single `LogSource` instance is shared by the whole
  `PassportService` session, so one subscription via `AddLogListener` observes both
  low-level APDU trace lines (tagged `"--> "`/`"<-- "`) and protocol-level narration.

```csharp
passportService.AddLogListener(new DelegateLogListener(logEvent =>
{
    Console.WriteLine($"[{logEvent.Level}] {logEvent.Category}: {logEvent.Message}");
}));
```

### 1.10 End-to-end usage flow

```csharp
using nMRTD;
using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.SmartCards;

var cardService = new PcscCardService(readerName: null);   // first reader found
var passportService = new PassportService(
    cardService,
    PassportService.NormalMaxTransceiveLength,
    PassportService.DefaultMaxBlocksize,
    isSfiEnabled: true,
    shouldCheckMac: true);

passportService.Open();

// Prefer PACE when EF.CardAccess advertises it; otherwise fall back to BAC.
byte[] cardAccessBytes = ReadFileBytes(passportService, PassportService.EF_CARD_ACCESS);
var cardAccessFile = new CardAccessFile(new MemoryStream(cardAccessBytes));
var paceInfo = cardAccessFile.GetSecurityInfos().OfType<PACEInfo>().FirstOrDefault();

if (paceInfo != null)
{
    var parameterId = paceInfo.GetParameterId();
    // Standardized parameters, or explicit ones from a PACEDomainParameterInfo in EF.CardAccess.
    object staticParameters = PaceParameters.Resolve(paceInfo, cardAccessFile.GetSecurityInfos());
    IAccessKeySpec paceKey = PaceKeySpec.CreateMrzKey(bacKey);

    passportService.DoPace(paceKey, paceInfo.GetObjectIdentifier(), staticParameters, parameterId);
    passportService.SendSelectApplet(true);
}
else
{
    passportService.SendSelectApplet(false);
    passportService.DoBAC(bacKey);
}

// Read data groups.
byte[] dg1Bytes = ReadFileBytes(passportService, PassportService.EF_DG1);
var mrz = new DG1File(new MemoryStream(dg1Bytes)).GetMRZInfo();

passportService.Close();

static byte[] ReadFileBytes(PassportService passportService, short fid)
{
    using Stream stream = passportService.GetInputStream(fid, PassportService.DefaultMaxBlocksize);
    using var buffer = new MemoryStream();
    stream.CopyTo(buffer);
    return buffer.ToArray();
}
```

A complete runnable version of this flow — including reader selection, PACE-with-BAC
fallback, DG1–DG16 parsing, and full Passive Authentication — is in
[`nMRTD.Cli/Program.cs`](nMRTD.Cli/Program.cs).

---

## 2. Access Control Protocols

All four protocols below are implemented as standalone classes that operate against the
narrow `IApduLevelXxxCapable` interfaces from §1.6, so they can in principle be exercised
independently of `PassportService`. Every OID is registered on the `SecurityInfo` base
class (`nMRTD/Lds/SecurityInfo.cs`), whose static factory

```csharp
public static SecurityInfo? GetInstance(Asn1Encodable obj)
```

parses a `{oid, requiredData, optionalData?}` ASN.1 SEQUENCE from `EF.CardAccess` or DG14
and dispatches on `oid` to `ActiveAuthenticationInfo`, `ChipAuthenticationPublicKeyInfo`,
`ChipAuthenticationInfo`, `TerminalAuthenticationInfo`, `PACEInfo`, or
`PACEDomainParameterInfo`, returning `null` for unrecognized OIDs rather than throwing
(`CardAccessFile`/`DG14File` silently skip entries they don't recognize).

### 2.1 BAC (Basic Access Control)

**Key derivation.** The BAC key seed is derived from three printed MRZ fields (document
number, date of birth, date of expiry, each with their ICAO 7-3-1 check digit) via SHA-1:
`Util.ComputeKeySeed(documentNumber, dateOfBirth, dateOfExpiry, "SHA-1", doTruncate: true)`,
exposed through `BacKey.GetKey()`.

**Entry point:**

```csharp
public class BACProtocol
{
    public BACProtocol(IApduLevelBacCapable service, int maxTransceiveLength, bool shouldCheckMac, LogSource? log = null);
    public BACResult DoBAC(IAccessKeySpec bacKey);
    public BACResult DoBAC(KeyParameter kEnc, KeyParameter kMac);
    public static byte[] ComputeKeySeedForBAC(IBacKeySpec bacKey);
    public static long ComputeSendSequenceCounter(byte[] rndIcc, byte[] rndIfd);
}
```

**Protocol flow** (`DoBAC(IAccessKeySpec)`):

1. Derive static 3DES keys `kEnc`/`kMac` from the key seed via `Util.DeriveKey` (ICAO 9303
   Appendix D.1 key derivation, "ENC"/"MAC" modes).
2. **GET CHALLENGE** — `SendGetChallenge()` returns the chip's 8-byte nonce `rndIcc`.
3. Generate the terminal's own nonce `rndIfd` (8 bytes) and ephemeral key material `kIfd`
   (16 bytes) with a cryptographically secure RNG.
4. **EXTERNAL AUTHENTICATE (mutual authenticate)** — `SendMutualAuth(rndIfd, rndIcc, kIfd,
   kEnc, kMac)` encrypts `rndIfd‖rndIcc‖kIfd` with 3DES-CBC under `kEnc` (zero IV), MACs it
   with retail-MAC under `kMac`, and sends it; the chip's response, decrypted the same way,
   yields `rndIcc‖rndIfd‖kIcc` (32 bytes) — proving both sides know the shared secret.
5. `keySeed = kIfd XOR kIcc`; derive session keys `ksEnc`/`ksMac` from it via
   `Util.DeriveKey`.
6. The send-sequence counter is initialized deterministically from the two nonces:
   `ssc = rndIcc[4..8] ‖ rndIfd[4..8]` as a 64-bit big-endian counter
   (`ComputeSendSequenceCounter`).
7. Returns a `BACResult` wrapping a fresh `DESedeSecureMessagingWrapper(ksEnc, ksMac,
   maxTransceiveLength, shouldCheckMac, ssc)`.

**`BACResult`**: `{ IAccessKeySpec? BacKey, SecureMessagingWrapper Wrapper }`.

**Failure modes.** Any card-side rejection (wrong keys, i.e. the MRZ data doesn't match the
document) or malformed response is wrapped as `CardServiceProtocolException`.

### 2.2 PACE (Password Authenticated Connection Establishment)

PACE (ICAO TR-SAC 1.01 / BSI TR-03110) supersedes BAC on modern documents: it establishes
a much stronger session key using a password-authenticated Diffie-Hellman exchange, so an
eavesdropper who cannot read the MRZ/CAN cannot brute-force the session.

**Access-key types.** `PaceKeySpec` covers all four password sources defined by the
standard:

```csharp
var mrzKey = PaceKeySpec.CreateMrzKey(bacKey);   // same MRZ fields as BAC
var canKey = PaceKeySpec.CreateCanKey("500540"); // Card Access Number printed on the document
var pinKey = PaceKeySpec.CreatePinKey(pin);
var pukKey = PaceKeySpec.CreatePukKey(puk);
```

> **Important:** a CAN can only be used for PACE. Unlike the MRZ, it cannot be used to
> derive a BAC key — there is no BAC fallback path for CAN-only authentication.

`PaceProtocol.ComputeKeySeedForPace(IAccessKeySpec)` dispatches on the concrete type: for
an `IBacKeySpec` (MRZ), it hashes the same three MRZ fields as BAC but with `isMrz: false`
(a different padding convention per TR-SAC); for a `PaceKeySpec` (CAN/PIN/PUK), the raw
bytes are used directly as input to the later PACE-specific KDF (mode 3, "PACE_MODE").

**OID → algorithm dispatch.** `PACEInfo` exposes static helpers that decode a PACE OID
into its constituent algorithm choices:

```csharp
static MappingType ToMappingType(string oid);        // GM | IM | CAM
static string ToKeyAgreementAlgorithm(string oid);    // "DH" | "ECDH"
static string ToCipherAlgorithm(string oid);          // "DESede" | "AES"
static string ToDigestAlgorithm(string oid);          // "SHA-1" | "SHA-256"
static int ToKeyLength(string oid);                   // 128 | 192 | 256
static object ToParameterSpec(BigInteger? standardDomainParameterId);
```

The `ToParameterSpec` mapping covers the 19 ICAO-standardized domain-parameter IDs
(`PARAM_ID_GFP_1024_160` … `PARAM_ID_ECP_NIST_P521_R1`), returning either a BouncyCastle
`DHParameters` (RFC 5114 groups) or `ECDomainParameters` (NIST/Brainpool named curves).
`PACEDomainParameterInfo` is used instead of `PACEInfo` when the document specifies
explicit, non-standard domain parameters (via a BouncyCastle `AlgorithmIdentifier`);
its `GetParameters()` returns them as `ECDomainParameters` (explicit EC parameters) or
`DHParameters` (X9.42 DH parameters).

`PaceParameters.Resolve(paceInfo, securityInfos)` (an nMRTD addition, not part of JMRTD)
picks the right one for a `PACEInfo` from all the security infos of EF.CardAccess: a
parameter id from 0 to 31 is standardized (`ToParameterSpec`), any other parameter id
names the `PACEDomainParameterInfo` with the same id, and no parameter id means the only
`PACEDomainParameterInfo` for the protocol. It throws `ArgumentException` when none fits.

`CardAccessFile` (`EF.CardAccess`) parses the bare `SET OF SecurityInfo` and exposes
`GetSecurityInfos()`, from which a consumer filters for a `PACEInfo`.

**Entry point:**

```csharp
public class PaceProtocol
{
    public PaceProtocol(
        IApduLevelPaceCapable service,
        SecureMessagingWrapper? wrapper,
        int maxTransceiveLengthForProtocol,
        int maxTransceiveLengthForSecureMessaging,
        bool shouldCheckMac,
        LogSource? log = null);

    public PACEResult DoPace(IAccessKeySpec accessKey, string oid, object staticParameters, BigInteger? parameterId);
}
```

**Protocol flow** (ICAO TR-SAC 1.01 Table 3.3):

1. **Step 0 — MSE:Set AT.** Resolve mapping type/agreement/cipher/digest/key length from
   the OID, validate them against the concrete type of `staticParameters`, then
   `SendMseSetAtMutualAuth(wrapper, oid, keyReference, encodedParameterId)`.
2. **Step 1 — nonce.** An empty GENERAL AUTHENTICATE returns the chip's nonce, encrypted
   under the static password-derived key; decrypting it (AES/3DES-CBC, zero IV) yields the
   plaintext nonce `s`.
3. **Step 2 — mapping.** Depending on `MappingType`:
   - **Generic Mapping (GM)** and **Chip Authentication Mapping (CAM):** both sides
     exchange ephemeral "mapping" public keys over the *static* domain parameters; the
     resulting shared point/value is combined with the nonce to derive the *ephemeral*
     (mapped) domain parameters used for the real key agreement (`G~ = [s]G + H` for ECDH,
     `g~ = g^s · h mod p` for DH).
   - **Integrated Mapping (IM):** the terminal generates its own nonce `t` instead of an
     ephemeral key pair; both nonces feed a pseudo-random function (`R_p`, TR 9303-11
     §4.4.3.3.2) whose output is mapped onto the curve/group directly (Icart point
     encoding for ECDH, exponentiation for DH) — this variant needs only one round trip
     instead of two ephemeral-key exchanges.
4. **Step 3 — ephemeral key agreement.** Both sides generate an ephemeral key pair over the
   *mapped* domain parameters, exchange public keys, and derive the raw shared secret `K`.
5. Session keys `encKey`/`macKey` are derived from `K` via `Util.DeriveKey`.
6. **Step 4 — authentication tokens.** Each side computes a MAC (retail-MAC for
   `DESede`/AES-CMAC for `AES`) over a TLV encoding of the *other* side's ephemeral public
   key, exchanges tokens, and verifies the received token against a locally recomputed
   expected value — proving both sides derived the same shared secret. A mismatch raises
   `CardServiceProtocolException` at step 4.
7. Secure Messaging restarts with a fresh `DESedeSecureMessagingWrapper`/
   `AESSecureMessagingWrapper` built from `encKey`/`macKey` (SSC reset to 0, except AES
   preserves the previous wrapper's SSC per a documented TR-SAC quirk).
8. **CAM only:** an additional encrypted Chip Authentication data block, delivered inside
   the step-4 response, is decrypted with `encKey` — folding Chip Authentication into the
   PACE exchange itself, so a separate `DoEACCA` call is unnecessary when CAM is used
   (decryption failure here is only logged, not fatal, and the result is still returned
   with a `null` chip-authentication payload).

**Result classes.** `PACEResult` carries `PaceKey`, `MappingType`, `AgreementAlg`,
`CipherAlg`, `DigestAlg`, `KeyLength`, `MappingResult`, the terminal's ephemeral key pair,
the chip's public key, and the resulting `Wrapper`. `PACECAMResult : PACEResult` adds
`GetEncryptedChipAuthenticationData()`/`GetChipAuthenticationData()`. Intermediate mapping
results (`PACEGMMappingResult`, `PACEGMWithDHMappingResult`,
`PACEGMWithECDHMappingResult`, `PACEIMMappingResult`) are exposed via
`PACEResult.MappingResult` for callers that need the raw ephemeral material.

**Error handling.** Every step wraps failures (card-side status words, cryptographic
mismatches) as `CardServiceProtocolException` tagged with a step number (0–4).
`ArgumentException` is thrown instead for pure configuration mistakes — an OID/parameter
combination that doesn't parse to a supported agreement/cipher/digest/key-length, or a
`staticParameters` object whose runtime type doesn't match the OID's agreement algorithm.

### 2.3 EAC — Chip Authentication (`EACCAProtocol`)

Chip Authentication (CA) proves the chip holds the private key corresponding to a public
key certified in `DG14`, and — as a side effect — re-keys Secure Messaging with a
stronger, ephemeral-DH-derived session key than BAC/PACE alone provide. (When PACE is run
in CAM mode, this step is already folded into PACE step 4 and does not need to be repeated
— see §2.2.)

```csharp
public class EACCAProtocol
{
    public EACCAProtocol(IApduLevelEacCACapable service, SecureMessagingWrapper wrapper, int maxTransceiveLength, bool shouldCheckMac, LogSource? log = null);
    public EACCAResult DoCA(BigInteger? keyId, string? oid, string? publicKeyOID, AsymmetricKeyParameter piccPublicKey);
}
```

**Protocol flow:**

1. If `oid` is not supplied, it is inferred from the DG14 public-key's own OID
   (`ID_PK_ECDH → ID_CA_ECDH_3DES_CBC_CBC`, `ID_PK_DH → ID_CA_DH_3DES_CBC_CBC`) — a
   best-effort fallback for documents whose DG14 omits an explicit
   `ChipAuthenticationInfo` entry for the key.
2. Resolve the agreement algorithm (`ChipAuthenticationInfo.ToKeyAgreementAlgorithm(oid)`)
   and generate an ephemeral terminal key pair over the chip's DG14 public-key domain
   parameters.
3. Send the terminal's public key to the chip: `MSE:KAT` for 3DES variants, or
   `MSE:Set AT` + `GENERAL AUTHENTICATE` (with command-chaining fallback) for AES variants.
4. Compute `KeyHash` — SHA-1 of the DH public value, or the field-sized affine X coordinate
   for ECDH — needed later as input to Terminal Authentication's signed challenge.
5. Compute the shared secret via `EACCAProtocol.ComputeSharedSecret(agreementAlg,
   piccPublicKey, pcdPrivateKey)` (ECDH/DH basic agreement, unsigned big-endian, sized to
   the field/modulus — this static method is also reused directly by `PaceProtocol` for its
   own ephemeral key agreement in §2.2 step 3, since both protocols need the same
   primitive).
6. Derive fresh session keys from the shared secret and restart Secure Messaging with a
   **new wrapper whose SSC is reset to 0**.

**`EACCAResult`**: `{ BigInteger? KeyId, AsymmetricKeyParameter? PublicKey (chip's),
SecureMessagingWrapper Wrapper, AsymmetricKeyParameter? PCDPublicKey, PCDPrivateKey,
GetKeyHash() }`. `GetKeyHash()` is what gets fed into Terminal Authentication.

### 2.4 EAC — Terminal Authentication (`EACTAProtocol`)

Terminal Authentication (TA) authenticates the *terminal* to the chip, unlocking access to
sensitive data groups (DG3 fingerprints, DG4 iris) that Chip Authentication alone does not
release. It requires a Card Verifiable (CV) certificate chain rooted at a Country
Verifying CA the chip trusts, and a terminal private key matching the leaf (Inspection
System) certificate.

```csharp
public class EACTAProtocol
{
    public EACTAProtocol(IApduLevelEacTACapable service, SecureMessagingWrapper wrapper, LogSource? log = null);

    public EACTAResult DoEACTA(
        CVCPrincipal? caReference,
        IReadOnlyList<CardVerifiableCertificate> terminalCertificates,
        AsymmetricKeyParameter? terminalKey,
        string? taAlg,
        EACCAResult? chipAuthenticationResult,
        string? documentNumber);

    public EACTAResult DoTA(
        CVCPrincipal? caReference,
        IReadOnlyList<CardVerifiableCertificate> terminalCertificates,
        AsymmetricKeyParameter? terminalKey,
        string? taAlg,
        EACCAResult? chipAuthenticationResult,
        PACEResult paceResult);
}
```

The chip-identifying challenge material (`idPICC`) is derived either from the BAC document
number (ISO-8859-1 bytes plus its ICAO check digit) or from the PACE result's chip public
key (same SHA-1/affine-X derivation used for `EACCAResult.GetKeyHash()`) — hence the two
overloads.

**Protocol flow** (BSI TR-03110 §B.2):

1. If the first certificate in `terminalCertificates` is self-signed with role `Cvca`, it
   is treated as a locally-trusted anchor (validated against `caReference` if supplied) and
   excluded from the certificates actually sent to the chip.
2. Validate the (possibly trimmed) chain: its first certificate must be signed by
   `caReference`, and the last certificate must have role `Is` (Inspection System /
   terminal certificate) — this becomes `terminalCert`.
3. For each certificate to send, in order: **MSE:Set DST** (naming the issuing authority)
   followed by **PSO:Verify Certificate** (sending the certificate body and signature) —
   this walks the chain up to the terminal certificate, letting the chip verify each link
   itself.
4. **MSE:Set AT** names the terminal certificate as the external-authenticate reference.
5. **GET CHALLENGE** retrieves the chip's fresh nonce `rPICC`.
6. **EXTERNAL AUTHENTICATE**: the terminal signs `idPICC ‖ rPICC ‖ caKeyHash` (the CA
   key-hash from step 2.3) with `terminalKey`, using the signature algorithm implied by the
   terminal certificate's public-key OID (e.g. `SHA256withECDSA`). ECDSA signatures are
   converted from BouncyCastle's DER encoding to the raw `r‖s` format TR-03110 requires
   before being sent.

**`EACTAResult`**: `{ EACCAResult? ChipAuthenticationResult, CVCPrincipal? CAReference,
IReadOnlyList<CardVerifiableCertificate> CVCertificates, AsymmetricKeyParameter?
TerminalKey, string? DocumentNumber, GetCardChallenge() }`.

`TerminalAuthenticationInfo` (a `SecurityInfo` found in DG14) carries the TA version and an
optional pointer to which file holds `EF.CVCA` (parsed by `CVCAFile` — a fixed 36-byte,
non-BER structure holding one or two Certification Authority References).

### 2.5 Card Verifiable (CV) certificate infrastructure

TR-03110-3 Appendix C certificates are implemented directly under `nMRTD.Cert`, with no
external CVC library dependency:

```csharp
public sealed class CardVerifiableCertificate
{
    public CVCPrincipal AuthorityReference { get; }
    public CVCPrincipal HolderReference { get; }
    public CVCAuthorizationTemplate AuthorizationTemplate { get; }
    public DateOnly NotBefore { get; }
    public DateOnly NotAfter { get; }
    public byte[] Signature { get; }
    public string? SigAlgName { get; }
    public AsymmetricKeyParameter? PublicKey { get; }        // null for an EC key without explicit domain params
    public byte[]? RawEcPublicKeyPoint { get; }               // 0x04‖X‖Y, always present for EC keys

    public static CardVerifiableCertificate Parse(Stream inputStream);
    public static CardVerifiableCertificate Parse(byte[] data);
    public byte[] GetEncoded();
    public byte[] GetCertBodyData();       // exactly the bytes the signature covers
    public void Verify(AsymmetricKeyParameter issuerPublicKey);   // throws CryptographicException on failure
}
```

ECDSA signatures use TR-03110's raw `r‖s` convention rather than BouncyCastle's default DER
`SEQUENCE{r,s}`; the class converts between the two internally. Dates are `YYMMDD` fields in unpacked BCD,
one digit per byte (6 bytes, TR-03110-3 D.2.1.3), with years 2000+YY.

`CVCertificateBuilder.CreateCertificate(publicKey, signerKey, algorithmName, caRef,
holderRef, authorizationTemplate, validFrom, validTo)` builds and signs a new certificate —
useful for terminal provisioning/testing. `CVCertificateFactorySpi.EngineGenerateCertificate(Stream)`
is a thin, statically-dispatched shim over `CardVerifiableCertificate.Parse` (see §5.2 for
why this is written as a plain static method rather than a dynamic factory-by-name).

`CVCAuthorizationTemplate` (the CHAT — Certificate Holder Authorization Template) encodes
the certificate's role (`Role.Cvca`, `Role.DvDomestic`, `Role.DvForeign`, `Role.Is`) and
its DG3/DG4 read permissions (`Permission.ReadAccessNone/Dg3/Dg4/Dg3AndDg4`) into a single
discretionary-data byte. `CVCPrincipal` models the flat CAR/CHR reference field (2-letter
country code + up to 9-character mnemonic + 5-digit sequence number).

### 2.6 Active Authentication (`AAProtocol`)

Active Authentication proves the chip (not just the data) is genuine, by having it sign a
terminal-supplied random challenge with a private key whose public counterpart is stored in
DG15 and certified via EF.SOD.

```csharp
public class AAProtocol
{
    public AAProtocol(IApduLevelAACapable service, SecureMessagingWrapper? wrapper, LogSource? log = null);
    public AAResult DoAA(AsymmetricKeyParameter publicKey, string? digestAlgorithm, string? signatureAlgorithm, byte[] challenge);
}
```

**Protocol flow:**

1. The caller supplies an 8-byte random `challenge`.
2. A single **INTERNAL AUTHENTICATE** round trip is sent
   (`SendInternalAuthenticate(wrapper, approximateSignatureLength, challenge)`), where
   `approximateSignatureLength` is estimated from the DG15 public key
   (`Util.GetApproximateSignatureSize`) to pick a suitable expected response length,
   including a retry with an extended `Le` if the card indicates more data is available.
3. `AAProtocol` returns the raw signature bytes; it does **not** verify them itself. The
   caller is expected to verify the returned signature over the challenge against
   `publicKey` (from DG15) using `digestAlgorithm`/`signatureAlgorithm` — both of which are
   carried through unchanged into the result purely so the caller doesn't have to track
   them separately.

**`AAResult`**: `{ AsymmetricKeyParameter? PublicKey, string? DigestAlgorithm, string?
SignatureAlgorithm, GetChallenge(), GetResponse() }`.

```csharp
// After DoAA(...):
AsymmetricKeyParameter dg15PublicKey = new DG15File(dg15Bytes).GetPublicKey()!;
ISigner verifier = SignerUtilities.GetSigner(aaResult.SignatureAlgorithm ?? "SHA1withRSA/ISO9796-2");
verifier.Init(forSigning: false, dg15PublicKey);
verifier.BlockUpdate(aaResult.GetChallenge(), 0, aaResult.GetChallenge().Length);
bool isGenuine = verifier.VerifySignature(aaResult.GetResponse());
```

`ActiveAuthenticationInfo` (a `SecurityInfo`, OID `2.23.136.1.1.5`) restricts the supported
signature algorithms to a fixed ECDSA-plain OID set under the BSI arc, when present in
`EF.CardAccess`/DG14; RSA-based Active Authentication (the far more common case in
practice, using ISO 9796-2 padding) is signaled implicitly by the presence of a DG15 RSA
key rather than a dedicated `SecurityInfo`.

---

## 3. Logical Data Structure (LDS) & Data Groups

### 3.1 File class hierarchy

```
LDSElement (interface)                    -- byte[]? GetEncoded()
  LDSFile (interface)                     -- + int GetLength(); ICAO tag constants
    AbstractLDSFile (abstract)            -- ReadObject/WriteObject template methods
      AbstractTaggedLDSFile (abstract)    -- BER-TLV tag/length framing via TlvInputStream/TlvOutputStream
        DataGroup (abstract)              -- marker base for EF.DG1..DG16
          CBEFFDataGroup (abstract)       -- DG2, DG3, DG4 (biometric container)
          DisplayedImageDataGroup         -- DG5, DG6, DG7
          AdditionalDetailDataGroup       -- DG11, DG12
          DG1File, DG14File, DG15File     -- direct DataGroup subclasses
        COMFile                          -- EF.COM (sibling of DataGroup, not a numbered DG)
        SODFile                          -- EF.SOD (sibling of DataGroup, not a numbered DG)
```

`AbstractTaggedLDSFile.ReadObject(Stream)` opens a `TlvInputStream`, reads and validates
the expected ICAO tag (`ArgumentException` on mismatch), reads the BER-TLV length, and
calls the abstract `ReadContent(Stream)` hook with the tag/length already consumed;
`WriteObject` mirrors this on the way out. `LDSFile` defines every relevant ICAO tag:
`EF_COM_TAG = 0x60`, DG tags generally follow `0x60 + n` **except** DG2 (`0x75`) and DG4
(`0x76`), and `EF_SOD_TAG = 0x77` — exactly per Doc 9303 Table A1.

### 3.2 Dispatch: `LDSFileUtil`

`LDSFileUtil.GetLDSFile(short fid, Stream inputStream)` is the factory that turns a raw
byte stream read from a given file ID into the correct concrete type:

```csharp
public static AbstractLDSFile GetLDSFile(short fid, Stream inputStream)
{
    switch (fid)
    {
        case PassportService.EF_COM: return new COMFile(inputStream);
        case PassportService.EF_DG1: return new DG1File(inputStream);
        case PassportService.EF_DG2: return new DG2File(inputStream);
        // ... DG3, DG4, DG5, DG6, DG7 ...
        case PassportService.EF_DG11: return new DG11File(inputStream);
        case PassportService.EF_DG12: return new DG12File(inputStream);
        case PassportService.EF_DG14: return new DG14File(inputStream);
        case PassportService.EF_DG15: return new DG15File(inputStream);
        case PassportService.EF_SOD: return new SODFile(inputStream);
        case PassportService.EF_CVCA: return new CVCAFile(inputStream);
        case PassportService.EF_DG8:
        case PassportService.EF_DG9:
        case PassportService.EF_DG10:
        case PassportService.EF_DG13:
        case PassportService.EF_DG16:
            throw new NotSupportedException("DGn files are not yet supported");
        // ...
    }
}
```

DG8–DG10, DG13, and DG16 have no ICAO-standardized parseable structure implemented (JMRTD
itself never implemented these either — they are largely unused in real-world deployments,
DG13/DG16 being nation-specific and DG8–DG10 reserved for data-feature/structure-feature
biometric variants that saw negligible adoption). `LDSFileUtil` also provides tag↔FID↔SFI↔
data-group-number lookup tables, and two convenience methods used when driving Passive
Authentication:

```csharp
public static List<int> GetDataGroupNumbers(SODFile? sodFile);   // from EF.SOD's hash table keys — the trustworthy source
public static List<int> GetDataGroupNumbers(COMFile? comFile);   // from EF.COM's advertised tag list
```

Consumers implementing Passive Authentication should prefer the `SODFile`-based list — the
comment in the source is explicit that **EF.COM's tag list should not be trusted** as
authoritative, since it isn't covered by the same signature as the data group hashes are
(see §4).

### 3.3 EF.COM

`COMFile` (tag `0x60`) declares the document's LDS/Unicode version and which data groups
are present:

```csharp
public COMFile(string versionLDS, string updateLevelLDS, string majorVersionUnicode,
    string minorVersionUnicode, string releaseLevelUnicode, int[] tagList);
public COMFile(string ldsVer, string unicodeVer, int[] tagList);  // "x.y"/"x.y.z" convenience form
public COMFile(Stream inputStream);

public string GetLDSVersion();       // e.g. "1.7"
public string GetUnicodeVersion();   // e.g. "4.0.0"
public int[] GetTagList();           // ICAO tags of the DGs present, per Doc 9303 Table A1
```

### 3.4 EF.SOD

See §4 for the full Passive Authentication treatment; the structural summary:

`SODFile` (tag `0x77`) wraps a BouncyCastle CMS `SignedData` (RFC 3369) whose
`encapContentInfo` carries an ICAO `LdsSecurityObject` — the per-data-group hash table.
Key read-side members:

```csharp
public SortedDictionary<int, byte[]> GetDataGroupHashes();  // DG number -> stored hash bytes
public string? GetDigestAlgorithm();                        // digest used for the DG hashes, e.g. "SHA-256"
public byte[] GetEContent();                                // exact bytes the signature covers
public byte[] GetEncryptedDigest();                          // raw signature bytes over GetEContent()
public string? GetDigestEncryptionAlgorithm();               // e.g. "SHA256withRSA"
public List<X509Certificate> GetDocSigningCertificates();
public X509Certificate? GetDocSigningCertificate();
```

### 3.5 DG1 — Machine Readable Zone

`DG1File` (tag `0x61`) wraps a single `MRZInfo` (inner tag `0x5F1F`):

```csharp
public DG1File(MRZInfo mrzInfo);
public DG1File(Stream inputStream);
public MRZInfo GetMRZInfo();
```

`MRZInfo` supports all three ICAO MRZ formats — TD1 (3×30 chars), TD2/MRV-B (2×36), TD3/
MRV-A (2×44) — auto-detected by length when parsed from the card, or built explicitly via
`CreateTD1MRZInfo`/`CreateTD2MRZInfo`/`CreateTD3MRZInfo`/`CreateMRVAMRZInfo`/
`CreateMRVBMRZInfo`. Full field accessor list:

```csharp
public string GetDocumentCode();              // e.g. "P" (passport), "PN", "V", "I"
public string GetIssuingState();               // 3-letter code
public string GetNameOfHolder();               // "PRIMARY<<SECONDARY" formatted
public string GetPrimaryIdentifier();          // surname(s)
public string GetSecondaryIdentifier();        // given name(s)
public string[] GetSecondaryIdentifierComponents();
public string GetNationality();                // 3-letter code
public string GetDocumentNumber();
public string? GetPersonalNumber();            // decoded from optional data (TD1/TD3)
public string GetDateOfBirth();                // raw "yyMMdd" — no century inference
public Gender GetGenderCode();
public string GetDateOfExpiry();               // raw "yyMMdd"
public string GetOptionalData1();
public string? GetOptionalData2();
public static char CheckDigit(string? str);    // ICAO 7-3-1 check digit, also used for BAC key derivation
public override string ToString();             // reconstructs the 2- or 3-line printable MRZ text
```

### 3.6 DG2, DG3, DG4 — Biometric data (face, fingerprint, iris)

DG2/DG3/DG4 all derive from `CBEFFDataGroup`, which decodes an ISO/IEC 7816-11 (CBEFF)
Biometric Information Template wrapping one of two possible encodings, auto-selected per
record from the record's Standard Biometric Header format-type value:

- **ISO/IEC 19794** (the common case — `19794-5` face, `19794-4` finger, `19794-6` iris).
- **ISO/IEC 39794** (the newer ASN.1-based replacement standard).

**DG2 (face, tag `0x75`):**

```csharp
public DG2File(Stream inputStream);
public static DG2File CreateISO19794DG2File(List<FaceInfo> faceInfos);
public static DG2File CreateISO39794DG2File(List<FaceImageDataBlock> faceImageDataBlocks, ISO39794EncodingProfile? profile = null);
[Obsolete] public List<FaceInfo> GetFaceInfos();   // ISO-19794 convenience accessor
```

Extraction chain for the ISO-19794 path (the interoperable format virtually every document
in the field uses):

```csharp
DG2File dg2 = new(dg2Stream);
foreach (FaceInfo faceInfo in dg2.GetFaceInfos())
{
    foreach (FaceImageInfo faceImageInfo in faceInfo.GetFaceImageInfos())
    {
        using Stream imageStream = faceImageInfo.GetImageInputStream();
        string? mimeType = faceImageInfo.GetMimeType();   // "image/jpeg" or "image/jp2"
        // faceImageInfo also exposes GetGender(), GetEyeColor(), GetHairColor(),
        // GetExpression(), GetPoseAngle()/GetPoseAngleUncertainty(), GetFeaturePoints(),
        // GetQuality(), GetWidth()/GetHeight(), and more Section 5.5-5.7 metadata.
    }
}
```

For documents encoded per ISO/IEC 39794, `GetSubRecords()` (inherited from
`CBEFFDataGroup`) returns `FaceImageDataBlock` entries instead, reachable through the
`nMRTD.Lds.Iso39794` block tree (`FaceImageRepresentationBlock` →
`FaceImageRepresentation2DBlock` → `FaceImageCoordinateTextureImageBlock`) rather than
through the simpler `FaceImageInfo` shape.

**DG3 (fingerprint, tag `0x63`)** and **DG4 (iris, tag `0x76`)** follow the identical
CBEFF/ISO-19794-vs-39794 structure, mirrored one level deeper for DG4 (iris records group
by eye first):

```csharp
// DG3:
DG3File dg3 = new(dg3Stream);
foreach (FingerInfo fingerInfo in dg3.GetFingerInfos())
    foreach (FingerImageInfo img in fingerInfo.GetFingerImageInfos())
        { /* img.GetPosition(), img.GetImpressionType(), img.GetImageInputStream(), ... */ }

// DG4:
DG4File dg4 = new(dg4Stream);
foreach (IrisInfo irisInfo in dg4.GetIrisInfos())
    foreach (IrisBiometricSubtypeInfo eye in irisInfo.GetIrisBiometricSubtypeInfos())  // EYE_LEFT / EYE_RIGHT
        foreach (IrisImageInfo img in eye.GetSubRecords())
            { /* img.GetImageInputStream(), img.GetQuality(), ... */ }
```

> DG3 and DG4 are protected by Extended Access Control on virtually every issuing state —
> reading them requires a successful Terminal Authentication run (§2.4) first; the library
> itself does not enforce this (the chip does), it simply returns whatever
> `CardServiceException` the chip raises if access is attempted without it.

### 3.7 DG5, DG6, DG7 — Displayed images

`DisplayedImageDataGroup` is the shared base for the three "displayed" image data groups
(distinct from the biometric-matching images in DG2–DG4: these are printed-photo-quality
JPEGs meant for human/visual verification, not automated matching):

```csharp
public DG5File(List<DisplayedImageInfo> images);   public DG5File(Stream inputStream);   // portrait
public DG6File(Stream inputStream);                                                       // (reserved)
public DG7File(List<DisplayedImageInfo> images);   public DG7File(Stream inputStream);   // signature/mark

public List<DisplayedImageInfo> GetImages();   // on DisplayedImageDataGroup
```

`DisplayedImageInfo` extends `AbstractImageInfo`, always JPEG, and enforces the expected
`ImageType` per file (`DG5File` requires `TYPE_PORTRAIT`, `DG7File` requires
`TYPE_SIGNATURE_OR_MARK`, throwing `ArgumentException` on a mismatched constructor call).

### 3.8 DG11, DG12 — Additional personal / document detail

Both derive from `AdditionalDetailDataGroup`, which implements a shared "tag list, then
fields in that order" TLV encoding.

> **Preserved upstream quirk:** `AdditionalDetailDataGroup`'s protected constructor ignores
> its `tag` parameter and always builds with the DG11 tag internally, as in JMRTD. It does not
> affect the encoding: `DG11File` and `DG12File` override `GetTag()`, which is what
> `WriteObject` writes, so a `DG12File` built from data is encoded with tag `0x6C` and reads
> back through the stream constructor.

```csharp
// DG11 (tag 0x6B):
public string? GetNameOfHolder();
public List<string>? GetOtherNames();
public string? GetPersonalNumber();
public string? GetFullDateOfBirth();          // "CCYYMMDD"
public List<string>? GetPlaceOfBirth();
public List<string>? GetPermanentAddress();
public string? GetTelephone();
public string? GetProfession();
public string? GetTitle();
public string? GetPersonalSummary();
public byte[]? GetProofOfCitizenship();       // JPEG (ISO/IEC 10918)
public List<string>? GetOtherValidTDNumbers();
public string? GetCustodyInformation();

// DG12 (tag 0x6C):
public string? GetIssuingAuthority();
public string? GetDateOfIssue();                        // "yyyyMMdd"
public List<string>? GetNamesOfOtherPersons();
public string? GetEndorsementsAndObservations();
public string? GetTaxOrExitRequirements();
public byte[]? GetImageOfFront();                       // JPEG
public byte[]? GetImageOfRear();                        // JPEG
public string? GetDateAndTimeOfPersonalization();        // "yyyyMMddHHmmss"
public string? GetPersonalizationSystemSerialNumber();
```

All fields on both types are optional — every accessor returns `null` (or an empty list)
when the corresponding tag isn't present on the document.

### 3.9 DG14, DG15 — Security infos and Active Authentication key

`DG14File` (tag `0x6E`) stores the document's `SET OF SecurityInfo` — this is where Chip
Authentication, PACE domain-parameter, and Terminal Authentication capability information
for EAC-capable documents live (`EF.CardAccess` typically only advertises PACE):

```csharp
public DG14File(IEnumerable<SecurityInfo> securityInfos);
public DG14File(Stream inputStream);
public IReadOnlyCollection<SecurityInfo> GetSecurityInfos();
```

`DG15File` (tag `0x6F`) stores the Active Authentication public key as a bare X.509
`SubjectPublicKeyInfo` (RSA or EC, dispatched by the embedded algorithm OID — never by
JCA-provider-name guessing):

```csharp
public DG15File(AsymmetricKeyParameter publicKey);
public DG15File(Stream inputStream);
public AsymmetricKeyParameter? GetPublicKey();
```

### 3.10 Country codes

`IcaoCountry.GetInstance(string alpha3Code)` layers ICAO-specific codes not present in ISO
3166-1 (legacy `D<<` for Germany, `XXA` stateless, UN organization codes, etc.) on top of
the standard `Country` lookup table — used internally when resolving `MRZInfo`'s raw
3-letter nationality/issuing-state codes for display.

### 3.11 CBEFF and biometric block layers (internal plumbing)

`nMRTD.Cbeff` (ISO/IEC 7816-11) and the per-format block trees under `nMRTD.Lds.Iso19794`
and `nMRTD.Lds.Iso39794` implement the container/record structure that DG2/DG3/DG4 decode
into. Application code normally reaches biometric data entirely through the `DGnFile`
accessors shown in §3.6 and rarely needs to touch `BiometricDataBlock`/
`StandardBiometricHeader` directly, except when writing code that must distinguish the
ISO-19794 and ISO-39794 encodings explicitly. `ISO39794EncodingProfile` is worth knowing
about specifically: it's a C# enum (`Base` vs `Icao39794_5EmrtdV1`) that only affects
*encoding* (`DGnFile.CreateISO39794DGnFile(..., profile)`) — decoding transparently accepts
either profile.

The TLV/ASN.1 substrate underneath all of this (`TlvInputStream`, `TlvOutputStream`,
`TlvUtil`, `ASN1Util`) is likewise internal plumbing: every `ReadContent`/`ReadObject`
override in the LDS layer uses it, but library consumers should not need to construct these
types directly.

---

## 4. Passive Authentication

Passive Authentication (Doc 9303 Part 11 §3) proves that the data groups read off a
document have not been tampered with since the issuing state signed them. It is called
"passive" because — unlike Active Authentication or Chip Authentication — it involves no
challenge/response with the chip: it is pure offline cryptographic verification of data
already read.

**It answers exactly one question: "does this data match what the issuer certified?"** It
does **not** prove the chip presenting the data is the genuine chip that data was written
to (that is what Active Authentication / Chip Authentication are for — a cloned chip can
replay a perfectly valid, passively-authenticatable data set).

### 4.1 What EF.SOD contains

`EF.SOD` is a CMS/PKCS#7 `SignedData` structure (RFC 3369) whose signed content is an ICAO
`LdsSecurityObject`: a digest algorithm identifier plus a list of `(dataGroupNumber,
hashValue)` pairs — one entry per data group the issuer included when personalizing the
document. The `SignedData` also embeds (or references) the Document Signer (DS)
certificate whose private key produced the signature, and that signature covers the
`LdsSecurityObject` content.

`SODFile` (§3.4) parses all of this and exposes it without performing any verification
itself — it is a pure data object. The verification logic below is intentionally left to
the API consumer; **the library ships no orchestration method that performs it for you**
(there is no `PassiveAuthenticationService`-style class), because the amount of trust
material required (a CSCA store, revocation status, national deviation lists) is
deployment-specific and outside the library's scope. `nMRTD.Cli/Program.cs` contains a
complete, runnable worked example — `VerifyPassiveAuthentication` — reproduced and
explained below.

### 4.2 Step 1 — per-data-group hash comparison

For every data group actually read off the document, recompute its hash with the digest
algorithm `SODFile` declares, and compare against the corresponding stored value:

```csharp
static byte[] ComputeDigest(string digestAlgorithm, byte[] data)
{
    IDigest digest = DigestUtilities.GetDigest(digestAlgorithm);
    digest.BlockUpdate(data, 0, data.Length);
    byte[] result = new byte[digest.GetDigestSize()];
    digest.DoFinal(result, 0);
    return result;
}

static void CheckDataGroupHashes(SODFile sodFile, IReadOnlyDictionary<int, byte[]> dataGroupBytes)
{
    string digestAlgorithm = sodFile.GetDigestAlgorithm()
        ?? throw new InvalidOperationException("EF.SOD does not declare a digest algorithm.");

    SortedDictionary<int, byte[]> storedHashes = sodFile.GetDataGroupHashes();

    foreach ((int dgNumber, byte[] rawBytes) in dataGroupBytes)
    {
        if (!storedHashes.TryGetValue(dgNumber, out byte[]? expectedHash))
        {
            // DG present on the chip but not listed in EF.SOD -- treat as a failure too.
            throw new InvalidOperationException($"DG{dgNumber} is not covered by EF.SOD.");
        }

        byte[] actualHash = ComputeDigest(digestAlgorithm, rawBytes);
        if (!actualHash.AsSpan().SequenceEqual(expectedHash))
        {
            throw new InvalidOperationException($"DG{dgNumber}: hash mismatch against EF.SOD.");
        }
    }
}
```

Note that `rawBytes` here is simply the byte stream read directly from the card for that
file ID (i.e. what `GetInputStream(fid).CopyTo(...)` produces) — the same bytes
`AbstractLDSFile.GetEncoded()` would reproduce for a parsed `DataGroup` object, including
the ICAO tag and length octets. There is no need to re-encode a parsed `DGnFile` object;
hashing the raw bytes read off the chip is both simpler and closer to what the issuer
actually signed.

Use `LDSFileUtil.GetDataGroupNumbers(sodFile)` (not the `COMFile` overload) to decide which
data groups *should* be checked — EF.COM's advertised tag list is not itself covered by the
EF.SOD signature and should not be trusted as authoritative for this purpose.

### 4.3 Step 2 — signature verification

```csharp
static void VerifySodSignature(SODFile sodFile)
{
    // GetEContent() also performs the RFC 5652 §5.4 content-digest-vs-signed-attribute
    // check internally, and throws if the two disagree -- so simply calling it is itself
    // a verification step, not just an accessor.
    byte[] eContent = sodFile.GetEContent();
    byte[] encryptedDigest = sodFile.GetEncryptedDigest();

    string digestEncryptionAlgorithm = sodFile.GetDigestEncryptionAlgorithm()
        ?? throw new InvalidOperationException("EF.SOD does not declare a signature algorithm.");
    X509Certificate docSigningCertificate = sodFile.GetDocSigningCertificate()
        ?? throw new InvalidOperationException("EF.SOD does not embed a document signer certificate.");

    AsymmetricKeyParameter publicKey = docSigningCertificate.GetPublicKey();
    ISigner verifier = SignerUtilities.GetSigner(digestEncryptionAlgorithm);
    verifier.Init(forSigning: false, publicKey);
    verifier.BlockUpdate(eContent, 0, eContent.Length);

    if (!verifier.VerifySignature(encryptedDigest))
    {
        throw new InvalidOperationException("EF.SOD signature is invalid.");
    }
}
```

`SODFile.GetEContent()` returns the DER encoding of the CMS `signedAttributes` set when
present (the case for every ICAO-conformant document, which always signs a message-digest
attribute rather than the raw content directly, per RFC 5652 §5.4) — and, as a documented
side effect, `SignedDataUtil.GetEContent` recomputes the digest of the raw
`LdsSecurityObject` content and compares it against the signed `messageDigest` attribute,
throwing if they disagree. This means simply calling `GetEContent()` already performs one
integrity check before you even get to verifying the outer signature.

### 4.4 What this does *not* prove: CSCA trust

The two checks above establish that EF.SOD, and every data group you compared against it,
are internally consistent and were signed by whoever holds the private key matching
`docSigningCertificate` — but **not** that this certificate belongs to a legitimate issuing
authority. A malicious actor who can produce their own self-signed (or otherwise untrusted)
Document Signer certificate can build a perfectly internally-consistent, signature-valid
`EF.SOD` for arbitrary data.

Full Passive Authentication additionally requires validating `docSigningCertificate`
against a **Country Signing CA (CSCA)** certificate from a trust store the relying party
controls (per Doc 9303 Part 12), and checking it hasn't been revoked (CRL/master list
status). **The library implements neither of these** — there is no bundled CSCA trust
store, and no certificate-path-validation helper in `nMRTD`. This is a deliberate scope
boundary: trust-anchor management is a deployment/policy concern (which CSCAs to trust,
how to refresh master lists, how to handle revocation) that belongs in application code,
not in the protocol library. Consumers building a production verifier should combine the
checks above with `X509Chain`/`CertPathValidator`-style validation against their own CSCA
store.

---

## 5. Native AOT & Trimming Best Practices

### 5.1 Current project configuration

Both projects multi-target `net6.0;net8.0;net10.0`. Native AOT tooling is only first-class in
the SDK from .NET 7/8 onward, so AOT- and trim-analyzer properties are split accordingly.
`net8.0` is out of support but kept on purpose: it gives .NET 8 and 9 apps an AOT-compatible
build (without it they would get the `net6.0` one, which is not AOT-annotated or analyzed).

`nMRTD/nMRTD.csproj` (the library):

```xml
<PropertyGroup>
  <TargetFrameworks>net6.0;net8.0;net10.0</TargetFrameworks>
  <IsTrimmable>true</IsTrimmable>
  <EnableTrimAnalyzer>true</EnableTrimAnalyzer>
  <InvariantGlobalization>true</InvariantGlobalization>
</PropertyGroup>

<!-- IsAotCompatible / EnableAotAnalyzer / EnableSingleFileAnalyzer: net8.0 and later. -->
<PropertyGroup Condition="$([MSBuild]::IsTargetFrameworkCompatible('$(TargetFramework)', 'net8.0'))">
  <IsAotCompatible>true</IsAotCompatible>
  <EnableAotAnalyzer>true</EnableAotAnalyzer>
  <EnableSingleFileAnalyzer>true</EnableSingleFileAnalyzer>
</PropertyGroup>
```

`IsTrimmable`/`EnableTrimAnalyzer`/`InvariantGlobalization` apply to **all** target
frameworks — the ILLink trim analyzer itself works from `net6.0` onward, even though full
Native AOT publishing does not. `IsAotCompatible`/`EnableAotAnalyzer`/
`EnableSingleFileAnalyzer` apply to `net8.0` and `net10.0`.

`nMRTD.Cli/nMRTD.Cli.csproj` (the console consumer, which actually publishes as a native
executable):

```xml
<PropertyGroup>
  <TargetFrameworks>net6.0;net8.0;net10.0</TargetFrameworks>
  <InvariantGlobalization>true</InvariantGlobalization>
</PropertyGroup>

<PropertyGroup Condition="$([MSBuild]::IsTargetFrameworkCompatible('$(TargetFramework)', 'net8.0'))">
  <PublishAot>true</PublishAot>
</PropertyGroup>
```

`net6.0` publishes as a normal (optionally trimmed, self-contained) build; `net8.0` and
`net10.0` publish as true Native AOT executables. Neither project pins a `RuntimeIdentifier` or
`TrimMode` — RID selection is deferred to publish time (`dotnet publish -r <rid> -f
net10.0`), and `TrimMode` stays at the SDK default (`link`: full member-level trimming, the
strictest and most failure-revealing mode) rather than being loosened to `partial` or
`copyused`, which would mask incompatibilities instead of surfacing them at build time.

To publish the CLI (or any AOT-compatible consumer of the library) as a self-contained
native binary:

```bash
dotnet publish nMRTD.Cli -c Release -f net10.0 -r win-x64
dotnet publish nMRTD.Cli -c Release -f net10.0 -r linux-x64
dotnet publish nMRTD.Cli -c Release -f net10.0 -r osx-arm64
dotnet publish nMRTD.Cli -c Release -f net8.0 -r win-x64
```

The only trim warning when publishing is `IL2104` for the third-party `PCSC` assembly; nMRTD
itself produces no AOT or trim warnings on either target. On Windows the native link step needs
`vswhere.exe` on the `PATH` (it is in `C:\Program Files (x86)\Microsoft Visual Studio\Installer`);
a Visual Studio Developer PowerShell has it.

### 5.2 No reflection, no dynamic dispatch — by design

The codebase has a standing, explicitly documented policy (see
[`docs/porting-conventions.md`](docs/porting-conventions.md)) against reflection-based
dispatch, stated in terms of the Java code being ported:

> *Dynamic reflection is always avoided (an AOT requirement). In particular,
> `CVCertificateFactorySpi` (a Java SPI/factory pattern) is translated with explicit
> dispatch (a switch statement or a static factory method), never with a dynamic
> `Class.forName`/`Activator.CreateInstance`.*
>
> *No reflection-based serialization (Java's `Serializable` has no equivalent need for a
> C# `[Serializable]`/`BinaryFormatter` counterpart).*

`CVCertificateFactorySpi` is the concrete example: where the Java original used the JCA
provider registry to look up a `CertificateFactorySpi` implementation dynamically by
algorithm name string, the C# port is a single static method with no lookup step:

```csharp
public static class CVCertificateFactorySpi
{
    public static CardVerifiableCertificate EngineGenerateCertificate(Stream inputStream)
        => CardVerifiableCertificate.Parse(inputStream);
}
```

A repository-wide check confirms this policy is followed consistently: there are no uses
of `Activator.CreateInstance`, `MakeGenericType`, `Reflection.Emit`, `DynamicMethod`,
`Expression.Compile`, `Type.GetType`, `MethodInfo`/`PropertyInfo`-based member lookup,
`BinaryFormatter`, or reflection-driven `System.Text.Json`/`XmlSerializer` anywhere in the
library or CLI, and no `using System.Reflection;` directive exists in any source file. The
many `obj.GetType()` call sites present (roughly 90, mostly in `Equals()` type guards and
in diagnostic/log message interpolation) are all AOT/trim-safe — they reflect only on an
already-live instance for identity comparison or display, never to drive member lookup or
dynamic instantiation.

**Guidance for consumers:** if you extend the library (e.g. adding a new `SecurityInfo`
subclass, a new CV certificate signature algorithm, or a new DG13/DG16 parser), preserve
this pattern — dispatch on OID/tag/type via an explicit `switch` or a static lookup table
populated at compile time, never via a runtime type-name-to-`Type` lookup or
`Activator.CreateInstance`. This is what keeps the whole call graph statically analyzable
by the AOT compiler and the trimmer.

### 5.3 One caveat: generic-enum helpers in the ISO/IEC 39794 block layer

A handful of ISO/IEC 39794 block types (`FaceImageInformation2DBlock`,
`IrisImageRepresentationBlock`, `PADDataBlock`, and a few siblings) use a small private
generic helper to decode an integer code into a nullable enum value:

```csharp
private static T? FromCode<T>(int code) where T : struct, Enum =>
    Enum.IsDefined(typeof(T), code) ? (T)(object)code : null;
```

This is the one call shape in the codebase that touches `typeof(T)`/`Enum.IsDefined`
reflection rather than pure static dispatch. It is a fully-constrained enum-generic
pattern that current .NET SDKs generally accept without a trim/AOT warning, but because it
is the sole exception to the "no reflection" rule, it is worth knowing about if a future
SDK tightens analysis around enum-constrained generics — `EnableTrimAnalyzer`/
`EnableAotAnalyzer` (already on for the library, per §5.1) are exactly the mechanism that
would catch a regression here, so keep them enabled in any downstream build that also
publishes AOT.

### 5.4 Dependency posture

The two third-party dependencies are both fully-managed, reflection-light:

- **`BouncyCastle.Cryptography`** (v2.x — the actively maintained managed C# port, distinct
  from the legacy `Portable.BC` package) is used directly through its typed APIs
  (`AsymmetricKeyParameter`, `ISigner`, `IDigest`, `Asn1Object`, etc.) rather than through
  any JCA-style provider-string registry. `SignedDataUtil`'s `LookupMnemonicByOid`/
  `LookupOidByMnemonic` are the project's own hand-written OID↔mnemonic tables (plain
  `if`/`string.Equals` chains) used specifically instead of relying on any external
  provider-lookup mechanism. BouncyCastle's own `DigestUtilities.GetDigest(string)` and
  `SignerUtilities.GetSigner(string)` (used throughout the protocol and Passive
  Authentication code) are backed by BC-internal static lookup tables populated at
  type-initialization time — not dynamic type loading — so they are AOT/trim-safe as used,
  though this is a property of BouncyCastle's own implementation rather than something
  nMRTD controls directly.
- **`PCSC`/`PCSC.Iso7816`** wrap the platform's native PC/SC library (WinSCard on Windows,
  PC/SC-lite on Linux/macOS) via P/Invoke, confined entirely to `PcscCardService.cs`. This
  is inherently a native-interop boundary rather than a reflection concern; it works
  unmodified under Native AOT since P/Invoke is fully supported (indeed one of the
  motivating use cases for AOT).

### 5.5 `InvariantGlobalization`

Both projects set `InvariantGlobalization=true` unconditionally (both target frameworks).
This is required for the smallest, most portable AOT/trimmed output (it removes the ICU
globalization data dependency), and is safe here because the library's parsing/formatting
needs are narrow and culture-invariant by nature: MRZ fields, hex-encoded APDUs, OIDs, and
BCD-encoded certificate dates are all fixed ASCII/binary formats with no locale-sensitive
interpretation. If you build a UI layer on top of `nMRTD` that needs full culture-aware
formatting (e.g. localized display of `MRZInfo.GetDateOfBirth()`), perform that formatting
in your own consuming project rather than reintroducing full ICU into the library's own
publish output — keep the culture-aware layer at the edge, above the protocol library.

### 5.6 Practical checklist for AOT-publishing a consumer

1. Target `net8.0` (or later) — `net6.0` cannot be AOT-published even though it builds and
   runs fine as a regular/trimmed app.
2. Set `<PublishAot>true</PublishAot>` in your own executable project, following the same
   `net8.0`-and-later conditioning pattern shown in §5.1 if you also multi-target `net6.0`.
3. Keep `EnableAotAnalyzer`/`EnableTrimAnalyzer` turned on during development so any
   incompatibility — in your own code, not just nMRTD's — surfaces as a build warning
   rather than a runtime failure after publishing.
4. Publish with an explicit runtime identifier: `dotnet publish -c Release -f net10.0 -r
   <rid>` (AOT compilation is inherently platform-specific; there is no portable AOT
   output).
5. If you add your own reflection-based logic on top of nMRTD's types (custom
   serialization, a plugin system, etc.), that code — not the library — becomes the
   trimming/AOT risk surface; annotate it explicitly with `[DynamicallyAccessedMembers]`/
   `[RequiresUnreferencedCode]`/`[RequiresDynamicCode]` as appropriate, or avoid the
   reflection entirely, following the same static-dispatch discipline the library itself
   uses.
