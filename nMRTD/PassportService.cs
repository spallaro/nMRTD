/*
 * nMRTD - A .Net API for accessing Machine Readable Travel Documents.
 *
 * Copyright (C) Sebastiano Pallaro.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * This is a porting from jMRTD, Copyright (C) The jMRTD Team (https://jmrtd.org/).
 *
 * Distributed under the terms of GNU LGPL v3.
 * See LICENSE for more information.
 */

using BigInteger = Org.BouncyCastle.Math.BigInteger;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

using nMRTD.Cert;
using nMRTD.Logging;
using nMRTD.Protocol;
using nMRTD.SmartCards;

namespace nMRTD;

/// <summary>
/// Port of <c>org.jmrtd.PassportService</c>: card service for reading files (such as data groups) and
/// using the various access control protocols (BAC, PACE, EAC-TA), clone-detection verification protocols
/// (AA, EAC-CA), and the resulting secure messaging as implemented by the MRTD ICC. This is the concrete
/// root-namespace integration layer that every other already-committed forward reference in this port
/// (<c>PaceKeySpec.cs</c>, <c>DefaultFileSystem.cs</c>, <c>Lds/CVCAFile.cs</c>, <c>Lds/LDSFileUtil.cs</c>)
/// points at; the constant names below (both the PascalCase <c>PaceKeyReference</c> family and the
/// ALL-CAPS <c>EF_*</c>/<c>SFI_*</c> family) are not a stylistic choice made here -- they are dictated
/// verbatim by those already-committed call sites (the two families were established by different earlier
/// porting passes and use different casing conventions; this file must satisfy both exactly).
///
/// ADAPTATION: Java's <c>synchronized</c> instance methods and <c>synchronized(this)</c>/
/// <c>synchronized(rootFileSystem)</c>/<c>synchronized(appletFileSystem)</c> blocks become a private
/// <see cref="_lock"/> object, matching the lock-object convention used throughout this port (e.g.
/// <c>BACAPDUSender.cs</c>). The one exception is <see cref="GetInputStream(short, int)"/>, which also locks
/// the file system instance itself: <see cref="CardFileInputStream"/> locks that same instance (as SCUBA's
/// <c>synchronized(fs)</c> does) while it re-selects its file and reads, so selecting a file and binding a
/// stream to it cannot interleave with another stream's reads.
/// </summary>
public class PassportService : AbstractMRTDCardService
{
    private const string LogCategory = "PassportService";

    /// <summary>Shared secret type for non-PACE key.</summary>
    public const byte NoPaceKeyReference = 0x00;

    /// <summary>Shared secret type for PACE according to BSI TR-03110 v2.03 B.11.1.</summary>
    public const byte MrzPaceKeyReference = 0x01;

    /// <summary>Shared secret type for PACE according to BSI TR-03110 v2.03 B.11.1.</summary>
    public const byte CanPaceKeyReference = 0x02;

    /// <summary>Shared secret type for PACE according to BSI TR-03110 v2.03 B.11.1.</summary>
    public const byte PinPaceKeyReference = 0x03;

    /// <summary>Shared secret type for PACE according to BSI TR-03110 v2.03 B.11.1.</summary>
    public const byte PukPaceKeyReference = 0x04;

    /// <summary>Card Access.</summary>
    public const short EF_CARD_ACCESS = 0x011C;

    /// <summary>Card Security.</summary>
    public const short EF_CARD_SECURITY = 0x011D;

    /// <summary>File identifier for data group 1. Data group 1 contains the MRZ.</summary>
    public const short EF_DG1 = 0x0101;

    /// <summary>File identifier for data group 2. Data group 2 contains face image data.</summary>
    public const short EF_DG2 = 0x0102;

    /// <summary>File identifier for data group 3. Data group 3 contains finger print data.</summary>
    public const short EF_DG3 = 0x0103;

    /// <summary>File identifier for data group 4. Data group 4 contains iris data.</summary>
    public const short EF_DG4 = 0x0104;

    /// <summary>File identifier for data group 5. Data group 5 contains displayed portrait.</summary>
    public const short EF_DG5 = 0x0105;

    /// <summary>File identifier for data group 6. Data group 6 is RFU.</summary>
    public const short EF_DG6 = 0x0106;

    /// <summary>File identifier for data group 7. Data group 7 contains displayed signature.</summary>
    public const short EF_DG7 = 0x0107;

    /// <summary>File identifier for data group 8. Data group 8 contains data features.</summary>
    public const short EF_DG8 = 0x0108;

    /// <summary>File identifier for data group 9. Data group 9 contains structure features.</summary>
    public const short EF_DG9 = 0x0109;

    /// <summary>File identifier for data group 10. Data group 10 contains substance features.</summary>
    public const short EF_DG10 = 0x010A;

    /// <summary>File identifier for data group 11. Data group 11 contains additional personal details.</summary>
    public const short EF_DG11 = 0x010B;

    /// <summary>File identifier for data group 12. Data group 12 contains additional document details.</summary>
    public const short EF_DG12 = 0x010C;

    /// <summary>File identifier for data group 13. Data group 13 contains optional details.</summary>
    public const short EF_DG13 = 0x010D;

    /// <summary>File identifier for data group 14. Data group 14 contains security infos.</summary>
    public const short EF_DG14 = 0x010E;

    /// <summary>File identifier for data group 15. Data group 15 contains the public key used for Active Authentication.</summary>
    public const short EF_DG15 = 0x010F;

    /// <summary>File identifier for data group 16. Data group 16 contains person(s) to notify.</summary>
    public const short EF_DG16 = 0x0110;

    /// <summary>The security document.</summary>
    public const short EF_SOD = 0x011D;

    /// <summary>The data group presence list.</summary>
    public const short EF_COM = 0x011E;

    /// <summary>
    /// Contains EAC CVA references. Note: this can be overridden by a file identifier in the DG14 file (in
    /// a TerminalAuthenticationInfo). Check DG14 first. Also, this file does not have a header tag, like
    /// the others.
    /// </summary>
    public const short EF_CVCA = 0x011C;

    /// <summary>Short file identifier for card access file.</summary>
    public const byte SFI_CARD_ACCESS = 0x1C;

    /// <summary>Short file identifier for card security file.</summary>
    public const byte SFI_CARD_SECURITY = 0x1D;

    /// <summary>Short file identifier for file.</summary>
    public const byte SFI_DG1 = 0x01;

    /// <summary>Short file identifier for file.</summary>
    public const byte SFI_DG2 = 0x02;

    /// <summary>Short file identifier for file.</summary>
    public const byte SFI_DG3 = 0x03;

    /// <summary>Short file identifier for file.</summary>
    public const byte SFI_DG4 = 0x04;

    /// <summary>Short file identifier for file.</summary>
    public const byte SFI_DG5 = 0x05;

    /// <summary>Short file identifier for file.</summary>
    public const byte SFI_DG6 = 0x06;

    /// <summary>Short file identifier for file.</summary>
    public const byte SFI_DG7 = 0x07;

    /// <summary>Short file identifier for file.</summary>
    public const byte SFI_DG8 = 0x08;

    /// <summary>Short file identifier for file.</summary>
    public const byte SFI_DG9 = 0x09;

    /// <summary>Short file identifier for file.</summary>
    public const byte SFI_DG10 = 0x0A;

    /// <summary>Short file identifier for file.</summary>
    public const byte SFI_DG11 = 0x0B;

    /// <summary>Short file identifier for file.</summary>
    public const byte SFI_DG12 = 0x0C;

    /// <summary>Short file identifier for file.</summary>
    public const byte SFI_DG13 = 0x0D;

    /// <summary>Short file identifier for file.</summary>
    public const byte SFI_DG14 = 0x0E;

    /// <summary>Short file identifier for file.</summary>
    public const byte SFI_DG15 = 0x0F;

    /// <summary>Short file identifier for file.</summary>
    public const byte SFI_DG16 = 0x10;

    /// <summary>Short file identifier for file.</summary>
    public const byte SFI_COM = 0x1E;

    /// <summary>Short file identifier for file.</summary>
    public const byte SFI_SOD = 0x1D;

    /// <summary>Short file identifier for file.</summary>
    public const byte SFI_CVCA = 0x1C;

    /// <summary>The default maximal blocksize used for unencrypted APDUs.</summary>
    public const int DefaultMaxBlocksize = 223;

    /// <summary>The normal maximal transceive length of APDUs.</summary>
    public const int NormalMaxTransceiveLength = 256;

    /// <summary>The extended maximal transceive length of APDUs.</summary>
    public const int ExtendedMaxTransceiveLength = 65536;

    /// <summary>The normal maximal transceive length of APDUs.</summary>
    [Obsolete("Misspelled, use NormalMaxTransceiveLength instead.")]
    public const int NormalMaxTranceiveLength = NormalMaxTransceiveLength;

    /// <summary>The extended maximal transceive length of APDUs.</summary>
    [Obsolete("Misspelled, use ExtendedMaxTransceiveLength instead.")]
    public const int ExtendedMaxTranceiveLength = ExtendedMaxTransceiveLength;

    /// <summary>The applet we select when we start a session.</summary>
    protected static readonly byte[] AppletAid = [0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01];

    private readonly object _lock = new();

    /// <summary>The file read block size, some passports cannot handle large values.</summary>
    private readonly int _maxBlockSize;

    private bool _isOpen;

    private SecureMessagingWrapper? _wrapper;

    private readonly int _maxTransceiveLengthForSecureMessaging;

    private readonly int _maxTransceiveLengthForPaceProtocol;

    private readonly bool _shouldCheckMac;

    private bool _isAppletSelected;

    private readonly DefaultFileSystem _rootFileSystem;

    private readonly DefaultFileSystem _appletFileSystem;

    private readonly SecureMessagingAPDUSender _secureMessagingSender;
    private readonly BACAPDUSender _bacSender;
    private readonly PACEAPDUSender _paceSender;
    private readonly AAAPDUSender _aaSender;
    private readonly EACCAAPDUSender _eacCaSender;
    private readonly EACTAAPDUSender _eacTaSender;
    private readonly ReadBinaryAPDUSender _readBinarySender;

    private readonly CardService _service;

    /// <summary>Creates a new passport service for accessing the passport.</summary>
    /// <param name="service">another service which will deal with sending the APDUs to the card</param>
    /// <param name="maxTransceiveLengthForSecureMessaging">maximum length to use in secure messaging APDUs, <c>256</c> or <c>65536</c></param>
    /// <param name="maxBlockSize">maximum buffer size for plain text APDUs</param>
    /// <param name="isSfiEnabled">whether short file identifiers should be used for read binaries when possible</param>
    /// <param name="shouldCheckMac">whether the secure messaging channels, resulting from BAC, PACE, EAC-CA, should check MACs on response APDUs</param>
    public PassportService(CardService service, int maxTransceiveLengthForSecureMessaging, int maxBlockSize, bool isSfiEnabled, bool shouldCheckMac)
        : this(service, NormalMaxTransceiveLength, maxTransceiveLengthForSecureMessaging, maxBlockSize, isSfiEnabled, shouldCheckMac)
    {
    }

    /// <summary>Creates a new passport service for accessing the passport.</summary>
    /// <param name="service">another service which will deal with sending the APDUs to the card</param>
    /// <param name="maxTransceiveLengthForPaceProtocol">maximum length to use in PACE protocol steps, <c>256</c> or <c>65536</c></param>
    /// <param name="maxTransceiveLengthForSecureMessaging">maximum length to use in secure messaging APDUs, <c>256</c> or <c>65536</c></param>
    /// <param name="maxBlockSize">maximum buffer size for plain text APDUs</param>
    /// <param name="isSfiEnabled">whether short file identifiers should be used for read binaries when possible</param>
    /// <param name="shouldCheckMac">whether the secure messaging channels, resulting from BAC, PACE, EAC-CA, should check MACs on response APDUs</param>
    public PassportService(CardService service, int maxTransceiveLengthForPaceProtocol, int maxTransceiveLengthForSecureMessaging, int maxBlockSize, bool isSfiEnabled, bool shouldCheckMac)
    {
        _service = service;

        /*
         * A single SecureMessagingAPDUSender is shared by all protocol senders below, so there is exactly
         * one APDU sequence number / listener registry for the whole session, and a listener registered
         * through any one of them (see AddApduListener) observes all APDU traffic.
         */
        _secureMessagingSender = new SecureMessagingAPDUSender(service);
        _bacSender = new BACAPDUSender(_secureMessagingSender);
        _paceSender = new PACEAPDUSender(_secureMessagingSender);
        _aaSender = new AAAPDUSender(_secureMessagingSender);
        _eacCaSender = new EACCAAPDUSender(_secureMessagingSender);
        _eacTaSender = new EACTAAPDUSender(_secureMessagingSender);
        _readBinarySender = new ReadBinaryAPDUSender(_secureMessagingSender);

        _maxTransceiveLengthForPaceProtocol = maxTransceiveLengthForPaceProtocol;
        _maxTransceiveLengthForSecureMessaging = maxTransceiveLengthForSecureMessaging;
        _maxBlockSize = maxBlockSize;
        _shouldCheckMac = shouldCheckMac;
        _isAppletSelected = false;
        _isOpen = false;

        _rootFileSystem = new DefaultFileSystem(_readBinarySender, false); // Some passports (UK?) don't support SFI for EF.CardAccess.
        _appletFileSystem = new DefaultFileSystem(_readBinarySender, isSfiEnabled);
    }

    /// <summary>
    /// Opens a session to the card. Caller is responsible to call <see cref="SendSelectApplet"/> afterwards.
    /// </summary>
    /// <exception cref="CardServiceException">on error</exception>
    public override void Open()
    {
        if (IsOpen)
        {
            return;
        }

        lock (_lock)
        {
            _service.Open();
            _isOpen = true;
            _secureMessagingSender.Log.Info(LogCategory, "Card service opened.");
        }
    }

    /// <inheritdoc />
    public override void SendSelectApplet(bool shouldUseSecureMessaging)
    {
        if (_isAppletSelected)
        {
            // NOTE: Java logs an info message ("Re-selecting ICAO applet") here; omitted per the
            // non-essential-warning-omission precedent used elsewhere in this port.
        }

        _secureMessagingSender.Log.Info(LogCategory, shouldUseSecureMessaging
            ? "Selecting ICAO applet (secure messaging already established)."
            : "Selecting ICAO applet (plain messaging).");

        if (shouldUseSecureMessaging)
        {
            /* Use SM as set up by DoPace(). */
            _readBinarySender.SendSelectApplet(_wrapper, AppletAid);
        }
        else
        {
            /* Use plain messaging to select the applet, caller will have to do DoBAC. */
            _readBinarySender.SendSelectApplet(null, AppletAid);
        }

        _isAppletSelected = true;
    }

    /// <summary>Sends a <c>SELECT MF</c> command to the card.</summary>
    /// <exception cref="CardServiceException">on transceive error</exception>
    public override void SendSelectMf()
    {
        _readBinarySender.SendSelectMf();
        _wrapper = null;
        _rootFileSystem.SetWrapper(null);
        _appletFileSystem.SetWrapper(null);
    }

    /// <inheritdoc />
    public override bool IsOpen => _isOpen;

    /// <inheritdoc />
    public override BACResult DoBAC(IAccessKeySpec bacKey)
    {
        lock (_lock)
        {
            if (bacKey is not IBacKeySpec)
            {
                throw new ArgumentException("Unsupported key type");
            }

            BACResult bacResult = new BACProtocol(_bacSender, _maxTransceiveLengthForSecureMessaging, _shouldCheckMac, _secureMessagingSender.Log).DoBAC(bacKey);
            _wrapper = bacResult.Wrapper;
            _appletFileSystem.SetWrapper(_wrapper);
            return bacResult;
        }
    }

    /// <inheritdoc />
    public override BACResult DoBAC(KeyParameter kEnc, KeyParameter kMac)
    {
        lock (_lock)
        {
            BACResult bacResult = new BACProtocol(_bacSender, _maxTransceiveLengthForSecureMessaging, _shouldCheckMac, _secureMessagingSender.Log).DoBAC(kEnc, kMac);
            _wrapper = bacResult.Wrapper;
            _appletFileSystem.SetWrapper(_wrapper);
            return bacResult;
        }
    }

    /// <inheritdoc />
    public override PACEResult DoPace(IAccessKeySpec keySpec, string oid, object staticParameters, BigInteger? parameterId)
    {
        lock (_lock)
        {
            PACEResult paceResult = new PaceProtocol(_paceSender, _wrapper, _maxTransceiveLengthForPaceProtocol, _maxTransceiveLengthForSecureMessaging, _shouldCheckMac, _secureMessagingSender.Log)
                .DoPace(keySpec, oid, staticParameters, parameterId);
            _wrapper = paceResult.Wrapper;
            _appletFileSystem.SetWrapper(_wrapper);
            return paceResult;
        }
    }

    /// <inheritdoc />
    public override EACCAResult DoEACCA(BigInteger? keyId, string? oid, string? publicKeyOID, AsymmetricKeyParameter publicKey)
    {
        lock (_lock)
        {
            EACCAResult caResult = new EACCAProtocol(_eacCaSender, GetWrapper()!, _maxTransceiveLengthForSecureMessaging, _shouldCheckMac, _secureMessagingSender.Log)
                .DoCA(keyId, oid, publicKeyOID, publicKey);
            _wrapper = caResult.Wrapper;
            _appletFileSystem.SetWrapper(_wrapper);
            return caResult;
        }
    }

    /*
     * From BSI-03110 v1.1, B.2: the following sequence of commands SHALL be used to implement Terminal
     * Authentication: 1. MSE:Set DST 2. PSO:Verify Certificate 3. MSE:Set AT 4. Get Challenge 5. External
     * Authenticate. Steps 1 and 2 are repeated for every CV certificate to be verified (CVCA Link
     * Certificates, DV Certificate, IS Certificate).
     */

    /// <inheritdoc />
    public override EACTAResult DoEACTA(
        CVCPrincipal? caReference,
        IReadOnlyList<CardVerifiableCertificate> terminalCertificates,
        AsymmetricKeyParameter? terminalKey,
        string? taAlg,
        EACCAResult? chipAuthenticationResult,
        string? documentNumber,
        TerminalKeySigner? terminalKeySigner = null,
        ECDomainParameters? terminalKeyEcDomainParameters = null)
    {
        lock (_lock)
        {
            return new EACTAProtocol(_eacTaSender, GetWrapper()!, _secureMessagingSender.Log)
                .DoEACTA(caReference, terminalCertificates, terminalKey, taAlg, chipAuthenticationResult, documentNumber, terminalKeySigner, terminalKeyEcDomainParameters);
        }
    }

    /// <inheritdoc />
    public override EACTAResult DoEACTA(
        CVCPrincipal? caReference,
        IReadOnlyList<CardVerifiableCertificate> terminalCertificates,
        AsymmetricKeyParameter? terminalKey,
        string? taAlg,
        EACCAResult? chipAuthenticationResult,
        PACEResult paceResult,
        TerminalKeySigner? terminalKeySigner = null,
        ECDomainParameters? terminalKeyEcDomainParameters = null)
    {
        lock (_lock)
        {
            return new EACTAProtocol(_eacTaSender, GetWrapper()!, _secureMessagingSender.Log)
                .DoTA(caReference, terminalCertificates, terminalKey, taAlg, chipAuthenticationResult, paceResult, terminalKeySigner, terminalKeyEcDomainParameters);
        }
    }

    /// <inheritdoc />
    public override AAResult DoAA(AsymmetricKeyParameter publicKey, string? digestAlgorithm, string signatureAlgorithm, byte[] challenge) =>
        new AAProtocol(_aaSender, GetWrapper(), _secureMessagingSender.Log).DoAA(publicKey, digestAlgorithm, signatureAlgorithm, challenge);

    /// <summary>Closes this service.</summary>
    public override void Close()
    {
        try
        {
            _service.Close();
            _wrapper = null;
            _rootFileSystem.SetWrapper(null);
            _appletFileSystem.SetWrapper(null);
            _secureMessagingSender.Log.Info(LogCategory, "Card service closed.");
        }
        finally
        {
            _isOpen = false;
        }
    }

    /// <summary>Returns the maximum transceive length of (protected) APDUs.</summary>
    /// <returns>the maximum APDU transceive length</returns>
    public int GetMaxTransceiveLength() => _maxTransceiveLengthForSecureMessaging;

    /// <summary>Returns the maximum transceive length of (protected) APDUs.</summary>
    /// <returns>the maximum APDU transceive length</returns>
    [Obsolete("Misspelled, use GetMaxTransceiveLength() instead.")]
    public int GetMaxTranceiveLength() => GetMaxTransceiveLength();

    /// <summary>Returns the secure messaging wrapper currently in use. Returns <c>null</c> until access control has been performed.</summary>
    /// <returns>the wrapper</returns>
    public override SecureMessagingWrapper? GetWrapper()
    {
        var ldsSecureMessagingWrapper = _appletFileSystem.GetWrapper() as SecureMessagingWrapper;

        // NOTE: preserved Java quirk -- if this is called before any access control protocol has run but
        // ldsSecureMessagingWrapper is somehow already non-null, _wrapper (null-forgiven below) would throw
        // a NullReferenceException here, matching Java's own NullPointerException in the same situation.
        // Not "fixed" per this port's quirk-preservation policy.
        if (ldsSecureMessagingWrapper != null && ldsSecureMessagingWrapper.SendSequenceCounter > _wrapper!.SendSequenceCounter)
        {
            _wrapper = ldsSecureMessagingWrapper;
        }

        return _wrapper;
    }

    /// <inheritdoc />
    public override ResponseApdu Transmit(CommandApdu commandApdu) => _service.Transmit(commandApdu);

    /// <summary>Returns the answer to reset.</summary>
    /// <returns>the answer to reset</returns>
    /// <exception cref="CardServiceException">on error</exception>
    public override byte[] GetAtr() => _service.GetAtr();

    /// <summary>Determines whether an exception indicates a tag is lost event.</summary>
    /// <param name="exception">an exception</param>
    /// <returns>whether the exception indicates a tag is lost event</returns>
    public override bool IsConnectionLost(Exception exception) => _service.IsConnectionLost(exception);

    /// <summary>Whether secure channels should check the MAC on response APDUs sent by the ICC.</summary>
    /// <returns>a boolean indicating whether the MAC should be checked</returns>
    public bool ShouldCheckMac() => _shouldCheckMac;

    /// <summary>Returns the file indicated by the file identifier as an input stream. The resulting input
    /// stream will send APDUs to the card as it is being read.</summary>
    /// <param name="fid">the file identifier</param>
    /// <returns>the file as an input stream</returns>
    /// <exception cref="CardServiceException">if the file cannot be read</exception>
    [Obsolete("Use the other overload with explicit max block size.")]
    public override CardFileInputStream GetInputStream(short fid) => GetInputStream(fid, _maxBlockSize);

    /// <summary>Returns the file indicated by the file identifier as an input stream. The resulting input
    /// stream will send APDUs to the card as it is being read.</summary>
    /// <param name="fid">the file identifier</param>
    /// <param name="maxBlockSize">the blocksize to request in plain READ BINARY commands</param>
    /// <returns>the file as an input stream</returns>
    /// <exception cref="CardServiceException">if the file cannot be read</exception>
    public override CardFileInputStream GetInputStream(short fid, int maxBlockSize)
    {
        lock (_lock)
        {
            _secureMessagingSender.Log.Info(LogCategory, $"Reading file {fid:X4}.");
            DefaultFileSystem fileSystem = _isAppletSelected ? _appletFileSystem : _rootFileSystem;

            // Select and bind the stream atomically with respect to other streams on the same file system,
            // which take this same lock while they re-select their own file and read (see CardFileInputStream).
            lock (fileSystem)
            {
                fileSystem.SelectFile(fid);
                return new CardFileInputStream(maxBlockSize, fileSystem);
            }
        }
    }

    /// <inheritdoc />
    public override int GetMaxReadBinaryLength() => _appletFileSystem?.GetMaxReadBinaryLength() ?? NormalMaxTransceiveLength;

    /// <inheritdoc />
    public override void AddApduListener(IApduListener listener) => _readBinarySender.AddApduListener(listener);

    /// <inheritdoc />
    public override void RemoveApduListener(IApduListener listener) => _readBinarySender.RemoveApduListener(listener);

    /// <inheritdoc />
    public override IReadOnlyCollection<IApduListener> ApduListeners => _readBinarySender.ApduListeners;

    /// <inheritdoc />
    protected override void NotifyExchangedApdu(ApduEvent apduEvent)
    {
        IReadOnlyCollection<IApduListener> apduListeners = ApduListeners;
        if (apduListeners.Count == 0)
        {
            return;
        }

        foreach (IApduListener listener in apduListeners)
        {
            listener.ExchangedApdu(apduEvent);
        }
    }

    /// <inheritdoc />
    public override SecureMessagingAPDUSender GetSecureMessagingAPDUSender() => _secureMessagingSender;

    /// <summary>
    /// Adds a listener for this session's log/trace events -- APDU exchanges, protocol steps, execution
    /// state changes, and errors, raised by every protocol object constructed by this service (see
    /// <see cref="LogSource"/>'s own doc comment). Registered through the single
    /// <see cref="SecureMessagingAPDUSender"/> shared by this service, so one subscription observes the
    /// whole session regardless of which protocol (BAC, PACE, EAC-CA, EAC-TA, AA) is running.
    /// </summary>
    /// <param name="listener">the listener to add</param>
    public void AddLogListener(ILogListener listener) => _secureMessagingSender.Log.AddListener(listener);

    /// <summary>Removes a log listener. If the specified listener is not present, this method has no effect.</summary>
    /// <param name="listener">the listener to remove</param>
    public void RemoveLogListener(ILogListener listener) => _secureMessagingSender.Log.RemoveListener(listener);

    /// <summary>Returns the currently registered log listeners.</summary>
    public IReadOnlyCollection<ILogListener> LogListeners => _secureMessagingSender.Log.Listeners;
}
