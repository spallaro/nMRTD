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

using System.Numerics;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

using nMRTD.Cert;
using nMRTD.Protocol;
using nMRTD.SmartCards;

namespace nMRTD;

/// <summary>
/// Port of <c>org.jmrtd.AbstractMRTDCardService</c>: base class for MRTD card services.
///
/// ADAPTATION: Java's <c>SecretKey</c>/<c>PublicKey</c>/<c>PrivateKey</c> parameters become BC's
/// <see cref="KeyParameter"/>/<see cref="AsymmetricKeyParameter"/>, per the convention already established
/// throughout this port (see <c>Util.cs</c>'s doc comment). Java's <c>AlgorithmParameterSpec</c> becomes a
/// plain <c>object</c>, per <c>PACEMappingResult.cs</c>'s/<c>PaceProtocol.cs</c>'s own convention. Java's
/// <c>List&lt;CardVerifiableCertificate&gt;</c> becomes <see cref="IReadOnlyList{T}"/>, matching
/// <c>EACTAProtocol.cs</c>'s own parameter type for the same certificate chain. Two distinct
/// <c>BigInteger</c> types are used side by side, matching the split already established by
/// <c>EACCAProtocol.cs</c>/<c>PaceProtocol.cs</c>: <see cref="BigInteger"/> (<c>System.Numerics</c>) for
/// <c>keyId</c> (a plain identifier, matching <c>EACCAProtocol.DoCA</c>'s own parameter type), and BC's own
/// <c>Org.BouncyCastle.Math.BigInteger</c> for <c>parameterId</c> (matching <c>PaceProtocol.DoPace</c>'s own
/// parameter type, since PACE parameter identifiers flow directly into BC big-integer arithmetic).
/// </summary>
public abstract class AbstractMRTDCardService : FileSystemCardService
{
    /// <summary>Performs the <i>Basic Access Control</i> protocol.</summary>
    /// <param name="bacKey">the key based on the document number, the card holder's birth date, and the document's expiration date</param>
    /// <returns>the BAC result</returns>
    /// <exception cref="CardServiceException">if authentication failed</exception>
    public abstract BACResult DoBAC(IAccessKeySpec bacKey);

    /// <summary>
    /// Performs the <i>Basic Access Control</i> protocol. It does BAC using kEnc and kMac keys, usually
    /// calculated from the document number, the card holder's date of birth, and the card's date of
    /// expiry. A secure messaging channel is set up as a result.
    /// </summary>
    /// <param name="kEnc">static 3DES key required for BAC</param>
    /// <param name="kMac">static 3DES key required for BAC</param>
    /// <returns>the result</returns>
    /// <exception cref="CardServiceException">if authentication failed</exception>
    public abstract BACResult DoBAC(KeyParameter kEnc, KeyParameter kMac);

    /// <summary>
    /// Performs the PACE 2.0 / SAC protocol. A secure messaging channel is set up as a result.
    /// </summary>
    /// <param name="keySpec">the MRZ</param>
    /// <param name="oid">as specified in the PACEInfo, indicates GM or IM or CAM, DH or ECDH, cipher, digest, length</param>
    /// <param name="staticParameters">explicit static domain parameters (<see cref="Org.BouncyCastle.Crypto.Parameters.DHParameters"/> or <see cref="Org.BouncyCastle.Crypto.Parameters.ECDomainParameters"/>) for DH or ECDH</param>
    /// <returns>the result</returns>
    /// <exception cref="CardServiceException">if authentication failed or on error</exception>
    [Obsolete("Use the overload with an additional parameter identifier.")]
    public PACEResult DoPace(IAccessKeySpec keySpec, string oid, object staticParameters) => DoPace(keySpec, oid, staticParameters, null);

    /// <summary>Performs the PACE 2.0 / SAC protocol. A secure messaging channel is set up as a result.</summary>
    /// <param name="keySpec">the MRZ</param>
    /// <param name="oid">as specified in the PACEInfo, indicates GM or IM or CAM, DH or ECDH, cipher, digest, length</param>
    /// <param name="staticParameters">explicit static domain parameters (<see cref="Org.BouncyCastle.Crypto.Parameters.DHParameters"/> or <see cref="Org.BouncyCastle.Crypto.Parameters.ECDomainParameters"/>) for DH or ECDH</param>
    /// <param name="parameterId">parameter identifier or <c>null</c></param>
    /// <returns>the result</returns>
    /// <exception cref="CardServiceException">if authentication failed or on error</exception>
    public abstract PACEResult DoPace(IAccessKeySpec keySpec, string oid, object staticParameters, Org.BouncyCastle.Math.BigInteger? parameterId);

    /// <summary>
    /// Selects the card side applet. If PACE has been executed successfully previously, then the card has
    /// authenticated us and a secure messaging channel has already been established. If not, then the
    /// caller should request BAC execution as a next step.
    /// </summary>
    /// <param name="shouldUseSecureMessaging">indicates whether a secure messaging channel has already been
    /// established (which is the case if PACE has been executed)</param>
    /// <exception cref="CardServiceException">on error</exception>
    public abstract void SendSelectApplet(bool shouldUseSecureMessaging);

    /// <summary>Selects the master file.</summary>
    /// <exception cref="CardServiceException">on error</exception>
    public abstract void SendSelectMf();

    /// <summary>Performs the <i>Active Authentication</i> protocol.</summary>
    /// <param name="publicKey">the public key to use (usually read from the card)</param>
    /// <param name="digestAlgorithm">the digest algorithm to use, or <c>null</c></param>
    /// <param name="signatureAlgorithm">signature algorithm</param>
    /// <param name="challenge">challenge</param>
    /// <returns>a boolean indicating whether the card was authenticated</returns>
    /// <exception cref="CardServiceException">on error</exception>
    public abstract AAResult DoAA(AsymmetricKeyParameter publicKey, string? digestAlgorithm, string signatureAlgorithm, byte[] challenge);

    /// <summary>
    /// Perform CA (Chip Authentication) part of EAC (version 1). For details see TR-03110 ver. 1.11. In
    /// short, we authenticate the chip with (EC)DH key agreement protocol and create new secure messaging
    /// keys. A new secure messaging channel is set up as a result.
    /// </summary>
    /// <param name="keyId">the chip's public key id (stored in DG14), <c>null</c> if none</param>
    /// <param name="oid">the object identifier indicating the Chip Authentication protocol</param>
    /// <param name="publicKeyOID">the object identifier indicating the public key algorithm used</param>
    /// <param name="publicKey">passport's public key (stored in DG14)</param>
    /// <returns>the Chip Authentication result</returns>
    /// <exception cref="CardServiceException">if CA failed or some error occurred</exception>
    public abstract EACCAResult DoEACCA(BigInteger? keyId, string? oid, string? publicKeyOID, AsymmetricKeyParameter publicKey);

    /// <summary>
    /// Performs <i>Terminal Authentication</i> (TA) part of EAC (version 1). For details see TR-03110 ver.
    /// 1.11. In short, we feed the sequence of terminal certificates to the card for verification, get a
    /// challenge from the card, sign it with the terminal private key, and send the result back to the
    /// card for verification.
    /// </summary>
    /// <param name="caReference">reference issuer</param>
    /// <param name="terminalCertificates">terminal certificate chain</param>
    /// <param name="terminalKey">terminal private key</param>
    /// <param name="taAlg">algorithm</param>
    /// <param name="chipAuthenticationResult">the chip authentication result</param>
    /// <param name="documentNumber">the document number</param>
    /// <returns>the Terminal Authentication result</returns>
    /// <exception cref="CardServiceException">on error</exception>
    public abstract EACTAResult DoEACTA(
        CVCPrincipal? caReference,
        IReadOnlyList<CardVerifiableCertificate> terminalCertificates,
        AsymmetricKeyParameter? terminalKey,
        string? taAlg,
        EACCAResult? chipAuthenticationResult,
        string? documentNumber);

    /// <summary>
    /// Performs <i>Terminal Authentication</i> (TA) part of EAC (version 1). For details see TR-03110 ver.
    /// 1.11. In short, we feed the sequence of terminal certificates to the card for verification, get a
    /// challenge from the card, sign it with the terminal private key, and send the result back to the
    /// card for verification.
    /// </summary>
    /// <param name="caReference">reference issuer</param>
    /// <param name="terminalCertificates">terminal certificate chain</param>
    /// <param name="terminalKey">terminal private key</param>
    /// <param name="taAlg">algorithm</param>
    /// <param name="chipAuthenticationResult">the chip authentication result</param>
    /// <param name="paceResult">the PACE result</param>
    /// <returns>the Terminal Authentication result</returns>
    /// <exception cref="CardServiceException">on error</exception>
    public abstract EACTAResult DoEACTA(
        CVCPrincipal? caReference,
        IReadOnlyList<CardVerifiableCertificate> terminalCertificates,
        AsymmetricKeyParameter? terminalKey,
        string? taAlg,
        EACCAResult? chipAuthenticationResult,
        PACEResult paceResult);

    /// <summary>Returns the secure messaging wrapper currently in use.</summary>
    /// <returns>the secure messaging wrapper</returns>
    public abstract SecureMessagingWrapper? GetWrapper();

    /// <summary>
    /// Returns the currently set maximum length to be requested in READ BINARY commands. If the applet
    /// file system has not yet been selected, this will return the normal length.
    /// </summary>
    /// <returns>the currently set maximum length to be requested in READ BINARY commands</returns>
    public abstract int GetMaxReadBinaryLength();

    /// <summary>
    /// Returns the secure messaging APDU sender shared by this service's protocol senders, if any.
    /// Intended for callers migrating off the deprecated <c>(CardService)</c> constructors of the
    /// <c>nMRTD.Protocol</c> APDU senders, who need a <see cref="SecureMessagingAPDUSender"/> to share.
    /// </summary>
    /// <returns>the shared secure messaging APDU sender, or <c>null</c> if this service does not expose one</returns>
    public virtual SecureMessagingAPDUSender? GetSecureMessagingAPDUSender() => null;
}
