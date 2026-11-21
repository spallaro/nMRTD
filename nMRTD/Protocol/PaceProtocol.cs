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

using System.Security.Cryptography;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

using nMRTD.Lds;
using nMRTD.Logging;
using nMRTD.SmartCards;

using BigInteger = Org.BouncyCastle.Math.BigInteger;
using ECCurve = Org.BouncyCastle.Math.EC.ECCurve;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace nMRTD.Protocol;

/// <summary>
/// Port of <c>org.jmrtd.protocol.PACEProtocol</c>: the Password Authenticated Connection Establishment
/// protocol (PACE, ICAO TR-SAC 1.01 / BSI TR-03110). This is the largest and most structurally adapted
/// file in <c>protocol/</c>; several JCA-bridging layers that Java needed have no counterpart here because
/// this port works directly against BC's own curve-aware crypto object model (see <c>Util.cs</c>'s and
/// <c>PACEGMWithECDHAgreement.cs</c>'s doc comments for the same general observation):
/// <list type="bullet">
/// <item>Java's <c>AlgorithmParameterSpec</c> (implemented by both <c>DHParameterSpec</c> and
/// <c>ECParameterSpec</c>) has no BC lightweight-API equivalent; it is ported as a plain <c>object</c>,
/// exactly as <see cref="PACEMappingResult"/> already does -- callers downcast to
/// <see cref="DHParameters"/>/<see cref="ECDomainParameters"/> as appropriate.</item>
/// <item>Java's <c>Cipher staticPACECipher</c> parameter (constructed once by the caller, reused across
/// <c>doPACEStep1</c>/<c>doPACEStep2</c>) is dropped -- BC ciphers are cheap, stateless-until-<c>Init</c>
/// objects, so each step that needs one constructs its own fresh <see cref="IBufferedCipher"/> from the
/// plain <c>cipherAlg</c> string ("AES" or "DESede") instead. Java's <c>doPACEStep2IM</c>/mapping helpers
/// only ever used the passed-in <c>Cipher</c> for its <c>getAlgorithm()</c> string anyway (to select AES vs
/// DESede in <see cref="PseudoRandomFunction"/>) -- passing that plain string directly removes an entire
/// layer of JCA-mnemonic-string round-tripping.</item>
/// <item>Java's <c>SecretKey staticPACEKey</c>/<c>KeyAgreement.generateSecret()</c>-based key derivation is
/// ported using BC's <see cref="KeyParameter"/> and, for actual DH/ECDH key agreement,
/// <see cref="EACCAProtocol.ComputeSharedSecret"/> is reused directly (it already reproduces the same
/// "unsigned big-endian octet string sized to the field/modulus" semantics that Java's
/// <c>KeyAgreement.generateSecret()</c> provides, per that method's own doc comment) rather than
/// duplicating <c>ECDHBasicAgreement</c>/<c>DHBasicAgreement</c> plumbing here. Java's private
/// <c>updateParameterSpec</c> helper (defensively rebuilding the PICC's public key against the PCD's
/// private key's domain parameters before key agreement) has no equivalent call here because
/// <see cref="DecodePublicKeyFromSmartCard"/> already constructs the PICC's public key directly against
/// the caller-supplied (already-correct, already-ephemeral) domain parameters -- there is no JCA-provider
/// round trip that could have left it with different/implicit parameters in the first place.</item>
/// <item>Java's <c>Util.getMac</c>/<c>Util.getPublicKey</c>/JCA <c>KeyPairGenerator.getInstance</c> factory
/// methods are gone (see <c>Util.cs</c>'s doc comment on the dropped JCA provider-lookup methods);
/// <see cref="CreateMacForCipherAlgorithm"/>, <see cref="DecodePublicKeyFromSmartCard"/>, and
/// <see cref="GenerateKeyPairForAgreement"/> below construct the equivalent BC lightweight-API objects
/// directly, following the exact same pattern already established by <c>EACCAProtocol.cs</c>'s
/// <c>GenerateEphemeralKeyPair</c>.</item>
/// <item>Java's Generic-Mapping/Integrated-Mapping point arithmetic (<c>mapNonceGMWithECDH</c>,
/// <c>icartPointEncode</c>) round-trips through <c>Util.toBouncyCastleECPoint</c>/
/// <c>Util.fromBouncyCastleECPoint</c> because JCA's <c>java.security.spec.ECPoint</c> is curve-agnostic.
/// Since every point in this port already is a curve-aware <see cref="ECPoint"/>, that round trip -- and
/// the throwaway <c>EllipticCurve</c>/<c>ECFieldFp</c> reconstruction used only to smuggle the curve back
/// into a fresh <c>ECParameterSpec</c> -- is unnecessary: the resulting <see cref="ECDomainParameters"/> is
/// built by reusing <c>staticParameters.Curve</c> (identical to the original curve; only the generator
/// point changes) directly.</item>
/// </list>
/// </summary>
public class PaceProtocol
{
    /// <summary>
    /// Used to derive the IV in the last step of PACE-CAM. From 9303-11: AES SHALL be used in CBC-mode
    /// according to [ISO/IEC 10116] with IV=E(KSEnc,-1), where -1 is the bit string of length 128 with
    /// all bits set to 1.
    ///
    /// NOTE: this is the plaintext "-1" block that gets encrypted (single AES block, i.e. ECB) with K_enc
    /// to derive the actual IV. It is NOT the IV itself -- see <see cref="DecryptChipAuthenticationData"/>.
    /// </summary>
    private static readonly byte[] MinusOneBlockForPaceCamIv =
    [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ];

    /// <summary>Constant used in IM pseudo random number mapping, see Doc 9303 - Part 11, 4.4.3.3.2.</summary>
    private static readonly byte[] C0Length128 =
    [
        0xA6, 0x68, 0x89, 0x2A, 0x7C, 0x41, 0xE3, 0xCA, 0x73, 0x9F, 0x40, 0xB0, 0x57, 0xD8, 0x59, 0x04,
    ];

    /// <summary>Constant used in IM pseudo random number mapping, see Doc 9303 - Part 11, 4.4.3.3.2.</summary>
    private static readonly byte[] C1Length128 =
    [
        0xA4, 0xE1, 0x36, 0xAC, 0x72, 0x5F, 0x73, 0x8B, 0x01, 0xC1, 0xF6, 0x02, 0x17, 0xC1, 0x88, 0xAD,
    ];

    /// <summary>Constant used in IM pseudo random number mapping, see Doc 9303 - Part 11, 4.4.3.3.2.</summary>
    private static readonly byte[] C0Length256 =
    [
        0xD4, 0x63, 0xD6, 0x52, 0x34, 0x12, 0x4E, 0xF7, 0x89, 0x70, 0x54, 0x98, 0x6D, 0xCA, 0x0A, 0x17,
        0x4E, 0x28, 0xDF, 0x75, 0x8C, 0xBA, 0xA0, 0x3F, 0x24, 0x06, 0x16, 0x41, 0x4D, 0x5A, 0x16, 0x76,
    ];

    /// <summary>Constant used in IM pseudo random number mapping, see Doc 9303 - Part 11, 4.4.3.3.2.</summary>
    private static readonly byte[] C1Length256 =
    [
        0x54, 0xBD, 0x72, 0x55, 0xF0, 0xAA, 0xF8, 0x31, 0xBE, 0xC3, 0x42, 0x3F, 0xCF, 0x39, 0xD6, 0x9B,
        0x6C, 0xBF, 0x06, 0x66, 0x77, 0xD0, 0xFA, 0xAE, 0x5A, 0xAD, 0xD9, 0x9D, 0xF8, 0xE5, 0x35, 0x17,
    ];

    private const string LogCategory = "PACE";

    private readonly IApduLevelPaceCapable _service;
    private SecureMessagingWrapper? _wrapper;
    private readonly int _maxTranceiveLengthForProtocol;
    private readonly int _maxTranceiveLengthForSecureMessaging;
    private readonly bool _shouldCheckMac;
    private readonly LogSource _log;

    /// <summary>
    /// Constructs a PACE protocol instance. The max tranceive lengths used during PACE protocol execution
    /// will be set to 256.
    /// </summary>
    /// <param name="service">the service for sending APDUs</param>
    /// <param name="wrapper">the already established secure messaging channel (or <c>null</c>)</param>
    /// <param name="maxTranceiveLength">the maximal tranceive length (on responses to <c>READ BINARY</c>)
    /// to use in the resulting secure messaging channel</param>
    /// <param name="shouldCheckMac">whether the resulting secure messaging channel should apply strict MAC
    /// checking on response APDUs</param>
    [Obsolete("Use the constructor with explicit max tranceive lengths for protocol and secure messaging.")]
    public PaceProtocol(IApduLevelPaceCapable service, SecureMessagingWrapper? wrapper, int maxTranceiveLength, bool shouldCheckMac)
        : this(service, wrapper, 256, maxTranceiveLength, shouldCheckMac)
    {
    }

    /// <summary>Constructs a PACE protocol instance.</summary>
    /// <param name="service">the service for sending APDUs</param>
    /// <param name="wrapper">the already established secure messaging channel (or <c>null</c>)</param>
    /// <param name="maxTranceiveLengthForProtocol">the maximal tranceive length PACE during protocol
    /// execution, <c>256</c> or <c>65536</c></param>
    /// <param name="maxTranceiveLengthForSecureMessaging">the maximal tranceive length (on responses to
    /// <c>READ BINARY</c>) to use in the resulting secure messaging channel</param>
    /// <param name="shouldCheckMac">whether the resulting secure messaging channel should apply strict MAC
    /// checking on response APDUs</param>
    /// <param name="log">the log/trace registry to raise protocol-step and error events on, or <c>null</c> for a private (unobserved) one</param>
    public PaceProtocol(IApduLevelPaceCapable service, SecureMessagingWrapper? wrapper, int maxTranceiveLengthForProtocol, int maxTranceiveLengthForSecureMessaging, bool shouldCheckMac, LogSource? log = null)
    {
        _service = service;
        _wrapper = wrapper;
        _maxTranceiveLengthForProtocol = maxTranceiveLengthForProtocol;
        _maxTranceiveLengthForSecureMessaging = maxTranceiveLengthForSecureMessaging;
        _shouldCheckMac = shouldCheckMac;
        _log = log ?? new LogSource();
    }

    /// <summary>Returns the secure messaging wrapper currently in use (updated as a side effect of <see cref="DoPace"/>).</summary>
    public SecureMessagingWrapper? Wrapper => _wrapper;

    /// <summary>Performs the PACE 2.0 / SAC protocol.</summary>
    /// <param name="accessKey">the MRZ or CAN based access key</param>
    /// <param name="oid">as specified in the PACEInfo, indicates GM or IM or CAM, DH or ECDH, cipher, digest, length</param>
    /// <param name="staticParameters">explicit static domain parameters (<see cref="DHParameters"/> or <see cref="ECDomainParameters"/>) for DH or ECDH</param>
    /// <param name="parameterId">parameter identifier or <c>null</c></param>
    /// <returns>a PACE result</returns>
    /// <exception cref="CardServiceException">if authentication failed or on some lower-level error</exception>
    public PACEResult DoPace(IAccessKeySpec accessKey, string oid, object staticParameters, BigInteger? parameterId)
    {
        _log.Info(LogCategory, $"Starting PACE (oid={oid}).");
        try
        {
            PACEResult result = DoPace(accessKey, DeriveStaticPaceKey(accessKey, oid), oid, staticParameters, parameterId);
            _log.Info(LogCategory, "PACE completed; secure messaging established.");
            return result;
        }
        catch (CardServiceException e)
        {
            _log.Error(LogCategory, "PACE failed.", e);
            throw;
        }
        catch (Exception e)
        {
            _log.Error(LogCategory, "PACE failed during key derivation.", e);
            throw new CardServiceProtocolException("PCD side error in key derivation step", 0, e);
        }
    }

    /// <summary>Performs the PACE 2.0 / SAC protocol.</summary>
    /// <param name="accessKey">the key specification from which the static PACE key is derived</param>
    /// <param name="staticPaceKey">the password key</param>
    /// <param name="oid">as specified in the PACEInfo, indicates GM or IM or CAM, DH or ECDH, cipher, digest, length</param>
    /// <param name="staticParameters">the domain params for DH or ECDH</param>
    /// <param name="parameterId">parameter identifier or <c>null</c></param>
    /// <returns>a PACE result</returns>
    /// <exception cref="CardServiceException">if authentication failed or on lower level errors</exception>
    private PACEResult DoPace(IAccessKeySpec accessKey, PaceSecretKeySpec staticPaceKey, string oid, object staticParameters, BigInteger? parameterId)
    {
        PACEInfo.MappingType mappingType = PACEInfo.ToMappingType(oid); /* Either GM, CAM, or IM. */
        string agreementAlg = PACEInfo.ToKeyAgreementAlgorithm(oid); /* Either DH or ECDH. */
        string cipherAlg = PACEInfo.ToCipherAlgorithm(oid); /* Either DESede or AES. */
        string digestAlg = PACEInfo.ToDigestAlgorithm(oid); /* Either SHA-1 or SHA-256. */
        int keyLength = PACEInfo.ToKeyLength(oid); /* Of the enc cipher. Either 128, 192, or 256. */

        CheckConsistency(agreementAlg, cipherAlg, digestAlg, keyLength, staticParameters);

        _log.Debug(LogCategory, $"Mapping={mappingType}, agreement={agreementAlg}, cipher={cipherAlg}, digest={digestAlg}, keyLength={keyLength}.");

        try
        {
            /*
             * Doc 9303 4.4.4: Reference of a public key / secret key. REQUIRED.
             * The password to be used is indicated as follows: 0x01: MRZ_information, 0x02: CAN.
             *
             * Doc 9303 4.4.4: Reference of a private key / Reference for computing a session key. CONDITIONAL.
             * This data object is REQUIRED to indicate the identifier of the domain parameters to be used
             * if the domain parameters are ambiguous, i.e. more than one set of domain parameters is
             * available for PACE.
             */
            byte paceKeyReference = staticPaceKey.KeyReference;
            byte[]? referencePrivateKeyOrForComputingSessionKey = parameterId == null ? null : Util.I2os(parameterId);

            /* Send to the PICC. */
            _log.Debug(LogCategory, "Step 0: sending MSE:Set AT.");
            _service.SendMseSetAtMutualAuth(_wrapper, oid, paceKeyReference, referencePrivateKeyOrForComputingSessionKey!);
        }
        catch (CardServiceException cse)
        {
            _log.Error(LogCategory, "MSE:Set AT failed (PICC side).", cse);
            throw new CardServiceProtocolException("PICC side error in static PACE key derivation step", 0, cse);
        }
        catch (Exception e)
        {
            /* NOTE: Any other exception, must be PCD side. */
            _log.Error(LogCategory, "MSE:Set AT failed (PCD side).", e);
            throw new CardServiceProtocolException("PCD side error in static PACE key derivation step", 0, e);
        }

        /*
         * PCD and PICC exchange a chain of general authenticate commands.
         * Steps 1 to 4 below correspond with steps in table 3.3 of ICAO TR-SAC 1.01.
         */

        /* Receive encrypted nonce z = E(K_pi, s). Decrypt nonce s = D(K_pi, z). */
        _log.Debug(LogCategory, "Step 1: receiving and decrypting PICC nonce.");
        byte[] piccNonce = DoPaceStep1(staticPaceKey, cipherAlg);

        /*
         * Receive additional data required for map, i.e., a public key from PICC, and (conditionally) a
         * nonce t. Compute ephemeral domain parameters D~ = Map(D_PICC, s).
         */
        _log.Debug(LogCategory, "Step 2: mapping nonce to ephemeral domain parameters.");
        PACEMappingResult mappingResult = DoPaceStep2(mappingType, agreementAlg, staticParameters, piccNonce, cipherAlg);
        object ephemeralParams = mappingResult.EphemeralParameters!;

        /* Choose random ephemeral PCD side keys (SK_PCD~, PK_PCD~, D~). */
        AsymmetricCipherKeyPair ephemeralPcdKeyPair = DoPaceStep3GenerateKeyPair(agreementAlg, ephemeralParams);

        /* Exchange PK_PCD~ and PK_PICC~ with PICC. Check that PK_PCD~ and PK_PICC~ differ. */
        _log.Debug(LogCategory, "Step 3: exchanging ephemeral public keys.");
        AsymmetricKeyParameter ephemeralPiccPublicKey = DoPaceStep3ExchangePublicKeys(ephemeralPcdKeyPair.Public, ephemeralParams);

        /* Key agreement K = KA(SK_PCD~, PK_PICC~, D~). */
        byte[] sharedSecretBytes = DoPaceStep3KeyAgreement(agreementAlg, ephemeralPcdKeyPair.Private, ephemeralPiccPublicKey);
        _log.Debug(LogCategory, "Step 3: key agreement complete.");

        /* Derive secure messaging keys. Compute session keys K_mac = KDF_mac(K), K_enc = KDF_enc(K). */
        KeyParameter encKey;
        KeyParameter macKey;
        try
        {
            encKey = new KeyParameter(Util.DeriveKey(sharedSecretBytes, cipherAlg, keyLength, Util.ENC_MODE));
            macKey = new KeyParameter(Util.DeriveKey(sharedSecretBytes, cipherAlg, keyLength, Util.MAC_MODE));
        }
        catch (Exception gse)
        {
            _log.Error(LogCategory, "Secure messaging key derivation failed.", gse);
            throw new CardServiceProtocolException("Security exception during secure messaging key derivation", 3, gse);
        }

        /*
         * Compute authentication token T_PCD = MAC(K_mac, PK_PICC~).
         * Exchange authentication token T_PCD and T_PICC with PICC. Check authentication token T_PICC.
         * Extract encryptedChipAuthenticationData, if mapping is CAM.
         */
        _log.Debug(LogCategory, "Step 4: exchanging and verifying authentication tokens.");
        byte[]? encryptedChipAuthenticationData = DoPaceStep4(oid, mappingType, ephemeralPcdKeyPair, ephemeralPiccPublicKey, macKey);
        byte[]? chipAuthenticationData = null;

        /*
         * Start secure messaging.
         *
         * 4.6 of TR-SAC: If Secure Messaging is restarted, the SSC is used as follows:
         *  - The commands used for key agreement are protected with the old session keys and old SSC.
         *    This applies in particular for the response of the last command used for session key agreement.
         *  - The Send Sequence Counter is set to its new start value, i.e. within this specification the SSC is set to 0.
         *  - The new session keys and the new SSC are used to protect subsequent commands/responses.
         */
        try
        {
            long ssc = _wrapper?.SendSequenceCounter ?? 0L;
            if (cipherAlg.StartsWith("DESede", StringComparison.Ordinal))
            {
                _wrapper = new DESedeSecureMessagingWrapper(encKey, macKey, _maxTranceiveLengthForSecureMessaging, _shouldCheckMac, 0L);
            }
            else if (cipherAlg.StartsWith("AES", StringComparison.Ordinal))
            {
                _wrapper = new AESSecureMessagingWrapper(encKey, macKey, _maxTranceiveLengthForSecureMessaging, _shouldCheckMac, ssc);
            }
            else
            {
                // NOTE: Java logs a warning ("Unsupported cipher algorithm ...") here; omitted per the
                // non-essential-warning-omission precedent used elsewhere in this port.
            }

            _log.Debug(LogCategory, $"Secure messaging established ({cipherAlg}).");
        }
        catch (Exception gse)
        {
            _log.Error(LogCategory, "Secure messaging establishment failed.", gse);
            throw new CardServiceProtocolException("Security exception in secure messaging establishment", 4, gse);
        }

        if (mappingType == PACEInfo.MappingType.CAM)
        {
            if (encryptedChipAuthenticationData == null)
            {
                // NOTE: Java logs a warning here; omitted per precedent.
            }

            /* Decrypt A_PICC to recover CA_PICC. */
            try
            {
                // NOTE: preserved Java quirk -- Java's decryptCipher.doFinal(encryptedChipAuthenticationData)
                // throws an (uncaught-here, propagating) NullPointerException if the data is null (only
                // GeneralSecurityException is caught locally); the null-forgiving operator below reproduces
                // that (a NullReferenceException here likewise isn't a CryptoException, so it propagates out
                // of this try, matching Java exactly). Not "fixed" per this port's quirk-preservation policy.
                chipAuthenticationData = DecryptChipAuthenticationData(encKey, encryptedChipAuthenticationData!);
                _log.Debug(LogCategory, "PACE-CAM chip authentication data decrypted.");
            }
            catch (Org.BouncyCastle.Crypto.CryptoException ce)
            {
                _log.Warn(LogCategory, $"PACE-CAM chip authentication data could not be decrypted: {ce.Message}");
            }

            /* CAM result. Include Chip Authentication data. */
            return new PACECAMResult(
                accessKey,
                agreementAlg,
                cipherAlg,
                digestAlg,
                keyLength,
                mappingResult,
                ephemeralPcdKeyPair,
                ephemeralPiccPublicKey,
                encryptedChipAuthenticationData,
                chipAuthenticationData,
                _wrapper);
        }

        /* GM or IM result. */
        return new PACEResult(
            accessKey,
            mappingType,
            agreementAlg,
            cipherAlg,
            digestAlg,
            keyLength,
            mappingResult,
            ephemeralPcdKeyPair,
            ephemeralPiccPublicKey,
            _wrapper);
    }

    /// <summary>
    /// The first step in the PACE protocol receives an encrypted nonce from the PICC and decrypts it.
    /// </summary>
    /// <param name="staticPaceKey">the static PACE key</param>
    /// <param name="cipherAlg">the cipher algorithm to use, either <c>"AES"</c> or <c>"DESede"</c></param>
    /// <returns>the decrypted encrypted PICC nonce</returns>
    /// <exception cref="CardServiceProtocolException">on error</exception>
    public byte[] DoPaceStep1(PaceSecretKeySpec staticPaceKey, string cipherAlg)
    {
        try
        {
            byte[] step1Data = [];
            /* Command data is empty. This implies an empty dynamic authentication object. */
            byte[] step1Response = _service.SendGeneralAuthenticate(_wrapper, step1Data, 256, false);
            byte[] step1EncryptedNonce = TlvUtil.UnwrapDO(0x80, step1Response);

            IBufferedCipher staticPaceCipher = CreateCbcCipher(cipherAlg);
            staticPaceCipher.Init(forEncryption: false, new ParametersWithIV(new KeyParameter(staticPaceKey.GetKey()), new byte[GetBlockSize(cipherAlg)]));

            return staticPaceCipher.DoFinal(step1EncryptedNonce);
        }
        catch (CardServiceException cse)
        {
            _log.Error(LogCategory, "Step 1 (nonce exchange) failed (PICC side).", cse);
            throw new CardServiceProtocolException("PICC side exception in tranceiving nonce step", 1, cse);
        }
        catch (Exception e)
        {
            _log.Error(LogCategory, "Step 1 (nonce exchange) failed (PCD side).", e);
            throw new CardServiceProtocolException("PCD side exception in tranceiving nonce step", 1, e);
        }
    }

    /// <summary>
    /// The second step in the PACE protocol computes ephemeral domain parameters by mapping the PICC
    /// generated nonce (and optionally the PCD generated nonce, which will be exchanged, in case of
    /// Integrated Mapping).
    /// </summary>
    /// <param name="mappingType">either CAM, GM, or IM</param>
    /// <param name="agreementAlg">the agreement algorithm, either DH or ECDH</param>
    /// <param name="staticParameters">the static domain parameters</param>
    /// <param name="piccNonce">the nonce received from the PICC</param>
    /// <param name="cipherAlg">the cipher algorithm to use in IM, either <c>"AES"</c> or <c>"DESede"</c></param>
    /// <returns>the newly computed ephemeral domain parameters</returns>
    /// <exception cref="CardServiceProtocolException">on error</exception>
    public PACEMappingResult DoPaceStep2(PACEInfo.MappingType mappingType, string agreementAlg, object staticParameters, byte[] piccNonce, string cipherAlg) =>
        mappingType switch
        {
            PACEInfo.MappingType.CAM or PACEInfo.MappingType.GM => DoPaceStep2Gm(agreementAlg, staticParameters, piccNonce),
            PACEInfo.MappingType.IM => DoPaceStep2Im(agreementAlg, staticParameters, piccNonce, cipherAlg),
            _ => throw new CardServiceProtocolException($"Unsupported mapping type {mappingType}", 2),
        };

    /// <summary>
    /// The second step in the PACE protocol (GM case) computes ephemeral domain parameters by performing
    /// a key agreement protocol with the PICC nonce as input.
    /// </summary>
    /// <param name="agreementAlg">the agreement algorithm, either DH or ECDH</param>
    /// <param name="staticParameters">the static domain parameters</param>
    /// <param name="piccNonce">the received nonce from the PICC</param>
    /// <returns>the computed ephemeral domain parameters</returns>
    /// <exception cref="CardServiceProtocolException">on error</exception>
    public PACEGMMappingResult DoPaceStep2Gm(string agreementAlg, object staticParameters, byte[] piccNonce)
    {
        try
        {
            AsymmetricCipherKeyPair pcdMappingKeyPair = GenerateKeyPairForAgreement(agreementAlg, staticParameters);
            AsymmetricKeyParameter pcdMappingPublicKey = pcdMappingKeyPair.Public;
            AsymmetricKeyParameter pcdMappingPrivateKey = pcdMappingKeyPair.Private;

            byte[] pcdMappingEncodedPublicKey = EncodePublicKeyForSmartCard(pcdMappingPublicKey);
            byte[] step2Data = TlvUtil.WrapDO(0x81, pcdMappingEncodedPublicKey);

            byte[] step2Response = _service.SendGeneralAuthenticate(
                _wrapper,
                step2Data,
                step2Data.Length > 233 ? PassportService.ExtendedMaxTranceiveLength : _maxTranceiveLengthForProtocol,
                false);

            byte[] piccMappingEncodedPublicKey = TlvUtil.UnwrapDO(0x82, step2Response);
            AsymmetricKeyParameter piccMappingPublicKey = DecodePublicKeyFromSmartCard(piccMappingEncodedPublicKey, staticParameters);
            if (piccMappingPublicKey is DHPublicKeyParameters piccMappingDHPublicKey)
            {
                CheckDHPublicValue(piccMappingDHPublicKey.Y, (DHParameters)staticParameters);
            }

            if (agreementAlg == "ECDH")
            {
                /* Treat shared secret as an ECPoint. */
                var mappingAgreement = new PACEGMWithECDHAgreement();
                mappingAgreement.Init((ECPrivateKeyParameters)pcdMappingPrivateKey);
                ECPoint mappingSharedSecretPoint = mappingAgreement.DoPhase((ECPublicKeyParameters)piccMappingPublicKey);
                ECDomainParameters ephemeralParameters = MapNonceGMWithECDH(piccNonce, mappingSharedSecretPoint, (ECDomainParameters)staticParameters);
                return new PACEGMWithECDHMappingResult(staticParameters, piccNonce, piccMappingPublicKey, pcdMappingKeyPair, mappingSharedSecretPoint, ephemeralParameters);
            }

            if (agreementAlg == "DH")
            {
                byte[] mappingSharedSecretBytes = EACCAProtocol.ComputeSharedSecret("DH", piccMappingPublicKey, pcdMappingPrivateKey);
                DHParameters ephemeralParameters = MapNonceGMWithDH(piccNonce, Util.Os2i(mappingSharedSecretBytes), (DHParameters)staticParameters);
                return new PACEGMWithDHMappingResult(staticParameters, piccNonce, piccMappingPublicKey, pcdMappingKeyPair, mappingSharedSecretBytes, ephemeralParameters);
            }

            throw new ArgumentException(
                $"Unsupported parameters for mapping nonce, expected \"ECDH\" or \"DH\", found \"{agreementAlg}\"");
        }
        catch (CardServiceException cse)
        {
            _log.Error(LogCategory, "Step 2 (nonce mapping, GM) failed (PICC side).", cse);
            throw new CardServiceProtocolException("PICC side exception in mapping nonce step", 2, cse);
        }
        catch (Exception e)
        {
            /* NOTE: Any exception, must be PCD side. */
            _log.Error(LogCategory, "Step 2 (nonce mapping, GM) failed (PCD side).", e);
            throw new CardServiceProtocolException("PCD side error in mapping nonce step", 2, e);
        }
    }

    /// <summary>
    /// The second step in the PACE protocol computes ephemeral domain parameters by performing a key
    /// agreement protocol with the PICC and PCD nonces as input.
    ///
    /// The function Map: G -&gt; G_Map is defined as G_Map = f_G(R_p(s,t)), where R_p() is a pseudo-random
    /// function that maps octet strings to elements of GF(p) and f_G() is a function that maps elements of
    /// GF(p) to &lt;G&gt;. The random nonce t SHALL be chosen randomly by the inspection system and sent to
    /// the MRTD chip.
    /// </summary>
    /// <param name="agreementAlg">the agreement algorithm, either DH or ECDH</param>
    /// <param name="staticParameters">the static domain parameters</param>
    /// <param name="piccNonce">the received nonce from the PICC</param>
    /// <param name="cipherAlg">the cipher algorithm to use, either <c>"AES"</c> or <c>"DESede"</c></param>
    /// <returns>the computed ephemeral domain parameters</returns>
    /// <exception cref="CardServiceProtocolException">on error</exception>
    public PACEIMMappingResult DoPaceStep2Im(string agreementAlg, object staticParameters, byte[] piccNonce, string cipherAlg)
    {
        try
        {
            byte[] pcdNonce = new byte[piccNonce.Length];
            RandomNumberGenerator.Fill(pcdNonce);

            byte[] step2Data = TlvUtil.WrapDO(0x81, pcdNonce);

            /* NOTE: The context specific data object 0x82 SHALL be empty (TR SAC 3.3.2). */
            _service.SendGeneralAuthenticate(
                _wrapper,
                step2Data,
                step2Data.Length > 233 ? PassportService.ExtendedMaxTranceiveLength : _maxTranceiveLengthForProtocol,
                false);

            if (agreementAlg == "ECDH")
            {
                ECDomainParameters ephemeralParameters = MapNonceImWithECDH(piccNonce, pcdNonce, cipherAlg, (ECDomainParameters)staticParameters);
                return new PACEIMMappingResult(staticParameters, piccNonce, pcdNonce, ephemeralParameters);
            }

            if (agreementAlg == "DH")
            {
                DHParameters ephemeralParameters = MapNonceImWithDH(piccNonce, pcdNonce, cipherAlg, (DHParameters)staticParameters);
                return new PACEIMMappingResult(staticParameters, piccNonce, pcdNonce, ephemeralParameters);
            }

            throw new ArgumentException(
                $"Unsupported parameters for mapping nonce, expected \"ECDH\" or \"DH\", found \"{agreementAlg}\"");
        }
        catch (CardServiceException cse)
        {
            _log.Error(LogCategory, "Step 2 (nonce mapping, IM) failed (PICC side).", cse);
            throw new CardServiceProtocolException("PICC side exception in mapping nonce step", 2, cse);
        }
        catch (Exception e)
        {
            _log.Error(LogCategory, "Step 2 (nonce mapping, IM) failed (PCD side).", e);
            throw new CardServiceProtocolException("PCD side error in mapping nonce step", 2, e);
        }
    }

    /// <summary>Chooses a random ephemeral key pair. (SK_PCD~, PK_PCD~, D~).</summary>
    /// <param name="agreementAlg">the agreement algorithm</param>
    /// <param name="ephemeralParams">the parameters</param>
    /// <returns>the key pair</returns>
    /// <exception cref="CardServiceProtocolException">on error</exception>
    public AsymmetricCipherKeyPair DoPaceStep3GenerateKeyPair(string agreementAlg, object ephemeralParams)
    {
        try
        {
            return GenerateKeyPairForAgreement(agreementAlg, ephemeralParams);
        }
        catch (Exception gse)
        {
            _log.Error(LogCategory, "Step 3 (ephemeral key pair generation) failed.", gse);
            throw new CardServiceProtocolException("PCD side error during generation of PCD key pair", 3, gse);
        }
    }

    /// <summary>Sends the PCD's public key to the PICC and receives and interprets the PICC's public key in exchange.</summary>
    /// <param name="pcdPublicKey">the PCD's public key</param>
    /// <param name="ephemeralParams">the ephemeral parameters to interpret the PICC's public key</param>
    /// <returns>the PICC's public key</returns>
    /// <exception cref="CardServiceProtocolException">on error</exception>
    public AsymmetricKeyParameter DoPaceStep3ExchangePublicKeys(AsymmetricKeyParameter pcdPublicKey, object ephemeralParams)
    {
        try
        {
            byte[] pcdEncodedPublicKey = EncodePublicKeyForSmartCard(pcdPublicKey);
            byte[] step3Data = TlvUtil.WrapDO(0x83, pcdEncodedPublicKey);
            byte[] step3Response = _service.SendGeneralAuthenticate(
                _wrapper,
                step3Data,
                step3Data.Length > 233 ? PassportService.ExtendedMaxTranceiveLength : _maxTranceiveLengthForProtocol,
                false);
            byte[] piccEncodedPublicKey = TlvUtil.UnwrapDO(0x84, step3Response);
            AsymmetricKeyParameter piccPublicKey = DecodePublicKeyFromSmartCard(piccEncodedPublicKey, ephemeralParams);
            if (piccPublicKey is DHPublicKeyParameters piccDHPublicKey)
            {
                CheckDHPublicValue(piccDHPublicKey.Y, (DHParameters)ephemeralParams);
            }

            if (KeysAreEqual(pcdPublicKey, piccPublicKey))
            {
                // NOTE: preserved Java quirk -- this CardServiceProtocolException is itself a
                // CardServiceException, so it gets caught and re-wrapped by the catch clause immediately
                // below (a double-wrapped exception chain in the Java original too). Not "fixed" per this
                // port's quirk-preservation policy.
                throw new CardServiceProtocolException("PCD's public key and PICC's public key are the same in key agreement step!", 3);
            }

            return piccPublicKey;
        }
        catch (CardServiceException cse)
        {
            _log.Error(LogCategory, "Step 3 (public key exchange) failed (PICC side).", cse);
            throw new CardServiceProtocolException("PICC side exception in key agreement step", 3, cse);
        }
        catch (Exception e)
        {
            _log.Error(LogCategory, "Step 3 (public key exchange) failed (PCD side).", e);
            throw new CardServiceProtocolException("PCD side exception in key agreement step", 3, e);
        }
    }

    /// <summary>Performs the key agreement.</summary>
    /// <param name="agreementAlg">the agreement algorithm, either <c>"DH"</c> or <c>"ECDH"</c></param>
    /// <param name="pcdPrivateKey">the PCD's private key</param>
    /// <param name="piccPublicKey">the PICC's public key</param>
    /// <returns>the shared secret</returns>
    /// <exception cref="CardServiceProtocolException">on error</exception>
    public byte[] DoPaceStep3KeyAgreement(string agreementAlg, AsymmetricKeyParameter pcdPrivateKey, AsymmetricKeyParameter piccPublicKey)
    {
        try
        {
            return EACCAProtocol.ComputeSharedSecret(agreementAlg, piccPublicKey, pcdPrivateKey);
        }
        catch (Exception e)
        {
            _log.Error(LogCategory, "Step 3 (key agreement) failed.", e);
            throw new CardServiceProtocolException("PCD side error during key agreement", 3, e);
        }
    }

    /// <summary>Exchanges authentication tokens.</summary>
    /// <param name="oid">the object identifier</param>
    /// <param name="mappingType">the mapping type (GM, IM, or CAM)</param>
    /// <param name="pcdKeyPair">the PCD's key pair</param>
    /// <param name="piccPublicKey">the PICC's public key</param>
    /// <param name="macKey">the MAC key to use</param>
    /// <returns>possible encrypted chip authentication data (PACE-CAM case), or <c>null</c></returns>
    /// <exception cref="CardServiceException">on error</exception>
    public byte[]? DoPaceStep4(string oid, PACEInfo.MappingType mappingType, AsymmetricCipherKeyPair pcdKeyPair, AsymmetricKeyParameter piccPublicKey, KeyParameter macKey)
    {
        try
        {
            byte[] pcdToken = GenerateAuthenticationToken(oid, macKey, piccPublicKey);
            byte[] step4Data = TlvUtil.WrapDO(0x85, pcdToken);
            byte[] step4Response = _service.SendGeneralAuthenticate(_wrapper, step4Data, 256, true);

            byte[]? encryptedChipAuthenticationData = null;
            using (var step4Stream = new MemoryStream(step4Response, writable: false))
            using (var step4ResponseInputStream = new TlvInputStream(step4Stream))
            {
                try
                {
                    int tag86 = step4ResponseInputStream.ReadTag();
                    if (tag86 != 0x86)
                    {
                        // NOTE: Java logs a warning here; omitted per precedent.
                    }

                    step4ResponseInputStream.ReadLength();
                    byte[] piccToken = step4ResponseInputStream.ReadValue();

                    byte[] expectedPiccToken = GenerateAuthenticationToken(oid, macKey, pcdKeyPair.Public);
                    if (!expectedPiccToken.AsSpan().SequenceEqual(piccToken))
                    {
                        throw new CryptographicException(
                            $"PICC authentication token mismatch, expectedPICCToken = {Hex.BytesToHexString(expectedPiccToken)}, piccToken = {Hex.BytesToHexString(piccToken)}");
                    }

                    if (mappingType == PACEInfo.MappingType.CAM)
                    {
                        int tag8A = step4ResponseInputStream.ReadTag();
                        if (tag8A != 0x8A)
                        {
                            // NOTE: Java logs a warning here; omitted per precedent.
                        }

                        step4ResponseInputStream.ReadLength();
                        encryptedChipAuthenticationData = step4ResponseInputStream.ReadValue();
                    }
                }
                catch (IOException)
                {
                    // NOTE: Java logs a warning ("Could not parse step 4 response") here; omitted per
                    // precedent. This intentionally only swallows TLV-parse errors (EndOfStreamException
                    // derives from IOException in .NET) -- the CryptographicException thrown above for a
                    // token mismatch is not an IOException and propagates to the outer catch below, matching
                    // Java's own catch(IOException)-does-not-catch-GeneralSecurityException behavior.
                }
            }

            return encryptedChipAuthenticationData;
        }
        catch (Exception e)
        {
            _log.Error(LogCategory, "Step 4 (authentication token exchange) failed.", e);
            throw new CardServiceProtocolException("PCD side exception in authentication token generation step", 4, e);
        }
    }

    /// <summary>
    /// Decrypts the Encrypted Chip Authentication Data (A_PICC) sent by the PICC in the last step of
    /// PACE-CAM, recovering the Chip Authentication Data (CA_PICC).
    ///
    /// Per Doc 9303-11, 4.4.5.5: AES SHALL be used in CBC-mode with IV=E(KSEnc,-1), where -1 is the bit
    /// string of length 128 with all bits set to 1. That is, the IV is not the all-ones block itself, but
    /// the result of encrypting that block (as a single AES block, i.e. ECB) with K_enc.
    /// </summary>
    /// <param name="encKey">the PACE session key K_enc</param>
    /// <param name="encryptedChipAuthenticationData">the encrypted Chip Authentication Data (A_PICC)</param>
    /// <returns>the decrypted, unpadded Chip Authentication Data (CA_PICC)</returns>
    public static byte[] DecryptChipAuthenticationData(KeyParameter encKey, byte[] encryptedChipAuthenticationData)
    {
        var ivEngine = new AesEngine();
        ivEngine.Init(forEncryption: true, encKey);
        byte[] iv = new byte[ivEngine.GetBlockSize()];
        ivEngine.ProcessBlock(MinusOneBlockForPaceCamIv, 0, iv, 0);

        IBufferedCipher decryptCipher = new BufferedBlockCipher(new CbcBlockCipher(new AesEngine()));
        decryptCipher.Init(forEncryption: false, new ParametersWithIV(encKey, iv));
        byte[] paddedChipAuthenticationData = decryptCipher.DoFinal(encryptedChipAuthenticationData);
        return Util.Unpad(paddedChipAuthenticationData);
    }

    /// <summary>Derives the static key K_pi.</summary>
    /// <param name="accessKey">the key material from the MRZ</param>
    /// <param name="oid">the PACE object identifier is needed to determine the cipher algorithm and the key length</param>
    /// <returns>the derived key</returns>
    public static PaceSecretKeySpec DeriveStaticPaceKey(IAccessKeySpec accessKey, string oid)
    {
        string cipherAlg = PACEInfo.ToCipherAlgorithm(oid); /* Either DESede or AES. */
        int keyLength = PACEInfo.ToKeyLength(oid); /* Of the enc cipher. Either 128, 192, or 256. */
        byte[] keySeed = ComputeKeySeedForPace(accessKey);

        byte paceKeyReference = accessKey is PaceKeySpec paceKeySpec ? paceKeySpec.KeyReference : (byte)0;

        byte[] keyBytes = Util.DeriveKey(keySeed, cipherAlg, keyLength, null, Util.PACE_MODE);
        return new PaceSecretKeySpec(keyBytes, cipherAlg, paceKeyReference);
    }

    /// <summary>Computes a key seed based on an access key.</summary>
    /// <param name="accessKey">the access key</param>
    /// <returns>a key seed for secure messaging keys</returns>
    public static byte[] ComputeKeySeedForPace(IAccessKeySpec accessKey)
    {
        ArgumentNullException.ThrowIfNull(accessKey);

        /* MRZ based key. */
        if (accessKey is IBacKeySpec bacKey)
        {
            string documentNumber = bacKey.GetDocumentNumber();
            string dateOfBirth = bacKey.GetDateOfBirth();
            string dateOfExpiry = bacKey.GetDateOfExpiry();

            if (dateOfBirth == null || dateOfBirth.Length != 6)
            {
                throw new ArgumentException($"Wrong date format used for date of birth. Expected yyMMdd, found {dateOfBirth}");
            }

            if (dateOfExpiry == null || dateOfExpiry.Length != 6)
            {
                throw new ArgumentException($"Wrong date format used for date of expiry. Expected yyMMdd, found {dateOfExpiry}");
            }

            if (documentNumber == null)
            {
                throw new ArgumentException($"Wrong document number. Found {documentNumber}");
            }

            documentNumber = FixDocumentNumber(documentNumber);

            return ComputeKeySeedForPaceMrz(documentNumber, dateOfBirth, dateOfExpiry);
        }

        if (accessKey is PaceKeySpec paceKeySpec)
        {
            return paceKeySpec.GetKey();
        }

        // NOTE: Java logs a warning ("JMRTD doesn't recognize this type of access key, best effort key
        // derivation!") here; omitted per precedent.
        return accessKey.GetKey();
    }

    /* Generic Mapping. */

    /// <summary>Maps the nonce for the ECDH case using Generic Mapping to get new parameters (notably a new generator).</summary>
    /// <param name="nonceS">the nonce received from the PICC</param>
    /// <param name="sharedSecretPointH">the shared secret</param>
    /// <param name="staticParameters">the static parameters</param>
    /// <returns>the new parameters</returns>
    public static ECDomainParameters MapNonceGMWithECDH(byte[] nonceS, ECPoint sharedSecretPointH, ECDomainParameters staticParameters)
    {
        /* D~ = (p, a, b, G~, n, h) where G~ = [s]G + H */
        ECPoint generator = staticParameters.G;
        ECPoint ephemeralGenerator = generator.Multiply(Util.Os2i(nonceS)).Add(sharedSecretPointH).Normalize();
        if (!ephemeralGenerator.IsValid())
        {
            throw new ArgumentException("Mapped generator is not a valid point");
        }

        return new ECDomainParameters(staticParameters.Curve, ephemeralGenerator, staticParameters.N, staticParameters.H);
    }

    /// <summary>Maps the nonce for the DH case using Generic Mapping to get new parameters (notably a new generator).</summary>
    /// <param name="nonceS">the nonce received from the PICC</param>
    /// <param name="sharedSecretH">the shared secret point</param>
    /// <param name="staticParameters">the static parameters</param>
    /// <returns>the new parameters, keeping q if the static parameters have it</returns>
    /// <exception cref="ArgumentException">if the mapped generator is 0 or 1</exception>
    public static DHParameters MapNonceGMWithDH(byte[] nonceS, BigInteger sharedSecretH, DHParameters staticParameters)
    {
        // g~ = g^s * h
        BigInteger p = staticParameters.P;
        BigInteger generator = staticParameters.G;
        BigInteger mappedGenerator = generator.ModPow(Util.Os2i(nonceS), p).Multiply(sharedSecretH).Mod(p);
        if (mappedGenerator.CompareTo(BigInteger.One) <= 0)
        {
            throw new ArgumentException($"Invalid mapped generator: {mappedGenerator}");
        }

        // Keep q (null if the static parameters do not have it), needed for public key validation in the
        // key agreement step.
        return new DHParameters(p, mappedGenerator, staticParameters.Q, staticParameters.L);
    }

    /// <summary>
    /// Validates a DH public value received from the PICC, as in RFC 2631, Section 2.1.5 (required by
    /// Doc 9303 - Part 11, 4.4.3.3 and 9.6). The value must be in <c>[2, p - 1]</c>, and (if q is known)
    /// in the subgroup of order q.
    /// </summary>
    /// <param name="y">the public value</param>
    /// <param name="parameters">the domain parameters</param>
    /// <exception cref="Org.BouncyCastle.Security.InvalidKeyException">if the public value is not valid</exception>
    internal static void CheckDHPublicValue(BigInteger y, DHParameters parameters)
    {
        BigInteger p = parameters.P;
        if (y.CompareTo(BigInteger.Two) < 0 || y.CompareTo(p.Subtract(BigInteger.One)) > 0)
        {
            throw new Org.BouncyCastle.Security.InvalidKeyException("DH public value not in [2, p - 1]");
        }

        BigInteger? q = parameters.Q;
        if (q != null && !y.ModPow(q, p).Equals(BigInteger.One))
        {
            throw new Org.BouncyCastle.Security.InvalidKeyException("DH public value not in the subgroup of order q");
        }
    }

    /* Integrated Mapping. */

    /// <summary>
    /// Transforms the nonces using a pseudo random number function and maps the resulting value to a point
    /// on the curve. The resulting point is used as a generator as part of the returned domain parameters.
    /// </summary>
    /// <param name="nonceS">the nonce from the PICC</param>
    /// <param name="nonceT">the nonce from the PCD</param>
    /// <param name="cipherAlgorithm">the cipher algorithm to be used by the pseudo random function, either <c>"AES"</c> or <c>"DESede"</c></param>
    /// <param name="staticParameters">the static domain parameters</param>
    /// <returns>the newly computed domain parameters</returns>
    public static ECDomainParameters MapNonceImWithECDH(byte[] nonceS, byte[] nonceT, string cipherAlgorithm, ECDomainParameters staticParameters)
    {
        BigInteger p = Util.GetPrime(staticParameters);
        BigInteger t = Util.Os2i(PseudoRandomFunction(nonceS, nonceT, p, cipherAlgorithm));
        ECPoint mappedGenerator = IcartPointEncode(t, staticParameters);
        return new ECDomainParameters(staticParameters.Curve, mappedGenerator, staticParameters.N, staticParameters.H);
    }

    /*
     * The function Map: g -> g~ is defined as g~ = f_g(R_p(s, t)), where R_p() is the pseudo-random function
     * that maps octet strings to elements of GF(p) and f_g() is a function that maps elements of GF(p) to
     * <g>. f_g(x) = x^a mod p, and a = (p-1)/q is the cofactor. Implementations MUST check that g~ != 1.
     */
    /// <summary>
    /// Transforms the nonces using a pseudo random number function and maps the resulting value to a field
    /// element. The resulting field element is used as a generator as part of the returned domain parameters.
    /// </summary>
    /// <param name="nonceS">the nonce from the PICC</param>
    /// <param name="nonceT">the nonce from the PCD</param>
    /// <param name="cipherAlgorithm">the cipher algorithm to be used by the pseudo random function, either <c>"AES"</c> or <c>"DESede"</c></param>
    /// <param name="staticParameters">the static domain parameters</param>
    /// <returns>the newly computed domain parameters</returns>
    public static DHParameters MapNonceImWithDH(byte[] nonceS, byte[] nonceT, string cipherAlgorithm, DHParameters staticParameters)
    {
        BigInteger g = staticParameters.G;
        if (g == null || g.Equals(BigInteger.One))
        {
            throw new ArgumentException($"Invalid generator: {g}");
        }

        if (staticParameters.Q == null)
        {
            // With q = 1 the mapped generator would always be x^(p - 1) mod p = 1.
            throw new ArgumentException("PACE-IM with DH requires the subgroup order q");
        }

        BigInteger p = staticParameters.P;
        BigInteger q = staticParameters.Q;

        BigInteger x = Util.Os2i(PseudoRandomFunction(nonceS, nonceT, p, cipherAlgorithm));

        BigInteger a = p.Subtract(BigInteger.One).Divide(q);

        BigInteger mappedGenerator = x.ModPow(a, p);
        if (mappedGenerator.Equals(BigInteger.One))
        {
            throw new InvalidOperationException("Mapped generator is 1");
        }
        return new DHParameters(p, mappedGenerator, q, staticParameters.L);
    }

    /*
     * The function R_p(s,t) is a function that maps octet strings s (of bit length l) and t (of bit length
     * k) to an element int(x_1 || x_2 || ... || x_n) mod p of GF(p), based on the respective block cipher
     * E() in CBC mode according to ISO/IEC 10116 with IV=0, where k is the key size (in bits) of E(). The
     * value n SHALL be selected as smallest number, such that n*l >= log2 p + 64.
     */
    /// <summary>Pseudo random number function as specified in Doc 9303 - Part 11, 4.4.3.3.2. Used in PACE IM.</summary>
    /// <param name="s">the nonce that was sent by the ICC</param>
    /// <param name="t">the nonce that was generated by the PCD</param>
    /// <param name="p">the order of the prime field</param>
    /// <param name="cipherAlg">the algorithm for block cipher E, either <c>"AES"</c> or <c>"DESede"</c></param>
    /// <returns>the resulting x</returns>
    public static byte[] PseudoRandomFunction(byte[] s, byte[] t, BigInteger p, string cipherAlg)
    {
        if (s == null || t == null)
        {
            throw new ArgumentException("Null nonce");
        }

        int l = s.Length * 8;
        int k = t.Length * 8; /* Key size in bits. */

        byte[] c0;
        byte[] c1;
        switch (l)
        {
            case 128:
                c0 = C0Length128;
                c1 = C1Length128;
                break;
            case 192: /* Fall through. */
            case 256:
                c0 = C0Length256;
                c1 = C1Length256;
                break;
            default:
                throw new ArgumentException($"Unknown length {l}, was expecting 128, 192, or 256");
        }

        IBufferedCipher cipher = CreateCbcCipher(cipherAlg);
        int blockSize = GetBlockSize(cipherAlg);
        byte[] zeroIv = new byte[blockSize];

        cipher.Init(forEncryption: true, new ParametersWithIV(new KeyParameter(t), zeroIv));
        byte[] key = cipher.DoFinal(s);

        using var x = new MemoryStream();
        int n = 0;
        while ((long)n * l < p.BitLength + 64)
        {
            cipher.Init(forEncryption: true, new ParametersWithIV(new KeyParameter(key, 0, k / 8), zeroIv));
            key = cipher.DoFinal(c0);
            byte[] xi = cipher.DoFinal(c1);
            x.Write(xi, 0, xi.Length);
            n++;
        }

        byte[] xBytes = x.ToArray();
        return Util.I2os(Util.Os2i(xBytes).Mod(p));
    }

    /*
     * Icart's point encoding. Based on the implementation for affine coordinates as described in ICAO SAC
     * TR 2010, Section 5.2.
     */
    /// <summary>Icart's point encoding for Elliptic Curve over a prime field. Maps a field element to a point on the curve. Used in PACE IM ECDH.</summary>
    /// <param name="t">the field element to encode</param>
    /// <param name="staticParameters">the parameters describing the curve and field</param>
    /// <returns>the point on the curve that the input is mapped to</returns>
    public static ECPoint IcartPointEncode(BigInteger t, ECDomainParameters staticParameters)
    {
        BigInteger p = Util.GetPrime(staticParameters);
        if (!BigInteger.ValueOf(3).Equals(p.Mod(BigInteger.ValueOf(4))))
        {
            throw new ArgumentException("Cannot encode point because p != 3 (mod 4)");
        }

        ECCurve curve = staticParameters.Curve;
        BigInteger a = curve.A.ToBigInteger();
        BigInteger b = curve.B.ToBigInteger();

        /* 1. */
        BigInteger alpha = t.ModPow(BigInteger.ValueOf(2), p).Negate().Mod(p);

        /* 2. (Using implementation note 5.2.2). */
        BigInteger alphaSq = alpha.ModPow(BigInteger.ValueOf(2), p);
        BigInteger alphaPlusAlphaSq = alpha.Add(alphaSq).Mod(p);
        BigInteger onePlusAlphaPlusAlphaSq = BigInteger.One.Add(alphaPlusAlphaSq);
        BigInteger pMinus2 = p.Subtract(BigInteger.One).Subtract(BigInteger.One);
        BigInteger x2 = b.Negate().Multiply(onePlusAlphaPlusAlphaSq).Multiply(a.Multiply(alphaPlusAlphaSq).ModPow(pMinus2, p)).Mod(p);

        /* 3. */
        BigInteger x3 = alpha.Multiply(x2).Mod(p);

        /* 4. */
        BigInteger h2 = x2.ModPow(BigInteger.ValueOf(3), p).Add(a.Multiply(x2)).Add(b).Mod(p);

        /* 6. */
        BigInteger u = t.ModPow(BigInteger.ValueOf(3), p).Multiply(h2).Mod(p);

        /* 7. */
        BigInteger pPlusOneOverFour = p.Add(BigInteger.One).Multiply(BigInteger.ValueOf(4).ModInverse(p)).Mod(p);
        BigInteger pMinusOneMinusPPlusOneOverFour = p.Subtract(BigInteger.One).Subtract(pPlusOneOverFour);
        BigInteger aa = h2.ModPow(pMinusOneMinusPPlusOneOverFour, p);

        BigInteger aaSqTimesH2 = aa.ModPow(BigInteger.ValueOf(2), p).Multiply(h2).Mod(p);

        bool useX2 = aaSqTimesH2.Equals(BigInteger.One);
        BigInteger xCoord = useX2 ? x2 : x3;
        BigInteger yCoord = useX2 ? aa.Multiply(h2).Mod(p) : aa.Multiply(u).Mod(p);

        ECPoint xy = curve.CreatePoint(xCoord, yCoord);

        int cofactor = staticParameters.H.IntValue;
        return cofactor == 1 ? xy.Normalize() : xy.Multiply(BigInteger.ValueOf(cofactor)).Normalize();
    }

    /// <summary>
    /// Generates an authentication token. The authentication token SHALL be computed over a public key
    /// data object containing the object identifier as indicated in MSE:Set AT, and the received ephemeral
    /// public key (i.e. excluding the domain parameters) using an authentication code and the key KS MAC
    /// derived from the key agreement.
    /// </summary>
    /// <param name="oid">the object identifier as indicated in MSE Set AT</param>
    /// <param name="macKey">the KS MAC key derived from the key agreement</param>
    /// <param name="publicKey">the received public key</param>
    /// <returns>the authentication code</returns>
    public static byte[] GenerateAuthenticationToken(string oid, KeyParameter macKey, AsymmetricKeyParameter publicKey)
    {
        string cipherAlg = PACEInfo.ToCipherAlgorithm(oid);
        IMac mac = CreateMacForCipherAlgorithm(cipherAlg);
        mac.Init(macKey);

        byte[] encodedPublicKeyDataObject = EncodePublicKeyDataObject(oid, publicKey);
        mac.BlockUpdate(encodedPublicKeyDataObject, 0, encodedPublicKeyDataObject.Length);
        byte[] maccedPublicKeyDataObject = new byte[mac.GetMacSize()];
        mac.DoFinal(maccedPublicKeyDataObject, 0);

        /* Output length needs to be 64 bits, copy first 8 bytes. */
        byte[] authenticationToken = new byte[8];
        Array.Copy(maccedPublicKeyDataObject, authenticationToken, authenticationToken.Length);
        return authenticationToken;
    }

    /// <summary>Computes a key seed given a card access number (CAN).</summary>
    /// <param name="cardAccessNumber">the card access number</param>
    /// <returns>a key seed for deriving secure messaging keys</returns>
    public static byte[] ComputeKeySeedForPace(string cardAccessNumber) => Util.ComputeKeySeed(cardAccessNumber, "SHA-1", false);

    /// <summary>
    /// Based on TR-SAC 1.01 4.5.1 and 4.5.2. For signing authentication token, not for sending to smart card.
    /// </summary>
    /// <param name="oid">object identifier</param>
    /// <param name="publicKey">public key</param>
    /// <param name="isContextKnown">whether context of public key is known to receiver (domain parameters
    /// are then not included); assumed known when omitted</param>
    /// <returns>encoded public key data object for signing as authentication token</returns>
    /// <exception cref="ArgumentException">when public key is not DH or EC, or when DH domain parameters
    /// are to be included and the order of the subgroup q is not known</exception>
    public static byte[] EncodePublicKeyDataObject(string oid, AsymmetricKeyParameter publicKey, bool isContextKnown = true)
    {
        /* Checked before writing, as closing the stream with an unfinished 0x7F49 throws (and would hide the actual error). */
        if (publicKey is not DHPublicKeyParameters && publicKey is not ECPublicKeyParameters)
        {
            throw new ArgumentException($"Unsupported public key: {publicKey?.GetType()}");
        }
        if (!isContextKnown && publicKey is DHPublicKeyParameters { Parameters.Q: null })
        {
            throw new ArgumentException("Cannot encode DH domain parameters without the order of the subgroup q");
        }

        var byteArrayOutputStream = new MemoryStream();
        using (var tlvOutputStream = new TlvOutputStream(byteArrayOutputStream, leaveOpen: true))
        {
            tlvOutputStream.WriteTag(0x7F49); /* FIXME: constant for 7F49 (carried over from Java). */

            if (publicKey is DHPublicKeyParameters dhPublicKey)
            {
                DHParameters dhParameters = dhPublicKey.Parameters;
                BigInteger p = dhParameters.P;
                BigInteger generator = dhParameters.G;
                BigInteger y = dhPublicKey.Y;

                tlvOutputStream.Write(new DerObjectIdentifier(oid).GetEncoded()); /* Object Identifier, NOTE: encoding already contains 0x06 tag. */
                if (!isContextKnown)
                {
                    /* p: Prime modulus */
                    tlvOutputStream.WriteTag(0x81);
                    tlvOutputStream.WriteValue(Util.I2os(p));

                    /* q: Order of the subgroup */
                    tlvOutputStream.WriteTag(0x82);
                    tlvOutputStream.WriteValue(Util.I2os(dhParameters.Q!));

                    /* Generator */
                    tlvOutputStream.WriteTag(0x83);
                    tlvOutputStream.WriteValue(Util.I2os(generator));
                }

                /* y: Public value */
                tlvOutputStream.WriteTag(0x84);
                tlvOutputStream.WriteValue(Util.I2os(y));
            }
            else if (publicKey is ECPublicKeyParameters ecPublicKey)
            {
                ECDomainParameters ecParameters = ecPublicKey.Parameters;
                BigInteger p = Util.GetPrime(ecParameters);
                BigInteger a = ecParameters.Curve.A.ToBigInteger();
                BigInteger b = ecParameters.Curve.B.ToBigInteger();
                ECPoint generator = ecParameters.G;
                BigInteger order = ecParameters.N;
                BigInteger coFactor = ecParameters.H;
                ECPoint publicPoint = ecPublicKey.Q;

                /* Object Identifier, NOTE: encoding already contains 0x06 tag. */
                tlvOutputStream.Write(new DerObjectIdentifier(oid).GetEncoded());

                if (!isContextKnown)
                {
                    /* Prime modulus */
                    tlvOutputStream.WriteTag(0x81);
                    tlvOutputStream.WriteValue(Util.I2os(p));

                    /* First coefficient */
                    tlvOutputStream.WriteTag(0x82);
                    tlvOutputStream.WriteValue(Util.I2os(a));

                    /* Second coefficient */
                    tlvOutputStream.WriteTag(0x83);
                    tlvOutputStream.WriteValue(Util.I2os(b));

                    /* Base point, an elliptic curve point, uncompressed encoding (Doc 9303 - Part 11, 9.4.1). */
                    tlvOutputStream.WriteTag(0x84);
                    tlvOutputStream.WriteValue(Util.EcPoint2OS(generator, ecParameters.Curve.FieldSize));

                    /* Order of the base point */
                    tlvOutputStream.WriteTag(0x85);
                    tlvOutputStream.WriteValue(Util.I2os(order));
                }

                /* Public point */
                tlvOutputStream.WriteTag(0x86);
                tlvOutputStream.WriteValue(Util.EcPoint2OS(publicPoint, ecParameters.Curve.FieldSize));

                if (!isContextKnown)
                {
                    /* Cofactor */
                    tlvOutputStream.WriteTag(0x87);
                    tlvOutputStream.WriteValue(Util.I2os(coFactor));
                }
            }
            else
            {
                throw new ArgumentException($"Unsupported public key: {publicKey?.GetType()}");
            }

            tlvOutputStream.WriteValueEnd(); /* 7F49 */
            tlvOutputStream.Flush();
        }

        return byteArrayOutputStream.ToArray();
    }

    /// <summary>Write uncompressed coordinates (for EC) or public value (DH).</summary>
    /// <param name="publicKey">public key</param>
    /// <returns>encoding for smart card</returns>
    public static byte[] EncodePublicKeyForSmartCard(AsymmetricKeyParameter publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        if (publicKey is ECPublicKeyParameters ecPublicKey)
        {
            return EncodeECPointForSmartCard(ecPublicKey.Q, ecPublicKey.Parameters.Curve.FieldSize);
        }

        if (publicKey is DHPublicKeyParameters dhPublicKey)
        {
            return Util.I2os(dhPublicKey.Y);
        }

        throw new ArgumentException($"Unsupported public key: {publicKey.GetType()}");
    }

    /// <summary>Encodes an EC point for use as an APDU public key value.</summary>
    /// <param name="w">the point</param>
    /// <param name="bitLength">the field size in bits</param>
    /// <returns>the encoded public key</returns>
    public static byte[] EncodeECPointForSmartCard(ECPoint w, int bitLength) => Util.EcPoint2OS(w, bitLength);

    /// <summary>Decodes a public key received from the PICC.</summary>
    /// <param name="encodedPublicKey">the encoded public key that was received</param>
    /// <param name="staticParameters">the parameters used for interpreting the public key (<see cref="ECDomainParameters"/> or <see cref="DHParameters"/>)</param>
    /// <returns>the decoded public key object</returns>
    public static AsymmetricKeyParameter DecodePublicKeyFromSmartCard(byte[] encodedPublicKey, object staticParameters)
    {
        ArgumentNullException.ThrowIfNull(staticParameters);

        if (staticParameters is ECDomainParameters ecParameters)
        {
            (BigInteger x, BigInteger y) = Util.Os2ECPoint(encodedPublicKey);
            ECPoint q = ecParameters.Curve.CreatePoint(x, y);
            return new ECPublicKeyParameters(q, ecParameters);
        }

        if (staticParameters is DHParameters dhParameters)
        {
            BigInteger y = Util.Os2i(encodedPublicKey);
            return new DHPublicKeyParameters(y, dhParameters);
        }

        throw new ArgumentException($"Expected ECDomainParameters or DHParameters, found {staticParameters.GetType()}");
    }

    /// <summary>Fixes the document number so that it is in MRZ format. Replaces white spaces with fillers
    /// and makes sure the length is at least 9.</summary>
    /// <param name="documentNumber">the document number</param>
    /// <returns>a fixed document number</returns>
    private static string FixDocumentNumber(string documentNumber)
    {
        string minDocumentNumber = documentNumber.Replace('<', ' ').Trim().Replace(' ', '<');

        var result = new System.Text.StringBuilder(minDocumentNumber);
        while (result.Length < 9)
        {
            result.Append('<');
        }

        return result.ToString();
    }

    /// <summary>Computes the static key seed to be used in PACE KDF, based on information from the MRZ.</summary>
    /// <param name="documentNumber">a string containing the document number</param>
    /// <param name="dateOfBirth">a string containing the date of birth (YYMMDD)</param>
    /// <param name="dateOfExpiry">a string containing the date of expiry (YYMMDD)</param>
    /// <returns>a byte array of length 16 containing the key seed</returns>
    private static byte[] ComputeKeySeedForPaceMrz(string documentNumber, string dateOfBirth, string dateOfExpiry) =>
        Util.ComputeKeySeed(documentNumber, dateOfBirth, dateOfExpiry, "SHA-1", false);

    /// <summary>
    /// Compares two keys, taking into account that an exception might be thrown doing so. Returns
    /// <c>false</c> if an exception is thrown. Unlike Java's <c>PublicKey.equals</c> (of unknown, possibly
    /// reference-identity, provider-dependent behavior), BC's own <see cref="ECPublicKeyParameters"/>/
    /// <see cref="DHPublicKeyParameters"/> both declare their own value-based <c>Equals</c> overrides
    /// (confirmed by reflection against the BouncyCastle.Cryptography package used by this port), so a
    /// plain <c>Equals</c> call already does the right (value) comparison here.
    /// </summary>
    /// <param name="first">the first key</param>
    /// <param name="second">the second key</param>
    /// <returns>a boolean indicating equivalence of the two keys</returns>
    private static bool KeysAreEqual(AsymmetricKeyParameter first, AsymmetricKeyParameter second)
    {
        try
        {
            return first.Equals(second);
        }
        catch (Exception)
        {
            // NOTE: Java logs a warning here; omitted per precedent.
            return false;
        }
    }

    /// <summary>Checks consistency of input parameters.</summary>
    /// <param name="agreementAlg">the agreement algorithm derived from the object identifier</param>
    /// <param name="cipherAlg">the cipher algorithm derived from the object identifier</param>
    /// <param name="digestAlg">the digest algorithm derived from the object identifier</param>
    /// <param name="keyLength">the key length algorithm derived from the object identifier</param>
    /// <param name="staticParameters">the parameters</param>
    private static void CheckConsistency(string agreementAlg, string cipherAlg, string digestAlg, int keyLength, object staticParameters)
    {
        if (agreementAlg == null)
        {
            throw new ArgumentException("Unknown agreement algorithm");
        }

        /* Agreement algorithm should be ECDH or DH. */
        if (!(string.Equals(agreementAlg, "ECDH", StringComparison.OrdinalIgnoreCase) || string.Equals(agreementAlg, "DH", StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException($"Unsupported agreement algorithm, expected \"ECDH\" or \"DH\", found \"{agreementAlg}\"");
        }

        if (cipherAlg == null)
        {
            throw new ArgumentException("Unknown cipher algorithm");
        }

        if (!(string.Equals(cipherAlg, "DESede", StringComparison.OrdinalIgnoreCase) || string.Equals(cipherAlg, "AES", StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException($"Unsupported cipher algorithm, expected \"DESede\" or \"AES\", found \"{cipherAlg}\"");
        }

        if (!(string.Equals(digestAlg, "SHA-1", StringComparison.OrdinalIgnoreCase) || string.Equals(digestAlg, "SHA1", StringComparison.OrdinalIgnoreCase)
            || string.Equals(digestAlg, "SHA-256", StringComparison.OrdinalIgnoreCase) || string.Equals(digestAlg, "SHA256", StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException($"Unsupported cipher algorithm, expected \"SHA-1\" or \"SHA-256\", found \"{digestAlg}\"");
        }

        if (!(keyLength == 128 || keyLength == 192 || keyLength == 256))
        {
            throw new ArgumentException($"Unsupported key length, expected 128, 192, or 256, found {keyLength}");
        }

        /* Params should be correct param spec type, given agreement algorithm. */
        if (string.Equals(agreementAlg, "ECDH", StringComparison.OrdinalIgnoreCase) && staticParameters is not ECDomainParameters)
        {
            throw new ArgumentException($"Expected ECDomainParameters for agreement algorithm \"{agreementAlg}\", found {staticParameters?.GetType()}");
        }

        if (string.Equals(agreementAlg, "DH", StringComparison.OrdinalIgnoreCase) && staticParameters is not DHParameters)
        {
            throw new ArgumentException($"Expected DHParameters for agreement algorithm \"{agreementAlg}\", found {staticParameters?.GetType()}");
        }
    }

    /// <summary>
    /// Constructs the MAC primitive matching a given cipher algorithm: ISO9797 algorithm 3 ("retail MAC")
    /// for 3-DES, AES-CMAC for AES. ADAPTATION: replaces Java's <c>inferMACAlgorithmFromCipherAlgorithm</c>
    /// (which produced the JCA mnemonic <c>"ISO9797ALG3WITHISO7816-4PADDING"</c>, subsequently passed to
    /// the now-dropped <c>Util.getMac</c>) with direct BC primitive construction, folding both Java methods
    /// into one.
    ///
    /// <see cref="ISO9797Alg3Mac"/> implements the "retail MAC" (CBC-MAC with single DES, then a full
    /// triple-DES operation on the final block) itself, splitting a 16-byte key into two 8-byte halves
    /// internally -- it must be constructed with a single-DES <see cref="DesEngine"/>, never a
    /// <see cref="DesEdeEngine"/> (which only accepts 16-/24-byte keys and rejects the class's internal
    /// 8-byte half-key, throwing on the very first <c>Init</c> call). The explicit
    /// <see cref="ISO7816d4Padding"/> argument matches Java's <c>"...WITH ISO7816-4PADDING"</c> mnemonic;
    /// omitting it falls back to a different BC default padding that produces a different (wrong) MAC
    /// whenever the input isn't an exact multiple of the 8-byte block size.
    /// </summary>
    /// <param name="cipherAlg">the encryption algorithm, either <c>"DESede"</c> or <c>"AES"</c></param>
    /// <returns>the MAC primitive</returns>
    private static IMac CreateMacForCipherAlgorithm(string cipherAlg)
    {
        if (cipherAlg == null)
        {
            throw new ArgumentException("Cannot infer MAC algorithm from cipher algorithm null");
        }

        /*
         * NOTE: AESCMAC generates 128 bit (16 byte) results, not 64 bit (8 byte); both authentication token
         * generation and secure messaging, where the Mac is applied, copy only the first 8 bytes.
         */
        if (cipherAlg.StartsWith("DESede", StringComparison.Ordinal))
        {
            return new ISO9797Alg3Mac(new DesEngine(), new ISO7816d4Padding());
        }

        if (cipherAlg.StartsWith("AES", StringComparison.Ordinal))
        {
            return new CMac(new AesEngine());
        }

        throw new ArgumentException($"Cannot infer MAC algorithm from cipher algorithm \"{cipherAlg}\"");
    }

    /// <summary>Constructs the block cipher engine matching a given cipher algorithm name.</summary>
    /// <param name="cipherAlg">either <c>"AES"</c> or <c>"DESede"</c></param>
    /// <returns>a fresh block cipher engine</returns>
    private static IBlockCipher CreateBlockCipherEngine(string cipherAlg) => cipherAlg switch
    {
        "AES" => new AesEngine(),
        "DESede" => new DesEdeEngine(),
        _ => throw new ArgumentException($"Unsupported cipher algorithm {cipherAlg}"),
    };

    /// <summary>Constructs a CBC/NoPadding buffered cipher for the given cipher algorithm name.</summary>
    /// <param name="cipherAlg">either <c>"AES"</c> or <c>"DESede"</c></param>
    /// <returns>a fresh, uninitialized buffered cipher</returns>
    private static IBufferedCipher CreateCbcCipher(string cipherAlg) => new BufferedBlockCipher(new CbcBlockCipher(CreateBlockCipherEngine(cipherAlg)));

    /// <summary>Returns the block size (in bytes) for the given cipher algorithm name.</summary>
    /// <param name="cipherAlg">either <c>"AES"</c> or <c>"DESede"</c></param>
    /// <returns>the block size in bytes: 16 for AES, 8 for DESede</returns>
    private static int GetBlockSize(string cipherAlg) => cipherAlg == "AES" ? 16 : 8;

    /// <summary>
    /// Generates an ephemeral key pair for the given agreement algorithm and domain parameters.
    /// ADAPTATION: there is no JCA <c>KeyPairGenerator</c> concept in this port (see <c>Util.cs</c>'s doc
    /// comment on the dropped provider-lookup factory methods); this instantiates BC's lightweight
    /// <c>ECKeyPairGenerator</c>/<c>DHKeyPairGenerator</c> directly, following the same pattern already
    /// established by <c>EACCAProtocol.GenerateEphemeralKeyPair</c>. Used both for the mapping key pair
    /// (Generic Mapping, keyed against the static domain parameters) and the final ephemeral key pair
    /// (keyed against the already-mapped ephemeral domain parameters) -- Java duplicates this same
    /// <c>KeyPairGenerator</c> construction in both call sites; this port shares one helper instead.
    /// </summary>
    /// <param name="agreementAlg">the agreement algorithm, either <c>"DH"</c> or <c>"ECDH"</c></param>
    /// <param name="domainParameters">the domain parameters (<see cref="ECDomainParameters"/> or <see cref="DHParameters"/>) to generate the key pair against</param>
    /// <returns>the generated key pair</returns>
    private static AsymmetricCipherKeyPair GenerateKeyPairForAgreement(string agreementAlg, object domainParameters)
    {
        var random = new SecureRandom();

        if (agreementAlg == "ECDH")
        {
            if (domainParameters is not ECDomainParameters ecParameters)
            {
                throw new ArgumentException("Expected ECDomainParameters for ECDH agreement.", nameof(domainParameters));
            }

            var generator = new ECKeyPairGenerator();
            generator.Init(new ECKeyGenerationParameters(ecParameters, random));
            return generator.GenerateKeyPair();
        }

        if (agreementAlg == "DH")
        {
            if (domainParameters is not DHParameters dhParameters)
            {
                throw new ArgumentException("Expected DHParameters for DH agreement.", nameof(domainParameters));
            }

            var generator = new DHKeyPairGenerator();
            generator.Init(new DHKeyGenerationParameters(random, dhParameters));
            return generator.GenerateKeyPair();
        }

        throw new ArgumentException($"Unsupported agreement algorithm {agreementAlg}");
    }
}
