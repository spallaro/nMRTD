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
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

using nMRTD.Lds;
using nMRTD.Logging;
using nMRTD.SmartCards;

using BcBigInteger = Org.BouncyCastle.Math.BigInteger;

namespace nMRTD.Protocol;

/// <summary>
/// Port of <c>org.jmrtd.protocol.EACCAProtocol</c>: the EAC Chip Authentication protocol (version 1).
///
/// ADAPTATION: Java relies on JCA's <c>KeyPairGenerator</c>/<c>KeyAgreement</c> (via the BouncyCastle
/// provider) for ephemeral key generation and Diffie-Hellman/EC Diffie-Hellman key agreement. There is no
/// JCA provider-lookup concept in this port (see <c>Util.cs</c>'s doc comment on the dropped
/// <c>getKeyAgreement</c>/<c>getKeyPairGenerator</c> factory methods) -- <see cref="GenerateEphemeralKeyPair"/>
/// and <see cref="ComputeSharedSecret"/> below instantiate BC's lightweight <c>ECKeyPairGenerator</c>/
/// <c>DHKeyPairGenerator</c> and <see cref="ECDHBasicAgreement"/>/<see cref="DHBasicAgreement"/> directly.
/// The shared-secret encoding in particular is a best-effort reproduction of what JCA's
/// <c>KeyAgreement.generateSecret()</c> (BC provider) returns for "DH"/"ECDH" -- an unsigned big-endian
/// octet string, left-padded/truncated to the byte length of the underlying field/modulus -- since there
/// is no reference implementation to interop-test against directly in this port; this matches the
/// TR-03110 octet-string convention already used for the same purpose elsewhere in this class (see
/// <see cref="GetKeyHash"/>) and in <c>Util.AlignKeyDataToSize</c>.
/// </summary>
public class EACCAProtocol
{
    private const int CommandChainingChunkSize = 223;
    private const string LogCategory = "EAC-CA";

    private readonly IApduLevelEacCACapable _service;

    private SecureMessagingWrapper _wrapper;

    private readonly int _maxTransceiveLength;

    private readonly bool _shouldCheckMac;

    private readonly LogSource _log;

    /// <summary>Constructs a protocol instance.</summary>
    /// <param name="service">the card service</param>
    /// <param name="wrapper">the existing secure messaging wrapper</param>
    /// <param name="maxTransceiveLength">the maximal transceive length (on responses to <c>READ BINARY</c>)
    /// to use in the resulting secure messaging channel</param>
    /// <param name="shouldCheckMac">whether the resulting secure messaging channel should apply strict
    /// MAC checking on response APDUs</param>
    /// <param name="log">the log/trace registry to raise protocol-step and error events on, or <c>null</c> for a private (unobserved) one</param>
    public EACCAProtocol(IApduLevelEacCACapable service, SecureMessagingWrapper wrapper, int maxTransceiveLength, bool shouldCheckMac, LogSource? log = null)
    {
        _service = service;
        _wrapper = wrapper;
        _maxTransceiveLength = maxTransceiveLength;
        _shouldCheckMac = shouldCheckMac;
        _log = log ?? new LogSource();
    }

    /// <summary>
    /// Perform EAC-CA (Chip Authentication) part of EAC (version 1). For details see TR-03110 ver. 1.11.
    /// In short, we authenticate the chip with DH or ECDH key agreement protocol and create new secure
    /// messaging keys.
    ///
    /// The newly established secure messaging wrapper is made available to the caller in the result.
    /// </summary>
    /// <param name="keyId">passport's public key id (stored in DG14), <c>null</c> if none</param>
    /// <param name="oid">the object identifier indicating the Chip Authentication protocol</param>
    /// <param name="publicKeyOID">the object identifier indicating the type of public key</param>
    /// <param name="piccPublicKey">PICC's public key (stored in DG14)</param>
    /// <returns>the Chip Authentication result</returns>
    /// <exception cref="CardServiceException">if Chip Authentication failed or some error occurred</exception>
    public EACCAResult DoCA(BigInteger? keyId, string? oid, string? publicKeyOID, AsymmetricKeyParameter piccPublicKey)
    {
        ArgumentNullException.ThrowIfNull(piccPublicKey);

        oid ??= InferChipAuthenticationOidFromPublicKeyOid(publicKeyOID);

        string? agreementAlg = null;
        try
        {
            agreementAlg = ChipAuthenticationInfo.ToKeyAgreementAlgorithm(oid);
        }
        catch (FormatException)
        {
            // NOTE: Java logs a warning ("Unknown object identifier ...") here; omitted per the
            // non-essential-warning-omission precedent used elsewhere in this port.
        }

        if (agreementAlg != "ECDH" && agreementAlg != "DH")
        {
            throw new ArgumentException($"Unsupported agreement algorithm, expected ECDH or DH, found {agreementAlg ?? "null"}");
        }

        _log.Info(LogCategory, $"Starting Chip Authentication (oid={oid}, agreement={agreementAlg}).");

        try
        {
            AsymmetricCipherKeyPair pcdKeyPair = GenerateEphemeralKeyPair(agreementAlg, piccPublicKey);
            AsymmetricKeyParameter pcdPublicKey = pcdKeyPair.Public;
            AsymmetricKeyParameter pcdPrivateKey = pcdKeyPair.Private;

            // agreementAlg is non-null here (checked above); oid must therefore also be non-null (it fed
            // the successful ToKeyAgreementAlgorithm(oid) call that produced agreementAlg).
            SendPublicKey(_service, _wrapper, oid!, keyId, pcdPublicKey);

            byte[] keyHash = GetKeyHash(agreementAlg, pcdPublicKey);

            byte[] sharedSecret = ComputeSharedSecret(agreementAlg, piccPublicKey, pcdPrivateKey);

            _wrapper = RestartSecureMessaging(oid!, sharedSecret, _maxTransceiveLength, _shouldCheckMac);

            _log.Info(LogCategory, "Chip Authentication completed; secure messaging restarted.");
            return new EACCAResult(keyId, piccPublicKey, keyHash, pcdPublicKey, pcdPrivateKey, _wrapper);
        }
        catch (CardServiceException e)
        {
            _log.Error(LogCategory, "Chip Authentication failed.", e);
            throw;
        }
        catch (Exception e)
        {
            _log.Error(LogCategory, "Chip Authentication failed.", e);
            // NOTE: Java only catches GeneralSecurityException here -- CardServiceException/
            // CardServiceProtocolException (thrown by SendPublicKey) are not a GeneralSecurityException
            // subtype in Java and so propagate unwrapped. There is no equivalent narrower checked-exception
            // family in this port (see Util.cs's doc comment on the dropped JCA provider-lookup methods),
            // so this catches everything except CardServiceException (rethrown above) instead -- the net
            // observable behavior (CardServiceException propagates raw, everything else gets wrapped) is
            // preserved.
            throw new CardServiceException("Security exception during Chip Authentication", e);
        }
    }

    /// <summary>Sends the PCD's public key to the PICC.</summary>
    /// <param name="service">the card service</param>
    /// <param name="wrapper">the existing secure messaging wrapper</param>
    /// <param name="oid">the Chip Authentication object identifier</param>
    /// <param name="keyId">a key identifier or <c>null</c></param>
    /// <param name="pcdPublicKey">the public key to send</param>
    /// <exception cref="CardServiceException">on error</exception>
    public static void SendPublicKey(IApduLevelEacCACapable service, SecureMessagingWrapper wrapper, string oid, BigInteger? keyId, AsymmetricKeyParameter pcdPublicKey)
    {
        string agreementAlg = ChipAuthenticationInfo.ToKeyAgreementAlgorithm(oid);
        string cipherAlg = ChipAuthenticationInfo.ToCipherAlgorithm(oid);
        byte[] keyData = GetKeyData(agreementAlg, pcdPublicKey);

        if (cipherAlg.StartsWith("DESede", StringComparison.Ordinal))
        {
            byte[]? idData = null;
            if (keyId != null)
            {
                byte[] keyIdBytes = keyId.Value.ToByteArray(isUnsigned: true, isBigEndian: true); // See EACCAAPDUSender.cs's NOTE on this same conversion.
                idData = TlvUtil.WrapDO(0x84, keyIdBytes); /* FIXME: Constant for 0x84 (carried over from Java). */
            }

            try
            {
                service.SendMseKat(wrapper, TlvUtil.WrapDO(0x91, keyData), idData); /* FIXME: Constant for 0x91 (carried over from Java). */
            }
            catch (Exception e)
            {
                throw new CardServiceProtocolException("Exception during MSE KAT", 1, e);
            }
        }
        else if (cipherAlg.StartsWith("AES", StringComparison.Ordinal))
        {
            try
            {
                service.SendMseSetAtIntAuth(wrapper, oid, keyId);
            }
            catch (Exception e)
            {
                throw new CardServiceProtocolException("Exception during MSE Set AT Int Auth", 1, e);
            }

            try
            {
                byte[] data = TlvUtil.WrapDO(0x80, keyData); /* FIXME: Constant for 0x80 (carried over from Java). */
                SendGeneralAuthenticate(service, wrapper, data);
            }
            catch (Exception e)
            {
                throw new CardServiceProtocolException("Exception during General Authenticate", 2, e);
            }
        }
        else
        {
            throw new InvalidOperationException($"Cannot set up secure channel with cipher {cipherAlg}");
        }
    }

    /// <summary>Performs the key agreement step. Generates a secret based on the PICC's public key and the PCD's private key.</summary>
    /// <param name="agreementAlg">the agreement algorithm</param>
    /// <param name="piccPublicKey">the PICC's public key</param>
    /// <param name="pcdPrivateKey">the PCD's private key</param>
    /// <returns>the shared secret</returns>
    public static byte[] ComputeSharedSecret(string agreementAlg, AsymmetricKeyParameter piccPublicKey, AsymmetricKeyParameter pcdPrivateKey)
    {
        if (agreementAlg == "ECDH")
        {
            if (pcdPrivateKey is not ECPrivateKeyParameters ecPrivateKey)
            {
                throw new ArgumentException("Expected an EC private key for ECDH agreement.", nameof(pcdPrivateKey));
            }

            var agreement = new ECDHBasicAgreement();
            agreement.Init(pcdPrivateKey);
            BcBigInteger z = agreement.CalculateAgreement(piccPublicKey);
            int fieldSize = (int)Math.Ceiling(ecPrivateKey.Parameters.Curve.FieldSize / 8.0);
            return Util.I2os(z, fieldSize);
        }

        if (agreementAlg == "DH")
        {
            if (pcdPrivateKey is not DHPrivateKeyParameters dhPrivateKey)
            {
                throw new ArgumentException("Expected a DH private key for DH agreement.", nameof(pcdPrivateKey));
            }

            var agreement = new DHBasicAgreement();
            agreement.Init(pcdPrivateKey);
            BcBigInteger z = agreement.CalculateAgreement(piccPublicKey);
            int modSize = (int)Math.Ceiling(dhPrivateKey.Parameters.P.BitLength / 8.0);
            return Util.I2os(z, modSize);
        }

        throw new ArgumentException($"Unsupported agreement algorithm {agreementAlg}");
    }

    /// <summary>Restarts secure messaging based on the shared secret.</summary>
    /// <param name="oid">the Chip Authentication object identifier</param>
    /// <param name="sharedSecret">the shared secret</param>
    /// <param name="maxTransceiveLength">the maximum APDU transceive length</param>
    /// <param name="shouldCheckMac">whether to check MAC</param>
    /// <returns>the secure messaging wrapper</returns>
    public static SecureMessagingWrapper RestartSecureMessaging(string oid, byte[] sharedSecret, int maxTransceiveLength, bool shouldCheckMac)
    {
        string cipherAlg = ChipAuthenticationInfo.ToCipherAlgorithm(oid);
        int keyLength = ChipAuthenticationInfo.ToKeyLength(oid);

        /* Start secure messaging. */
        var ksEnc = new KeyParameter(Util.DeriveKey(sharedSecret, cipherAlg, keyLength, Util.ENC_MODE));
        var ksMac = new KeyParameter(Util.DeriveKey(sharedSecret, cipherAlg, keyLength, Util.MAC_MODE));

        if (cipherAlg.StartsWith("DESede", StringComparison.Ordinal))
        {
            return new DESedeSecureMessagingWrapper(ksEnc, ksMac, maxTransceiveLength, shouldCheckMac, 0L);
        }

        if (cipherAlg.StartsWith("AES", StringComparison.Ordinal))
        {
            return new AESSecureMessagingWrapper(ksEnc, ksMac, maxTransceiveLength, shouldCheckMac, 0L);
        }

        throw new InvalidOperationException($"Unsupported cipher algorithm {cipherAlg}");
    }

    /// <summary>Returns the secure messaging wrapper currently in use.</summary>
    public SecureMessagingWrapper Wrapper => _wrapper;

    /// <summary>Returns the key hash which will be used as input for Terminal Authentication.</summary>
    /// <param name="agreementAlg">the agreement algorithm, either <c>"DH"</c> or <c>"ECDH"</c></param>
    /// <param name="pcdPublicKey">the inspection system's public key</param>
    /// <returns>the key hash</returns>
    public static byte[] GetKeyHash(string agreementAlg, AsymmetricKeyParameter pcdPublicKey)
    {
        if (agreementAlg == "DH" || pcdPublicKey is DHPublicKeyParameters)
        {
            /* Comp(PK) for DH: SHA-1 of the public value (Doc 9303 - Part 11, 7.1.4.1.3), an unsigned integer (9.4.1). */
            IDigest md = DigestUtilities.GetDigest("SHA-1");
            byte[] data = GetKeyData(agreementAlg, pcdPublicKey);
            md.BlockUpdate(data, 0, data.Length);
            byte[] result = new byte[md.GetDigestSize()];
            md.DoFinal(result, 0);
            return result;
        }

        if (agreementAlg == "ECDH" || pcdPublicKey is ECPublicKeyParameters)
        {
            /* Comp(PK) for ECDH: the x-coordinate, fixed length (Doc 9303 - Part 11, 7.1.4.2.3). */
            var pcdECPublicKey = (ECPublicKeyParameters)pcdPublicKey;
            byte[] t = Util.I2os(pcdECPublicKey.Q.AffineXCoord.ToBigInteger());
            int keySize = (int)Math.Ceiling(pcdECPublicKey.Parameters.Curve.FieldSize / 8.0);
            return Util.AlignKeyDataToSize(t, keySize);
        }

        throw new ArgumentException($"Unsupported agreement algorithm {agreementAlg}");
    }

    /// <summary>Sends the General Authenticate APDU in the AES case, possibly falling back to Command Chaining.</summary>
    /// <param name="service">the card service</param>
    /// <param name="wrapper">the existing secure messaging wrapper</param>
    /// <param name="data">the key data, already wrapped as a data-object</param>
    /// <exception cref="CardServiceException">on low-level communication error</exception>
    private static void SendGeneralAuthenticate(IApduLevelEacCACapable service, SecureMessagingWrapper wrapper, byte[] data)
    {
        try
        {
            service.SendGeneralAuthenticate(wrapper, data, true);
        }
        catch (CardServiceException)
        {
            // NOTE: Java logs a warning ("Failed to send GENERAL AUTHENTICATE, falling back to command
            // chaining") here before retrying; omitted per the non-essential-warning-omission precedent
            // used elsewhere in this port.
            List<byte[]> segments = Util.Partition(CommandChainingChunkSize, data);

            int index = 0;
            foreach (byte[] segment in segments)
            {
                service.SendGeneralAuthenticate(wrapper, segment, ++index >= segments.Count);
            }
        }
    }

    /// <summary>Returns the public key data to be sent.</summary>
    /// <param name="agreementAlg">the agreement algorithm, either <c>"DH"</c> or <c>"ECDH"</c></param>
    /// <param name="pcdPublicKey">the inspection system's public key</param>
    /// <returns>the key data</returns>
    private static byte[] GetKeyData(string agreementAlg, AsymmetricKeyParameter pcdPublicKey)
    {
        if (agreementAlg == "DH")
        {
            var pcdDHPublicKey = (DHPublicKeyParameters)pcdPublicKey;
            return Util.I2os(pcdDHPublicKey.Y);
        }

        if (agreementAlg == "ECDH")
        {
            var pcdECPublicKey = (ECPublicKeyParameters)pcdPublicKey;
            return pcdECPublicKey.Q.GetEncoded(false);
        }

        throw new ArgumentException($"Unsupported agreement algorithm {agreementAlg}");
    }

    /// <summary>Infers the Chip Authentication OID from a Chip Authentication public key OID. This is a best effort.</summary>
    /// <param name="publicKeyOID">the Chip Authentication public key OID</param>
    /// <returns>an OID or <c>null</c></returns>
    private static string? InferChipAuthenticationOidFromPublicKeyOid(string? publicKeyOID)
    {
        if (SecurityInfo.ID_PK_ECDH.Equals(publicKeyOID))
        {
            /*
             * This seems to work for French passports (generation 2013, 2014), but it is best effort.
             * NOTE: Java also logs a warning here; omitted per the non-essential-warning-omission
             * precedent used elsewhere in this port.
             */
            return SecurityInfo.ID_CA_ECDH_3DES_CBC_CBC;
        }

        if (SecurityInfo.ID_PK_DH.Equals(publicKeyOID))
        {
            /* Not tested. Best effort. */
            return SecurityInfo.ID_CA_DH_3DES_CBC_CBC;
        }

        return null;
    }

    /// <summary>
    /// Generates the inspection system's ephemeral key pair, using the PICC's domain parameters.
    /// ADAPTATION: see this class's doc comment -- there is no JCA <c>KeyPairGenerator</c> concept in this
    /// port, so this instantiates BC's lightweight <c>ECKeyPairGenerator</c>/<c>DHKeyPairGenerator</c> directly.
    /// </summary>
    private static AsymmetricCipherKeyPair GenerateEphemeralKeyPair(string agreementAlg, AsymmetricKeyParameter piccPublicKey)
    {
        var random = new SecureRandom();

        if (agreementAlg == "ECDH")
        {
            if (piccPublicKey is not ECPublicKeyParameters piccECPublicKey)
            {
                throw new ArgumentException("Expected an EC public key for ECDH agreement.", nameof(piccPublicKey));
            }

            var generator = new ECKeyPairGenerator();
            generator.Init(new ECKeyGenerationParameters(piccECPublicKey.Parameters, random));
            return generator.GenerateKeyPair();
        }

        if (agreementAlg == "DH")
        {
            if (piccPublicKey is not DHPublicKeyParameters piccDHPublicKey)
            {
                throw new ArgumentException("Expected a DH public key for DH agreement.", nameof(piccPublicKey));
            }

            var generator = new DHKeyPairGenerator();
            generator.Init(new DHKeyGenerationParameters(random, piccDHPublicKey.Parameters));
            return generator.GenerateKeyPair();
        }

        throw new ArgumentException($"Unsupported agreement algorithm {agreementAlg}");
    }
}
