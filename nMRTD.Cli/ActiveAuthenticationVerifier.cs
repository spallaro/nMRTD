/*
 * nMRTD - A .Net API for accessing Machine Readable Travel Documents.
 *
 * Copyright (C) Sebastiano Pallaro.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * Distributed under the terms of GNU LGPL v3.
 * See LICENSE for more information.
 */

using nMRTD.Lds;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace nMRTD.Cli;

/// <summary>
/// Verifies an Active Authentication response (ICAO Doc 9303-11, 6.1): the chip's signature over the
/// terminal's 8-byte challenge, with the DG15 public key. The library only transports the challenge and the
/// response (as JMRTD does), so the verification is the terminal's job.
/// </summary>
public static class ActiveAuthenticationVerifier
{
    /// <summary>The outcome: <c>true</c> or <c>false</c>, or <c>null</c> when it cannot be decided (an ECDSA
    /// key without an <c>ActiveAuthenticationInfo</c> naming the hash, or an unsupported key type).</summary>
    public sealed record Result(bool? Valid, string Algorithm);

    /// <param name="publicKey">the DG15 public key</param>
    /// <param name="signatureAlgorithmOid">the ECDSA signature algorithm from the <c>ActiveAuthenticationInfo</c>
    /// in DG14, or <c>null</c> if DG14 has none (it is only needed for ECDSA keys)</param>
    /// <param name="challenge">the challenge sent to the chip</param>
    /// <param name="response">the chip's response</param>
    public static Result Verify(AsymmetricKeyParameter publicKey, string? signatureAlgorithmOid, byte[] challenge, byte[] response)
    {
        switch (publicKey)
        {
            case RsaKeyParameters rsa:
                return VerifyRsa(rsa, challenge, response);
            case ECPublicKeyParameters ec:
                if (signatureAlgorithmOid == null)
                {
                    return new Result(null, "ECDSA (DG14 has no ActiveAuthenticationInfo naming the hash)");
                }
                string mnemonic = ActiveAuthenticationInfo.LookupMnemonicByOID(signatureAlgorithmOid);
                return new Result(VerifyEcdsa(ec, mnemonic, challenge, response), mnemonic);
            default:
                return new Result(null, publicKey.GetType().Name);
        }
    }

    /// <summary>ISO/IEC 9796-2 digital signature scheme 1, with the challenge as the non-recoverable part. The
    /// hash is implicit SHA-1 (trailer 0xBC) or named in an explicit trailer (0x..CC); each is tried.</summary>
    private static Result VerifyRsa(RsaKeyParameters key, byte[] challenge, byte[] response)
    {
        (Func<IDigest> Digest, bool Implicit, string Name)[] candidates =
        [
            (() => new Sha1Digest(), true, "SHA-1"),
            (() => new Sha1Digest(), false, "SHA-1"),
            (() => new Sha224Digest(), false, "SHA-224"),
            (() => new Sha256Digest(), false, "SHA-256"),
            (() => new Sha384Digest(), false, "SHA-384"),
            (() => new Sha512Digest(), false, "SHA-512"),
        ];
        if (response.Length == 0)
        {
            return new Result(false, "RSA ISO/IEC 9796-2");
        }

        foreach ((Func<IDigest> digest, bool isImplicit, string name) in candidates)
        {
            try
            {
                var verifier = new Iso9796d2Signer(new RsaEngine(), digest(), isImplicit);
                verifier.Init(false, key);
                verifier.UpdateWithRecoveredMessage(response);
                verifier.BlockUpdate(challenge, 0, challenge.Length);
                if (verifier.VerifySignature(response))
                {
                    return new Result(true, $"RSA ISO/IEC 9796-2, {name}");
                }
            }
            catch (Exception e) when (e is InvalidCipherTextException or InvalidOperationException)
            {
                // The response does not use this hash or trailer (Bouncy Castle throws
                // InvalidOperationException for a trailer naming another hash); try the next one.
            }
        }

        return new Result(false, "RSA ISO/IEC 9796-2");
    }

    /// <summary>ECDSA with a plain signature, r || s (BSI TR-03111).</summary>
    private static bool VerifyEcdsa(ECPublicKeyParameters key, string mnemonic, byte[] challenge, byte[] response)
    {
        if (response.Length == 0 || response.Length % 2 != 0)
        {
            return false;
        }

        IDigest digest = DigestUtilities.GetDigest(Util.InferDigestAlgorithmFromSignatureAlgorithm(mnemonic)!);
        digest.BlockUpdate(challenge, 0, challenge.Length);
        byte[] hash = new byte[digest.GetDigestSize()];
        digest.DoFinal(hash, 0);

        var verifier = new ECDsaSigner();
        verifier.Init(false, key);
        int half = response.Length / 2;
        return verifier.VerifySignature(hash, new BigInteger(1, response[..half]), new BigInteger(1, response[half..]));
    }
}
