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
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.SmartCards;

using BigInteger = Org.BouncyCastle.Math.BigInteger;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace nMRTD;

/// <summary>Port of <c>org.jmrtd.Util</c>: static helper functions, mostly dealing with low-level crypto.
///
/// This file makes several structural adaptations to fit the BC-lightweight-API design already
/// established by the ported <c>Lds</c> classes (see e.g. <see cref="ChipAuthenticationPublicKeyInfo"/>
/// and <see cref="PACEInfo"/>'s doc comments), rather than a mechanical method-for-method port:
/// <list type="bullet">
/// <item>Java's <c>java.security.PublicKey</c>/<c>PrivateKey</c> map to BC's
/// <see cref="Org.BouncyCastle.Crypto.AsymmetricKeyParameter"/> (and its <c>ECPublicKeyParameters</c> /
/// <c>DHPublicKeyParameters</c> / etc. subclasses), and JCA's <c>ECParameterSpec</c>/<c>DHParameterSpec</c>
/// map to BC's own <see cref="ECDomainParameters"/>/<see cref="DHParameters"/> -- both already established
/// throughout <c>Lds</c>.</item>
/// <item>An entire category of Java methods (<c>getCipher</c>, <c>getKeyAgreement</c>,
/// <c>getKeyPairGenerator</c>, <c>getMac</c>, <c>getMessageDigest</c>, <c>getPublicKey</c>,
/// <c>getSignature</c>, <c>getCertificateFactory</c>, <c>getBouncyCastleProvider</c>) existed only to try
/// the default JCA provider and fall back to an explicit BC <c>Provider</c> instance. BC's lightweight API
/// used throughout this port has no provider/fallback concept at all -- there is exactly one
/// implementation -- so none of these have a counterpart here; callers instantiate BC engines/digests
/// directly (e.g. <see cref="DigestUtilities.GetDigest(string)"/>, <c>new DesEdeEngine()</c>). This is a
/// deliberate omission, not an oversight.</item>
/// <item><see cref="DeriveKey(byte[], string, int, byte[], int)"/> returns the raw derived key bytes
/// instead of Java's <c>SecretKey</c>/<c>PACESecretKeySpec</c>. Java's <c>paceKeyReference</c> parameter
/// never affected the derived bytes themselves -- it only selected which wrapper type
/// (<c>SecretKeySpec</c> vs <c>PACESecretKeySpec</c>) to instantiate around the same bytes -- so that
/// overload is dropped; callers that need a <see cref="PaceSecretKeySpec"/> construct one directly from
/// the returned bytes (that type already exists in this codebase for exactly this purpose).</item>
/// <item><see cref="Os2ECPoint"/>/<see cref="EcPoint2OS(BigInteger, BigInteger, int)"/>: Java's
/// <c>os2ECPoint</c>/<c>ecPoint2OS</c> operate on <c>java.security.spec.ECPoint</c>, a curve-agnostic
/// value type holding only affine X/Y. BC has no equivalent -- <see cref="Org.BouncyCastle.Math.EC.ECPoint"/>
/// always requires a curve to construct. <see cref="Os2ECPoint"/> therefore returns a raw
/// <c>(BigInteger X, BigInteger Y)</c> tuple; callers combine it with an explicit curve
/// (<c>ECCurve.CreatePoint(x, y)</c>) when they need an actual point object. An <see cref="ECPoint"/>-typed
/// overload of <c>EcPoint2OS</c> is also provided for convenience.</item>
/// <item>Java's <c>toExplicitDHParameterSpec</c>/<c>toExplicitECParameterSpec</c>/<c>getECParameterSpec</c>
/// (JCA-provider-independent-encoding workarounds) and the private <c>toNamedCurveSpec</c>/
/// <c>toECNamedCurveSpec</c> helpers are omitted: BC's own <see cref="DHParameters"/> (which already
/// carries <c>Q</c>) and <see cref="ECDomainParameters"/> built via <c>ECNamedCurveTable</c> are already
/// explicit, provider-independent representations, exactly as already noted in <c>PACEInfo.cs</c>.
/// <see cref="GetECDomainParameters"/> replaces <c>getECParameterSpec</c> directly.</item>
/// <item><c>add</c>/<c>multiply</c>/<c>isValid</c>/<c>normalize</c>/<c>toBouncyCastleECPoint</c>/
/// <c>fromBouncyCastleECPoint</c> existed only to bridge JCA's naive <c>ECPoint</c> and BC's own
/// curve-aware <see cref="Org.BouncyCastle.Math.EC.ECPoint"/>. Since every point in this port already is a
/// BC <see cref="Org.BouncyCastle.Math.EC.ECPoint"/> (which has <c>Add</c>/<c>Multiply</c>/<c>IsValid</c>/
/// <c>Normalize</c> instance methods of its own), the surviving <see cref="Add"/>/<see cref="Multiply"/>/
/// <see cref="IsValid"/>/<see cref="Normalize"/> below are trivial one-line forwarders, kept only so a
/// future port of <c>protocol/</c> can 1:1 trace Java call sites against this API.</item>
/// </list></summary>
public static class Util
{
    /// <summary>Mode for KDF.</summary>
    public const int ENC_MODE = 1;

    public const int MAC_MODE = 2;

    public const int PACE_MODE = 3;

    /* RFC 5114 explicit (p, g, q) DH groups. Deliberately duplicated (not shared) with the private copies
     * in PACEInfo.cs -- this mirrors upstream JMRTD, where org.jmrtd.Util and org.jmrtd.lds.PACEInfo
     * likewise each define their own private copies of the same hex constants. */
    private const string RFC5114_1024_160_P =
        "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6" +
        "9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0" +
        "13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70" +
        "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0" +
        "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708" +
        "DF1FB2BC2E4A4371";
    private const string RFC5114_1024_160_G =
        "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F" +
        "D6406CFF14266D31266FEA1E5C41564B777E690F5504F213" +
        "160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1" +
        "909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A" +
        "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24" +
        "855E6EEB22B3B2E5";
    private const string RFC5114_1024_160_Q = "F518AA8781A8DF278ABA4E7D64B7CB9D49462353";

    private const string RFC5114_2048_224_P =
        "AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1" +
        "B54B1597B61D0A75E6FA141DF95A56DBAF9A3C407BA1DF15" +
        "EB3D688A309C180E1DE6B85A1274A0A66D3F8152AD6AC212" +
        "9037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207" +
        "C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708" +
        "B3BF8A317091883681286130BC8985DB1602E714415D9330" +
        "278273C7DE31EFDC7310F7121FD5A07415987D9ADC0A486D" +
        "CDF93ACC44328387315D75E198C641A480CD86A1B9E587E8" +
        "BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763" +
        "C9B53DCF4BA80A29E3FB73C16B8E75B97EF363E2FFA31F71" +
        "CF9DE5384E71B81C0AC4DFFE0C10E64F";
    private const string RFC5114_2048_224_G =
        "AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF" +
        "74866A08CFE4FFE3A6824A4E10B9A6F0DD921F01A70C4AFA" +
        "AB739D7700C29F52C57DB17C620A8652BE5E9001A8D66AD7" +
        "C17669101999024AF4D027275AC1348BB8A762D0521BC98A" +
        "E247150422EA1ED409939D54DA7460CDB5F6C6B250717CBE" +
        "F180EB34118E98D119529A45D6F834566E3025E316A330EF" +
        "BB77A86F0C1AB15B051AE3D428C8F8ACB70A8137150B8EEB" +
        "10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381" +
        "B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269" +
        "EDFE72FE9B6AA4BD7B5A0F1C71CFFF4C19C418E1F6EC0179" +
        "81BC087F2A7065B384B890D3191F2BFA";
    private const string RFC5114_2048_224_Q = "801C0D34C58D93FE997177101F80535A4738CEBCBF389A99B36371EB";

    private const string RFC5114_2048_256_P =
        "87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F2" +
        "5D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA30" +
        "16C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD" +
        "5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B" +
        "6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C" +
        "4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0E" +
        "F13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D9" +
        "67E144E5140564251CCACB83E6B486F6B3CA3F7971506026" +
        "C0B857F689962856DED4010ABD0BE621C3A3960A54E710C3" +
        "75F26375D7014103A4B54330C198AF126116D2276E11715F" +
        "693877FAD7EF09CADB094AE91E1A1597";
    private const string RFC5114_2048_256_G =
        "3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF2054" +
        "07F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555" +
        "BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18" +
        "A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B" +
        "777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC83" +
        "1D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55" +
        "A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14" +
        "C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915" +
        "B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6" +
        "184B523D1DB246C32F63078490F00EF8D647D148D4795451" +
        "5E2327CFEF98C582664B4C0F6CC41659";
    private const string RFC5114_2048_256_Q =
        "8CF83642A709A097B447997640129DA299B1A47D1EB3750B" +
        "A308B0FE64F5FBD3";

    /// <summary>Existence of a "hidden SNFS" backdoor cannot be ruled out. See https://eprint.iacr.org/2016/961.pdf</summary>
    [Obsolete("Existence of a \"hidden SNFS\" backdoor cannot be ruled out. See https://eprint.iacr.org/2016/961.pdf")]
    public static readonly DHParameters RFC5114_1024_160 = FromPGQ(RFC5114_1024_160_P, RFC5114_1024_160_G, RFC5114_1024_160_Q);

    /// <summary>Existence of a "hidden SNFS" backdoor cannot be ruled out. See https://eprint.iacr.org/2016/961.pdf</summary>
    [Obsolete("Existence of a \"hidden SNFS\" backdoor cannot be ruled out. See https://eprint.iacr.org/2016/961.pdf")]
    public static readonly DHParameters RFC5114_2048_224 = FromPGQ(RFC5114_2048_224_P, RFC5114_2048_224_G, RFC5114_2048_224_Q);

    /// <summary>Existence of a "hidden SNFS" backdoor cannot be ruled out. See https://eprint.iacr.org/2016/961.pdf</summary>
    [Obsolete("Existence of a \"hidden SNFS\" backdoor cannot be ruled out. See https://eprint.iacr.org/2016/961.pdf")]
    public static readonly DHParameters RFC5114_2048_256 = FromPGQ(RFC5114_2048_256_P, RFC5114_2048_256_G, RFC5114_2048_256_Q);

    /// <summary>Derives the ENC or MAC key for BAC from the keySeed.</summary>
    /// <param name="keySeed">the key seed</param>
    /// <param name="mode">either <see cref="ENC_MODE"/> or <see cref="MAC_MODE"/></param>
    /// <returns>the key bytes</returns>
    public static byte[] DeriveKey(byte[] keySeed, int mode) => DeriveKey(keySeed, "DESede", 128, mode);

    /// <summary>Derives the ENC or MAC key for BAC or PACE.</summary>
    /// <param name="keySeed">the key seed</param>
    /// <param name="cipherAlgName">either AES or DESede</param>
    /// <param name="keyLength">key length in bits</param>
    /// <param name="mode">either <see cref="ENC_MODE"/>, <see cref="MAC_MODE"/>, or <see cref="PACE_MODE"/></param>
    /// <returns>the key bytes</returns>
    public static byte[] DeriveKey(byte[] keySeed, string cipherAlgName, int keyLength, int mode) =>
        DeriveKey(keySeed, cipherAlgName, keyLength, null, mode);

    /// <summary>Derives a shared key.</summary>
    /// <param name="keySeed">the shared secret, as octets</param>
    /// <param name="cipherAlg">in JCA mnemonic notation (for example "DESede", "AES")</param>
    /// <param name="keyLength">length in bits</param>
    /// <param name="nonce">optional nonce or <c>null</c></param>
    /// <param name="mode">the mode, either <see cref="ENC_MODE"/>, <see cref="MAC_MODE"/>, or <see cref="PACE_MODE"/></param>
    /// <returns>the derived key bytes</returns>
    public static byte[] DeriveKey(byte[] keySeed, string cipherAlg, int keyLength, byte[]? nonce, int mode)
    {
        string digestAlg = InferDigestAlgorithmFromCipherAlgorithmForKeyDerivation(cipherAlg, keyLength);
        IDigest digest = DigestUtilities.GetDigest(digestAlg);
        digest.Reset();
        digest.BlockUpdate(keySeed, 0, keySeed.Length);
        if (nonce != null)
        {
            digest.BlockUpdate(nonce, 0, nonce.Length);
        }

        byte[] modeSuffix = [0x00, 0x00, 0x00, (byte)mode];
        digest.BlockUpdate(modeSuffix, 0, modeSuffix.Length);
        byte[] hashResult = new byte[digest.GetDigestSize()];
        digest.DoFinal(hashResult, 0);

        byte[]? keyBytes = null;
        if (string.Equals(cipherAlg, "DESede", StringComparison.OrdinalIgnoreCase) || string.Equals(cipherAlg, "3DES", StringComparison.OrdinalIgnoreCase))
        {
            /* TR-SAC 1.01, 4.2.1. */
            switch (keyLength)
            {
                case 112: /* Fall through. */
                case 128:
                    keyBytes = new byte[24];
                    Array.Copy(hashResult, 0, keyBytes, 0, 8); /* E  (octets 1 to 8) */
                    Array.Copy(hashResult, 8, keyBytes, 8, 8); /* D  (octets 9 to 16) */
                    Array.Copy(hashResult, 0, keyBytes, 16, 8); /* E (again octets 1 to 8, i.e. 112-bit 3DES key) */
                    break;
                default:
                    throw new ArgumentException("KDF can only use DESede with 128-bit key length");
            }
        }
        else if (string.Equals(cipherAlg, "AES", StringComparison.OrdinalIgnoreCase) || cipherAlg.StartsWith("AES", StringComparison.OrdinalIgnoreCase))
        {
            /* TR-SAC 1.01, 4.2.2. */
            switch (keyLength)
            {
                case 128:
                    keyBytes = new byte[16]; /* NOTE: 128 = 16 * 8 */
                    Array.Copy(hashResult, 0, keyBytes, 0, 16);
                    break;
                case 192:
                    keyBytes = new byte[24]; /* NOTE: 192 = 24 * 8 */
                    Array.Copy(hashResult, 0, keyBytes, 0, 24);
                    break;
                case 256:
                    keyBytes = new byte[32]; /* NOTE: 256 = 32 * 8 */
                    Array.Copy(hashResult, 0, keyBytes, 0, 32);
                    break;
                default:
                    throw new ArgumentException($"KDF can only use AES with 128-bit, 192-bit key or 256-bit length, found: {keyLength}-bit key length");
            }
        }

        if (keyBytes == null)
        {
            /* NOTE: preserved Java quirk -- if cipherAlg matches neither DESede/3DES nor AES*, Java falls
             * through to `new SecretKeySpec(null, cipherAlg)`, which throws IllegalArgumentException
             * ("Empty key"). Reproduced directly here since there is no SecretKeySpec to defer to. */
            throw new ArgumentException("Empty key");
        }

        return keyBytes;
    }

    /// <summary>Computes the static key seed, based on information from the MRZ.</summary>
    /// <param name="documentNumber">a string containing the document number</param>
    /// <param name="dateOfBirth">a string containing the date of birth (YYMMDD)</param>
    /// <param name="dateOfExpiry">a string containing the date of expiry (YYMMDD)</param>
    /// <param name="digestAlg">a JCA mnemonic algorithm string to indicate the digest algorithm (typically SHA-1)</param>
    /// <param name="doTruncate">whether to truncate the resulting output to 16 bytes</param>
    /// <returns>a byte array of length 16 containing the key seed</returns>
    public static byte[] ComputeKeySeed(string documentNumber, string dateOfBirth, string dateOfExpiry, string digestAlg, bool doTruncate)
    {
        string text = documentNumber
            + MRZInfo.CheckDigit(documentNumber)
            + dateOfBirth
            + MRZInfo.CheckDigit(dateOfBirth)
            + dateOfExpiry
            + MRZInfo.CheckDigit(dateOfExpiry);

        return ComputeKeySeed(text, digestAlg, doTruncate);
    }

    /// <summary>Computes the key seed from a card access number (CAN) to derive secure messaging keys from.</summary>
    /// <param name="cardAccessNumber">the card access number</param>
    /// <param name="digestAlg">the digest algorithm to use</param>
    /// <param name="doTruncate">whether to truncate to 16 bytes or not</param>
    /// <returns>the resulting key seed</returns>
    public static byte[] ComputeKeySeed(string cardAccessNumber, string digestAlg, bool doTruncate)
    {
        IDigest shaDigest = DigestUtilities.GetDigest(digestAlg);
        byte[] input = GetBytes(cardAccessNumber);
        shaDigest.BlockUpdate(input, 0, input.Length);
        byte[] hash = new byte[shaDigest.GetDigestSize()];
        shaDigest.DoFinal(hash, 0);

        if (doTruncate)
        {
            byte[] keySeed = new byte[16];
            Array.Copy(hash, 0, keySeed, 0, 16);
            return keySeed;
        }

        return hash;
    }

    /// <summary>Pads the input <paramref name="input"/> according to ISO9797-1 padding method 2, using the given block size.</summary>
    public static byte[] Pad(byte[] input, int blockSize) => Pad(input, 0, input.Length, blockSize);

    /// <summary>Pads the input <paramref name="bytes"/> indicated by <paramref name="offset"/> and
    /// <paramref name="length"/> according to ISO9797-1 padding method 2, using the given block size.</summary>
    public static byte[] Pad(byte[] bytes, int offset, int length, int blockSize)
    {
        int paddedLength = length + 1; // At least 1 byte for 0x80.
        int remainder = paddedLength % blockSize;
        if (remainder != 0)
        {
            paddedLength += blockSize - remainder;
        }

        byte[] padded = new byte[paddedLength];
        Array.Copy(bytes, offset, padded, 0, length);
        padded[length] = 0x80;
        return padded;
    }

    /// <summary>Unpads the input <paramref name="bytes"/> according to ISO9797-1 padding method 2.</summary>
    /// <exception cref="CryptographicException">on padding exception (Java: checked <c>BadPaddingException</c>)</exception>
    public static byte[] Unpad(byte[] bytes)
    {
        int i = bytes.Length - 1;
        while (i >= 0 && bytes[i] == 0x00)
        {
            i--;
        }

        if (i < 0)
        {
            throw new CryptographicException("Expected constant 0x80, found only 0x00 bytes");
        }

        if ((bytes[i] & 0xFF) != 0x80)
        {
            throw new CryptographicException($"Expected constant 0x80, found 0x{bytes[i] & 0x000000FF:x}");
        }

        byte[] result = new byte[i];
        Array.Copy(bytes, 0, result, 0, i);
        return result;
    }

    /// <summary>Recovers the M1 part of the message sent back by the AA protocol (INTERNAL AUTHENTICATE
    /// command). The algorithm is described in ISO 9796-2:2002 9.3.</summary>
    /// <param name="digestLength">should be 20</param>
    /// <param name="decryptedResponse">response from card, already 'decrypted' (using the AA public key)</param>
    /// <returns>the m1 part of the message</returns>
    public static byte[] RecoverMessage(int digestLength, byte[]? decryptedResponse)
    {
        if (decryptedResponse == null || decryptedResponse.Length < 1)
        {
            throw new ArgumentException("Plaintext is too short to recover message");
        }

        /* Trailer. */
        if (((decryptedResponse[^1] & 0xF) ^ 0xC) != 0)
        {
            /*
             * Trailer.
             * NOTE: 0xF = 0000 1111, 0xC = 0000 1100.
             */
            throw new FormatException("Could not get M1, malformed trailer");
        }

        int trailerLength;
        /* Trailer. Find out whether this is t=1 or t=2. */
        if (((decryptedResponse[^1] & 0xFF) ^ 0xBC) == 0)
        {
            /* Option 1 (t = 1): the trailer shall consist of a single octet; this octet shall be equal to hexadecimal 'BC'. */
            trailerLength = 1;
        }
        else if (((decryptedResponse[^1] & 0xFF) ^ 0xCC) == 0)
        {
            /*
             * Option 2 (t = 2): the trailer shall consist of two consecutive octets;
             * the rightmost octet shall be equal hexadecimal 'CC' and the leftmost octet shall be the hash-function identifier.
             * The hash-function identifier indicates the hash-function in use.
             */
            trailerLength = 2;
        }
        else
        {
            throw new FormatException("Not an ISO 9796-2 scheme 2 signature trailer");
        }

        /* Header. */
        if (((decryptedResponse[0] & 0xC0) ^ 0x40) != 0)
        {
            /*
             * First two bits (working from left to right) should be '01'.
             * NOTE: 0xC0 = 1100 0000, 0x40 = 0100 0000.
             */
            throw new FormatException("Could not get M1");
        }

        if ((decryptedResponse[0] & 0x20) == 0)
        {
            /* Third bit (working from left to right) should be '1' for partial recovery. */
            throw new FormatException($"Could not get M1, first byte indicates partial recovery not enabled: 0x{decryptedResponse[0]:x}");
        }

        /* Padding to the left of M1, find out how long. */
        int paddingLength = 0;
        for (; paddingLength < decryptedResponse.Length; paddingLength++)
        {
            // 0x0A = 0000 1010
            if (((decryptedResponse[paddingLength] & 0x0F) ^ 0x0A) == 0)
            {
                break;
            }
        }

        int messageOffset = paddingLength + 1;

        int paddedMessageLength = decryptedResponse.Length - trailerLength - digestLength;
        int messageLength = paddedMessageLength - messageOffset;

        /* There must be at least one byte of message string. */
        if (messageLength <= 0)
        {
            throw new FormatException("Could not get M1");
        }

        /* TODO: If we contain the whole message as well, check the hash of that. */

        byte[] recoveredMessage = new byte[messageLength];
        Array.Copy(decryptedResponse, messageOffset, recoveredMessage, 0, messageLength);

        return recoveredMessage;
    }

    /// <summary>For ECDSA the EAC 1.11 specification requires the signature to be stripped down from any ASN.1 wrappers, as so.</summary>
    /// <param name="signedData">signed data</param>
    /// <param name="keySize">key size</param>
    /// <returns>signature without wrappers</returns>
    public static byte[] GetRawECDSASignature(byte[] signedData, int keySize)
    {
        using var input = new MemoryStream(signedData, writable: false);
        var asn1In = new Asn1InputStream(input);
        using var outputStream = new MemoryStream();
        var obj = (Asn1Sequence)asn1In.ReadObject();
        for (int i = 0; i < obj.Count; i++)
        {
            var integer = (DerInteger)obj[i];
            byte[] t = integer.Value.ToByteArray();
            t = AlignKeyDataToSize(t, keySize);
            outputStream.Write(t, 0, t.Length);
        }

        return outputStream.ToArray();
    }

    /* FIXME: improve documentation. Is used in PACE, EAC-CA, EAC-TA. -- MO (carried over from JMRTD source comment) */

    /// <summary>Align the given key data.</summary>
    /// <param name="keyData">the key data</param>
    /// <param name="size">the new size</param>
    /// <returns>a byte array with key data</returns>
    public static byte[] AlignKeyDataToSize(byte[] keyData, int size)
    {
        byte[] result = new byte[size];
        int copySize = size;
        if (keyData.Length < size)
        {
            copySize = keyData.Length;
        }

        Array.Copy(keyData, keyData.Length - copySize, result, result.Length - copySize, copySize);
        return result;
    }

    /// <summary>Converts an integer to an octet string. Based on BSI TR 03111 Section 3.1.2.</summary>
    /// <param name="val">a non-negative integer</param>
    /// <param name="length">the desired length of the octet string</param>
    /// <returns>octet string</returns>
    public static byte[] I2os(BigInteger val, int length)
    {
        byte[] bytes = val.ToByteArray();
        byte[] result = new byte[length];
        int bytesLen = bytes.Length;
        int srcOffset = 0;

        // BigInteger.ToByteArray() adds a leading zero byte to preserve sign; skip it if present.
        if (bytesLen > 0 && bytes[0] == 0)
        {
            srcOffset = 1;
            bytesLen--;
        }

        if (bytesLen > length)
        {
            Array.Copy(bytes, srcOffset + (bytesLen - length), result, 0, length);
        }
        else
        {
            Array.Copy(bytes, srcOffset, result, length - bytesLen, bytesLen);
        }

        return result;
    }

    /// <summary>Converts a non-negative integer to an octet string.</summary>
    /// <param name="val">non-negative integer</param>
    /// <returns>the octet string</returns>
    public static byte[] I2os(BigInteger val)
    {
        int length = Math.Max(1, (val.BitLength + 7) / 8);
        return I2os(val, length);
    }

    /// <summary>Converts an octet string to an integer. Based on BSI TR 03111 Section 3.1.2.</summary>
    /// <param name="bytes">octet string</param>
    /// <returns>a non-negative integer</returns>
    public static BigInteger Os2i(byte[]? bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        return Os2i(bytes, 0, bytes.Length);
    }

    /// <summary>Converts an octet string to an integer. Based on BSI TR 03111 Section 3.1.2.</summary>
    /// <param name="bytes">a byte array containing the octet string</param>
    /// <param name="offset">the offset of the octet string within the given byte array</param>
    /// <param name="length">the length of the octet string</param>
    /// <returns>a non-negative integer</returns>
    public static BigInteger Os2i(byte[]? bytes, int offset, int length)
    {
        ArgumentNullException.ThrowIfNull(bytes);

        if (offset == 0 && length == bytes.Length)
        {
            return new BigInteger(1, bytes);
        }

        byte[] slice = new byte[length];
        Array.Copy(bytes, offset, slice, 0, length);
        return new BigInteger(1, slice);
    }

    /// <summary>Converts an octet string to a field element via OS2FE as specified in BSI TR-03111.</summary>
    /// <param name="bytes">octet string</param>
    /// <param name="p">the modulus</param>
    /// <returns>a non-negative integer modulo p</returns>
    public static BigInteger Os2fe(byte[] bytes, BigInteger p) => Os2i(bytes).Mod(p);

    /// <summary>Infers a digest algorithm mnemonic from a signature algorithm mnemonic.</summary>
    /// <param name="signatureAlgorithm">a signature algorithm</param>
    /// <returns>a digest algorithm, or <c>null</c> if inference failed</returns>
    public static string? InferDigestAlgorithmFromSignatureAlgorithm(string signatureAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(signatureAlgorithm);

        string? digestAlgorithm = null;
        string signatureAlgorithmToUppercase = signatureAlgorithm.ToUpperInvariant();
        if (signatureAlgorithmToUppercase.Contains("WITH", StringComparison.Ordinal))
        {
            string[] components = signatureAlgorithmToUppercase.Split("WITH");
            digestAlgorithm = components[0];
        }

        if (string.Equals("SHA1", digestAlgorithm, StringComparison.OrdinalIgnoreCase))
        {
            return "SHA-1";
        }

        if (string.Equals("SHA224", digestAlgorithm, StringComparison.OrdinalIgnoreCase))
        {
            return "SHA-224";
        }

        if (string.Equals("SHA256", digestAlgorithm, StringComparison.OrdinalIgnoreCase))
        {
            return "SHA-256";
        }

        if (string.Equals("SHA384", digestAlgorithm, StringComparison.OrdinalIgnoreCase))
        {
            return "SHA-384";
        }

        if (string.Equals("SHA512", digestAlgorithm, StringComparison.OrdinalIgnoreCase))
        {
            return "SHA-512";
        }

        return digestAlgorithm;
    }

    /// <summary>Infers a digest algorithm mnemonic from a signature algorithm mnemonic for use in key derivation.</summary>
    /// <param name="cipherAlg">a cipher algorithm</param>
    /// <param name="keyLength">the key length</param>
    /// <returns>a (best effort approximation) digest algorithm that is typically used in conjunction with
    /// the given cipher algorithm and key length</returns>
    /// <exception cref="ArgumentException">if inference failed</exception>
    public static string InferDigestAlgorithmFromCipherAlgorithmForKeyDerivation(string cipherAlg, int keyLength)
    {
        ArgumentNullException.ThrowIfNull(cipherAlg);

        if (cipherAlg == "DESede" || cipherAlg == "AES-128")
        {
            return "SHA-1";
        }

        if (cipherAlg == "AES" && keyLength == 128)
        {
            return "SHA-1";
        }

        if (cipherAlg == "AES-256" || cipherAlg == "AES-192")
        {
            return "SHA-256";
        }

        if (cipherAlg == "AES" && (keyLength == 192 || keyLength == 256))
        {
            return "SHA-256";
        }

        throw new ArgumentException($"Unsupported cipher algorithm or key length \"{cipherAlg}\", {keyLength}");
    }

    /// <summary>Returns detailed information about the given public key (like RSA) with some extra
    /// information (like 1024 bits).</summary>
    /// <param name="publicKey">a public key</param>
    /// <returns>the algorithm</returns>
    public static string GetDetailedPublicKeyAlgorithm(AsymmetricKeyParameter? publicKey)
    {
        switch (publicKey)
        {
            case null:
                return "null";
            case RsaKeyParameters rsa:
                return $"RSA [{rsa.Modulus.BitLength} bit]";
            case ECPublicKeyParameters ec:
            {
                string? name = GetCurveName(ec.Parameters);
                return name != null ? $"EC [{name}]" : "EC";
            }

            case DHPublicKeyParameters dh:
                return $"DH [p.length = {dh.Parameters.P.BitLength}, g.length = {dh.Parameters.G.BitLength}, l = {dh.Parameters.L}]";
            default:
                return publicKey.GetType().Name;
        }
    }

    /// <summary>Returns detailed algorithm information (including key length) about the given private key.</summary>
    /// <param name="privateKey">a private key</param>
    /// <returns>detailed information about the given private key</returns>
    public static string GetDetailedPrivateKeyAlgorithm(AsymmetricKeyParameter? privateKey)
    {
        switch (privateKey)
        {
            case null:
                return "null";
            case RsaKeyParameters rsa:
                return $"RSA [{rsa.Modulus.BitLength} bit]";
            case ECPrivateKeyParameters ec:
            {
                string? name = GetCurveName(ec.Parameters);
                return name != null ? $"EC [{name}]" : "EC";
            }

            default:
                return privateKey.GetType().Name;
        }
    }

    /// <summary>Returns the explicit domain parameters for the given named curve.</summary>
    /// <param name="curveName">a curve name</param>
    /// <returns>the domain parameters</returns>
    public static ECDomainParameters GetECDomainParameters(string curveName) => new(ECNamedCurveTable.GetByName(curveName));

    /// <summary>Returns the approximate size of signatures made or verifiable using that key in bits. The
    /// key should be a public or private key suitable for signature creation or verification. For RSA
    /// this is just <c>N</c>. For ECDSA this is <c>2 * N</c> (but the actual size of signatures will be
    /// slightly larger). Silently returns <c>0</c> for unsupported key types (such as DSA).</summary>
    /// <param name="key">the key</param>
    /// <returns>the size in bits</returns>
    public static int GetApproximateSignatureSize(AsymmetricKeyParameter key)
    {
        switch (key)
        {
            case RsaKeyParameters rsa:
                return rsa.Modulus.BitLength;
            case ECKeyParameters ec:
                /* NOTE: Java takes Math.ceil() of an already-integral bit count here (a harmless no-op);
                 * omitted since Curve.FieldSize is already an int. */
                int keySize = ec.Parameters.Curve.FieldSize;
                return 2 * keySize;
            default:
                /* NOTE: Java logs a warning "Unknown key type, returning 0" here; omitted per the
                 * non-essential-warning-omission precedent (see AbstractLDSFile.cs). */
                return 0;
        }
    }

    /// <summary>Returns the curve name, if known, or <c>null</c>.</summary>
    /// <param name="domainParameters">domain parameters specifying the curve</param>
    /// <returns>the curve name</returns>
    public static string? GetCurveName(ECDomainParameters domainParameters)
    {
        ArgumentNullException.ThrowIfNull(domainParameters);

        foreach (string name in NamedCurveNames())
        {
            X9ECParameters? candidate = ECNamedCurveTable.GetByName(name);
            if (candidate == null)
            {
                continue;
            }

            if (candidate.Curve.Equals(domainParameters.Curve)
                && candidate.G.Equals(domainParameters.G)
                && candidate.N.Equals(domainParameters.N)
                && candidate.H.Equals(domainParameters.H))
            {
                return name;
            }
        }

        return null;
    }

    /// <summary>Convert the given public key to a BC subject public key info structure, with explicit
    /// (not named-curve-OID) EC domain parameters -- EAC requires all key information to include the
    /// domain parameters explicitly.
    ///
    /// NOTE on structural simplification vs. Java: Java's version parses <c>publicKey.getEncoded()</c> to
    /// determine whether the *original* JCA-provider encoding referenced a named curve (an OID) or was
    /// already explicit, and (only in the named-curve case) looks up the canonical curve to rebuild an
    /// explicit <c>AlgorithmIdentifier</c>. Here, <paramref name="publicKey"/> is always a BC
    /// <see cref="ECPublicKeyParameters"/> already carrying fully explicit domain parameters (curve/G/N/H,
    /// regardless of whether they originated from <c>ECNamedCurveTable</c> or elsewhere) -- there is no
    /// "named vs explicit" ambiguity to resolve in the first place, so this always builds the explicit
    /// form directly from <c>publicKey.Parameters</c>. This produces the same end result as Java's method
    /// for the case that matters (EAC wants explicit params), just without the encode/detect/re-encode
    /// round trip Java needed to bridge JCA provider quirks that don't exist here.</summary>
    /// <param name="publicKey">a public key</param>
    /// <returns>a BC subject public key info structure, or <c>null</c> on error</returns>
    public static SubjectPublicKeyInfo? ToSubjectPublicKeyInfo(AsymmetricKeyParameter publicKey)
    {
        try
        {
            switch (publicKey)
            {
                case ECPublicKeyParameters ecPublicKey:
                {
                    ECDomainParameters domainParameters = ecPublicKey.Parameters;
                    var x9Params = new X9ECParameters(
                        domainParameters.Curve,
                        new X9ECPoint(domainParameters.G, false),
                        domainParameters.N,
                        domainParameters.H,
                        domainParameters.GetSeed());
                    var algorithmIdentifier = new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, x9Params.ToAsn1Object());
                    return new SubjectPublicKeyInfo(algorithmIdentifier, ecPublicKey.Q.GetEncoded(false));
                }

                case DHPublicKeyParameters dhPublicKey:
                {
                    /* NOTE: deviation from Java -- Java round-trips whatever AlgorithmIdentifier OID was
                     * present in the key's own original encoding. BC's lightweight DHPublicKeyParameters
                     * carries no such encoded-OID history, so the standard X9.42 "dhpublicnumber" OID
                     * (matching PACEDomainParameterInfo.ID_DH_PUBLIC_NUMBER, which is what JMRTD's own DH
                     * domain parameter encodings use) is used instead. */
                    DHParameters dhParameters = dhPublicKey.Parameters;
                    var algorithmIdentifier = new AlgorithmIdentifier(
                        new DerObjectIdentifier(PACEDomainParameterInfo.ID_DH_PUBLIC_NUMBER),
                        new DHParameter(dhParameters.P, dhParameters.G, dhParameters.L).ToAsn1Object());
                    return new SubjectPublicKeyInfo(algorithmIdentifier, new DerInteger(dhPublicKey.Y));
                }

                default:
                    throw new ArgumentException($"Unrecognized key type, found {publicKey?.GetType()}, should be DH or ECDH");
            }
        }
        catch (Exception)
        {
            /* NOTE: Java logs a warning here; omitted per the non-essential-warning-omission precedent
             * (see AbstractLDSFile.cs). */
            return null;
        }
    }

    /// <summary>Extracts a public key from a BC subject public key info structure.</summary>
    /// <param name="subjectPublicKeyInfo">the BC subject public key info structure</param>
    /// <returns>a public key or <c>null</c></returns>
    public static AsymmetricKeyParameter? ToPublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo)
    {
        try
        {
            return PublicKeyFactory.CreateKey(subjectPublicKeyInfo);
        }
        catch (Exception)
        {
            /* NOTE: Java logs a warning here; omitted per the non-essential-warning-omission precedent
             * (see AbstractLDSFile.cs). */
            return null;
        }
    }

    /// <summary>Port of Java's <c>reconstructPublicKey</c>. There, some JCA providers could hand back EC
    /// public keys with unreliable/implicit domain parameters, and this method rebuilt the key using an
    /// explicit spec. BC's own <see cref="ECPublicKeyParameters"/> always already carries fully explicit
    /// domain parameters (see <see cref="ChipAuthenticationPublicKeyInfo"/>'s doc comment for the same
    /// observation), so this is a no-op, kept only for 1:1 traceability against Java call sites.</summary>
    /// <param name="publicKey">the public key</param>
    /// <returns>the same public key</returns>
    public static AsymmetricKeyParameter ReconstructPublicKey(AsymmetricKeyParameter publicKey) => publicKey;

    /// <summary>Attempts to add missing parameters to a public key. If the public key already has
    /// appropriate parameters, then this does nothing.</summary>
    /// <param name="domainParameters">the domain parameters (an <see cref="ECDomainParameters"/>)</param>
    /// <param name="publicKey">the public key</param>
    /// <returns>a public key with possibly added parameters</returns>
    public static AsymmetricKeyParameter? AddMissingParametersToPublicKey(object? domainParameters, AsymmetricKeyParameter? publicKey)
    {
        if (publicKey == null)
        {
            return null;
        }

        if (publicKey is ECPublicKeyParameters ecPublicKey && domainParameters is ECDomainParameters ecDomainParameters)
        {
            return new ECPublicKeyParameters(ecPublicKey.Q, ecDomainParameters);
        }

        return publicKey;
    }

    /// <summary>Decodes an EC point from a BSI encoded octet string (uncompressed point: <c>0x04 || X || Y</c>).
    ///
    /// NOTE: unlike Java's <c>os2ECPoint</c> (which returns a curve-agnostic <c>java.security.spec.ECPoint</c>),
    /// BC's own <see cref="Org.BouncyCastle.Math.EC.ECPoint"/> always requires a curve to construct -- there is
    /// no curve-independent point value type in BC.NET. This therefore returns the raw affine coordinates;
    /// callers combine them with an explicit curve (e.g. <c>ECCurve.CreatePoint(x, y)</c>) when they need
    /// an actual point object.</summary>
    /// <param name="encodedECPoint">the encoded EC point</param>
    /// <returns>the affine X and Y coordinates of the EC point</returns>
    public static (BigInteger X, BigInteger Y) Os2ECPoint(byte[] encodedECPoint)
    {
        if (encodedECPoint == null || encodedECPoint.Length < 3 || encodedECPoint.Length % 2 != 1)
        {
            throw new ArgumentException("Expected an encoded ECPoint of odd length (0x04, x, y)");
        }

        if (encodedECPoint[0] != 0x04)
        {
            throw new ArgumentException("Expected encoded ECPoint to start with 0x04");
        }

        int length = (encodedECPoint.Length - 1) / 2;
        byte[] xCoordBytes = new byte[length];
        byte[] yCoordBytes = new byte[length];
        Array.Copy(encodedECPoint, 1, xCoordBytes, 0, length);
        Array.Copy(encodedECPoint, 1 + length, yCoordBytes, 0, length);

        BigInteger x = Os2i(xCoordBytes);
        BigInteger y = Os2i(yCoordBytes);
        return (x, y);
    }

    /// <summary>Encodes (using BSI encoding) an EC point (for use as public key value). Prefixes a
    /// <c>0x04</c> tag (without a length).</summary>
    /// <param name="affineX">the affine X coordinate of an EC point</param>
    /// <param name="affineY">the affine Y coordinate of an EC point</param>
    /// <param name="bitLength">the length in bits to use for each coordinate (the field size)</param>
    /// <returns>an octet string</returns>
    public static byte[] EcPoint2OS(BigInteger affineX, BigInteger affineY, int bitLength)
    {
        int coordinateLength = (int)Math.Ceiling(bitLength / 8.0);
        byte[] xBytes = I2os(affineX, coordinateLength);
        byte[] yBytes = I2os(affineY, coordinateLength);

        byte[] result = new byte[1 + (2 * coordinateLength)];
        result[0] = 0x04; // FIXME: Constant for 0x04 (carried over from Java).
        Array.Copy(xBytes, 0, result, 1, coordinateLength);
        Array.Copy(yBytes, 0, result, 1 + coordinateLength, coordinateLength);
        return result;
    }

    /// <summary>Convenience overload of <see cref="EcPoint2OS(BigInteger, BigInteger, int)"/> accepting a
    /// BC <see cref="Org.BouncyCastle.Math.EC.ECPoint"/> directly.</summary>
    /// <param name="point">an EC point</param>
    /// <param name="bitLength">the length in bits to use for each coordinate (the field size)</param>
    /// <returns>an octet string</returns>
    public static byte[] EcPoint2OS(ECPoint point, int bitLength)
    {
        ECPoint normalized = point.Normalize();
        return EcPoint2OS(normalized.AffineXCoord.ToBigInteger(), normalized.AffineYCoord.ToBigInteger(), bitLength);
    }

    /// <summary>Infers an EAC object identifier for an EC or DH public key.</summary>
    /// <param name="publicKey">a public key</param>
    /// <returns>either <see cref="SecurityInfo.ID_PK_ECDH"/> or <see cref="SecurityInfo.ID_PK_DH"/></returns>
    public static string InferProtocolIdentifier(AsymmetricKeyParameter publicKey) => publicKey switch
    {
        ECPublicKeyParameters => SecurityInfo.ID_PK_ECDH,
        DHPublicKeyParameters => SecurityInfo.ID_PK_DH,
        _ => throw new ArgumentException("Wrong key type. Was expecting ECDH or DH public key."),
    };

    /// <summary>Adds two EC points.</summary>
    /// <param name="x">an EC point</param>
    /// <param name="y">another EC point</param>
    /// <returns>the resulting EC point</returns>
    public static ECPoint Add(ECPoint x, ECPoint y) => x.Add(y);

    /// <summary>Multiplies a scalar and an EC point.</summary>
    /// <param name="s">the scalar</param>
    /// <param name="point">the EC point</param>
    /// <returns>the resulting EC point</returns>
    public static ECPoint Multiply(BigInteger s, ECPoint point) => point.Multiply(s);

    /// <summary>Checks whether the given point is on the given curve. This just checks the Weierstrass
    /// equation (unlike <see cref="IsValid"/>, this does not go through BC's own point validation -- see
    /// this method's presence alongside <see cref="IsValid"/> in the Java original).</summary>
    /// <param name="x">the affine X coordinate of a point</param>
    /// <param name="y">the affine Y coordinate of a point</param>
    /// <param name="domainParameters">domain parameters specifying the curve</param>
    /// <returns>a boolean indicating whether the point is on the curve</returns>
    public static bool IsPointOnCurve(BigInteger x, BigInteger y, ECDomainParameters domainParameters)
    {
        BigInteger p = GetPrime(domainParameters);

        BigInteger a = domainParameters.Curve.A.ToBigInteger();
        BigInteger b = domainParameters.Curve.B.ToBigInteger();
        BigInteger lhs = y.Multiply(y).Mod(p);
        BigInteger rhs = x.Multiply(x).Multiply(x).Add(a.Multiply(x)).Add(b).Mod(p);

        return lhs.Equals(rhs);
    }

    /// <summary>Converts a string to bytes using UTF-8.</summary>
    /// <param name="str">a string</param>
    /// <returns>the bytes</returns>
    public static byte[] GetBytes(string str) => System.Text.Encoding.UTF8.GetBytes(str);

    /// <summary>Extracts the prime from the given DH or EC domain parameters, which (hopefully) specify a
    /// curve over a prime field.</summary>
    /// <param name="domainParameters">domain parameters (a <see cref="DHParameters"/> or <see cref="ECDomainParameters"/>)</param>
    /// <returns>the prime</returns>
    public static BigInteger GetPrime(object? domainParameters)
    {
        switch (domainParameters)
        {
            case null:
                throw new ArgumentException("Parameters null");
            case DHParameters dhParameters:
                return dhParameters.P;
            case ECDomainParameters ecDomainParameters:
                return ecDomainParameters.Curve.Field.Characteristic;
            default:
                throw new ArgumentException($"Unsupported agreement algorithm, was expecting DHParameters or ECDomainParameters, found {domainParameters.GetType()}");
        }
    }

    /// <summary>Attempts to infer a relevant key agreement algorithm (either <c>"DH"</c> or <c>"ECDH"</c>)
    /// given a public key.</summary>
    /// <param name="publicKey">the public key</param>
    /// <returns>either <c>"DH"</c> or <c>"ECDH"</c></returns>
    public static string InferKeyAgreementAlgorithm(AsymmetricKeyParameter publicKey) => publicKey switch
    {
        ECPublicKeyParameters => "ECDH",
        DHPublicKeyParameters => "DH",
        _ => throw new ArgumentException($"Unsupported public key: {publicKey}"),
    };

    /// <summary>This just solves the curve equation for y.</summary>
    /// <param name="affineX">the x coord of a point on the curve</param>
    /// <param name="domainParameters">domain parameters for curve over Fp</param>
    /// <returns>the corresponding y coord</returns>
    public static BigInteger ComputeAffineY(BigInteger affineX, ECDomainParameters domainParameters)
    {
        Org.BouncyCastle.Math.EC.ECCurve curve = domainParameters.Curve;
        ECFieldElement a = curve.A;
        ECFieldElement b = curve.B;
        ECFieldElement x = curve.FromBigInteger(affineX);
        ECFieldElement y = x.Multiply(x).Add(a).Multiply(x).Add(b).Sqrt();

        return y.ToBigInteger();
    }

    /// <summary>Determines whether an EC point is valid with respect to its own curve.</summary>
    /// <param name="ecPoint">an EC point</param>
    /// <returns>a boolean indicating whether the EC point is valid</returns>
    public static bool IsValid(ECPoint ecPoint) => ecPoint.IsValid();

    /// <summary>Normalizes an EC point.</summary>
    /// <param name="ecPoint">the EC point</param>
    /// <returns>the normalized EC point</returns>
    public static ECPoint Normalize(ECPoint ecPoint) => ecPoint.Normalize();

    /// <summary>Converts the EC public key to a BC public key parameter object.</summary>
    /// <param name="publicKey">the EC public key</param>
    /// <returns>the same object, since <see cref="ECPublicKeyParameters"/> already is the BC public key
    /// parameter type in this port (Java's version converted from a JCA <c>ECPublicKey</c>)</returns>
    public static ECPublicKeyParameters ToBouncyECPublicKeyParameters(ECPublicKeyParameters publicKey) => publicKey;

    /// <summary>Converts the EC private key to a BC private key parameter object.</summary>
    /// <param name="privateKey">the EC private key</param>
    /// <returns>the same object, since <see cref="ECPrivateKeyParameters"/> already is the BC private key
    /// parameter type in this port (Java's version converted from a JCA <c>ECPrivateKey</c>)</returns>
    public static ECPrivateKeyParameters ToBouncyECPrivateKeyParameters(ECPrivateKeyParameters privateKey) => privateKey;

    /// <summary>Encodes an object identifier.
    /// 0x80 Cryptographic mechanism reference.
    /// Object Identifier of the protocol to select (value only, tag 0x06 is omitted).</summary>
    /// <param name="oid">the object identifier</param>
    /// <returns>the encoding</returns>
    public static byte[] ToOIDBytes(string oid)
    {
        try
        {
            byte[] encoded = new DerObjectIdentifier(oid).GetEncoded();
            byte[] oidBytes;
            using (var oidStream = new MemoryStream(encoded, writable: false))
            using (var oidTlvIn = new TlvInputStream(oidStream))
            {
                oidTlvIn.ReadTag(); /* Should be 0x06 */
                oidTlvIn.ReadLength();
                oidBytes = oidTlvIn.ReadValue();
            }

            return TlvUtil.WrapDO(0x80, oidBytes); /* FIXME: define constant for 0x80 (carried over from Java). */
        }
        catch (Exception e)
        {
            throw new ArgumentException($"Illegal OID: \"{oid}", e);
        }
    }

    /// <summary>Partitions a byte array into a number of segments of the given size, and a final segment
    /// if there is a remainder.</summary>
    /// <param name="segmentSize">the number of bytes per segment</param>
    /// <param name="data">the data to be partitioned</param>
    /// <returns>a list with the segments</returns>
    public static List<byte[]> Partition(int segmentSize, byte[]? data)
    {
        var segments = new List<byte[]>();
        if (data == null || segmentSize <= 0)
        {
            throw new ArgumentException("Cannot partition");
        }

        /* Check if all data fits in one segment. */
        segmentSize = Math.Min(data.Length, segmentSize);

        /* NOTE: preserved Java quirk -- for empty data, segmentSize becomes 0 above, and the division
         * below throws (DivideByZeroException here, ArithmeticException in Java) rather than returning an
         * empty list. Not "fixed" per this codebase's quirk-preservation policy. */
        int segmentCount = data.Length / segmentSize; // Excluding the remainder.
        int lastSegmentSize = data.Length % segmentSize;

        int offset = 0;
        for (int i = 0; i < segmentCount; i++)
        {
            byte[] segment = new byte[segmentSize];
            Array.Copy(data, offset, segment, 0, segmentSize);
            segments.Add(segment);
            offset += segmentSize;
        }

        if (lastSegmentSize != 0)
        {
            byte[] segment = new byte[lastSegmentSize];
            Array.Copy(data, offset, segment, 0, lastSegmentSize);
            segments.Add(segment);
        }

        return segments;
    }

    /// <summary>Returns the domain parameters from the given key.</summary>
    /// <param name="key">the key</param>
    /// <returns>domain parameters (a <see cref="DHParameters"/> or <see cref="ECDomainParameters"/>)</returns>
    public static object GetAlgorithmParams(AsymmetricKeyParameter? key)
    {
        switch (key)
        {
            case null:
                throw new ArgumentException("Key is null");
            case DHPublicKeyParameters dhPublic:
                return dhPublic.Parameters;
            case ECPublicKeyParameters ecPublic:
                return ecPublic.Parameters;
            case DHPrivateKeyParameters dhPrivate:
                return dhPrivate.Parameters;
            case ECPrivateKeyParameters ecPrivate:
                return ecPrivate.Parameters;
            default:
                /* NOTE: porting hazard, flagged rather than guessed at -- Java's RSAKey.getParams() /
                 * DSAPublicKey.getParams() (algorithm parameter specs for RSA-PSS parameters / DSA domain
                 * parameters) have no BC lightweight-API equivalent (RsaKeyParameters carries no PSS
                 * parameters; there is no DSA key parameter type used anywhere in this port). This path
                 * isn't exercised by PACE/EAC-CA key agreement (the only real callers of this method, which
                 * only ever pass DH/EC keys), so RSA/DSA are intentionally unsupported here. */
                throw new NotSupportedException($"Unsupported key type: {key.GetType()}");
        }
    }

    /// <summary>Strips any leading zeroes from a byte array and returns the resulting byte array.</summary>
    /// <param name="bytes">the input byte array (which is not modified in the process)</param>
    /// <returns>a copy of the input byte array, without the leading zeroes</returns>
    public static byte[]? StripLeadingZeroes(byte[]? bytes)
    {
        if (bytes == null || bytes.Length <= 1)
        {
            return bytes;
        }

        int firstNonZero = 0;
        while (firstNonZero < bytes.Length && bytes[firstNonZero] == 0x00)
        {
            firstNonZero++;
        }

        if (firstNonZero == 0)
        {
            return bytes;
        }

        byte[] result = new byte[bytes.Length - firstNonZero];
        Array.Copy(bytes, firstNonZero, result, 0, result.Length);
        return result;
    }

    /* ONLY PRIVATE METHODS BELOW */

    private static IEnumerable<string> NamedCurveNames()
    {
        var names = ECNamedCurveTable.Names;
        foreach (var name in names)
        {
            yield return (string)name;
        }
    }

    private static DHParameters FromPGQ(string hexP, string hexG, string hexQ) =>
        new(FromHex(hexP), FromHex(hexG), FromHex(hexQ));

    private static BigInteger FromHex(string hex) => new(1, Org.BouncyCastle.Utilities.Encoders.Hex.DecodeStrict(hex));
}
