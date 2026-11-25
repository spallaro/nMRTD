using System.Globalization;
using CryptographicException = System.Security.Cryptography.CryptographicException;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

namespace nMRTD.Tests.Jmrtd;

/// <summary>Port of JMRTD's <c>org.jmrtd.UtilTest</c>.</summary>
/// <remarks>
/// ADAPTATION: Java's <c>java.security.spec.ECPoint</c> has no .NET counterpart; nMRTD's
/// <c>Os2ECPoint</c> returns an (X, Y) tuple and <c>IsPointOnCurve</c> takes the coordinates, while
/// <c>IsValid</c> and <c>Multiply</c> take a Bouncy Castle point. Java's checked
/// <c>BadPaddingException</c> and <c>NumberFormatException</c> map to <c>CryptographicException</c>
/// and <c>FormatException</c>, <c>IllegalArgumentException</c> and <c>NullPointerException</c> to
/// <c>ArgumentException</c> (or a subclass).
/// </remarks>
public class UtilTest
{
    private static readonly SecureRandom Random = new();

    [Fact]
    public void testPadding()
    {
        CheckPadding(3, 64);
        CheckPadding(31, 64);
        CheckPadding(32, 64);
        CheckPadding(58, 64);
        CheckPadding(63, 64);
        CheckPadding(64, 64);
        CheckPadding(65, 64);
        CheckPadding(65, 128);
        CheckPadding(127, 128);
    }

    private static void CheckPadding(int arraySize, int blockSize)
    {
        var bytes = new byte[arraySize];
        Random.NextBytes(bytes);
        byte[] paddedBytes = Util.Pad(bytes, blockSize);
        Assert.NotNull(paddedBytes);
        Assert.True(paddedBytes.Length >= bytes.Length);
        Assert.True(IsPrefixOf(bytes, paddedBytes));

        byte[] unpaddedPaddedBytes = Util.Unpad(paddedBytes);
        Assert.Equal(bytes, unpaddedPaddedBytes);
    }

    [Fact]
    public void testApproximateSignatureSize()
    {
        CheckApproximateSignatureSize(512, "SHA256WithRSA", GenerateRsaKeyPair(512));
        CheckApproximateSignatureSize(1024, "SHA256WithRSA", GenerateRsaKeyPair(1024));
        CheckApproximateSignatureSize(2048, "SHA256WithRSA", GenerateRsaKeyPair(2048));

        CheckApproximateSignatureSize(448, "SHA256WithECDSA", GenerateECKeyPair("secp224r1"));
        CheckApproximateSignatureSize(512, "SHA256WithECDSA", GenerateECKeyPair("secp256r1"));
        CheckApproximateSignatureSize(768, "SHA256WithECDSA", GenerateECKeyPair("secp384r1"));
        CheckApproximateSignatureSize(448, "SHA256WithECDSA", GenerateECKeyPair("brainpoolP224r1"));
        CheckApproximateSignatureSize(768, "SHA256WithECDSA", GenerateECKeyPair("brainpoolP384r1"));
        CheckApproximateSignatureSize(1024, "SHA256WithECDSA", GenerateECKeyPair("brainpoolP512r1"));
    }

    private static void CheckApproximateSignatureSize(int expectedSize, string sigAlg, AsymmetricCipherKeyPair keyPair)
    {
        Assert.Equal(expectedSize, Util.GetApproximateSignatureSize(keyPair.Public));
        Assert.Equal(expectedSize, Util.GetApproximateSignatureSize(keyPair.Private));

        ISigner sig = SignerUtilities.GetSigner(sigAlg);
        sig.Init(true, keyPair.Private);
        sig.BlockUpdate(new byte[8], 0, 8);
        int sigSize = 8 * sig.GenerateSignature().Length;
        Assert.True(expectedSize <= sigSize && sigSize <= expectedSize + (expectedSize / 2));
    }

    [Fact]
    public void testPartition()
    {
        for (int dataSize = 23; dataSize < 987; dataSize++)
        {
            for (int segmentSize = 13; segmentSize < 63; segmentSize++)
            {
                CheckPartition(dataSize, segmentSize);
            }
        }
    }

    private static void CheckPartition(int dataSize, int segmentSize)
    {
        var data = new byte[dataSize];
        Random.NextBytes(data);
        List<byte[]> segments = Util.Partition(segmentSize, data);

        /* This should be approximately true. */
        Assert.True(segmentSize * (segments.Count - 1) <= dataSize);
        Assert.True(segmentSize * segments.Count >= dataSize);

        var isLasts = new List<bool>(segments.Count);
        int index = 0;
        foreach (byte[] _ in segments)
        {
            bool isLast = ++index >= segments.Count;
            isLasts.Add(isLast);
        }

        for (int i = 0; i < segments.Count - 1; i++)
        {
            Assert.False(isLasts[i]);
        }

        Assert.True(isLasts[segments.Count - 1]);
    }

    [Fact]
    public void testStripLeadingZeroes()
    {
        byte[] example = [0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04];
        byte[] stripped = Util.StripLeadingZeroes(example)!;
        Assert.True(stripped[0] != 0x00);
        Assert.Equal(new byte[] { 0x01, 0x02, 0x03, 0x04 }, stripped);
    }

    [Fact]
    public void testBigIntegerI2OSStripLeadingZeroes()
    {
        for (long i = 0; i < 66666; i++)
        {
            BigInteger bigInteger = BigInteger.ValueOf(i);
            byte[] bigIBytes = bigInteger.ToByteArray();
            byte[] os = Util.I2os(bigInteger);
            Assert.True(os.AsSpan().SequenceEqual(Util.StripLeadingZeroes(bigIBytes)),
                i + ": " + Hex.BytesToHexString(bigIBytes) + ", " + Hex.BytesToHexString(os));
        }
    }

    [Fact]
    public void testI2osWithExplicitLength()
    {
        /* Zero. */
        Assert.Equal(new byte[] { 0x00 }, Util.I2os(BigInteger.Zero, 1));
        Assert.Equal(new byte[] { 0x00, 0x00 }, Util.I2os(BigInteger.Zero, 2));

        /* High bit set -- BigInteger.toByteArray() prepends an extra sign byte here. */
        Assert.Equal(new byte[] { 0x80 }, Util.I2os(BigInteger.ValueOf(128), 1));
        Assert.Equal(new byte[] { 0xFF }, Util.I2os(BigInteger.ValueOf(255), 1));

        /* Padding: requested length longer than the value's natural size. */
        Assert.Equal(new byte[] { 0x00, 0x00, 0x01 }, Util.I2os(BigInteger.One, 3));
        Assert.Equal(new byte[] { 0x00, 0x80 }, Util.I2os(BigInteger.ValueOf(128), 2));

        /*
         * Truncation: requested length shorter than the value's natural size takes the
         * least-significant bytes, matching the old mod/divide loop's behavior.
         */
        Assert.Equal(new byte[] { 0xCD, 0xEF }, Util.I2os(new BigInteger("ABCDEF", 16), 2));
    }

    [Fact]
    public void testECPointSerDeser()
    {
        var x = new BigInteger("1711296670204813060243268632676822234344359677243986977215350947079259342020");
        var y = new BigInteger("136486234017883437884169815369656174240202926550835833245936368423753881551");
        byte[] bytes = Util.EcPoint2OS(x, y, 256);
        Assert.Equal(65, bytes.Length); // 1 byte prefix + twice the size of p (as described in BSI TR03111 3.2.1
        (BigInteger X, BigInteger Y) deserializedPoint = Util.Os2ECPoint(bytes);
        Assert.Equal(x, deserializedPoint.X);
        Assert.Equal(y, deserializedPoint.Y);
    }

    private static bool IsPrefixOf(byte[] bytes, byte[] paddedBytes)
    {
        if (bytes.Length > paddedBytes.Length)
        {
            return false;
        }

        for (int i = 0; i < bytes.Length; i++)
        {
            if (paddedBytes[i] != bytes[i])
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>https://sourceforge.net/p/jmrtd/bugs/57/</summary>
    [Fact]
    public void testECPointLeadingZeroes()
    {
        var x = new BigInteger(TestData.Hex("13426B4FE5577053F0374CF79ACFA6F7750B8E0D60DCA9FE627AB49A21D2C4C4"));
        var y = new BigInteger(TestData.Hex("004D3F9BC97AFDF8ABD9B561E63C0239763976A9FEB1EFFD816A140D791217CF"));
        byte[] os = Util.EcPoint2OS(x, y, 256);
        (BigInteger X, BigInteger Y) p = Util.Os2ECPoint(os);
        byte[] os2 = Util.EcPoint2OS(p.X, p.Y, 256);
        Assert.Equal(os, os2);
    }

    [Fact]
    public void testToOIDBytes()
    {
        byte[] oidBytes = Util.ToOIDBytes("1.2.840.113549.1.1.1");
        Assert.NotNull(oidBytes);
        Assert.Equal(0x80, oidBytes[0]);
        Assert.Equal(9, oidBytes[1]);

        // malformed OID should throw IllegalArgumentException
        Assert.ThrowsAny<ArgumentException>(() => Util.ToOIDBytes("invalid-oid"));

        // Java: NullPointerException; nMRTD wraps it in an ArgumentException.
        Assert.ThrowsAny<ArgumentException>(() => Util.ToOIDBytes(null!));
    }

    /// <summary>
    /// BAC key derivation worked example from ICAO Doc 9303 Part 11, Appendix D.2.
    /// Document number "L898902C3", date of birth 690806, date of expiry 940623.
    /// </summary>
    [Fact]
    public void testBACKeyDerivationICAOWorkedExample()
    {
        byte[] keySeed = Util.ComputeKeySeed("L898902C3", "690806", "940623", "SHA-1", true);
        Assert.Equal("7FF74C962710A2404373FC9CE8A1C6E2", Hex.BytesToHexString(keySeed).ToUpperInvariant());

        byte[] kEnc = Util.DeriveKey(keySeed, Util.ENC_MODE);
        Assert.Equal("906CFE5E080051EFA05FC5B044E535CA906CFE5E080051EF", Hex.BytesToHexString(kEnc).ToUpperInvariant());

        byte[] kMac = Util.DeriveKey(keySeed, Util.MAC_MODE);
        Assert.Equal("E4F1F75506EC63594CA27D0EF91C01D7E4F1F75506EC6359", Hex.BytesToHexString(kMac).ToUpperInvariant());
    }

    /*
     * ISO/IEC 9796-2 scheme 2 message recovery. Header byte 0x6A itself doubles as the padding
     * terminator here (its low nibble is 0xA), so the message starts right after it.
     */
    [Fact]
    public void testRecoverMessageNoExplicitPadding()
    {
        byte[] message = [0x01, 0x02, 0x03, 0x04];
        int digestLength = 20;
        byte[] decryptedResponse = BuildRecoverableMessage(0x6A, message, digestLength, 0xBC);

        byte[] recovered = Util.RecoverMessage(digestLength, decryptedResponse);
        Assert.Equal(message, recovered);
    }

    /*
     * Same scheme, but this time the header (0x60) does not itself match the padding
     * terminator pattern, so an explicit padding byte (0x0A) is needed before the message.
     */
    [Fact]
    public void testRecoverMessageWithExplicitPadding()
    {
        byte[] message = [0x11, 0x22, 0x33, 0x44];
        int digestLength = 20;
        var output = new MemoryStream();
        output.WriteByte(0x60);
        output.WriteByte(0x0A);
        output.Write(message, 0, message.Length);
        output.Write(new byte[digestLength], 0, digestLength);
        output.WriteByte(0xBC);
        byte[] decryptedResponse = output.ToArray();

        byte[] recovered = Util.RecoverMessage(digestLength, decryptedResponse);
        Assert.Equal(message, recovered);
    }

    [Fact]
    public void testRecoverMessageThrowsOnEmptyInput()
    {
        Assert.ThrowsAny<ArgumentException>(() => Util.RecoverMessage(20, []));
    }

    [Fact]
    public void testRecoverMessageThrowsOnMalformedTrailer()
    {
        /* Last byte's low nibble must be 0xC; 0x00 is not. */
        byte[] decryptedResponse = [0x00, 0x00];
        FormatException exception = Assert.Throws<FormatException>(() => Util.RecoverMessage(20, decryptedResponse));
        Assert.Contains("trailer", exception.Message);
    }

    [Fact]
    public void testRecoverMessageThrowsOnUnrecognizedTrailerVariant()
    {
        /* Low nibble matches (0xC), but the full trailer byte is neither 0xBC (t=1) nor 0xCC (t=2). */
        byte[] decryptedResponse = [0x00, 0xDC];
        FormatException exception = Assert.Throws<FormatException>(() => Util.RecoverMessage(20, decryptedResponse));
        Assert.Contains("ISO 9796-2", exception.Message);
    }

    [Fact]
    public void testRecoverMessageThrowsOnBadHeaderBits()
    {
        /* First byte's top two bits must be '01' (0x40); 0x00 does not satisfy that. */
        byte[] decryptedResponse = [0x00, 0xBC];
        Assert.Throws<FormatException>(() => Util.RecoverMessage(20, decryptedResponse));
    }

    [Fact]
    public void testRecoverMessageThrowsWhenPartialRecoveryNotEnabled()
    {
        /* Top two bits are '01' (0x40) but the partial-recovery bit (0x20) is not set. */
        byte[] decryptedResponse = [0x40, 0xBC];
        FormatException exception = Assert.Throws<FormatException>(() => Util.RecoverMessage(20, decryptedResponse));
        Assert.Contains("partial recovery", exception.Message);
    }

    [Fact]
    public void testRecoverMessageThrowsWhenNoRoomForMessage()
    {
        /* Valid header/trailer, but nothing left over for an actual message. */
        byte[] decryptedResponse = [0x6A, 0xBC];
        Assert.Throws<FormatException>(() => Util.RecoverMessage(0, decryptedResponse));
    }

    private static byte[] BuildRecoverableMessage(byte header, byte[] message, int digestLength, byte trailer)
    {
        var output = new MemoryStream();
        output.WriteByte(header);
        output.Write(message, 0, message.Length);
        output.Write(new byte[digestLength], 0, digestLength);
        output.WriteByte(trailer);
        return output.ToArray();
    }

    /*
     * getRawECDSASignature strips a DER-encoded ECDSA signature (SEQUENCE of two INTEGERs)
     * down to raw, fixed-length, concatenated (r || s), as required by EAC 1.11 for
     * Terminal Authentication.
     */
    [Fact]
    public void testGetRawECDSASignature()
    {
        var r = new BigInteger("5A1B2C3D4E5F60718293A4B5C6D7E8F900112233A", 16);
        var s = new BigInteger("0102030405060708090A0B0C0D0E0F101112131F", 16);
        int keySize = 32;

        var vector = new Asn1EncodableVector { new DerInteger(r), new DerInteger(s) };
        byte[] derEncodedSignature = new DerSequence(vector).GetEncoded();

        byte[] rawSignature = Util.GetRawECDSASignature(derEncodedSignature, keySize);
        Assert.Equal("000000000000000000000005A1B2C3D4E5F60718293A4B5C6D7E8F900112233A"
            + "0000000000000000000000000102030405060708090A0B0C0D0E0F101112131F",
            Hex.BytesToHexString(rawSignature).ToUpperInvariant());
    }

    [Fact]
    public void testOs2i()
    {
        Assert.Equal(BigInteger.Zero, Util.Os2i([]));
        Assert.Equal(BigInteger.ValueOf(0x01), Util.Os2i([0x01]));
        Assert.Equal(BigInteger.ValueOf(0xFF), Util.Os2i([0xFF]));
        Assert.Equal(BigInteger.ValueOf(0x0102), Util.Os2i([0x01, 0x02]));

        /* os2i is an unsigned big-endian decoding, unlike the signed two's complement new BigInteger(byte[]). */
        byte[] highBitSet = TestData.Hex("FFEEDDCCBBAA99887766554433221100");
        Assert.Equal(new BigInteger(1, highBitSet), Util.Os2i(highBitSet));
    }

    [Fact]
    public void testOs2iWithOffsetAndLength()
    {
        byte[] bytes = TestData.Hex("0011223344556677");
        Assert.Equal(BigInteger.ValueOf(0x33445566L), Util.Os2i(bytes, 3, 4));
        Assert.Equal(Util.Os2i(bytes), Util.Os2i(bytes, 0, bytes.Length));
    }

    [Fact]
    public void testOs2iInverseOfI2os()
    {
        for (int i = 0; i < 200; i++)
        {
            var x = new BigInteger(128, Random);
            Assert.Equal(x, Util.Os2i(Util.I2os(x)));
        }
    }

    [Fact]
    public void testOs2iThrowsOnNull()
    {
        Assert.ThrowsAny<ArgumentException>(() => Util.Os2i(null));
        Assert.ThrowsAny<ArgumentException>(() => Util.Os2i(null, 0, 0));
    }

    /*
     * isPointOnCurve and isValid are the checks PACE/Chip Authentication rely on to reject a
     * maliciously chosen point that isn't actually on the agreed curve.
     */
    [Fact]
    public void testIsPointOnCurve()
    {
        CheckIsPointOnCurve("secp256r1");
        CheckIsPointOnCurve("brainpoolP256r1");
    }

    private static void CheckIsPointOnCurve(string curveName)
    {
        ECDomainParameters parameters = Util.GetECDomainParameters(curveName);
        ECPoint generator = parameters.G.Normalize();
        Assert.True(Util.IsPointOnCurve(generator.AffineXCoord.ToBigInteger(), generator.AffineYCoord.ToBigInteger(), parameters), curveName);

        ECPoint doubledGenerator = Util.Multiply(BigInteger.Two, generator).Normalize();
        Assert.True(Util.IsPointOnCurve(doubledGenerator.AffineXCoord.ToBigInteger(), doubledGenerator.AffineYCoord.ToBigInteger(), parameters), curveName);

        Assert.False(Util.IsPointOnCurve(generator.AffineXCoord.ToBigInteger(), generator.AffineYCoord.ToBigInteger().Add(BigInteger.One), parameters), curveName);
    }

    [Fact]
    public void testIsValidEcPoint()
    {
        CheckIsValidEcPoint("secp256r1");
        CheckIsValidEcPoint("brainpoolP256r1");
    }

    private static void CheckIsValidEcPoint(string curveName)
    {
        ECDomainParameters parameters = Util.GetECDomainParameters(curveName);
        ECPoint generator = parameters.G.Normalize();
        Assert.True(Util.IsValid(generator), curveName);

        ECPoint offCurvePoint = parameters.Curve.CreatePoint(generator.AffineXCoord.ToBigInteger(), generator.AffineYCoord.ToBigInteger().Add(BigInteger.One));
        Assert.False(Util.IsValid(offCurvePoint), curveName);
    }

    [Fact]
    public void testAlignKeyDataToSize()
    {
        byte[] original = [0x01, 0x02, 0x03];

        // Case 1: original is smaller than target size (padding with leading zeros)
        byte[] padded = Util.AlignKeyDataToSize(original, 5);
        Assert.Equal(new byte[] { 0x00, 0x00, 0x01, 0x02, 0x03 }, padded);

        // Case 2: original size matches target size
        byte[] matched = Util.AlignKeyDataToSize(original, 3);
        Assert.Equal(new byte[] { 0x01, 0x02, 0x03 }, matched);

        // Case 3: original is larger than target size (trim leading bytes, keep last 'size' bytes)
        byte[] trimmed = Util.AlignKeyDataToSize(original, 2);
        Assert.Equal(new byte[] { 0x02, 0x03 }, trimmed);
    }

    /*
     * In a Turkish locale "with".toUpperCase() is "WİTH" (dotted capital I), so the digest was not found.
     */
    [Fact]
    public void testInferDigestAlgorithmInTurkishLocale()
    {
        CultureInfo defaultCulture = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = new CultureInfo("tr-TR");
            Assert.Equal("SHA-256", Util.InferDigestAlgorithmFromSignatureAlgorithm("SHA256withECDSA"));
        }
        finally
        {
            CultureInfo.CurrentCulture = defaultCulture;
        }
    }

    /*
     * Padding without the 0x80 marker is a BadPaddingException (was an ArrayIndexOutOfBoundsException).
     */
    [Fact]
    public void testUnpadWithoutMarker()
    {
        Assert.Throws<CryptographicException>(() => Util.Unpad(new byte[8]));
        Assert.Throws<CryptographicException>(() => Util.Unpad([]));
    }

    /*
     * An encoded point is 0x04 followed by two coordinates of equal length, so of odd length.
     */
    [Fact]
    public void testOS2ECPointWrongLength()
    {
        Assert.ThrowsAny<ArgumentException>(() => Util.Os2ECPoint(TestData.Hex("04 01 02 03")));
        Assert.ThrowsAny<ArgumentException>(() => Util.Os2ECPoint([0x04]));
        Assert.ThrowsAny<ArgumentException>(() => Util.Os2ECPoint(null!));
        Assert.Equal((BigInteger.One, BigInteger.ValueOf(2)), Util.Os2ECPoint(TestData.Hex("04 01 02")));
    }

    private static AsymmetricCipherKeyPair GenerateRsaKeyPair(int bits)
    {
        var generator = new RsaKeyPairGenerator();
        generator.Init(new KeyGenerationParameters(Random, bits));
        return generator.GenerateKeyPair();
    }

    private static AsymmetricCipherKeyPair GenerateECKeyPair(string curveName)
    {
        var generator = new ECKeyPairGenerator();
        generator.Init(new ECKeyGenerationParameters(Util.GetECDomainParameters(curveName), Random));
        return generator.GenerateKeyPair();
    }

    /// <summary>Doc 9303-11, 9.5.1: a DH public key with standardized domain parameters (ID 0, 1024 bit MODP group)
    /// (JMRTD 0.8.10, d2b9471c).</summary>
    [Fact]
    public void testToPublicKeyWithStandardizedDHDomainParameters()
    {
        var parameters = (Org.BouncyCastle.Crypto.Parameters.DHParameters)nMRTD.Lds.PACEInfo.ToParameterSpec(nMRTD.Lds.PACEInfo.PARAM_ID_GFP_1024_160);
        Org.BouncyCastle.Math.BigInteger y = parameters.G.ModPow(Org.BouncyCastle.Math.BigInteger.ValueOf(123456789L), parameters.P);
        var subjectPublicKeyInfo = new Org.BouncyCastle.Asn1.X509.SubjectPublicKeyInfo(
            new Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier(new Org.BouncyCastle.Asn1.DerObjectIdentifier("0.4.0.127.0.7.1.2"), new Org.BouncyCastle.Asn1.DerInteger(0)),
            new Org.BouncyCastle.Asn1.DerInteger(y));
        var publicKey = Assert.IsType<Org.BouncyCastle.Crypto.Parameters.DHPublicKeyParameters>(Util.ToPublicKey(subjectPublicKeyInfo));
        Assert.Equal(y, publicKey.Y);
        Assert.Equal(parameters.P, publicKey.Parameters.P);
        Assert.Equal(parameters.G, publicKey.Parameters.G);
    }

    /// <summary>An unknown standardized domain parameter ID gives no key, as other undecodable keys.</summary>
    [Fact]
    public void testToPublicKeyWithUnknownStandardizedDomainParameters()
    {
        var subjectPublicKeyInfo = new Org.BouncyCastle.Asn1.X509.SubjectPublicKeyInfo(
            new Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier(new Org.BouncyCastle.Asn1.DerObjectIdentifier("0.4.0.127.0.7.1.2"), new Org.BouncyCastle.Asn1.DerInteger(99)),
            new byte[] { 0x04, 0x01, 0x02 });
        Assert.Null(Util.ToPublicKey(subjectPublicKeyInfo));
    }
}
