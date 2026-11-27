using nMRTD.Lds;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using static nMRTD.Tests.Helpers.TestData;

namespace nMRTD.Tests.Jmrtd.Lds;

/// <summary>Port of JMRTD's <c>org.jmrtd.lds.PACEInfoTest</c>.</summary>
/// <remarks>
/// ADAPTATION: JCA's <c>DHParameterSpec</c> and <c>ECParameterSpec</c> are Bouncy Castle's
/// <c>DHParameters</c> and <c>ECDomainParameters</c>.
/// </remarks>
public class PACEInfoTest
{
    [Fact]
    public void testPACEInfo()
    {
        var paceInfo = new PACEInfo(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256, 2, PACEInfo.PARAM_ID_ECP_NIST_P256_R1);
        Assert.Equal(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256, paceInfo.GetObjectIdentifier());
        Assert.Equal("id-PACE-ECDH-GM-AES-CBC-CMAC-256", paceInfo.GetProtocolOIDString());
        Assert.Equal(PACEInfo.PARAM_ID_ECP_NIST_P256_R1, paceInfo.GetParameterId()!.IntValue); // 12
        Assert.Equal(12, paceInfo.GetParameterId()!.IntValue); // ID-ECP-NST-P256-R1
        Assert.Equal(2, paceInfo.GetVersion());

        var anotherPACEInfo = new PACEInfo(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256, 2, PACEInfo.PARAM_ID_ECP_NIST_P256_R1);
        Assert.Equal(paceInfo.GetHashCode(), anotherPACEInfo.GetHashCode());
        Assert.Equal(paceInfo, anotherPACEInfo);
        Assert.Equal(paceInfo.ToString(), anotherPACEInfo.ToString());
    }

    [Fact]
    public void testPACEInfoCanCreate()
    {
        CheckPACEInfoCanCreate(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, 2, PACEInfo.PARAM_ID_ECP_NIST_P224_R1);
        CheckPACEInfoCanCreate(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_192, 2, PACEInfo.PARAM_ID_ECP_NIST_P192_R1);
        CheckPACEInfoCanCreate(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256, 2, PACEInfo.PARAM_ID_ECP_NIST_P256_R1);
        CheckPACEInfoCanCreate(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256, 2, PACEInfo.PARAM_ID_ECP_BRAINPOOL_P256_R1);
        CheckPACEInfoCanCreate(SecurityInfo.ID_PACE_ECDH_GM_3DES_CBC_CBC, 2, PACEInfo.PARAM_ID_ECP_NIST_P192_R1);
        CheckPACEInfoCanCreate(SecurityInfo.ID_PACE_ECDH_GM_3DES_CBC_CBC, 2, PACEInfo.PARAM_ID_ECP_BRAINPOOL_P320_R1);
        CheckPACEInfoCanCreate(SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_192, 2, PACEInfo.PARAM_ID_ECP_NIST_P192_R1);
        CheckPACEInfoCanCreate(SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_256, 2, PACEInfo.PARAM_ID_ECP_BRAINPOOL_P256_R1);
        CheckPACEInfoCanCreate(SecurityInfo.ID_PACE_DH_GM_3DES_CBC_CBC, 2, PACEInfo.PARAM_ID_GFP_1024_160);
        CheckPACEInfoCanCreate(SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_128, 2, PACEInfo.PARAM_ID_GFP_1024_160);
        CheckPACEInfoCanCreate(SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_192, 2, PACEInfo.PARAM_ID_GFP_2048_224);
        CheckPACEInfoCanCreate(SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_256, 2, PACEInfo.PARAM_ID_GFP_2048_224);
        CheckPACEInfoCanCreate(SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_256, 2, PACEInfo.PARAM_ID_GFP_2048_256);
        CheckPACEInfoCanCreate(SecurityInfo.ID_PACE_DH_IM_3DES_CBC_CBC, 2, PACEInfo.PARAM_ID_GFP_2048_224);
        CheckPACEInfoCanCreate(SecurityInfo.ID_PACE_DH_IM_AES_CBC_CMAC_192, 2, PACEInfo.PARAM_ID_GFP_2048_224);
        CheckPACEInfoCanCreate(SecurityInfo.ID_PACE_DH_IM_AES_CBC_CMAC_256, 2, PACEInfo.PARAM_ID_GFP_2048_256);
    }

    private static void CheckPACEInfoCanCreate(string oid, int version, int paramId)
    {
        Assert.NotNull(new PACEInfo(oid, version, paramId));
    }

    [Fact]
    public void testPACEInfoGetProtocolOIDString()
    {
        CheckPACEInfoGetProtocolOIDString("id-PACE-DH-GM-3DES-CBC-CBC", SecurityInfo.ID_PACE_DH_GM_3DES_CBC_CBC);
        CheckPACEInfoGetProtocolOIDString("id-PACE-DH-GM-AES-CBC-CMAC-128", SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_128);
        CheckPACEInfoGetProtocolOIDString("id-PACE-DH-GM-AES-CBC-CMAC-192", SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_192);
        CheckPACEInfoGetProtocolOIDString("id-PACE-DH-GM-AES-CBC-CMAC-256", SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_256);
        CheckPACEInfoGetProtocolOIDString("id-PACE-DH-IM-3DES-CBC-CBC", SecurityInfo.ID_PACE_DH_IM_3DES_CBC_CBC);
        CheckPACEInfoGetProtocolOIDString("id-PACE-DH-IM-AES-CBC-CMAC-128", SecurityInfo.ID_PACE_DH_IM_AES_CBC_CMAC_128);
        CheckPACEInfoGetProtocolOIDString("id-PACE-DH-IM-AES-CBC-CMAC-192", SecurityInfo.ID_PACE_DH_IM_AES_CBC_CMAC_192);
        CheckPACEInfoGetProtocolOIDString("id-PACE-DH-IM-AES-CBC-CMAC-256", SecurityInfo.ID_PACE_DH_IM_AES_CBC_CMAC_256);
        CheckPACEInfoGetProtocolOIDString("id-PACE-ECDH-GM-3DES-CBC-CBC", SecurityInfo.ID_PACE_ECDH_GM_3DES_CBC_CBC);
        CheckPACEInfoGetProtocolOIDString("id-PACE-ECDH-GM-AES-CBC-CMAC-128", SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128);
        CheckPACEInfoGetProtocolOIDString("id-PACE-ECDH-GM-AES-CBC-CMAC-192", SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_192);
        CheckPACEInfoGetProtocolOIDString("id-PACE-ECDH-GM-AES-CBC-CMAC-256", SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256);
        CheckPACEInfoGetProtocolOIDString("id-PACE-ECDH-IM-3DES-CBC-CBC", SecurityInfo.ID_PACE_ECDH_IM_3DES_CBC_CBC);
        CheckPACEInfoGetProtocolOIDString("id-PACE-ECDH-IM-AES-CBC-CMAC-128", SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_128);
        CheckPACEInfoGetProtocolOIDString("id-PACE-ECDH-IM-AES-CBC-CMAC-192", SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_192);
        CheckPACEInfoGetProtocolOIDString("id-PACE-ECDH-IM-AES-CBC-CMAC-256", SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_256);
        CheckPACEInfoGetProtocolOIDString("id-PACE-ECDH-CAM-AES-CBC-CMAC-128", SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_128);
        CheckPACEInfoGetProtocolOIDString("id-PACE-ECDH-CAM-AES-CBC-CMAC-192", SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_192);
        CheckPACEInfoGetProtocolOIDString("id-PACE-ECDH-CAM-AES-CBC-CMAC-256", SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_256);
    }

    private static void CheckPACEInfoGetProtocolOIDString(string str, string oid)
    {
        int[] parameterIds =
        [
            PACEInfo.PARAM_ID_ECP_NIST_P192_R1, PACEInfo.PARAM_ID_ECP_NIST_P224_R1, PACEInfo.PARAM_ID_ECP_NIST_P256_R1,
            PACEInfo.PARAM_ID_ECP_NIST_P384_R1, PACEInfo.PARAM_ID_ECP_NIST_P521_R1, PACEInfo.PARAM_ID_ECP_BRAINPOOL_P192_R1, PACEInfo.PARAM_ID_ECP_BRAINPOOL_P224_R1,
            PACEInfo.PARAM_ID_ECP_BRAINPOOL_P256_R1, PACEInfo.PARAM_ID_ECP_BRAINPOOL_P320_R1, PACEInfo.PARAM_ID_ECP_BRAINPOOL_P384_R1, PACEInfo.PARAM_ID_ECP_BRAINPOOL_P512_R1,
            PACEInfo.PARAM_ID_GFP_1024_160, PACEInfo.PARAM_ID_GFP_2048_224, PACEInfo.PARAM_ID_GFP_2048_256,
        ];
        foreach (int parameterId in parameterIds)
        {
            var paceInfo = new PACEInfo(oid, 2, parameterId);
            Assert.Contains("-", str);
            Assert.DoesNotContain("_", str);
            Assert.Equal(str, paceInfo.GetProtocolOIDString());
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(8)]
    [InlineData(9)]
    [InlineData(10)]
    [InlineData(11)]
    [InlineData(12)]
    [InlineData(13)]
    [InlineData(14)]
    [InlineData(15)]
    [InlineData(16)]
    [InlineData(17)]
    [InlineData(18)]
    public void testToParameterSpecNotNull(int stdDomainParams)
    {
        object paramSpec = PACEInfo.ToParameterSpec(BigInteger.ValueOf(stdDomainParams));
        Assert.NotNull(paramSpec);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(8)]
    [InlineData(9)]
    [InlineData(10)]
    [InlineData(11)]
    [InlineData(12)]
    [InlineData(13)]
    [InlineData(14)]
    [InlineData(15)]
    [InlineData(16)]
    [InlineData(17)]
    [InlineData(18)]
    public void testToParameterSpecDHParameterSpecOrECParameterSpec(int stdDomainParams)
    {
        object paramSpec = PACEInfo.ToParameterSpec(BigInteger.ValueOf(stdDomainParams));
        Assert.True(paramSpec is DHParameters || paramSpec is ECDomainParameters);
    }

    [Fact]
    public void testECDHPrime()
    {
        object paramSpec = PACEInfo.ToParameterSpec(PACEInfo.PARAM_ID_ECP_NIST_P256_R1);
        Assert.IsAssignableFrom<ECDomainParameters>(paramSpec);
    }
}

/// <summary>Port of JMRTD's <c>org.jmrtd.lds.PACEDomainParameterInfoTest</c>.</summary>
/// <remarks>
/// ADAPTATION: JCA's <c>ECParameterSpec</c> is Bouncy Castle's <c>ECDomainParameters</c>.
/// Java-only, not ported: <c>testSerializable</c> (Java serialization).
/// </remarks>
public class PACEDomainParameterInfoTest
{
    private const string ID_EC_PUBLIC_KEY = "1.2.840.10045.2.1";

    /// <summary>Testing some internal functions here, these should be removed at some point.</summary>
    [Fact]
    public void testECParameterSpec()
    {
        ECDomainParameters ecParameterSpec = GetSampleECParameterSpec();
        Assert.NotNull(ecParameterSpec);

        AlgorithmIdentifier algorithmIdentifier = PACEDomainParameterInfo.ToAlgorithmIdentifier(ecParameterSpec);
        Assert.NotNull(algorithmIdentifier);
        Assert.Equal(ID_EC_PUBLIC_KEY, algorithmIdentifier.Algorithm.Id); // 1.2.840.10045.2.1 - EC Public Key

        Asn1Encodable parameters = algorithmIdentifier.Parameters;
        Asn1Sequence paramSeq = Asn1Sequence.GetInstance(parameters);
        X962Parameters x = X962Parameters.GetInstance(paramSeq);
        Assert.NotNull(x);

        ECDomainParameters anotherECParameterSpec = PACEDomainParameterInfo.ToECDomainParameters(algorithmIdentifier);
        Assert.Equal(ecParameterSpec.Curve, anotherECParameterSpec.Curve);
        Assert.Equal(ecParameterSpec.G, anotherECParameterSpec.G);
        Assert.Equal(ecParameterSpec.N, anotherECParameterSpec.N);
        Assert.Equal(ecParameterSpec.H, anotherECParameterSpec.H);

        /* Encoding and decoding... */
        byte[] encoded = algorithmIdentifier.GetEncoded();
        Assert.NotNull(encoded);
        Assert.Equal(
            Hex("3081DE06072A8648CE3D02013081D2020101302906072A8648CE3D0101021E7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFF3040041E7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFC041E6B016C3BDCF18941D0D654921475CA71A9DB2FB27D1D37796185C2942C0A043D040FFA963CDCA8816CCC33B8642BEDF905C3D358573D3F27FBBD3B3CB9AAAF7DEBE8E4E90A5DAE6E4054CA530BA04654B36818CE226B39FCCB7B02F1AE021E7FFFFFFFFFFFFFFFFFFFFFFF7FFFFF9E5E9A9F5D9071FBD1522688909D0B020101"),
            encoded);

        Asn1Object obj;
        using (var asn1In = new Asn1InputStream(new MemoryStream(encoded)))
        {
            obj = asn1In.ReadObject();
        }
        Assert.NotNull(obj);
        AlgorithmIdentifier decodedAlgorithmIdentifier = AlgorithmIdentifier.GetInstance(obj);
        Assert.Equal(algorithmIdentifier, decodedAlgorithmIdentifier);
    }

    private static ECDomainParameters GetSampleECParameterSpec()
    {
        var n = new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307"); // n
        var curve = new FpCurve(
            new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839"), // q
            new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
            new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16), // b
            n,
            BigInteger.One);
        return new ECDomainParameters(curve, curve.DecodePoint(Hex("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
            n,
            BigInteger.One); // h
    }
}

/// <summary>Port of JMRTD's <c>org.jmrtd.lds.DisplayedImageInfoTest</c>.</summary>
/// <remarks>
/// ADAPTATION: JMRTD encodes a blank image of the given size with ImageIO; .NET has no built-in JPEG
/// encoder, so a fixed minimal JPEG is used (the image is opaque to <c>DisplayedImageInfo</c>).
/// </remarks>
public class DisplayedImageInfoTest
{
    /// <summary>A minimal 1x1 baseline JPEG.</summary>
    private static readonly byte[] TrivialJpeg = Convert.FromBase64String(
        "/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////"
        + "wAALCAABAAEBAREA/8QAJgABAAAAAAAAAAAAAAAAAAAAAxABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQAAPwBH/9k=");

    [Fact]
    public void testToString()
    {
        CheckToString(CreateNonEmptyTestObject(), "DisplayedImageInfo [type: Signature or usual mark, size: ");
    }

    private static void CheckToString(DisplayedImageInfo imageInfo, string expectedResult)
    {
        Assert.NotNull(imageInfo);
        string asString = imageInfo.ToString();
        Assert.NotNull(asString);
        Assert.StartsWith(expectedResult, asString);
    }

    [Fact]
    public void testNonNullEncoded()
    {
        DisplayedImageInfo imageInfo = CreateNonEmptyTestObject();
        Assert.NotNull(imageInfo);
        byte[]? encoded = imageInfo.GetEncoded();
        Assert.NotNull(encoded);
    }

    [Fact]
    public void testEncodeDecode()
    {
        CheckEncodeDecode(CreateNonEmptyTestObject());
    }

    private static void CheckEncodeDecode(DisplayedImageInfo original)
    {
        byte[]? encoded = original.GetEncoded();
        Assert.NotNull(encoded);
        var input = new MemoryStream(encoded);
        var copy = new DisplayedImageInfo(input);
        Assert.Equal(original.GetImageType(), copy.GetImageType());
        Assert.Equal(original, copy);
        byte[]? encodedCopy = copy.GetEncoded();
        Assert.NotNull(encodedCopy);
        Assert.Equal(Convert.ToHexString(encoded), Convert.ToHexString(encodedCopy));
    }

    [Fact]
    public void testValidType()
    {
        DisplayedImageInfo signatureInfo = CreateNonEmptyTestObject(ImageInfoTypes.TYPE_SIGNATURE_OR_MARK);
        CheckValidType(signatureInfo);
        DisplayedImageInfo portraitInfo = CreateNonEmptyTestObject(ImageInfoTypes.TYPE_PORTRAIT);
        CheckValidType(portraitInfo);
    }

    private static void CheckValidType(DisplayedImageInfo imageInfo)
    {
        int type = imageInfo.GetImageType();
        Assert.True(type == ImageInfoTypes.TYPE_PORTRAIT || type == ImageInfoTypes.TYPE_SIGNATURE_OR_MARK);
    }

    internal static DisplayedImageInfo CreateNonEmptyTestObject(int type = ImageInfoTypes.TYPE_SIGNATURE_OR_MARK) =>
        new(type, TrivialJpeg);
}
