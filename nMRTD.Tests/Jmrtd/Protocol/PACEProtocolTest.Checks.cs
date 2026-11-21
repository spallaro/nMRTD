using nMRTD.Lds;
using nMRTD.Protocol;
using nMRTD.SmartCards;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using static nMRTD.Tests.Helpers.TestData;

namespace nMRTD.Tests.Jmrtd.Protocol;

/// <remarks>
/// ADAPTATION: JCA's <c>InvalidKeyException</c> from <c>checkDHPublicValue</c> is Bouncy Castle's
/// <c>InvalidKeyException</c>; JMRTD's <c>InvalidKeyException</c> (DH encoding without q) and
/// <c>InvalidAlgorithmParameterException</c> (PACE-IM with DH without q) are <c>ArgumentException</c> in
/// nMRTD. JMRTD's anonymous <c>DHPublicKey</c> is a <c>DHPublicKeyParameters</c>.
/// </remarks>
public partial class PACEProtocolTest
{
    [Fact]
    public void testCheckDHPublicValue()
    {
        var parameters = (DHParameters)PACEInfo.ToParameterSpec(PACEInfo.PARAM_ID_GFP_1024_160);
        BigInteger p = parameters.P;
        PaceProtocol.CheckDHPublicValue(parameters.G, parameters);
        foreach (BigInteger y in new[] { BigInteger.Zero, BigInteger.One, p })
        {
            Assert.Throws<InvalidKeyException>(() => PaceProtocol.CheckDHPublicValue(y, parameters));
        }

        Assert.Throws<InvalidKeyException>(() => PaceProtocol.CheckDHPublicValue(p.Subtract(BigInteger.One), parameters));
    }

    [Fact]
    public void testPACEGMWithDHMappedGeneratorOne()
    {
        var parameters = (DHParameters)PACEInfo.ToParameterSpec(PACEInfo.PARAM_ID_GFP_1024_160);
        byte[] s = Hex("FA5B7E3E 49753A0D B9178B7B 9BD898C8");
        BigInteger h = parameters.G.ModPow(Util.Os2i(s), parameters.P).ModInverse(parameters.P);
        Assert.ThrowsAny<ArgumentException>(() => PaceProtocol.MapNonceGMWithDH(s, h, parameters));
    }

    [Fact]
    public void testEncodeECPublicKeyDataObjectWithDomainParameters()
    {
        string oid = SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128;
        var parameters = (ECDomainParameters)PACEInfo.ToParameterSpec(PACEInfo.PARAM_ID_ECP_BRAINPOOL_P256_R1);
        var publicKey = (ECPublicKeyParameters)Helpers.KeyPairs.EC(parameters).Public;

        var expected = new MemoryStream();
        expected.Write(new DerObjectIdentifier(oid).GetEncoded());
        expected.Write(TlvUtil.WrapDO(0x81, Util.I2os(Util.GetPrime(parameters))));
        expected.Write(TlvUtil.WrapDO(0x82, Util.I2os(parameters.Curve.A.ToBigInteger())));
        expected.Write(TlvUtil.WrapDO(0x83, Util.I2os(parameters.Curve.B.ToBigInteger())));
        expected.Write(TlvUtil.WrapDO(0x84, Util.EcPoint2OS(parameters.G, 256)));
        expected.Write(TlvUtil.WrapDO(0x85, Util.I2os(parameters.N)));
        expected.Write(TlvUtil.WrapDO(0x86, Util.EcPoint2OS(publicKey.Q, 256)));
        expected.Write(TlvUtil.WrapDO(0x87, Util.I2os(parameters.H)));

        byte[] encoded = PaceProtocol.EncodePublicKeyDataObject(oid, publicKey, false);
        Assert.Equal(TlvUtil.WrapDO(0x7F49, expected.ToArray()), encoded);
    }

    [Fact]
    public void testEncodeDHPublicKeyDataObjectWithDomainParameters()
    {
        string oid = SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_128;
        var parameters = (DHParameters)PACEInfo.ToParameterSpec(PACEInfo.PARAM_ID_GFP_1024_160);
        BigInteger y = parameters.G.ModPow(BigInteger.ValueOf(12345), parameters.P);

        var expected = new MemoryStream();
        expected.Write(new DerObjectIdentifier(oid).GetEncoded());
        expected.Write(TlvUtil.WrapDO(0x81, Util.I2os(parameters.P)));
        expected.Write(TlvUtil.WrapDO(0x82, Util.I2os(parameters.Q)));
        expected.Write(TlvUtil.WrapDO(0x83, Util.I2os(parameters.G)));
        expected.Write(TlvUtil.WrapDO(0x84, Util.I2os(y)));

        byte[] encoded = PaceProtocol.EncodePublicKeyDataObject(oid, new DHPublicKeyParameters(y, parameters), false);
        Assert.Equal(TlvUtil.WrapDO(0x7F49, expected.ToArray()), encoded);
    }

    [Fact]
    public void testEncodeDHPublicKeyDataObjectWithoutQ()
    {
        var dhcParams = (DHParameters)PACEInfo.ToParameterSpec(PACEInfo.PARAM_ID_GFP_1024_160);
        var parameters = new DHParameters(dhcParams.P, dhcParams.G);
        Assert.ThrowsAny<ArgumentException>(() =>
            PaceProtocol.EncodePublicKeyDataObject(SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_128, new DHPublicKeyParameters(parameters.G, parameters), false));
    }

    [Fact]
    public void testPACEGMWithECDHMappedGeneratorAtInfinity()
    {
        var parameters = (ECDomainParameters)PACEInfo.ToParameterSpec(PACEInfo.PARAM_ID_ECP_BRAINPOOL_P256_R1);
        byte[] s = Hex("3F00C4D3 9D153F2B 2A214A07 8D899B22");
        ECPoint sG = Util.Multiply(Util.Os2i(s), parameters.G).Normalize();
        ECPoint h = parameters.Curve.CreatePoint(sG.AffineXCoord.ToBigInteger(), Util.GetPrime(parameters).Subtract(sG.AffineYCoord.ToBigInteger()));
        Assert.ThrowsAny<ArgumentException>(() => PaceProtocol.MapNonceGMWithECDH(s, h, parameters));
    }

    [Fact]
    public void testPACEIMWithDHWithoutQ()
    {
        var parameters = new DHParameters(Util.RFC5114_1024_160.P, Util.RFC5114_1024_160.G);
        byte[] s = Hex("FA5B7E3E 49753A0D B9178B7B 9BD898C8");
        byte[] t = Hex("B3A6DB3C 870C3E99 245E0D1C 06B747DE");
        Assert.ThrowsAny<ArgumentException>(() => PaceProtocol.MapNonceImWithDH(s, t, "AES", parameters));
    }

    [Fact]
    public void testIcartPointEncodeWithCofactor()
    {
        BigInteger p = BigInteger.ValueOf(1019);
        BigInteger n = BigInteger.ValueOf(263);
        var curve = new FpCurve(p, BigInteger.One, BigInteger.One, n, BigInteger.ValueOf(4));
        var parameters = new ECDomainParameters(curve, curve.CreatePoint(BigInteger.ValueOf(10), BigInteger.ValueOf(537)), n, BigInteger.ValueOf(4));

        ECPoint mappedGenerator = PaceProtocol.IcartPointEncode(BigInteger.ValueOf(5), parameters).Normalize();
        Assert.Equal(BigInteger.ValueOf(59), mappedGenerator.AffineXCoord.ToBigInteger());
        Assert.Equal(BigInteger.ValueOf(568), mappedGenerator.AffineYCoord.ToBigInteger());
        Assert.True(mappedGenerator.Multiply(n).IsInfinity);
    }
}
