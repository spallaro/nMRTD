using nMRTD.Lds;
using nMRTD.Lds.Icao;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using static nMRTD.Tests.Helpers.TestData;

namespace nMRTD.Tests;

public class LdsRoundTripTests
{
    [Theory]
    [InlineData("brainpoolP256r1")]
    [InlineData("brainpoolP384r1")]
    [InlineData("brainpoolP512r1")]
    public void PaceDomainParameterInfoExplicitEcParametersRoundTrip(string curveName)
    {
        var original = EcParameters(curveName);
        var decoded = PACEDomainParameterInfo.ToECDomainParameters(PACEDomainParameterInfo.ToAlgorithmIdentifier(original));
        Assert.Equal(original.N, decoded.N);
        Assert.Equal(original.H, decoded.H);
        Assert.Equal(original.Curve.Field.Characteristic, decoded.Curve.Field.Characteristic);
        Assert.Equal(original.Curve.A.ToBigInteger(), decoded.Curve.A.ToBigInteger());
        Assert.Equal(original.Curve.B.ToBigInteger(), decoded.Curve.B.ToBigInteger());
        Assert.Equal(original.G.GetEncoded(false), decoded.G.GetEncoded(false));
        Assert.Equal(original.N, decoded.Curve.Order);
        Assert.Equal(original.H, decoded.Curve.Cofactor);
    }

    /// <summary>Regression (review fix 1): DG14 read from a stream was always empty.</summary>
    [Fact]
    public void Dg14ReadFromStreamKeepsSecurityInfos()
    {
        var ca = new ChipAuthenticationInfo(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128, 1);
        byte[] enc = new DG14File(new SecurityInfo[] { ca }).GetEncoded()!;
        var parsed = new DG14File(new MemoryStream(enc));
        Assert.Single(parsed.GetSecurityInfos());
        Assert.Equal(enc, parsed.GetEncoded());
    }

    /// <summary>Regression (review fix 3): DG12 built from data was written with the DG11 tag.</summary>
    [Fact]
    public void Dg12BuiltFromDataUsesTag6CAndReadsBack()
    {
        var dg12 = new DG12File("UTOPIA", "20260101", null, null, null, null, null, "20260101123000", "SN123");
        byte[] enc = dg12.GetEncoded()!;
        Assert.Equal(0x6C, enc[0]);
        var parsed = new DG12File(new MemoryStream(enc));
        Assert.Equal("UTOPIA", parsed.GetIssuingAuthority());
        Assert.Equal("SN123", parsed.GetPersonalizationSystemSerialNumber());
        Assert.Equal(0x6C, ((DataGroup)parsed).GetTag());
    }

    /// <summary>Regression (review fix 6): DG15 failed for RSA keys.</summary>
    [Fact]
    public void Dg15WithRsaKeyRoundTrips()
    {
        var rsaGen = new RsaKeyPairGenerator();
        rsaGen.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 1024));
        var rsaPub = (RsaKeyParameters)rsaGen.GenerateKeyPair().Public;
        byte[] enc = new DG15File(rsaPub).GetEncoded()!;
        var parsed = new DG15File(new MemoryStream(enc));
        var key = Assert.IsType<RsaKeyParameters>(parsed.GetPublicKey());
        Assert.Equal(rsaPub.Modulus, key.Modulus);
        Assert.Equal(rsaPub.Exponent, key.Exponent);
        Assert.Equal(enc, parsed.GetEncoded());
    }

    /// <summary>Regression (review fix 6): DG15 with a named-curve EC key re-encodes byte for byte.</summary>
    [Fact]
    public void Dg15WithNamedCurveEcKeyReencodesIdentically()
    {
        var q = BrainpoolP256r1.G.Multiply(BigInteger.ValueOf(12345)).Normalize();
        var spki = new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, TeleTrusTObjectIdentifiers.BrainpoolP256R1),
            q.GetEncoded(false)).GetEncoded();
        byte[] ef = new byte[] { 0x6F, (byte)spki.Length }.Concat(spki).ToArray();
        var parsed = new DG15File(new MemoryStream(ef));
        Assert.IsAssignableFrom<ECPublicKeyParameters>(parsed.GetPublicKey());
        Assert.Equal(ef, parsed.GetEncoded());
    }
}
