using nMRTD.Cert;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using static nMRTD.Tests.Helpers.TestData;

namespace nMRTD.Tests;

/// <summary>Card verifiable certificates. Regressions for review fix 2 (dates in the wrong format).</summary>
public class CvcTests
{
    private static CardVerifiableCertificate LoadCvc(string set, string name)
    {
        byte[] b = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "certs", set, $"cert{name}_{set}.cvcert"));
        var c = CardVerifiableCertificate.Parse(b);
        Assert.Equal(b, c.GetEncoded());
        return c;
    }

    /// <summary>The key of <paramref name="c"/>, with the domain parameters taken from its issuer's key.</summary>
    private static ECPublicKeyParameters WithDomain(CardVerifiableCertificate c, ECPublicKeyParameters domainFrom) =>
        new(domainFrom.Parameters.Curve.DecodePoint(c.RawEcPublicKeyPoint!), domainFrom.Parameters);

    [Fact]
    public void DatesAreUnpackedBcdAndCertificatesRoundTripAndVerify()
    {
        var gen = new ECKeyPairGenerator();
        gen.Init(new ECKeyGenerationParameters(BrainpoolP256r1, new SecureRandom()));
        var kp = gen.GenerateKeyPair();
        var who = new CVCPrincipal("UT", "CVCA", "00001");
        var chat = new CVCAuthorizationTemplate(CVCAuthorizationTemplate.Role.Cvca, CVCAuthorizationTemplate.Permission.ReadAccessDg3);
        var cert = CVCertificateBuilder.CreateCertificate(kp.Public, kp.Private, "SHA256withECDSA", who, who, chat,
            new DateOnly(2026, 11, 21), new DateOnly(2029, 11, 20));
        byte[] enc = cert.GetEncoded();
        AssertContains(Hex("5F25 06 02 06 01 01 02 01"), enc, "effective date not in unpacked BCD");
        AssertContains(Hex("5F24 06 02 09 01 01 02 00"), enc, "expiration date not in unpacked BCD");
        var parsed = CardVerifiableCertificate.Parse(enc);
        Assert.Equal(new DateOnly(2026, 11, 21), parsed.NotBefore);
        Assert.Equal(new DateOnly(2029, 11, 20), parsed.NotAfter);
        Assert.Equal(enc, parsed.GetEncoded());
        parsed.Verify(kp.Public);
    }

    [Fact]
    public void RealCertificateChainsParseReencodeAndVerify()
    {
        var cvca1 = LoadCvc("orig", "CVCA");
        var cvca2 = LoadCvc("new", "CVCA");
        var cvca1Key = Assert.IsType<ECPublicKeyParameters>(cvca1.PublicKey);
        var cvca2Key = Assert.IsType<ECPublicKeyParameters>(cvca2.PublicKey);
        Assert.Equal(new DateOnly(2008, 5, 19), cvca1.NotBefore);
        Assert.Equal(new DateOnly(2011, 5, 19), cvca1.NotAfter);
        cvca1.Verify(cvca1Key); // self-signed root
        cvca2.Verify(cvca1Key); // link certificate 00001 -> 00002
        var dv1 = LoadCvc("orig", "DVD");
        var is1 = LoadCvc("orig", "IS");
        var dv2 = LoadCvc("new", "DVD");
        var is2 = LoadCvc("new", "IS");
        dv1.Verify(cvca1Key);
        is1.Verify(WithDomain(dv1, cvca1Key));
        dv2.Verify(cvca2Key);
        is2.Verify(WithDomain(dv2, cvca2Key));
    }
}
