using nMRTD.Cert;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Crypto;
using static nMRTD.Cert.CVCAuthorizationTemplate;

namespace nMRTD.Tests.Jmrtd.Cert;

/// <summary>Port of JMRTD's <c>org.jmrtd.cert.CVCertificateFactorySpiTest</c>.</summary>
/// <remarks>
/// ADAPTATION: nMRTD's <c>CVCertificateFactorySpi</c> is a static class and reports parse failures as
/// <c>IOException</c> (Java: <c>CertificateException</c>); its wrong-tag message names the tag value
/// 0x7F21 rather than the constant <c>CV_CERTIFICATE_TAG</c>. Not ported:
/// <c>testUnimplementedMethodsReturnNull</c>, as the CRL stubs were not ported.
/// </remarks>
public class CVCertificateFactorySpiTest
{
    private const int CV_CERTIFICATE_TAG = 0x7F21;

    [Fact]
    public void testEngineGenerateCertificateRoundTrip()
    {
        CardVerifiableCertificate originalCert = CreateSelfSignedCertificate();
        byte[] encoded = originalCert.GetEncoded();

        CardVerifiableCertificate parsedCvCert = CVCertificateFactorySpi.EngineGenerateCertificate(new MemoryStream(encoded));

        Assert.Equal(originalCert, parsedCvCert);
        Assert.Equal(originalCert.GetHashCode(), parsedCvCert.GetHashCode());
        Assert.Equal(encoded, parsedCvCert.GetEncoded());
        Assert.Equal(originalCert.HolderReference, parsedCvCert.HolderReference);
        Assert.Equal(originalCert.AuthorityReference, parsedCvCert.AuthorityReference);
        Assert.Equal(originalCert.AuthorizationTemplate, parsedCvCert.AuthorizationTemplate);
        Assert.Equal(originalCert.PublicKey, parsedCvCert.PublicKey);
    }

    [Fact]
    public void testEngineGenerateCertificateRejectsWrongTag()
    {
        var output = new MemoryStream();
        using (var tlvOut = new TlvOutputStream(output))
        {
            tlvOut.WriteTag(0x7F20); /* Not CV_CERTIFICATE_TAG (0x7F21). */
            tlvOut.WriteValue([0x01, 0x02, 0x03]);
        }
        byte[] wronglyTaggedBytes = output.ToArray();

        IOException exception = Assert.ThrowsAny<IOException>(
            () => CVCertificateFactorySpi.EngineGenerateCertificate(new MemoryStream(wronglyTaggedBytes)));
        Assert.Contains(CV_CERTIFICATE_TAG.ToString("X"), exception.Message);
    }

    [Fact]
    public void testEngineGenerateCertificateRejectsMalformedBody()
    {
        var output = new MemoryStream();
        using (var tlvOut = new TlvOutputStream(output))
        {
            tlvOut.WriteTag(CV_CERTIFICATE_TAG);
            tlvOut.WriteValue([0x01, 0x02, 0x03, 0x04, 0x05]); /* Not a valid CV certificate body. */
        }
        byte[] malformedBytes = output.ToArray();

        Assert.ThrowsAny<IOException>(() => CVCertificateFactorySpi.EngineGenerateCertificate(new MemoryStream(malformedBytes)));
    }

    private static CardVerifiableCertificate CreateSelfSignedCertificate()
    {
        AsymmetricCipherKeyPair keyPair = KeyPairs.Rsa(1024);
        var caRef = new CVCPrincipal("NLDVCS00001");
        var holderRef = new CVCPrincipal("NLIS00001");
        var authZTemplate = new CVCAuthorizationTemplate(Role.Is, Permission.ReadAccessDg3AndDg4);
        DateOnly validFrom = DateOnly.FromDateTime(DateTime.UtcNow.AddSeconds(-10));
        DateOnly validTo = DateOnly.FromDateTime(DateTime.UtcNow.AddSeconds(10));
        return CVCertificateBuilder.CreateCertificate(keyPair.Public, keyPair.Private, "SHA256WithRSA",
            caRef, holderRef, authZTemplate, validFrom, validTo);
    }
}
