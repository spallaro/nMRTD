using nMRTD.Cert;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Crypto;
using static nMRTD.Cert.CVCAuthorizationTemplate;

namespace nMRTD.Tests.Jmrtd.Cert;

/// <summary>Port of JMRTD's <c>org.jmrtd.cert.CVCertificateBuilderTest</c>.</summary>
/// <remarks>
/// ADAPTATION: CV certificate dates are day-precision, so Java's <c>Date</c> is a <c>DateOnly</c>;
/// keys are Bouncy Castle key parameters and there is no JCA provider argument.
/// </remarks>
public class CVCertificateBuilderTest
{
    [Fact]
    public void testCreateCertificateSuccess()
    {
        AsymmetricCipherKeyPair keyPair = KeyPairs.Rsa(1024);
        AsymmetricKeyParameter publicKey = keyPair.Public;
        AsymmetricKeyParameter privateKey = keyPair.Private;

        var caRef = new CVCPrincipal("NLDVCS00001");
        var holderRef = new CVCPrincipal("NLIS00001");
        var authZTemplate = new CVCAuthorizationTemplate(Role.Is, Permission.ReadAccessDg3AndDg4);
        DateOnly validFrom = DateOnly.FromDateTime(DateTime.UtcNow.AddSeconds(-10));
        DateOnly validTo = DateOnly.FromDateTime(DateTime.UtcNow.AddSeconds(10));

        CardVerifiableCertificate cert = CVCertificateBuilder.CreateCertificate(
            publicKey,
            privateKey,
            "SHA256WithRSA",
            caRef,
            holderRef,
            authZTemplate,
            validFrom,
            validTo);

        Assert.NotNull(cert);
        Assert.Equal(caRef, cert.AuthorityReference);
        Assert.Equal(holderRef, cert.HolderReference);
        Assert.Equal(publicKey, cert.PublicKey);
        Assert.Equal("SHA256withRSA".ToUpperInvariant(), cert.SigAlgName!.ToUpperInvariant());
        Assert.Equal(authZTemplate, cert.AuthorizationTemplate);
    }

    [Fact]
    public void testRoleAndAccessRightMapping()
    {
        AsymmetricCipherKeyPair keyPair = KeyPairs.Rsa(1024);
        AsymmetricKeyParameter publicKey = keyPair.Public;
        AsymmetricKeyParameter privateKey = keyPair.Private;

        var caRef = new CVCPrincipal("NLDVCS00001");
        var holderRef = new CVCPrincipal("NLIS00001");
        DateOnly validFrom = DateOnly.FromDateTime(DateTime.UtcNow);
        DateOnly validTo = DateOnly.FromDateTime(DateTime.UtcNow);

        foreach (Role role in Enum.GetValues<Role>())
        {
            foreach (Permission permission in Enum.GetValues<Permission>())
            {
                var template = new CVCAuthorizationTemplate(role, permission);
                CardVerifiableCertificate cert = CVCertificateBuilder.CreateCertificate(
                    publicKey,
                    privateKey,
                    "SHA256WithRSA",
                    caRef,
                    holderRef,
                    template,
                    validFrom,
                    validTo);

                Assert.NotNull(cert);
                Assert.Equal(role, cert.AuthorizationTemplate.AuthorizationRole);
                Assert.Equal(permission, cert.AuthorizationTemplate.AccessRight);
            }
        }
    }
}
