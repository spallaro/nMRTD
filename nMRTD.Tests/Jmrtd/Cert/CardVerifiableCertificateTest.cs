using System.Security.Cryptography;
using nMRTD.Cert;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using static nMRTD.Cert.CVCAuthorizationTemplate;

namespace nMRTD.Tests.Jmrtd.Cert;

/// <summary>Port of JMRTD's <c>org.jmrtd.cert.CardVerifiableCertificateTest</c>.</summary>
/// <remarks>
/// ADAPTATION: dates are <c>DateOnly</c>; Java's <c>SignatureException</c> maps to
/// <c>CryptographicException</c>; <c>verify(key, provider)</c> has no counterpart (no JCA providers).
/// Java-only, not ported: <c>testGetPublicKeyAfterSerialization</c> (Java serialization).
/// </remarks>
public class CardVerifiableCertificateTest
{
    [Fact]
    public void testCardVerifiableCertificate()
    {
        var authorityReference = new CVCPrincipal("CBDVCS00001");
        var holderReference = new CVCPrincipal("UTIS00001");
        AsymmetricCipherKeyPair keyPair = KeyPairs.Rsa(1024);
        AsymmetricKeyParameter publicKey = keyPair.Public;
        string algorithm = "SHA256WithRSA";
        var notBefore = new DateOnly(2017, 1, 1); // Java: "2017-01-01" parsed as yyyy-dd-MM
        var notAfter = new DateOnly(2017, 2, 2); // Java: "2017-02-02" parsed as yyyy-dd-MM
        Role role = Role.Is;
        Permission permission = Permission.ReadAccessDg3AndDg4;
        var signatureData = new byte[128]; // NOTE: replace this with a real sig.
        var cvCert = new CardVerifiableCertificate(authorityReference, holderReference, publicKey, algorithm, notBefore, notAfter, role, permission, signatureData);
        Assert.Equal(holderReference, cvCert.HolderReference);
        Assert.Equal(authorityReference, cvCert.AuthorityReference);
        Assert.Equal(new CVCAuthorizationTemplate(role, permission), cvCert.AuthorizationTemplate);
        Assert.Equal(algorithm, cvCert.SigAlgName, ignoreCase: true);
        Assert.Equal(publicKey, cvCert.PublicKey);
    }

    [Fact]
    public void testVerifySucceedsWithMatchingKey()
    {
        AsymmetricCipherKeyPair keyPair = KeyPairs.Rsa(1024);
        CardVerifiableCertificate cert = CreateSelfSignedRSACertificate(keyPair);

        /* Self-signed: the embedded subject key is also the one that signed it. */
        cert.Verify(keyPair.Public);
    }

    [Fact]
    public void testVerifyFailsWithWrongKey()
    {
        AsymmetricCipherKeyPair keyPair = KeyPairs.Rsa(1024);
        CardVerifiableCertificate cert = CreateSelfSignedRSACertificate(keyPair);
        AsymmetricKeyParameter wrongPublicKey = KeyPairs.Rsa(1024).Public;

        Assert.Throws<CryptographicException>(() => cert.Verify(wrongPublicKey));
    }

    [Fact]
    public void testGetPublicKeyECDSA()
    {
        AsymmetricCipherKeyPair keyPair = KeyPairs.EC("secp256r1");
        AsymmetricKeyParameter publicKey = keyPair.Public;
        AsymmetricKeyParameter privateKey = keyPair.Private;

        var caRef = new CVCPrincipal("NLDVCS00001");
        var holderRef = new CVCPrincipal("NLIS00001");
        var authZTemplate = new CVCAuthorizationTemplate(Role.Is, Permission.ReadAccessDg3AndDg4);
        DateOnly validFrom = DateOnly.FromDateTime(DateTime.UtcNow.AddSeconds(-10));
        DateOnly validTo = DateOnly.FromDateTime(DateTime.UtcNow.AddSeconds(10));

        CardVerifiableCertificate cert = CVCertificateBuilder.CreateCertificate(publicKey, privateKey,
            "SHA256WithECDSA", caRef, holderRef, authZTemplate, validFrom, validTo);

        AsymmetricKeyParameter? resultKey = cert.PublicKey;
        Assert.IsNotType<RsaKeyParameters>(resultKey);
        ECPublicKeyParameters ecResultKey = Assert.IsType<ECPublicKeyParameters>(resultKey);
        Assert.Equal(((ECPublicKeyParameters)publicKey).Q.Normalize().GetEncoded(false), ecResultKey.Q.Normalize().GetEncoded(false));

        /* And it verifies, exercising ECDSA in verify() too. */
        cert.Verify(publicKey);
    }

    [Fact]
    public void testEqualsReflexiveAndTypeChecks()
    {
        CardVerifiableCertificate cert = CreateSelfSignedRSACertificate(KeyPairs.Rsa(1024));
        Assert.True(cert.Equals(cert));
        Assert.False(cert.Equals(null));
        Assert.False(cert.Equals("not a certificate"));
        Assert.Equal(cert.GetHashCode(), cert.GetHashCode());
    }

    /// <summary>
    /// CardVerifiableCertificate.equals compares encoded (DER) content, not object identity, so two
    /// separately constructed certificates with byte-identical content are equal.
    /// </summary>
    [Fact]
    public void testEqualsIsContentBasedAcrossInstances()
    {
        AsymmetricCipherKeyPair keyPair = KeyPairs.Rsa(1024);
        var caRef = new CVCPrincipal("NLDVCS00001");
        var holderRef = new CVCPrincipal("NLIS00001");
        var authZTemplate = new CVCAuthorizationTemplate(Role.Is, Permission.ReadAccessDg3AndDg4);
        DateOnly validFrom = DateOnly.FromDateTime(DateTime.UtcNow.AddSeconds(-10));
        DateOnly validTo = DateOnly.FromDateTime(DateTime.UtcNow.AddSeconds(10));

        CardVerifiableCertificate cert1 = CVCertificateBuilder.CreateCertificate(keyPair.Public,
            keyPair.Private, "SHA256WithRSA", caRef, holderRef, authZTemplate, validFrom, validTo);
        CardVerifiableCertificate cert2 = CVCertificateBuilder.CreateCertificate(keyPair.Public,
            keyPair.Private, "SHA256WithRSA", caRef, holderRef, authZTemplate, validFrom, validTo);
        Assert.Equal(cert1, cert2);
        Assert.Equal(cert1.GetHashCode(), cert2.GetHashCode());

        /* A certificate over a different holder reference is genuinely different content. */
        CardVerifiableCertificate cert3 = CVCertificateBuilder.CreateCertificate(keyPair.Public,
            keyPair.Private, "SHA256WithRSA", caRef, new CVCPrincipal("NLIS00002"), authZTemplate,
            validFrom, validTo);
        Assert.NotEqual(cert1, cert3);
    }

    private static CardVerifiableCertificate CreateSelfSignedRSACertificate(AsymmetricCipherKeyPair keyPair)
    {
        var caRef = new CVCPrincipal("NLDVCS00001");
        var holderRef = new CVCPrincipal("NLIS00001");
        var authZTemplate = new CVCAuthorizationTemplate(Role.Is, Permission.ReadAccessDg3AndDg4);
        DateOnly validFrom = DateOnly.FromDateTime(DateTime.UtcNow.AddSeconds(-10));
        DateOnly validTo = DateOnly.FromDateTime(DateTime.UtcNow.AddSeconds(10));
        return CVCertificateBuilder.CreateCertificate(keyPair.Public, keyPair.Private,
            "SHA256WithRSA", caRef, holderRef, authZTemplate, validFrom, validTo);
    }
}
