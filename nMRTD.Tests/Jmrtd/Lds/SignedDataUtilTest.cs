using nMRTD.Lds;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;

namespace nMRTD.Tests.Jmrtd.Lds;

/// <summary>Port of JMRTD's <c>org.jmrtd.lds.SignedDataUtilTest</c>.</summary>
/// <remarks>ADAPTATION: Java's <c>NoSuchAlgorithmException</c> maps to <c>NotSupportedException</c>.</remarks>
public class SignedDataUtilTest
{
    [Fact]
    public void testOidMnemonicTranslations()
    {
        Assert.Equal("SHA-256", SignedDataUtil.LookupMnemonicByOid("2.16.840.1.101.3.4.2.1"));
        Assert.Equal("SHA-512", SignedDataUtil.LookupMnemonicByOid("2.16.840.1.101.3.4.2.3"));
        Assert.Equal("SHA-384", SignedDataUtil.LookupMnemonicByOid("2.16.840.1.101.3.4.2.2"));
        Assert.Equal("SHA-224", SignedDataUtil.LookupMnemonicByOid("2.16.840.1.101.3.4.2.4"));

        Assert.Equal("2.16.840.1.101.3.4.2.1", SignedDataUtil.LookupOidByMnemonic("SHA-256"));
        Assert.Equal("2.16.840.1.101.3.4.2.3", SignedDataUtil.LookupOidByMnemonic("SHA-512"));
        Assert.Equal("2.16.840.1.101.3.4.2.2", SignedDataUtil.LookupOidByMnemonic("SHA-384"));
        Assert.Equal("2.16.840.1.101.3.4.2.4", SignedDataUtil.LookupOidByMnemonic("SHA-224"));

        Assert.Equal("CN", SignedDataUtil.LookupMnemonicByOid("2.5.4.3"));
        Assert.Equal("OU", SignedDataUtil.LookupMnemonicByOid("2.5.4.11"));
        Assert.Equal("O", SignedDataUtil.LookupMnemonicByOid("2.5.4.10"));
        Assert.Equal("C", SignedDataUtil.LookupMnemonicByOid("2.5.4.6"));

        Assert.Equal("2.5.4.3", SignedDataUtil.LookupOidByMnemonic("CN"));
        Assert.Equal("2.5.4.11", SignedDataUtil.LookupOidByMnemonic("OU"));
        Assert.Equal("2.5.4.10", SignedDataUtil.LookupOidByMnemonic("O"));
        Assert.Equal("2.5.4.6", SignedDataUtil.LookupOidByMnemonic("C"));

        Assert.Equal("SHA256withRSA", SignedDataUtil.LookupMnemonicByOid("1.2.840.113549.1.1.11"));
        Assert.Equal("1.2.840.113549.1.1.11", SignedDataUtil.LookupOidByMnemonic("SHA256withRSA"));

        Assert.Null(SignedDataUtil.LookupMnemonicByOid(null));

        Assert.Throws<NotSupportedException>(() => SignedDataUtil.LookupMnemonicByOid("1.3.5.7.9"));
        Assert.Throws<NotSupportedException>(() => SignedDataUtil.LookupOidByMnemonic("InvalidMnemonicName"));
    }

    [Fact]
    public void testSignedDataRoundTripAndVerification()
    {
        AsymmetricCipherKeyPair keyPair = KeyPairs.Rsa(1024);
        AsymmetricKeyParameter publicKey = keyPair.Public;
        AsymmetricKeyParameter privateKey = keyPair.Private;
        DateTime validFrom = DateTime.UtcNow.AddSeconds(-10);
        DateTime validTo = DateTime.UtcNow.AddSeconds(10);

        X509Certificate docSigningCertificate = CertificateUtil.CreateCertificate(
            "C=NL, O=JMRTD, CN=DocSigning",
            "C=NL, O=JMRTD, CN=DocSigning",
            validFrom,
            validTo,
            publicKey,
            privateKey,
            "SHA256withRSA");

        var testOid = new DerObjectIdentifier("1.2.3.4.5.6");
        var testInner = new DerOctetString(new byte[] { 0x10, 0x20, 0x30, 0x40 });
        var testData = new DerOctetString(testInner.GetEncoded());
        var contentInfo = new ContentInfo(testOid, testData);

        byte[]? encryptedDigest = SignedDataUtil.SignData(
            "SHA-256",
            "SHA256withRSA",
            "1.2.3.4.5.6",
            contentInfo,
            privateKey);
        Assert.NotNull(encryptedDigest);

        SignedData signedData = SignedDataUtil.CreateSignedData(
            "SHA-256",
            "SHA256withRSA",
            "1.2.3.4.5.6",
            contentInfo,
            encryptedDigest,
            docSigningCertificate);
        Assert.NotNull(signedData);

        var baos = new MemoryStream();
        SignedDataUtil.WriteData(signedData, baos);
        byte[] serializedBytes = baos.ToArray();
        Assert.True(serializedBytes.Length > 0);

        SignedData parsedSignedData = SignedDataUtil.ReadSignedData(new MemoryStream(serializedBytes));
        Assert.NotNull(parsedSignedData);

        Assert.Equal("SHA-256", SignedDataUtil.GetSignerInfoDigestAlgorithm(parsedSignedData));
        Assert.Equal("SHA256withRSA", SignedDataUtil.GetDigestEncryptionAlgorithm(parsedSignedData));

        byte[] parsedEncryptedDigest = SignedDataUtil.GetEncryptedDigest(parsedSignedData);
        Assert.NotNull(parsedEncryptedDigest);
        Assert.True(parsedEncryptedDigest.Length > 0);

        List<X509Certificate> certificates = SignedDataUtil.GetCertificates(parsedSignedData);
        Assert.NotNull(certificates);
        Assert.Single(certificates);
        Assert.Equal(docSigningCertificate.SerialNumber, certificates[0].SerialNumber);

        Asn1Object? content = SignedDataUtil.GetContent(parsedSignedData);
        Assert.NotNull(content);
        Assert.IsAssignableFrom<Asn1OctetString>(content); // Java: DEROctetString
        Assert.Equal(testInner, content);

        Assert.NotNull(SignedDataUtil.GetIssuerAndSerialNumber(parsedSignedData));
    }
}
