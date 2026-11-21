using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;

namespace nMRTD.Tests.Helpers;

/// <summary>Port of JMRTD's test helper <c>org.jmrtd.CertificateUtil</c>.</summary>
internal static class CertificateUtil
{
    /// <summary>Generates an X.509 certificate with serial number 1.</summary>
    /// <param name="issuer">the issuer DN as a comma-separated list</param>
    /// <param name="subject">the subject DN as a comma-separated list</param>
    /// <param name="dateOfIssuing">the date of issuing</param>
    /// <param name="dateOfExpiry">the date of expiry</param>
    /// <param name="subjectPublicKey">the subject's public key</param>
    /// <param name="issuerPrivateKey">the issuer's private key</param>
    /// <param name="signatureAlgorithm">the signature algorithm to use in Java mnemonic notation</param>
    public static X509Certificate CreateCertificate(string issuer, string subject, DateTime dateOfIssuing, DateTime dateOfExpiry,
        AsymmetricKeyParameter subjectPublicKey, AsymmetricKeyParameter issuerPrivateKey, string signatureAlgorithm)
    {
        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(BigInteger.One);
        generator.SetIssuerDN(new X509Name(issuer));
        generator.SetSubjectDN(new X509Name(subject));
        generator.SetNotBefore(dateOfIssuing);
        generator.SetNotAfter(dateOfExpiry);
        generator.SetPublicKey(subjectPublicKey);
        return generator.Generate(new Asn1SignatureFactory(signatureAlgorithm, issuerPrivateKey));
    }
}
