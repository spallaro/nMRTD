using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Icao;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace nMRTD.Tests.Helpers;

/// <summary>
/// A throwaway passive authentication PKI built at run time (no certificate files in the repository):
/// Country Signing CAs and Document Signer certificates issued by them, and ICAO CSCA master lists.
/// </summary>
internal static class TestPki
{
    public sealed record Issuer(AsymmetricCipherKeyPair KeyPair, X509Certificate Certificate);

    private static readonly SecureRandom Random = new();
    private static long serial = 1000;

    public static readonly DateTime Now = DateTime.UtcNow;

    public static AsymmetricCipherKeyPair Rsa(int bits = 2048)
    {
        var generator = new RsaKeyPairGenerator();
        generator.Init(new KeyGenerationParameters(Random, bits));
        return generator.GenerateKeyPair();
    }

    public static AsymmetricCipherKeyPair Ec() => SimulatedDocument.GenerateEc(13); // brainpoolP256r1

    /// <summary>A self-signed CSCA certificate with a subject key identifier.</summary>
    public static Issuer Csca(string subject, AsymmetricCipherKeyPair keyPair, string signatureAlgorithm = "SHA256WITHRSA",
        DateTime? notBefore = null, DateTime? notAfter = null)
    {
        var name = new X509Name(subject);
        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(BigInteger.ValueOf(Interlocked.Increment(ref serial)));
        generator.SetIssuerDN(name);
        generator.SetSubjectDN(name);
        generator.SetNotBefore(notBefore ?? Now.AddYears(-5));
        generator.SetNotAfter(notAfter ?? Now.AddYears(10));
        generator.SetPublicKey(keyPair.Public);
        generator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(0));
        generator.AddExtension(X509Extensions.SubjectKeyIdentifier, false, X509ExtensionUtilities.CreateSubjectKeyIdentifier(keyPair.Public));
        return new Issuer(keyPair, generator.Generate(new Asn1SignatureFactory(signatureAlgorithm, keyPair.Private)));
    }

    /// <summary>A Document Signer certificate issued by <paramref name="csca"/>, with an authority key identifier.</summary>
    public static X509Certificate DocumentSigner(Issuer csca, AsymmetricKeyParameter publicKey, string signatureAlgorithm = "SHA256WITHRSA",
        DateTime? notBefore = null, DateTime? notAfter = null, bool authorityKeyId = true)
    {
        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(BigInteger.ValueOf(Interlocked.Increment(ref serial)));
        generator.SetIssuerDN(csca.Certificate.SubjectDN);
        generator.SetSubjectDN(new X509Name("C=UT, O=Utopia, CN=Document Signer " + serial));
        generator.SetNotBefore(notBefore ?? Now.AddMonths(-1));
        generator.SetNotAfter(notAfter ?? Now.AddYears(5));
        generator.SetPublicKey(publicKey);
        if (authorityKeyId)
        {
            generator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, X509ExtensionUtilities.CreateAuthorityKeyIdentifier(csca.KeyPair.Public));
        }
        return generator.Generate(new Asn1SignatureFactory(signatureAlgorithm, csca.KeyPair.Private));
    }

    /// <summary>An ICAO CSCA master list (CMS SignedData with content type id-icao-cscaMasterList). It carries
    /// no signer: the trust store does not check the signature of a master list.</summary>
    public static byte[] MasterList(params X509Certificate[] certificates)
    {
        var list = new CscaMasterList(certificates.Select(c => c.CertificateStructure).ToArray());
        var content = new ContentInfo(IcaoObjectIdentifiers.IdIcaoCscaMasterList, new DerOctetString(list.GetEncoded(Asn1Encodable.Der)));
        var signedData = new SignedData(new DerSet(), content, null, null, new DerSet());
        return new ContentInfo(CmsObjectIdentifiers.SignedData, signedData).GetEncoded(Asn1Encodable.Der);
    }
}
