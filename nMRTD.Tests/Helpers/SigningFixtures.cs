using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace nMRTD.Tests.Helpers;

/// <summary>A throwaway RSA document signer: key pair and self-signed certificate.</summary>
internal static class SigningFixtures
{
    private static readonly Lazy<(AsymmetricCipherKeyPair KeyPair, X509Certificate Certificate)> Signer = new(CreateSigner);

    public static AsymmetricCipherKeyPair KeyPair => Signer.Value.KeyPair;

    public static X509Certificate Certificate => Signer.Value.Certificate;

    private static (AsymmetricCipherKeyPair, X509Certificate) CreateSigner()
    {
        var generator = new RsaKeyPairGenerator();
        generator.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
        AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();

        var name = new X509Name("C=UT, O=nMRTD tests, CN=Document Signer");
        var certificateGenerator = new X509V3CertificateGenerator();
        certificateGenerator.SetSerialNumber(BigInteger.ValueOf(4242));
        certificateGenerator.SetIssuerDN(name);
        certificateGenerator.SetSubjectDN(name);
        certificateGenerator.SetNotBefore(new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        certificateGenerator.SetNotAfter(new DateTime(2036, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        certificateGenerator.SetPublicKey(keyPair.Public);
        X509Certificate certificate = certificateGenerator.Generate(new Asn1SignatureFactory("SHA256withRSA", keyPair.Private));
        return (keyPair, certificate);
    }
}
