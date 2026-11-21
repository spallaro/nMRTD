using nMRTD.Lds;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace nMRTD.Tests;

/// <summary>EF.SOD: the building blocks of Passive Authentication.</summary>
public class SodTests
{
    private static readonly Dictionary<int, byte[]> DataGroupHashes = new()
    {
        [1] = DigestUtilities.CalculateDigest("SHA-256", "DG1 content"u8.ToArray()),
        [2] = DigestUtilities.CalculateDigest("SHA-256", "DG2 content"u8.ToArray()),
        [14] = DigestUtilities.CalculateDigest("SHA-256", "DG14 content"u8.ToArray()),
    };

    private static SODFile ReadBack() =>
        new(new MemoryStream(new SODFile("SHA-256", "SHA256withRSA", DataGroupHashes,
            SigningFixtures.KeyPair.Private, SigningFixtures.Certificate).GetEncoded()!));

    private static bool SignatureIsValid(SODFile sod)
    {
        byte[] eContent = sod.GetEContent();
        ISigner verifier = SignerUtilities.GetSigner(sod.GetDigestEncryptionAlgorithm()!);
        verifier.Init(false, sod.GetDocSigningCertificate()!.GetPublicKey());
        verifier.BlockUpdate(eContent, 0, eContent.Length);
        return verifier.VerifySignature(sod.GetEncryptedDigest());
    }

    [Fact]
    public void SignedSodReadsBackWithItsHashesAlgorithmsAndSigner()
    {
        SODFile sod = ReadBack();

        Assert.Equal(DataGroupHashes.Keys, sod.GetDataGroupHashes().Keys);
        foreach ((int dg, byte[] hash) in DataGroupHashes)
        {
            Assert.Equal(hash, sod.GetDataGroupHashes()[dg]);
        }
        Assert.Equal("SHA-256", sod.GetDigestAlgorithm());
        Assert.Equal("SHA256withRSA", sod.GetDigestEncryptionAlgorithm());
        Assert.Equal(SigningFixtures.Certificate.IssuerDN, sod.GetIssuerName());
        Assert.Equal(SigningFixtures.Certificate.SerialNumber.ToString(), sod.GetSerialNumber()?.ToString());
        Assert.Equal(SigningFixtures.Certificate, sod.GetDocSigningCertificate());
    }

    [Fact]
    public void SignatureOverSignedAttributesVerifies()
    {
        Assert.True(SignatureIsValid(ReadBack()));
    }

    /// <summary>
    /// RSASSA-PSS with SHA-512 (as on Italian CIE 3.0 documents): the generic algorithm name plus the PSS
    /// parameters from the signer info are enough to verify the signature. Mirrors the CLI's verifier.
    /// </summary>
    [Fact]
    public void RsassaPssSignatureVerifiesWithTheParametersFromTheSod()
    {
        var sha512 = new Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier(Org.BouncyCastle.Asn1.Nist.NistObjectIdentifiers.IdSha512, Org.BouncyCastle.Asn1.DerNull.Instance);
        var pss = new Org.BouncyCastle.Asn1.Pkcs.RsassaPssParameters(sha512,
            new Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier(Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers.IdMgf1, sha512),
            new Org.BouncyCastle.Asn1.DerInteger(64), new Org.BouncyCastle.Asn1.DerInteger(1));
        byte[] encoded = new SODFile("SHA-512", "SSAwithRSA/PSS", pss, DataGroupHashes,
            SigningFixtures.KeyPair.Private, SigningFixtures.Certificate).GetEncoded()!;

        var sod = new SODFile(new MemoryStream(encoded));

        Assert.Equal("SSAwithRSA/PSS", sod.GetDigestEncryptionAlgorithm());
        var parameters = sod.GetDigestEncryptionAlgorithmParams();
        Assert.NotNull(parameters);
        Assert.Equal(64, parameters!.SaltLength.IntValueExact);
        // The generic name alone is not a BouncyCastle signer name; the parameters are needed.
        Assert.ThrowsAny<Exception>(() => SignerUtilities.GetSigner(sod.GetDigestEncryptionAlgorithm()!));

        var verifier = new Org.BouncyCastle.Crypto.Signers.PssSigner(new Org.BouncyCastle.Crypto.Engines.RsaBlindedEngine(),
            DigestUtilities.GetDigest(parameters.HashAlgorithm.Algorithm),
            DigestUtilities.GetDigest(Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier.GetInstance(parameters.MaskGenAlgorithm.Parameters).Algorithm),
            parameters.SaltLength.IntValueExact, Org.BouncyCastle.Crypto.Signers.PssSigner.TrailerImplicit);
        byte[] eContent = sod.GetEContent();
        verifier.Init(false, sod.GetDocSigningCertificate()!.GetPublicKey());
        verifier.BlockUpdate(eContent, 0, eContent.Length);
        Assert.True(verifier.VerifySignature(sod.GetEncryptedDigest()));
    }

    [Fact]
    public void TamperedDataGroupHashIsDetected()
    {
        byte[] encoded = new SODFile("SHA-256", "SHA256withRSA", DataGroupHashes,
            SigningFixtures.KeyPair.Private, SigningFixtures.Certificate).GetEncoded()!;
        int index = encoded.AsSpan().IndexOf(DataGroupHashes[2]);
        Assert.True(index >= 0);
        encoded[index] ^= 0x01;

        var sod = new SODFile(new MemoryStream(encoded));

        // The stored hash changed, so the eContent no longer matches the signed messageDigest attribute.
        Assert.Throws<IOException>(() => sod.GetEContent());
    }
}
