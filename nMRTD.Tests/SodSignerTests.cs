using nMRTD.Lds;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace nMRTD.Tests;

/// <summary>
/// EF.SOD details that Passive Authentication depends on: a signer identified by subject key identifier
/// (the alternative to issuer and serial number in CMS), the algorithm name tables used to verify the
/// signature, and equality of SOD files.
/// </summary>
public class SodSignerTests
{
    private static readonly Dictionary<int, byte[]> DataGroupHashes = new()
    {
        [1] = DigestUtilities.CalculateDigest("SHA-256", "DG1 content"u8.ToArray()),
        [2] = DigestUtilities.CalculateDigest("SHA-256", "DG2 content"u8.ToArray()),
    };

    private static readonly byte[] SubjectKeyIdentifier = TestData.Hex("0102030405060708090A0B0C0D0E0F1011121314");

    private static byte[] SignedSod(IReadOnlyDictionary<int, byte[]> hashes) =>
        new SODFile("SHA-256", "SHA256withRSA", hashes, SigningFixtures.KeyPair.Private, SigningFixtures.Certificate).GetEncoded()!;

    /// <summary>The same SOD with its signer identified by subject key identifier instead of issuer and
    /// serial number. The signed attributes and the signature are unchanged.</summary>
    private static byte[] WithSubjectKeyIdentifier(byte[] sod)
    {
        var wrapper = (Asn1TaggedObject)Asn1Object.FromByteArray(sod);
        ContentInfo contentInfo = ContentInfo.GetInstance(wrapper.GetExplicitBaseObject());
        SignedData signedData = SignedData.GetInstance(contentInfo.Content);
        SignerInfo signerInfo = SignerInfo.GetInstance(signedData.SignerInfos[0]);
        var skiSignerInfo = new SignerInfo(
            new SignerIdentifier(new DerOctetString(SubjectKeyIdentifier)),
            signerInfo.DigestAlgorithm, signerInfo.SignedAttrs, signerInfo.SignatureAlgorithm,
            signerInfo.Signature, signerInfo.UnsignedAttrs);
        var skiSignedData = new SignedData(signedData.DigestAlgorithms, signedData.EncapContentInfo,
            signedData.Certificates, signedData.CRLs, new DerSet(skiSignerInfo));
        var skiContentInfo = new ContentInfo(contentInfo.ContentType, skiSignedData);
        return new DerTaggedObject(true, Asn1Tags.Application, 23, skiContentInfo).GetEncoded(Asn1Encodable.Der);
    }

    [Fact]
    public void SignerIdentifiedBySubjectKeyIdentifier()
    {
        var sod = new SODFile(new MemoryStream(WithSubjectKeyIdentifier(SignedSod(DataGroupHashes))));

        Assert.Equal(SubjectKeyIdentifier, sod.GetSubjectKeyIdentifier());
        Assert.Null(sod.GetIssuerName());
        Assert.Null(sod.GetSerialNumber());
        Assert.Equal(SigningFixtures.Certificate, sod.GetDocSigningCertificate());
        Assert.Equal(DataGroupHashes[1], sod.GetDataGroupHashes()[1]);

        byte[] eContent = sod.GetEContent();
        ISigner verifier = SignerUtilities.GetSigner(sod.GetDigestEncryptionAlgorithm()!);
        verifier.Init(false, sod.GetDocSigningCertificate()!.GetPublicKey());
        verifier.BlockUpdate(eContent, 0, eContent.Length);
        Assert.True(verifier.VerifySignature(sod.GetEncryptedDigest()));
    }

    [Fact]
    public void SignerIdentifiedByIssuerAndSerialNumberHasNoSubjectKeyIdentifier()
    {
        var sod = new SODFile(new MemoryStream(SignedSod(DataGroupHashes)));

        Assert.Null(sod.GetSubjectKeyIdentifier());
        Assert.NotNull(sod.GetIssuerName());
    }

    [Fact]
    public void EqualityFollowsTheEncoding()
    {
        byte[] encoded = SignedSod(DataGroupHashes);
        var sod = new SODFile(new MemoryStream(encoded));
        var same = new SODFile(new MemoryStream(encoded));
        var other = new SODFile(new MemoryStream(SignedSod(new Dictionary<int, byte[]> { [1] = DataGroupHashes[1], [2] = DataGroupHashes[1] })));

        Assert.Equal(sod, same);
        Assert.Equal(sod.GetHashCode(), same.GetHashCode());
        Assert.NotEqual(sod, other);
        Assert.False(sod.Equals(null));
        Assert.Contains("CN=Document Signer", sod.ToString());
    }

    /// <summary>Well-known object identifiers; a wrong entry would make signature verification pick the
    /// wrong algorithm.</summary>
    [Theory]
    [InlineData("SHA-1", "1.3.14.3.2.26")]
    [InlineData("SHA-224", "2.16.840.1.101.3.4.2.4")]
    [InlineData("SHA-256", "2.16.840.1.101.3.4.2.1")]
    [InlineData("SHA-384", "2.16.840.1.101.3.4.2.2")]
    [InlineData("SHA-512", "2.16.840.1.101.3.4.2.3")]
    [InlineData("RSA", "1.2.840.113549.1.1.1")]
    [InlineData("SHA1withRSA", "1.2.840.113549.1.1.5")]
    [InlineData("SHA224withRSA", "1.2.840.113549.1.1.14")]
    [InlineData("SHA256withRSA", "1.2.840.113549.1.1.11")]
    [InlineData("SHA384withRSA", "1.2.840.113549.1.1.12")]
    [InlineData("SHA512withRSA", "1.2.840.113549.1.1.13")]
    [InlineData("SHA1withECDSA", "1.2.840.10045.4.1")]
    [InlineData("SHA224withECDSA", "1.2.840.10045.4.3.1")]
    [InlineData("SHA256withECDSA", "1.2.840.10045.4.3.2")]
    [InlineData("SHA384withECDSA", "1.2.840.10045.4.3.3")]
    [InlineData("SHA512withECDSA", "1.2.840.10045.4.3.4")]
    [InlineData("SSAwithRSA/PSS", "1.2.840.113549.1.1.10")]
    [InlineData("MGF1", "1.2.840.113549.1.1.8")]
    [InlineData("CN", "2.5.4.3")]
    [InlineData("C", "2.5.4.6")]
    [InlineData("O", "2.5.4.10")]
    [InlineData("OU", "2.5.4.11")]
    [InlineData("ST", "2.5.4.8")]
    [InlineData("L", "2.5.4.7")]
    public void AlgorithmAndAttributeNamesMapToTheirObjectIdentifiers(string mnemonic, string oid)
    {
        Assert.Equal(oid, SignedDataUtil.LookupOidByMnemonic(mnemonic));
        Assert.Equal(mnemonic, SignedDataUtil.LookupMnemonicByOid(oid));
    }

    [Theory]
    [InlineData("SHA256", "SHA-256")]
    [InlineData("sha-256", "SHA-256")]
    [InlineData("RSASSA-PSS", "SSAwithRSA/PSS")]
    [InlineData("SAwithRSA/PSS", "SSAwithRSA/PSS")]
    public void AlternativeNamesMapToTheSameObjectIdentifier(string alias, string mnemonic)
    {
        Assert.Equal(SignedDataUtil.LookupOidByMnemonic(mnemonic), SignedDataUtil.LookupOidByMnemonic(alias));
    }

    [Fact]
    public void UnknownNamesAndObjectIdentifiersAreRejected()
    {
        Assert.Throws<NotSupportedException>(() => SignedDataUtil.LookupOidByMnemonic("SHA3-256"));
        Assert.Throws<NotSupportedException>(() => SignedDataUtil.LookupMnemonicByOid("1.2.3.4"));
    }
}
