using nMRTD.Lds;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;

namespace nMRTD.Tests;

/// <summary>
/// The less common paths of <see cref="SignedDataUtil"/>: malformed or unusual signed data (no signed attributes,
/// unknown algorithms, RSASSA-PSS without or with malformed parameters, no or malformed signer info, no
/// certificates), and the helpers that are not used when reading a document.
/// </summary>
public class SignedDataUtilEdgeTests
{
    private const string ContentTypeOid = "1.2.3.4.5.6";

    private static readonly AsymmetricCipherKeyPair KeyPair = KeyPairs.Rsa(1024);

    private static readonly X509Certificate Certificate = CertificateUtil.CreateCertificate(
        "C=NL, O=JMRTD, CN=DocSigning", "C=NL, O=JMRTD, CN=DocSigning",
        DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(1), KeyPair.Public, KeyPair.Private, "SHA256withRSA");

    private static readonly ContentInfo Content = new(new DerObjectIdentifier(ContentTypeOid), new DerOctetString([0x04, 0x02, 0x10, 0x20]));

    [Fact]
    public void ContentThatIsNotASequenceIsRejected()
    {
        IOException e = Assert.Throws<IOException>(() => SignedDataUtil.ReadSignedData(new MemoryStream(new DerInteger(1).GetEncoded())));
        Assert.StartsWith("Was expecting a DER sequence, found DerInteger", e.Message);

        e = Assert.Throws<IOException>(() => SignedDataUtil.ReadSignedData(new MemoryStream([])));
        Assert.StartsWith("Was expecting a DER sequence, found no content", e.Message);
    }

    [Fact]
    public void ContentTypeThatIsNotAnObjectIdentifierIsRejected()
    {
        byte[] encoded = new DerSequence(new DerInteger(1), new DerTaggedObject(0, new DerSequence())).GetEncoded();

        IOException e = Assert.Throws<IOException>(() => SignedDataUtil.ReadSignedData(new MemoryStream(encoded)));

        Assert.StartsWith("Was expecting a content type OID", e.Message);
    }

    [Fact]
    public void UnknownAlgorithmsHaveNoName()
    {
        SignedData signedData = WithSignerInfo(SignerInfoWith(new AlgorithmIdentifier(new DerObjectIdentifier("1.2.3.4")),
            new AlgorithmIdentifier(new DerObjectIdentifier("1.2.3.5")), SignedAttributes()));

        Assert.Null(SignedDataUtil.GetSignerInfoDigestAlgorithm(signedData));
        Assert.Null(SignedDataUtil.GetDigestEncryptionAlgorithm(signedData));
    }

    [Fact]
    public void PssParametersThatAreAbsentOrMalformedAreNull()
    {
        var sha256 = new AlgorithmIdentifier(new DerObjectIdentifier(SignedDataUtil.LookupOidByMnemonic("SHA-256")));
        var pss = new DerObjectIdentifier(SignedDataUtil.Pkcs1RsaSsaPssOid);

        Assert.Null(SignedDataUtil.GetDigestEncryptionAlgorithmParams(WithSignerInfo(SignerInfoWith(sha256, new AlgorithmIdentifier(pss), SignedAttributes()))));
        Assert.Null(SignedDataUtil.GetDigestEncryptionAlgorithmParams(WithSignerInfo(SignerInfoWith(sha256, new AlgorithmIdentifier(pss, new DerInteger(1)), SignedAttributes()))));
    }

    [Fact]
    public void WithoutSignedAttributesTheContentIsWhatIsSigned()
    {
        var sha256 = new AlgorithmIdentifier(new DerObjectIdentifier(SignedDataUtil.LookupOidByMnemonic("SHA-256")));
        var rsa = new AlgorithmIdentifier(new DerObjectIdentifier(SignedDataUtil.LookupOidByMnemonic("SHA256withRSA")));

        byte[] eContent = SignedDataUtil.GetEContent(WithSignerInfo(SignerInfoWith(sha256, rsa, null)));

        Assert.Equal(((Asn1OctetString)Content.Content).GetOctets(), eContent);
    }

    [Fact]
    public void SignedAttributesWithAnUnknownDigestAlgorithmAreAnIOException()
    {
        var unknown = new AlgorithmIdentifier(new DerObjectIdentifier("1.2.3.4"));
        var rsa = new AlgorithmIdentifier(new DerObjectIdentifier(SignedDataUtil.LookupOidByMnemonic("SHA256withRSA")));

        IOException e = Assert.Throws<IOException>(() => SignedDataUtil.GetEContent(WithSignerInfo(SignerInfoWith(unknown, rsa, SignedAttributes()))));

        Assert.Equal("Error checking eContent", e.Message);
    }

    [Fact]
    public void MissingOrMalformedSignerInfoIsAnArgumentException()
    {
        ArgumentException e = Assert.Throws<ArgumentException>(() => SignedDataUtil.GetSignerInfo(WithSignerInfos(new DerSet())));
        Assert.StartsWith("No signer info", e.Message);

        // Not a sequence: BouncyCastle's own ArgumentException.
        Assert.ThrowsAny<ArgumentException>(() => SignedDataUtil.GetSignerInfo(WithSignerInfos(new DerSet(new DerInteger(1)))));

        // Signed attributes explicitly tagged instead of implicitly: BouncyCastle's InvalidOperationException becomes
        // an ArgumentException.
        var algorithm = new AlgorithmIdentifier(new DerObjectIdentifier("1.2.3"));
        var malformed = new DerSequence(new DerInteger(1), new SignerIdentifier(new DerOctetString([1, 2])), algorithm,
            new DerTaggedObject(true, 0, new DerInteger(5)), algorithm, new DerOctetString([1]));
        e = Assert.ThrowsAny<ArgumentException>(() => SignedDataUtil.GetSignerInfo(WithSignerInfos(new DerSet((Asn1Encodable)malformed))));
        Assert.StartsWith("Malformed signer info", e.Message);
    }

    [Fact]
    public void SignedDataWithoutCertificatesHasNone()
    {
        var signedData = new SignedData(new DerSet(), Content, null, null, new DerSet(SignerInfoWith(
            new AlgorithmIdentifier(new DerObjectIdentifier(SignedDataUtil.LookupOidByMnemonic("SHA-256"))),
            new AlgorithmIdentifier(new DerObjectIdentifier(SignedDataUtil.LookupOidByMnemonic("SHA256withRSA"))), SignedAttributes())));

        Assert.Empty(SignedDataUtil.GetCertificates(signedData));
    }

    [Fact]
    public void ObjectsAreReadFromAnOctetStringUntilTheFirstMalformedOne()
    {
        byte[] two = [.. new DerInteger(1).GetEncoded(), .. new DerInteger(2).GetEncoded()];
        Assert.Equal([new DerInteger(1), new DerInteger(2)], SignedDataUtil.GetObjectsFromOctetString(new DerOctetString(two)));

        byte[] truncated = [.. new DerInteger(1).GetEncoded(), 0x02, 0x05, 0x01];
        Assert.Equal([new DerInteger(1)], SignedDataUtil.GetObjectsFromOctetString(new DerOctetString(truncated)));
    }

    [Fact]
    public void SignerInfoWithoutPssParametersUsesTheIssuerAndSerialNumber()
    {
        SignerInfo signerInfo = SignedDataUtil.CreateSignerInfo("SHA-256", "SHA256withRSA", ContentTypeOid, Content, [0x01], Certificate);

        Assert.Equal(SignedDataUtil.LookupOidByMnemonic("SHA-256"), signerInfo.DigestAlgorithm.Algorithm.Id);
        Assert.Equal(Certificate.SerialNumber, IssuerAndSerialNumber.GetInstance(signerInfo.SignerID.ID).SerialNumber.Value);
    }

    /// <summary>"SHA256" without the hyphen is accepted too (JMRTD: "bug found by Paulo Assumpco").</summary>
    [Fact]
    public void AuthenticatedAttributesAcceptSha256WithoutHyphen() =>
        Assert.Equal(
            SignedDataUtil.CreateAuthenticatedAttributes("SHA-256", ContentTypeOid, Content).GetEncoded(),
            SignedDataUtil.CreateAuthenticatedAttributes("SHA256", ContentTypeOid, Content).GetEncoded());

    [Fact]
    public void SigningWithAnUnknownAlgorithmGivesNull() =>
        Assert.Null(SignedDataUtil.SignData("SHA-256", "NoSuchAlgorithm", ContentTypeOid, Content, KeyPair.Private));

    private static Asn1Set SignedAttributes() => SignedDataUtil.CreateAuthenticatedAttributes("SHA-256", ContentTypeOid, Content);

    private static SignerInfo SignerInfoWith(AlgorithmIdentifier digestAlgorithm, AlgorithmIdentifier signatureAlgorithm, Asn1Set? signedAttributes) =>
        new(new SignerIdentifier(new IssuerAndSerialNumber(Certificate.IssuerDN, Certificate.SerialNumber)),
            digestAlgorithm, signedAttributes, signatureAlgorithm, new DerOctetString([0x01, 0x02]), null);

    private static SignedData WithSignerInfo(SignerInfo signerInfo) => WithSignerInfos(new DerSet(signerInfo));

    private static SignedData WithSignerInfos(Asn1Set signerInfos) =>
        new(new DerSet(), Content, new DerSet(Certificate.CertificateStructure), null, signerInfos);
}
