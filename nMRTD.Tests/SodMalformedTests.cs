using nMRTD.Lds;
using Org.BouncyCastle.Asn1;

namespace nMRTD.Tests;

/// <summary>EF.SOD content that is not CMS signed data is rejected with a clear error.</summary>
public class SodMalformedTests
{
    private static readonly DerObjectIdentifier SignedDataOid = new(SignedDataUtil.Rfc3369SignedDataOid);

    public static TheoryData<string, byte[]> Malformed => new()
    {
        { "Was expecting a DER sequence of length 2", new DerSequence(SignedDataOid).GetEncoded() },
        { "Was expecting signed-data content type OID", new DerSequence(new DerObjectIdentifier("1.2.840.113549.1.7.1"), new DerTaggedObject(0, new DerSequence())).GetEncoded() },
        { "Was expecting an Asn1TaggedObject", new DerSequence(SignedDataOid, new DerSequence()).GetEncoded() },
        { "Was expecting CONTEXT_SPECIFIC tag class", new DerSequence(SignedDataOid, new DerTaggedObject(true, Asn1Tags.Application, 0, new DerSequence())).GetEncoded() },
        { "Was expecting tag 0", new DerSequence(SignedDataOid, new DerTaggedObject(1, new DerSequence())).GetEncoded() },
        { "Was expecting an ASN.1 sequence as content", new DerSequence(SignedDataOid, new DerTaggedObject(0, new DerInteger(1))).GetEncoded() },
    };

    [Theory]
    [MemberData(nameof(Malformed))]
    public void MalformedSignedDataIsRejected(string message, byte[] encoded)
    {
        IOException e = Assert.Throws<IOException>(() => SignedDataUtil.ReadSignedData(new MemoryStream(encoded)));

        Assert.StartsWith(message, e.Message);
    }
}
