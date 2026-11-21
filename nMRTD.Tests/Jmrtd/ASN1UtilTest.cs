using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;

namespace nMRTD.Tests.Jmrtd;

/// <summary>Port of JMRTD's <c>org.jmrtd.ASN1UtilTest</c>.</summary>
/// <remarks>
/// ADAPTATION: Java's <c>BERTags</c> constants are Bouncy Castle .NET's <c>Asn1Tags</c>;
/// <c>NumberFormatException</c> maps to <c>FormatException</c>.
/// </remarks>
public class ASN1UtilTest
{
    [Fact]
    public void testReadASN1Object()
    {
        byte[] sequenceBytes = new DerSequence(new DerInteger(42)).GetEncoded();
        var bais = new MemoryStream(sequenceBytes);
        Asn1Encodable obj = ASN1Util.ReadAsn1Object(bais);
        Assert.NotNull(obj);
        Assert.IsAssignableFrom<Asn1Object>(obj);
    }

    [Fact]
    public void testCheckTag()
    {
        var octets = new DerOctetString(new byte[] { 1, 2, 3 });
        var tagged = new DerTaggedObject(true, 1, octets);

        Asn1Encodable baseObject = ASN1Util.CheckTag(tagged, Asn1Tags.ContextSpecific, 1);
        Assert.NotNull(baseObject);
        Assert.IsType<DerOctetString>(baseObject);

        // mismatched tag class
        Assert.ThrowsAny<ArgumentException>(() => ASN1Util.CheckTag(tagged, Asn1Tags.Application, 1));

        // mismatched tag number
        Assert.ThrowsAny<ArgumentException>(() => ASN1Util.CheckTag(tagged, Asn1Tags.ContextSpecific, 2));

        // null object
        Assert.ThrowsAny<ArgumentException>(() => ASN1Util.CheckTag(null, Asn1Tags.ContextSpecific, 1));
    }

    [Fact]
    public void testIsSequenceOfSequences()
    {
        var inner1 = new DerSequence(new DerInteger(1));
        var inner2 = new DerSequence(new DerInteger(2));
        var outerSequence = new DerSequence(new Asn1Encodable[] { inner1, inner2 });
        Assert.True(ASN1Util.IsSequenceOfSequences(outerSequence));

        var invalidSequence = new DerSequence(new Asn1Encodable[] { inner1, DerBoolean.True });
        Assert.False(ASN1Util.IsSequenceOfSequences(invalidSequence));

        Assert.False(ASN1Util.IsSequenceOfSequences(DerBoolean.True));
    }

    [Fact]
    public void testDecodeTaggedObjects()
    {
        var octets1 = new DerOctetString(new byte[] { 1 });
        var octets2 = new DerOctetString(new byte[] { 2 });
        var tagged1 = new DerTaggedObject(true, 1, octets1);
        var tagged2 = new DerTaggedObject(true, 2, octets2);

        var sequenceOfTagged = new DerSequence(new Asn1Encodable[] { tagged1, tagged2 });
        Dictionary<int, Asn1Encodable> map = ASN1Util.DecodeTaggedObjects(sequenceOfTagged);
        Assert.NotNull(map);
        Assert.Equal(2, map.Count);
        Assert.True(map.ContainsKey(1));
        Assert.True(map.ContainsKey(2));

        Dictionary<int, Asn1Encodable> singleMap = ASN1Util.DecodeTaggedObjects(tagged1);
        Assert.NotNull(singleMap);
        Assert.Single(singleMap);
        Assert.True(singleMap.ContainsKey(1));
    }

    [Fact]
    public void testList()
    {
        var seq = new DerSequence(new Asn1Encodable[] { new DerInteger(1), new DerInteger(2) });
        List<Asn1Encodable>? list = ASN1Util.List(seq);
        Assert.NotNull(list);
        Assert.Equal(2, list.Count);
        Assert.Equal(new DerInteger(1), list[0]);
        Assert.Equal(new DerInteger(2), list[1]);

        var single = new DerInteger(42);
        List<Asn1Encodable>? listSingle = ASN1Util.List(single);
        Assert.NotNull(listSingle);
        Assert.Single(listSingle);
        Assert.Equal(single, listSingle[0]);

        List<Asn1Encodable>? listNull = ASN1Util.List(null);
        Assert.Null(listNull);
    }

    [Fact]
    public void testDecodeIntAndBigInteger()
    {
        byte[] bytes = [0x01, 0x02]; // 258
        var octets = new DerOctetString(bytes);

        Assert.Equal(258, ASN1Util.DecodeInt(octets));
        Assert.Equal(BigInteger.ValueOf(258), ASN1Util.DecodeBigInteger(octets));

        Assert.Throws<FormatException>(() => ASN1Util.DecodeInt(new DerInteger(1)));
        Assert.Throws<FormatException>(() => ASN1Util.DecodeBigInteger(new DerInteger(1)));
    }

    [Fact]
    public void testDecodeAndEncodeBoolean()
    {
        Asn1Encodable encTrue = ASN1Util.EncodeBoolean(true);
        Assert.True(ASN1Util.DecodeBoolean(encTrue));

        Asn1Encodable encFalse = ASN1Util.EncodeBoolean(false);
        Assert.False(ASN1Util.DecodeBoolean(encFalse));

        Assert.True(ASN1Util.DecodeBoolean(DerBoolean.True));
        Assert.False(ASN1Util.DecodeBoolean(DerBoolean.False));

        Assert.ThrowsAny<ArgumentException>(() => ASN1Util.DecodeBoolean(new DerInteger(1)));
    }

    [Fact]
    public void testEncodeIntAndBigInteger()
    {
        Asn1Encodable encInt = ASN1Util.EncodeInt(12345);
        Assert.Equal(BigInteger.ValueOf(12345), ASN1Util.DecodeBigInteger(encInt));

        Asn1Encodable encBig = ASN1Util.EncodeBigInteger(BigInteger.ValueOf(9876543210L));
        Assert.Equal(BigInteger.ValueOf(9876543210L), ASN1Util.DecodeBigInteger(encBig));
    }

    [Fact]
    public void testEncodeTaggedObjects()
    {
        var map = new Dictionary<int, Asn1Encodable>
        {
            [3] = new DerInteger(100),
            [4] = null!, // should be skipped
            [5] = new DerInteger(200),
        };

        Asn1Encodable? encoded = ASN1Util.EncodeTaggedObjects(map);
        Assert.NotNull(encoded);
        Assert.IsAssignableFrom<Asn1Sequence>(encoded); // Java: DERSequence

        Dictionary<int, Asn1Encodable> decoded = ASN1Util.DecodeTaggedObjects(encoded);
        Assert.Equal(2, decoded.Count);
        Assert.Equal(new DerInteger(100), decoded[3]);
        Assert.Equal(new DerInteger(200), decoded[5]);

        Assert.Null(ASN1Util.EncodeTaggedObjects(null));
    }
}
