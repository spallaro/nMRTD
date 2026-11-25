using nMRTD.SmartCards;

namespace nMRTD.Tests.Scuba;

/// <summary>
/// Port of SCUBA's <c>net.sf.scuba.tlv.TLVInputStreamTest</c> (SCUBA 0.1.0: 03bc03f, a04c2b1, 6d2c9f2, b96948f):
/// <see cref="TlvInputStream"/> on malformed input, lengths that are invalid or larger than the available data,
/// multi byte tags, and <see cref="TlvInputStream.SkipToTag"/>. Not ported, because nMRTD's reader keeps no state
/// about enclosing objects: the tests that expect an <see cref="IOException"/> for a nested tag, length or value that
/// does not fit in its parent, and the one that reads a constructed value byte by byte.
/// </summary>
public class TLVInputStreamTest
{
    /// <summary>The chunk size used when reading a value.</summary>
    private const int ChunkSize = 64 * 1024;

    [Fact]
    public void readValue_hugeLengthOnShortStream_throwsEOFException()
    {
        TlvInputStream input = NewStream("5F2E847FFFFFF000");
        Assert.Equal(0x5F2E, input.ReadTag());
        Assert.Equal(0x7FFFFFF0, input.ReadLength());
        Assert.Throws<EndOfStreamException>(() => input.ReadValue()); // not an OutOfMemoryException
    }

    [Fact]
    public void readValue_largeLengthWithoutValue_throwsEOFException()
    {
        TlvInputStream input = NewStream("5F2E8440000000");
        input.ReadTag();
        Assert.Equal(0x40000000, input.ReadLength());
        Assert.Throws<EndOfStreamException>(() => input.ReadValue());
    }

    [Fact]
    public void readValue_shortValue_throwsEOFException()
    {
        TlvInputStream input = NewStream("0405AABBCC");
        input.ReadTag();
        Assert.Equal(5, input.ReadLength());
        Assert.Throws<EndOfStreamException>(() => input.ReadValue());
    }

    [Fact]
    public void readValue_lengthAroundChunkSize_roundTrips()
    {
        foreach (int length in new[] { 0, 1, ChunkSize - 1, ChunkSize, ChunkSize + 1, (3 * ChunkSize) + 17 })
        {
            byte[] value = new byte[length];
            for (int i = 0; i < length; i++)
            {
                value[i] = (byte)i;
            }
            var input = new TlvInputStream(new MemoryStream(TlvUtil.WrapDO(0x04, value)));
            Assert.Equal(0x04, input.ReadTag());
            Assert.Equal(length, input.ReadLength());
            Assert.Equal(value, input.ReadValue());
        }
    }

    [Fact]
    public void readValue_valueLongerThanChunkFromSlowStream_readsAll()
    {
        byte[] value = Enumerable.Repeat((byte)0x5A, (2 * ChunkSize) + 5).ToArray();
        var input = new TlvInputStream(new SlowStream(TlvUtil.WrapDO(0x04, value)));
        input.ReadTag();
        input.ReadLength();
        Assert.Equal(value, input.ReadValue());
    }

    [Fact]
    public void readValue_nestedValues_updateParentState()
    {
        // 30 { 04 {AA BB} 04 {CC} }, value read in parts.
        TlvInputStream input = NewStream("30070402AABB0401CC");
        Assert.Equal(0x30, input.ReadTag());
        Assert.Equal(7, input.ReadLength());
        Assert.Equal(0x04, input.ReadTag());
        Assert.Equal(2, input.ReadLength());
        Assert.Equal(Convert.FromHexString("AABB"), input.ReadValue());
        Assert.Equal(0x04, input.ReadTag());
        Assert.Equal(1, input.ReadLength());
        Assert.Equal(Convert.FromHexString("CC"), input.ReadValue());
    }

    [Fact]
    public void readLength_moreThanFourSignificantLengthBytes_throwsIOException() =>
        AssertReadLengthThrowsIOException("5F2E850100000005AABBCCDDEE");

    [Fact]
    public void readLength_leadingZeroLengthBytes_areAccepted()
    {
        TlvInputStream input = NewStream("5F2E850000000005AABBCCDDEE");
        input.ReadTag();
        Assert.Equal(5, input.ReadLength());
        Assert.Equal(Convert.FromHexString("AABBCCDDEE"), input.ReadValue());
    }

    [Fact]
    public void readLength_negativeLength_throwsIOException()
    {
        AssertReadLengthThrowsIOException("5F2E84FFFFFFFF00");
        AssertReadLengthThrowsIOException("5F2E8480000000");
    }

    [Fact]
    public void readLength_indefiniteLength_throwsIOException() =>
        AssertReadLengthThrowsIOException("5F2E80AABB0000");

    [Fact]
    public void readLength_maxLength_isAccepted()
    {
        TlvInputStream input = NewStream("04847FFFFFFF");
        input.ReadTag();
        Assert.Equal(int.MaxValue, input.ReadLength());
    }

    [Fact]
    public void skipToTag_nestedTag_isFound()
    {
        // 61 { 5F01 {AA BB} 5F1F {CC DD} }
        TlvInputStream input = NewStream("610A5F0102AABB5F1F02CCDD");
        input.SkipToTag(0x5F1F);
        Assert.Equal(2, input.ReadLength());
        Assert.Equal(Convert.FromHexString("CCDD"), input.ReadValue());
    }

    [Fact]
    public void skipToTag_truncatedValueBeforeTag_throwsEOFException()
    {
        // 61 { 57 with length 0x1F but only 3 value bytes }, no 5F1F.
        TlvInputStream input = NewStream("6121571FAABBCC");
        Assert.Throws<EndOfStreamException>(() => input.SkipToTag(0x5F1F));
    }

    [Fact]
    public void skipToTag_tagMissing_throwsEOFException()
    {
        TlvInputStream input = NewStream("610A5F0102AABB5F0202CCDD");
        Assert.Throws<EndOfStreamException>(() => input.SkipToTag(0x5F1F));
    }

    [Fact]
    public void readTag_afterEmptyConstructedObject_isSibling()
    {
        // 30 {} 04 {AA}
        TlvInputStream input = NewStream("30000401AA");
        Assert.Equal(0x30, input.ReadTag());
        Assert.Equal(0, input.ReadLength());
        Assert.Equal(0x04, input.ReadTag());
        Assert.Equal(1, input.ReadLength());
        Assert.Equal(Convert.FromHexString("AA"), input.ReadValue());
    }

    [Fact]
    public void readTag_chainCompletedByEmptyInnermostObject_nextTagIsSibling()
    {
        // F1 { F1 { F1 { F1 { F1 {} } } } } 04 {AA}
        TlvInputStream input = NewStream("F108F106F104F102F1000401AA");
        for (int length = 8; length >= 0; length -= 2)
        {
            Assert.Equal(0xF1, input.ReadTag());
            Assert.Equal(length, input.ReadLength());
        }
        Assert.Equal(0x04, input.ReadTag());
        Assert.Equal(1, input.ReadLength());
        Assert.Equal(Convert.FromHexString("AA"), input.ReadValue());
    }

    [Fact]
    public void skipToTag_afterEmptyConstructedObject_findsSibling()
    {
        TlvInputStream input = NewStream("3000310004020102");
        input.SkipToTag(0x04);
        Assert.Equal(2, input.ReadLength());
        Assert.Equal(Convert.FromHexString("0102"), input.ReadValue());
    }

    [Fact]
    public void readTag_threeByteTagWithContinuationByte_keepsAllBits()
    {
        // 5F 81 01: the middle byte has the "more bytes follow" bit set.
        TlvInputStream input = NewStream("5F810101AA");
        Assert.Equal(0x5F8101, input.ReadTag());
        Assert.Equal(1, input.ReadLength());
        Assert.Equal(Convert.FromHexString("AA"), input.ReadValue());
    }

    [Theory]
    [InlineData("5F1F")]
    [InlineData("7F61")]
    [InlineData("5F8101")]
    [InlineData("5FFF4A")]
    [InlineData("9F818101")]
    [InlineData("DFFFFF7F")]
    public void readTag_multiByteTags_roundTripThroughWrapDO(string tagHex)
    {
        byte[] encoded = Convert.FromHexString(tagHex + "01AA");
        int tag = NewStream(tagHex + "01AA").ReadTag();
        Assert.Equal(encoded, TlvUtil.WrapDO(tag, Convert.FromHexString("AA")));
        Assert.Equal(Convert.FromHexString("AA"), TlvUtil.UnwrapDO(tag, encoded));
    }

    [Fact]
    public void readTag_moreThanFourTagBytes_throwsIOException()
    {
        TlvInputStream input = NewStream("5F8080800101AA");
        var e = Assert.ThrowsAny<IOException>(() => input.ReadTag());
        Assert.IsNotType<EndOfStreamException>(e); // the leading bytes used to be shifted out, giving a wrong tag
    }

    private static void AssertReadLengthThrowsIOException(string hex)
    {
        TlvInputStream input = NewStream(hex);
        input.ReadTag();
        Assert.ThrowsAny<IOException>(() => input.ReadLength());
    }

    private static TlvInputStream NewStream(string hex) => new(new MemoryStream(Convert.FromHexString(hex)));

    /// <summary>A stream that returns at most 1000 bytes per read.</summary>
    private sealed class SlowStream(byte[] bytes) : MemoryStream(bytes)
    {
        public override int Read(byte[] buffer, int offset, int count) => base.Read(buffer, offset, Math.Min(count, 1000));
    }
}
