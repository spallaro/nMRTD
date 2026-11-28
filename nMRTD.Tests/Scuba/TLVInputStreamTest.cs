using nMRTD.SmartCards;

namespace nMRTD.Tests.Scuba;

/// <summary>
/// Port of SCUBA's <c>net.sf.scuba.tlv.TLVInputStreamTest</c> (SCUBA 0.1.0: 03bc03f, a04c2b1, 6d2c9f2, b96948f):
/// <see cref="TlvInputStream"/> on malformed input, lengths that are invalid or larger than the available data,
/// nested tags, lengths and values that do not fit in their parent, multi byte tags, and
/// <see cref="TlvInputStream.SkipToTag"/>. Not ported: <c>skipToTag_carrierSkipsNothing_stillFindsTag</c>, because
/// nMRTD skips by reading. The tests after those of SCUBA cover what is particular to nMRTD's reader, which works with
/// the position of the wrapped stream.
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

    [Fact]
    public void readLength_nestedValueLongerThanParent_throwsIOException()
    {
        // 30 with length 3, containing 04 with length 5.
        TlvInputStream input = NewStream("30030405AABBCCDDEE");
        input.ReadTag();
        input.ReadLength();
        input.ReadTag();
        AssertNestingError(() => input.ReadLength()); // before reading the value
    }

    [Fact]
    public void readLength_hugeNestedLength_throwsIOExceptionBeforeReading()
    {
        TlvInputStream input = NewStream("300604847FFFFFF0");
        input.ReadTag();
        input.ReadLength();
        input.ReadTag();
        AssertNestingError(() => input.ReadLength());
    }

    [Fact]
    public void readLength_nestedLengthBytesBeyondParent_throwsIOException()
    {
        // 30 with length 2, containing 04 with a 2 byte length (82 00 00) that ends outside 30.
        TlvInputStream input = NewStream("3002048200000000");
        input.ReadTag();
        input.ReadLength();
        input.ReadTag();
        AssertNestingError(() => input.ReadLength());
    }

    [Fact]
    public void readTag_nestedTagBeyondParent_throwsIOException()
    {
        // 30 with length 1, containing the 2 byte tag 5F1F.
        TlvInputStream input = NewStream("30015F1F01AA");
        input.ReadTag();
        input.ReadLength();
        AssertNestingError(() => input.ReadTag());
    }

    [Fact]
    public void readTag_emptyObjectsCompletingParent_nextTagIsSibling()
    {
        // 31 { 30 {} 04 {} } 02 {05}: the empty 04 completes 31.
        TlvInputStream input = NewStream("310430000400020105");
        Assert.Equal(0x31, input.ReadTag());
        Assert.Equal(4, input.ReadLength());
        Assert.Equal(0x30, input.ReadTag());
        Assert.Equal(0, input.ReadLength());
        Assert.Equal(0x04, input.ReadTag());
        Assert.Equal(0, input.ReadLength());
        Assert.Empty(input.ReadValue());
        Assert.Equal(0x02, input.ReadTag());
        Assert.Equal(1, input.ReadLength());
        Assert.Equal(Convert.FromHexString("05"), input.ReadValue());
    }

    [Fact]
    public void readTag_emptyObjectCompletingLastChild_nextTagIsSiblingOfParent()
    {
        // 30 { 04 {AA} 31 { 32 {} } } 02 {05}
        TlvInputStream input = NewStream("30070401AA31023200020105");
        Assert.Equal(0x30, input.ReadTag());
        Assert.Equal(7, input.ReadLength());
        Assert.Equal(0x04, input.ReadTag());
        Assert.Equal(1, input.ReadLength());
        Assert.Equal(Convert.FromHexString("AA"), input.ReadValue());
        Assert.Equal(0x31, input.ReadTag());
        Assert.Equal(2, input.ReadLength());
        Assert.Equal(0x32, input.ReadTag());
        Assert.Equal(0, input.ReadLength());
        Assert.Equal(0x02, input.ReadTag());
        Assert.Equal(1, input.ReadLength());
        Assert.Equal(Convert.FromHexString("05"), input.ReadValue());
    }

    [Fact]
    public void read_constructedValueByteByByte_followedBySibling()
    {
        // 30 {04 01 AA} read as raw bytes from the wrapped stream (SCUBA reads them through its stream), then
        // sibling 04 {BB}.
        var stream = new MemoryStream(Convert.FromHexString("30030401AA0401BB"));
        var input = new TlvInputStream(stream);
        input.ReadTag();
        Assert.Equal(3, input.ReadLength());
        for (int i = 0; i < 3; i++)
        {
            stream.ReadByte();
        }
        Assert.Equal(0x04, input.ReadTag());
        Assert.Equal(1, input.ReadLength());
        Assert.Equal(Convert.FromHexString("BB"), input.ReadValue());
    }

    // nMRTD only: the check works with the position of the wrapped stream.

    [Fact]
    public void readTag_childrenReadByAnotherReader_nextTagIsSibling()
    {
        // 30 { 04 {AA} 04 {BB} } 02 {05}: the decoders read a value with another reader over the same stream.
        var stream = new MemoryStream(Convert.FromHexString("30060401AA0401BB020105"));
        var outer = new TlvInputStream(stream, leaveOpen: true);
        Assert.Equal(0x30, outer.ReadTag());
        Assert.Equal(6, outer.ReadLength());
        var inner = new TlvInputStream(stream, leaveOpen: true);
        for (int i = 0; i < 2; i++)
        {
            Assert.Equal(0x04, inner.ReadTag());
            Assert.Equal(1, inner.ReadLength());
            inner.ReadValue();
        }
        Assert.Equal(0x02, outer.ReadTag());
        Assert.Equal(1, outer.ReadLength());
        Assert.Equal(Convert.FromHexString("05"), outer.ReadValue());
    }

    [Fact]
    public void readLength_nestedValueLongerThanParent_positionOnlyStream_throwsIOException()
    {
        // A forward-only stream that reports its position, as CardFileInputStream does.
        var stream = new nMRTD.Io.PositionInputStream(new ForwardOnlyStream(Convert.FromHexString("30030405AABBCCDDEE")));
        var input = new TlvInputStream(stream);
        input.ReadTag();
        input.ReadLength();
        input.ReadTag();
        AssertNestingError(() => input.ReadLength());
    }

    [Fact]
    public void readLength_nestedValueLongerThanParent_streamWithoutPosition_isNotChecked()
    {
        var input = new TlvInputStream(new ForwardOnlyStream(Convert.FromHexString("30030405AABBCCDDEE")));
        input.ReadTag();
        input.ReadLength();
        input.ReadTag();
        Assert.Equal(5, input.ReadLength());
        Assert.Equal(Convert.FromHexString("AABBCCDDEE"), input.ReadValue());
    }

    [Fact]
    public void readTag_afterRewindingBeforeParent_readsAgain()
    {
        // 30 { 04 {AA} }, read, rewound to the start and read again.
        var stream = new MemoryStream(Convert.FromHexString("30030401AA"));
        var input = new TlvInputStream(stream);
        for (int pass = 0; pass < 2; pass++)
        {
            stream.Position = 0;
            Assert.Equal(0x30, input.ReadTag());
            Assert.Equal(3, input.ReadLength());
            Assert.Equal(0x04, input.ReadTag());
            Assert.Equal(1, input.ReadLength());
            Assert.Equal(Convert.FromHexString("AA"), input.ReadValue());
        }
    }

    [Fact]
    public void readTag_afterRewindingIntoParent_isStillChecked()
    {
        // 30 with length 3, containing 04 {AA}; rewound into the value of 30 and read as 04 with length 5.
        var stream = new MemoryStream(Convert.FromHexString("30030401AA"));
        var input = new TlvInputStream(stream);
        input.ReadTag();
        input.ReadLength();
        input.ReadTag();
        input.ReadLength();
        input.ReadValue();
        stream.Position = 2;
        stream.Write([0x04, 0x05], 0, 2);
        stream.Position = 2;
        input.ReadTag();
        AssertNestingError(() => input.ReadLength());
    }

    private static void AssertNestingError(Func<int> read)
    {
        IOException e = Assert.ThrowsAny<IOException>(() => read());
        Assert.IsNotType<EndOfStreamException>(e);
        Assert.Contains("does not fit in the remaining", e.Message);
    }

    private static void AssertReadLengthThrowsIOException(string hex)
    {
        TlvInputStream input = NewStream(hex);
        input.ReadTag();
        Assert.ThrowsAny<IOException>(() => input.ReadLength());
    }

    private static TlvInputStream NewStream(string hex) => new(new MemoryStream(Convert.FromHexString(hex)));

    /// <summary>A stream that can only be read forward and does not report its position.</summary>
    private sealed class ForwardOnlyStream(byte[] bytes) : MemoryStream(bytes)
    {
        public override bool CanSeek => false;

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }
    }

    /// <summary>A stream that returns at most 1000 bytes per read.</summary>
    private sealed class SlowStream(byte[] bytes) : MemoryStream(bytes)
    {
        public override int Read(byte[] buffer, int offset, int count) => base.Read(buffer, offset, Math.Min(count, 1000));
    }
}
