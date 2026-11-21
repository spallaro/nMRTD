using nMRTD.Cbeff;

namespace nMRTD.Tests.Jmrtd.Cbeff;

/// <summary>Port of JMRTD's <c>org.jmrtd.cbeff.ISO781611CodecTest</c>.</summary>
/// <remarks>
/// ADAPTATION: nMRTD's <c>ISO781611Encoder.Encode</c> takes a <c>ComplexCBEFFInfo</c> only. JMRTD encodes
/// a <c>SimpleCBEFFInfo</c> as a BIT group holding that single record, so the simple record is wrapped in
/// a one-record group, which gives the same bytes.
/// </remarks>
public class ISO781611CodecTest
{
    [Fact]
    public void roundTripsMultipleBiometricInformationTemplates()
    {
        StandardBiometricHeader firstHeader = CreateHeader(0x01);
        StandardBiometricHeader secondHeader = CreateHeader(0x02);
        var first = new TestBiometricDataBlock(firstHeader, [0x11, 0x12]);
        var second = new TestBiometricDataBlock(secondHeader, [0x21, 0x22, 0x23]);
        var group = new ComplexCBEFFInfo<TestBiometricDataBlock>();
        group.Add(new SimpleCBEFFInfo<TestBiometricDataBlock>(first));
        group.Add(new SimpleCBEFFInfo<TestBiometricDataBlock>(second));

        var outputStream = new MemoryStream();
        new ISO781611Encoder<TestBiometricDataBlock>(new TestEncoder(BiometricEncodingType.Iso19794)).Encode(group, outputStream);
        var decoder = new RecordingDecoder();
        var containerDecoder = new ISO781611Decoder<TestBiometricDataBlock>(decoder);

        ComplexCBEFFInfo<TestBiometricDataBlock> decoded = containerDecoder.Decode(new MemoryStream(outputStream.ToArray()));

        List<CBEFFInfo<TestBiometricDataBlock>> records = decoded.GetSubRecords();
        Assert.Equal(2, records.Count);
        AssertBlock(records[0], firstHeader, first.GetPayload());
        AssertBlock(records[1], secondHeader, second.GetPayload());
        Assert.Equal(2, decoder.GetDecodeCount());
        Assert.Equal(BiometricEncodingType.Iso19794, containerDecoder.GetEncodingType());
    }

    [Fact]
    public void selectsDecoderUsingBiometricDataBlockTag()
    {
        var block = new TestBiometricDataBlock(CreateHeader(0x03), [0x31]);
        var outputStream = new MemoryStream();
        var single = new ComplexCBEFFInfo<TestBiometricDataBlock>(); // Java: encodes the SimpleCBEFFInfo directly
        single.Add(new SimpleCBEFFInfo<TestBiometricDataBlock>(block));
        new ISO781611Encoder<TestBiometricDataBlock>(new TestEncoder(BiometricEncodingType.Iso39794)).Encode(single, outputStream);

        var primitiveDecoder = new RecordingDecoder();
        var constructedDecoder = new RecordingDecoder();
        var decoders = new Dictionary<int, BiometricDataBlockDecoder<TestBiometricDataBlock>>
        {
            [ISO781611.BIOMETRIC_DATA_BLOCK_TAG] = primitiveDecoder,
            [ISO781611.BIOMETRIC_DATA_BLOCK_CONSTRUCTED_TAG] = constructedDecoder,
        };
        var decoder = new ISO781611Decoder<TestBiometricDataBlock>(decoders);

        decoder.Decode(new MemoryStream(outputStream.ToArray()));

        Assert.Equal(0, primitiveDecoder.GetDecodeCount());
        Assert.Equal(1, constructedDecoder.GetDecodeCount());
        Assert.Equal(BiometricEncodingType.Iso39794, decoder.GetEncodingType());
    }

    [Fact]
    public void rejectsMalformedGroupAndCountTags()
    {
        var decoder = new ISO781611Decoder<TestBiometricDataBlock>(new RecordingDecoder());

        Assert.ThrowsAny<ArgumentException>(() => decoder.Decode(new MemoryStream([0x7F, 0x62, 0x00])));
        Assert.ThrowsAny<ArgumentException>(() => decoder.Decode(new MemoryStream([0x7F, 0x61, 0x04, 0x02, 0x02, 0x01, 0x00])));
    }

    private static StandardBiometricHeader CreateHeader(byte subtype)
    {
        var elements = new Dictionary<int, byte[]>
        {
            [ISO781611.BIOMETRIC_TYPE_TAG] = [0x02],
            [ISO781611.BIOMETRIC_SUBTYPE_TAG] = [subtype],
        };
        return new StandardBiometricHeader(elements);
    }

    private static void AssertBlock(CBEFFInfo<TestBiometricDataBlock> info, StandardBiometricHeader expectedHeader, byte[] expectedPayload)
    {
        TestBiometricDataBlock block = ((SimpleCBEFFInfo<TestBiometricDataBlock>)info).GetBiometricDataBlock();
        Assert.Equal(expectedHeader, block.GetStandardBiometricHeader());
        Assert.Equal(expectedPayload, block.GetPayload());
    }

    private sealed class TestEncoder(BiometricEncodingType encodingType) : BiometricDataBlockEncoder<TestBiometricDataBlock>
    {
        public void Encode(TestBiometricDataBlock bdb, Stream outputStream)
        {
            byte[] payload = bdb.GetPayload();
            outputStream.Write(payload, 0, payload.Length);
        }

        public BiometricEncodingType GetEncodingType() => encodingType;
    }

    private sealed class RecordingDecoder : BiometricDataBlockDecoder<TestBiometricDataBlock>
    {
        private int _decodeCount;

        public TestBiometricDataBlock Decode(Stream inputStream, StandardBiometricHeader sbh, int index, int length)
        {
            var payload = new byte[length];
            int offset = 0;
            while (offset < payload.Length)
            {
                int count = inputStream.Read(payload, offset, payload.Length - offset);
                if (count <= 0)
                {
                    throw new IOException("Unexpected end of biometric data block");
                }
                offset += count;
            }
            Assert.Equal(_decodeCount, index);
            _decodeCount++;
            return new TestBiometricDataBlock(sbh, payload);
        }

        public int GetDecodeCount() => _decodeCount;
    }

    private sealed class TestBiometricDataBlock(StandardBiometricHeader header, byte[] payload) : BiometricDataBlock
    {
        private readonly byte[] _payload = (byte[])payload.Clone();

        public StandardBiometricHeader GetStandardBiometricHeader() => header;

        public byte[] GetPayload() => (byte[])_payload.Clone();
    }
}
