using nMRTD.SmartCards;

namespace nMRTD.Tests.Scuba;

/// <summary>Port of SCUBA's <c>net.sf.scuba.tlv.TLVOutputStreamTest</c> (SCUBA 0.1.0, ebe3825): nested objects
/// written with explicit or zero lengths.</summary>
public class TLVOutputStreamTest
{
    [Fact]
    public void nested_valuesEndedWithWriteValueEnd()
    {
        Assert.Equal("61085F1F02AABB0401CC", Write(output =>
        {
            output.WriteTag(0x61);
            output.WriteTag(0x5F1F);
            output.WriteValue(Convert.FromHexString("AABB"));
            output.WriteTag(0x04);
            output.Write([0xCC]);
            output.WriteValueEnd();
            output.WriteValueEnd();
        }));
    }

    /// <summary>WriteValue after WriteLength used to set the length of the parent to that of the value.</summary>
    [Fact]
    public void nested_primitiveWithLengthWrittenFirst_keepsParentLength()
    {
        Assert.Equal("30070402AABB0401CC", Write(output =>
        {
            output.WriteTag(0x30);
            output.WriteTag(0x04);
            output.WriteLength(2);
            output.WriteValue(Convert.FromHexString("AABB"));
            output.WriteTag(0x04);
            output.WriteValue(Convert.FromHexString("CC"));
            output.WriteValueEnd();
        }));
    }

    [Fact]
    public void nested_primitiveWithLengthWrittenFirstInExplicitLengthParent()
    {
        Assert.Equal("300604000402AABB020105", Write(output =>
        {
            output.WriteTag(0x30);
            output.WriteLength(6);
            output.WriteTag(0x04);
            output.WriteLength(0);
            output.WriteValue([]);
            output.WriteTag(0x04);
            output.WriteLength(2);
            output.WriteValue(Convert.FromHexString("AABB"));
            output.WriteTag(0x02);
            output.WriteValue(Convert.FromHexString("05"));
        }));
    }

    /// <summary>An object written with WriteLength(0) used to stay open, so that siblings ended up inside it.</summary>
    [Fact]
    public void nested_emptyObjectWithLengthZero_isCompleted()
    {
        Assert.Equal("60065C005F0101AA", Write(output =>
        {
            output.WriteTag(0x60);
            output.WriteTag(0x5C);
            output.WriteLength(0);
            output.WriteTag(0x5F01);
            output.WriteValue(Convert.FromHexString("AA"));
            output.WriteValueEnd();
        }));
    }

    /// <summary>Like a COM file with an empty tag list, which used to write nothing.</summary>
    [Fact]
    public void nested_emptyLastObjectWithLengthZero_isCompleted()
    {
        Assert.Equal("60065F0101AA5C00", Write(output =>
        {
            output.WriteTag(0x60);
            output.WriteTag(0x5F01);
            output.WriteValue(Convert.FromHexString("AA"));
            output.WriteTag(0x5C);
            output.WriteLength(0);
            output.WriteValueEnd();
        }));
    }

    [Fact]
    public void nested_emptyConstructedObjectInExplicitLengthParent()
    {
        Assert.Equal("300231000401AA", Write(output =>
        {
            output.WriteTag(0x30);
            output.WriteLength(2);
            output.WriteTag(0x31);
            output.WriteLength(0);
            output.WriteTag(0x04);
            output.WriteValue(Convert.FromHexString("AA"));
        }));
    }

    [Fact]
    public void writeValueEnd_directlyAfterTag_writesEmptyValue()
    {
        Assert.Equal("30023100", Write(output =>
        {
            output.WriteTag(0x30);
            output.WriteTag(0x31);
            output.WriteValueEnd();
            output.WriteValueEnd();
        }));
    }

    [Fact]
    public void wrapDO_emptyValue()
    {
        Assert.Equal(Convert.FromHexString("0400"), TlvUtil.WrapDO(0x04, []));
        Assert.Equal(Convert.FromHexString("3000"), TlvUtil.WrapDO(0x30, []));
    }

    private static string Write(Action<TlvOutputStream> write)
    {
        var bytes = new MemoryStream();
        using (var output = new TlvOutputStream(bytes, leaveOpen: true))
        {
            write(output);
        }
        return Convert.ToHexString(bytes.ToArray());
    }
}
