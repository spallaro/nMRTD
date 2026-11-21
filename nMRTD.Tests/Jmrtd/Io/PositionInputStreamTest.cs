using nMRTD.Io;

namespace nMRTD.Tests.Jmrtd.Io;

/// <summary>Port of JMRTD's <c>org.jmrtd.io.PositionInputStreamTest</c>.</summary>
/// <remarks>ADAPTATION: Java's <c>read(byte[])</c> returns -1 at end of stream, .NET's <c>Read</c> returns 0.</remarks>
public class PositionInputStreamTest
{
    [Fact]
    public void testBasicReadingAndPosition()
    {
        byte[] data = [0x10, 0x20, 0x30, 0x40, 0x50];
        var bais = new MemoryStream(data);
        var pis = new PositionInputStream(bais);

        Assert.Equal(0L, pis.Position);

        Assert.Equal(0x10, pis.ReadByte());
        Assert.Equal(1L, pis.Position);

        var buf = new byte[2];
        int read = pis.Read(buf, 0, buf.Length);
        Assert.Equal(2, read);
        Assert.Equal(0x20, buf[0]);
        Assert.Equal(0x30, buf[1]);
        Assert.Equal(3L, pis.Position);

        long skipped = pis.Skip(1);
        Assert.Equal(1L, skipped);
        Assert.Equal(4L, pis.Position);

        Assert.Equal(0x50, pis.ReadByte());
        Assert.Equal(5L, pis.Position);

        // EOF reads should not decrement the position!
        Assert.Equal(-1, pis.ReadByte());
        Assert.Equal(5L, pis.Position);

        read = pis.Read(buf, 0, buf.Length);
        Assert.Equal(0, read); // Java: -1
        Assert.Equal(5L, pis.Position);

        read = pis.Read(buf, 0, 1);
        Assert.Equal(0, read); // Java: -1
        Assert.Equal(5L, pis.Position);
    }

    [Fact]
    public void testMarkAndReset()
    {
        byte[] data = [1, 2, 3, 4, 5];
        var bais = new MemoryStream(data);
        var pis = new PositionInputStream(bais);

        Assert.True(pis.MarkSupported);

        pis.ReadByte(); // pos 1
        pis.ReadByte(); // pos 2
        Assert.Equal(2L, pis.Position);

        pis.Mark(10);
        pis.ReadByte(); // pos 3
        pis.ReadByte(); // pos 4
        Assert.Equal(4L, pis.Position);

        pis.Reset();
        Assert.Equal(2L, pis.Position);
        Assert.Equal(3, pis.ReadByte());
        Assert.Equal(3L, pis.Position);
    }
}
