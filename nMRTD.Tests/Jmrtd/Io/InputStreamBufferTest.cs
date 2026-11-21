using nMRTD.Io;

namespace nMRTD.Tests.Jmrtd.Io;

/// <summary>Port of JMRTD's <c>org.jmrtd.io.InputStreamBufferTest</c>.</summary>
/// <remarks>
/// ADAPTATION: Java's <c>read(byte[])</c> returns -1 at end of stream, .NET's <c>Read</c> returns 0;
/// Java's NullPointerException and IndexOutOfBoundsException map to ArgumentNullException and
/// ArgumentOutOfRangeException.
/// </remarks>
public class InputStreamBufferTest
{
    [Fact]
    public void testBasicRead()
    {
        byte[] data = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
        var bais = new MemoryStream(data);
        var isb = new InputStreamBuffer(bais, data.Length);

        Assert.Equal(data.Length, isb.GetLength());
        Assert.Equal(0, isb.GetPosition());
        Assert.Equal(0, isb.GetBytesBuffered());

        InputStreamBuffer.SubInputStream sis = isb.GetInputStream();
        Assert.NotNull(sis);
        Assert.True(sis.MarkSupported);
        Assert.Equal(0, sis.Position);
        Assert.Equal(0, sis.Available());

        // Read first byte
        Assert.Equal(10, sis.ReadByte());
        Assert.Equal(1, sis.Position);
        Assert.Equal(1, isb.GetBytesBuffered());
        Assert.Equal(0, sis.Available()); // Available tells how many are buffered after the current position

        // Read next two bytes
        Assert.Equal(20, sis.ReadByte());
        Assert.Equal(30, sis.ReadByte());
        Assert.Equal(3, sis.Position);
        Assert.Equal(3, isb.GetBytesBuffered());

        // Read using block
        var buffer = new byte[3];
        int read = sis.Read(buffer, 0, buffer.Length);
        Assert.Equal(3, read);
        Assert.Equal(40, buffer[0]);
        Assert.Equal(50, buffer[1]);
        Assert.Equal(60, buffer[2]);
        Assert.Equal(6, sis.Position);
        Assert.Equal(6, isb.GetBytesBuffered());

        // Read remaining bytes
        Assert.Equal(70, sis.ReadByte());
        Assert.Equal(80, sis.ReadByte());
        Assert.Equal(90, sis.ReadByte());
        Assert.Equal(100, sis.ReadByte());
        Assert.Equal(10, sis.Position);
        Assert.Equal(10, isb.GetBytesBuffered());

        // EOF
        Assert.Equal(-1, sis.ReadByte());
        Assert.Equal(10, sis.Position);
    }

    [Fact]
    public void testMultipleInterleavedSubstreams()
    {
        var data = new byte[100];
        for (int i = 0; i < data.Length; i++)
        {
            data[i] = (byte)i;
        }

        var bais = new MemoryStream(data);
        var isb = new InputStreamBuffer(bais, data.Length);

        InputStreamBuffer.SubInputStream sis1 = isb.GetInputStream();
        InputStreamBuffer.SubInputStream sis2 = isb.GetInputStream();

        // Read 5 bytes from sis1
        for (int i = 0; i < 5; i++)
        {
            Assert.Equal(i, sis1.ReadByte());
        }
        Assert.Equal(5, sis1.Position);
        Assert.Equal(5, isb.GetBytesBuffered());

        // Available for sis2 should be 0 because it's at position 0, but 5 bytes are buffered from pos 0 to 5
        Assert.Equal(5, sis2.Available());

        // Read 10 bytes from sis2. It should serve 0-4 from the buffer and 5-9 from the carrier
        for (int i = 0; i < 10; i++)
        {
            Assert.Equal(i, sis2.ReadByte());
        }
        Assert.Equal(10, sis2.Position);
        Assert.Equal(10, isb.GetBytesBuffered());

        // sis1 is at pos 5. Since sis2 read up to 10, sis1 should have 5 bytes available in the buffer
        Assert.Equal(5, sis1.Available());

        // Read the remaining bytes from sis1 using block read
        var buf = new byte[95];
        int read = sis1.Read(buf, 0, buf.Length);
        Assert.Equal(95, read);
        Assert.Equal(5, buf[0]);
        Assert.Equal(99, buf[94]);
        Assert.Equal(100, sis1.Position);
        Assert.Equal(100, isb.GetBytesBuffered());

        // sis2 should now see remaining 90 bytes available in the buffer
        Assert.Equal(90, sis2.Available());
        int read2 = sis2.Read(buf, 0, 90);
        Assert.Equal(90, read2);
        Assert.Equal(10, buf[0]);
        Assert.Equal(99, buf[89]);
        Assert.Equal(100, sis2.Position);
    }

    [Fact]
    public void testSkipAndMarkReset()
    {
        byte[] data = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        var bais = new MemoryStream(data);
        var isb = new InputStreamBuffer(bais, data.Length);

        InputStreamBuffer.SubInputStream sis = isb.GetInputStream();

        Assert.Equal(0, sis.ReadByte());
        Assert.Equal(1, sis.ReadByte());

        // Mark at position 2
        sis.Mark(10);

        Assert.Equal(2, sis.ReadByte());
        Assert.Equal(3, sis.ReadByte());
        Assert.Equal(4, sis.ReadByte());
        Assert.Equal(5, sis.Position);

        // Reset to position 2
        sis.Reset();
        Assert.Equal(2, sis.Position);
        Assert.Equal(2, sis.ReadByte());

        // Skip forward
        long skipped = sis.Skip(3); // Should skip 3, 4, 5 -> land at 6
        Assert.Equal(3L, skipped);
        Assert.Equal(6, sis.Position);
        Assert.Equal(6, sis.ReadByte());

        // Skip beyond end of stream
        long skippedBeyond = sis.Skip(20);
        Assert.Equal(3L, skippedBeyond); // Only 3 bytes left (7, 8, 9)
        Assert.Equal(10, sis.Position);
        Assert.Equal(-1, sis.ReadByte());
    }

    [Fact]
    public void testUpdateFrom()
    {
        byte[] data = [1, 2, 3, 4, 5];
        var isb1 = new InputStreamBuffer(new MemoryStream(data), data.Length);
        var isb2 = new InputStreamBuffer(new MemoryStream(data), data.Length);

        InputStreamBuffer.SubInputStream sis1 = isb1.GetInputStream();
        Assert.Equal(1, sis1.ReadByte());
        Assert.Equal(2, sis1.ReadByte());
        Assert.Equal(2, isb1.GetBytesBuffered());
        Assert.Equal(0, isb2.GetBytesBuffered());

        // Update isb2 from isb1
        isb2.UpdateFrom(isb1);
        Assert.Equal(2, isb2.GetBytesBuffered());

        InputStreamBuffer.SubInputStream sis2 = isb2.GetInputStream();
        Assert.Equal(2, sis2.Available());
        Assert.Equal(1, sis2.ReadByte());
        Assert.Equal(2, sis2.ReadByte());
    }

    [Fact]
    public void testReadWithOffsetsAndBounds()
    {
        byte[] data = [100, 101, 102, 103, 104];
        var isb = new InputStreamBuffer(new MemoryStream(data), data.Length);
        InputStreamBuffer.SubInputStream sis = isb.GetInputStream();

        var target = new byte[10];

        // Exception for null array
        Assert.Throws<ArgumentNullException>(() => sis.Read(null!, 0, 1));

        // Exception for index out of bounds
        Assert.ThrowsAny<ArgumentException>(() => sis.Read(target, -1, 5));
        Assert.ThrowsAny<ArgumentException>(() => sis.Read(target, 0, -1));
        Assert.ThrowsAny<ArgumentException>(() => sis.Read(target, 8, 5));

        // Valid zero length read
        Assert.Equal(0, sis.Read(target, 0, 0));

        // Valid block read into offset
        int read = sis.Read(target, 2, 3);
        Assert.Equal(3, read);
        Assert.Equal(0, target[0]);
        Assert.Equal(0, target[1]);
        Assert.Equal(100, target[2]);
        Assert.Equal(101, target[3]);
        Assert.Equal(102, target[4]);
        Assert.Equal(0, target[5]);
    }

    [Fact]
    public void testResetWithoutMark()
    {
        byte[] data = [1, 2, 3];
        var isb = new InputStreamBuffer(new MemoryStream(data), data.Length);
        InputStreamBuffer.SubInputStream sis = isb.GetInputStream();

        Assert.Throws<IOException>(() => sis.Reset());
    }

    [Fact]
    public void testEmptyStream()
    {
        byte[] data = [];
        var isb = new InputStreamBuffer(new MemoryStream(data), data.Length);
        InputStreamBuffer.SubInputStream sis = isb.GetInputStream();

        Assert.Equal(0, isb.GetLength());
        Assert.Equal(-1, sis.ReadByte());

        var target = new byte[5];
        Assert.Equal(0, sis.Read(target, 0, target.Length)); // Java: -1
    }
}
