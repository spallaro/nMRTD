using nMRTD.Io;

namespace nMRTD.Tests.Jmrtd.Io;

/// <summary>Port of JMRTD's <c>org.jmrtd.io.SplittableInputStreamTest</c>.</summary>
public class SplittableInputStreamTest
{
    [Fact]
    public void testBasicSplitReading()
    {
        var data = new byte[20];
        for (int i = 0; i < data.Length; i++)
        {
            data[i] = (byte)i;
        }

        var bais = new MemoryStream(data);
        var sis = new SplittableInputStream(bais, data.Length);

        Assert.Equal(0, sis.GetPosition());

        // Read 5 bytes
        for (int i = 0; i < 5; i++)
        {
            Assert.Equal(i, sis.ReadByte());
        }
        Assert.Equal(5, sis.GetPosition());

        // Split off a copy stream at position 2
        Stream copyStream = sis.GetInputStream(2);
        Assert.NotNull(copyStream);

        // Copy stream should yield bytes from index 2 onwards
        Assert.Equal(2, copyStream.ReadByte());
        Assert.Equal(3, copyStream.ReadByte());
        Assert.Equal(4, copyStream.ReadByte());

        // Main stream should continue from index 5
        Assert.Equal(5, sis.ReadByte());
        Assert.Equal(6, sis.GetPosition());

        // Copy stream again at position 0
        Stream copyStreamFromStart = sis.GetInputStream(0);
        Assert.Equal(0, copyStreamFromStart.ReadByte());
        Assert.Equal(1, copyStreamFromStart.ReadByte());
    }

    [Fact]
    public void testSkipAndAvailable()
    {
        byte[] data = [10, 20, 30, 40, 50];
        var bais = new MemoryStream(data);
        var sis = new SplittableInputStream(bais, data.Length);

        Assert.True(sis.Available() >= 0);

        long skipped = sis.Skip(2);
        Assert.Equal(2L, skipped);
        Assert.Equal(2, sis.GetPosition());
        Assert.Equal(30, sis.ReadByte());
    }
}
