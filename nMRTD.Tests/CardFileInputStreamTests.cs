using nMRTD.Protocol;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using static nMRTD.Tests.Helpers.TestData;

namespace nMRTD.Tests;

/// <summary>Regressions for review fixes 4 (truncated files) and 5 (files mixed up).</summary>
public class CardFileInputStreamTests
{
    private static readonly byte[] File1 = Enumerable.Range(0, 1000).Select(i => (byte)i).ToArray();
    private static readonly byte[] File2 = Enumerable.Range(0, 700).Select(i => (byte)(255 - i % 256)).ToArray();

    [Fact]
    public void EmptyBlockIsRetriedNotTreatedAsEndOfFile()
    {
        var fs = new FakeFs(new() { [0x0101] = File1 }) { EmptyReadsAt = new() { 0, 500 } };
        fs.SelectFile(0x0101);
        var stream = new CardFileInputStream(250, fs);
        Assert.Equal(File1, ReadAll(stream));
    }

    [Fact]
    public void StreamKeepsReadingItsOwnFileAfterAnotherIsSelected()
    {
        var fs = new FakeFs(new() { [0x0101] = File1, [0x0102] = File2 });
        fs.SelectFile(0x0101);
        var a = new CardFileInputStream(100, fs);
        fs.SelectFile(0x0102);
        var b = new CardFileInputStream(100, fs);
        var aFirst = new byte[150];
        for (int got = 0; got < aFirst.Length;) got += a.Read(aFirst, got, aFirst.Length - got);
        var bAll = ReadAll(b);
        var aRest = ReadAll(a);
        Assert.Equal(1000L, a.Length);
        Assert.Equal(700L, b.Length);
        Assert.Equal(File1, aFirst.Concat(aRest).ToArray());
        Assert.Equal(File2, bAll);
    }

    [Fact]
    public void FileSystemThatNeverReturnsDataFailsInsteadOfLooping()
    {
        var fs = new FakeFs(new() { [0x0101] = File1 }) { AlwaysEmpty = true };
        fs.SelectFile(0x0101);
        Assert.ThrowsAny<IOException>(() => ReadAll(new CardFileInputStream(250, fs)));
    }

    [Fact]
    public void DefaultFileSystemReadsWholeFileAfterLeFallback()
    {
        // The card rejects Le > 223 with 6700.
        byte[] content = Enumerable.Range(0, 1000).Select(i => (byte)(i * 7)).ToArray();
        byte[] ef = new byte[] { 0x61, 0x82, 0x03, 0xE8 }.Concat(content).ToArray();
        int rejected = 0;
        var card = new FakeCard(cmd =>
        {
            if (cmd.Ins == 0xA4) return [0x90, 0x00];
            if (cmd.Ins == 0xB0)
            {
                if (cmd.Ne > 223)
                {
                    rejected++;
                    return [0x67, 0x00];
                }
                int off = (cmd.P1 << 8) | cmd.P2;
                return ef.Skip(off).Take(cmd.Ne).Concat(new byte[] { 0x90, 0x00 }).ToArray();
            }
            return [0x6D, 0x00];
        });
        var fs = new DefaultFileSystem(new ReadBinaryAPDUSender(new SecureMessagingAPDUSender(card)), false);
        fs.SelectFile(0x0101);
        var stream = new CardFileInputStream(1000, fs);
        Assert.Equal((long)ef.Length, stream.Length);
        Assert.Equal(ef, ReadAll(stream));
        Assert.True(rejected > 0, "the card never rejected a long read, so the fallback was not exercised");
    }
}
