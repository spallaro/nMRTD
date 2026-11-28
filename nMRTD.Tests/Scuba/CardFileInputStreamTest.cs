using nMRTD.SmartCards;
using FileInfo = nMRTD.SmartCards.FileInfo;

namespace nMRTD.Tests.Scuba;

/// <summary>
/// Port of SCUBA's <c>net.sf.scuba.smartcards.CardFileInputStreamTest</c> (SCUBA 0.1.0, 83dc2c5): reading card files
/// with <see cref="CardFileInputStream"/>, and skipping forward with <see cref="CardFileInputStream.Skip"/>. The
/// tests after those of SCUBA check that skipped bytes are not read from the card.
/// </summary>
public class CardFileInputStreamTest
{
    private static readonly byte[] Contents = Enumerable.Range(0, 1000).Select(i => (byte)(i * 7)).ToArray();

    [Fact]
    public void read_wholeFileInBlocks_returnsContents()
    {
        var fs = new StubFileSystem(Contents.Length);
        var input = new CardFileInputStream(223, fs);

        Assert.Equal(Contents, ReadAll(input, Contents.Length));
        Assert.Equal(-1, input.ReadByte());
        Assert.Equal(0, input.Read(new byte[10], 0, 10));
        Assert.Equal(5, fs.ReadBinaryCount);
    }

    /// <summary>As nMRTD's file system does after lowering its block size.</summary>
    [Fact]
    public void read_singleEmptyResponse_isRetried()
    {
        var fs = new StubFileSystem(Contents.Length);
        fs.Responses.Enqueue([]);
        var input = new CardFileInputStream(100, fs);

        Assert.Equal(Contents[0], input.ReadByte());
    }

    [Fact]
    public void read_onlyEmptyResponses_throwsIOException()
    {
        var fs = new StubFileSystem(Contents.Length) { IsAlwaysEmpty = true };
        var input = new CardFileInputStream(100, fs);

        var e = Assert.Throws<IOException>(() => input.ReadByte());

        Assert.Contains("offset 0", e.Message);
        Assert.Equal(0, input.Position);
    }

    [Fact]
    public void read_moreDataThanRequested_isIgnored()
    {
        var fs = new StubFileSystem(Contents.Length) { ExtraBytes = 50 };
        var input = new CardFileInputStream(100, fs);

        Assert.Equal(Contents, ReadAll(input, Contents.Length));
        Assert.Equal(-1, input.ReadByte());
    }

    /// <summary>A file system that returns more than the rest of the file: the stream ends at the file length.</summary>
    [Fact]
    public void read_dataBeyondTheEndOfTheFile_isIgnored()
    {
        var fs = new StubFileSystem(Contents.Length) { ExtraBytes = 50, IgnoresFileLength = true };
        var input = new CardFileInputStream(100, fs);

        Assert.Equal(Contents[..990], ReadAll(input, 990));
        Assert.Equal(10, input.Read(new byte[100], 0, 100));
        Assert.Equal(Contents.Length, input.Position);
    }

    [Fact]
    public void read_readBinaryFails_throwsIOExceptionWithOffsetAndCause()
    {
        var fs = new StubFileSystem(Contents.Length);
        var input = new CardFileInputStream(100, fs);
        ReadAll(input, 300);
        var failure = new CardServiceException("Security status not satisfied", 0x6982);
        fs.Failure = failure;

        var e = Assert.Throws<IOException>(() => input.ReadByte());

        Assert.Same(failure, e.InnerException);
        Assert.Contains("offset 300", e.Message);
        Assert.Contains("101", e.Message);

        // The position is unchanged, so reading can continue after the failure.
        fs.Failure = null;
        Assert.Equal(300, input.Position);
        Assert.Equal(Contents[300], input.ReadByte());
    }

    [Fact]
    public void skip_beyondEndOfFile_stopsAtEnd()
    {
        var input = new CardFileInputStream(100, new StubFileSystem(Contents.Length));
        Assert.Equal(Contents[0], input.ReadByte());
        Assert.Equal(Contents.Length - 1, input.Skip(5000));
        Assert.Equal(Contents.Length, input.Position);
        Assert.Equal(0, input.Skip(1));
        Assert.Equal(-1, input.ReadByte());
    }

    [Fact]
    public void skip_withinAndBeyondBlock_readsFromNewPosition()
    {
        var input = new CardFileInputStream(100, new StubFileSystem(Contents.Length));
        input.ReadByte();
        Assert.Equal(10, input.Skip(10));
        Assert.Equal(Contents[11], input.ReadByte());
        Assert.Equal(500, input.Skip(500));
        Assert.Equal(Contents[512], input.ReadByte());
    }

    [Fact]
    public void skip_negative_skipsNothing()
    {
        var input = new CardFileInputStream(100, new StubFileSystem(Contents.Length));
        input.ReadByte();
        Assert.Equal(0, input.Skip(-5));
        Assert.Equal(1, input.Position);
        Assert.Equal(Contents[1], input.ReadByte());
    }

    [Fact]
    public void skip_hugeCount_stopsAtEnd()
    {
        var input = new CardFileInputStream(100, new StubFileSystem(Contents.Length));
        Assert.Equal(Contents.Length, input.Skip(long.MaxValue));
        Assert.Equal(-1, input.ReadByte());
    }

    // nMRTD only.

    [Fact]
    public void skip_doesNotReadTheSkippedBytes()
    {
        var fs = new StubFileSystem(Contents.Length);
        var input = new CardFileInputStream(100, fs);
        Assert.Equal(950, input.Skip(950));
        Assert.Equal(0, fs.ReadBinaryCount);
        Assert.Equal(Contents[950..], ReadAll(input, 50));
        Assert.Equal(1, fs.ReadBinaryCount);
    }

    [Fact]
    public void tlvSkip_overCardFile_doesNotReadTheSkippedBytes()
    {
        var fs = new StubFileSystem(Contents.Length);
        var input = new CardFileInputStream(100, fs);
        using var tlv = new TlvInputStream(input, leaveOpen: true);
        Assert.Equal(500, tlv.Skip(500));
        Assert.Equal(0, fs.ReadBinaryCount);
        Assert.Equal(Contents[500], input.ReadByte());
    }

    [Fact]
    public void constructor_blockSizeZero_throwsArgumentException() =>
        Assert.ThrowsAny<ArgumentException>(() => new CardFileInputStream(0, new StubFileSystem(Contents.Length)));

    private static byte[] ReadAll(Stream input, int length)
    {
        byte[] result = new byte[length];
        int total = 0;
        while (total < length)
        {
            int read = input.Read(result, total, length - total);
            Assert.True(read > 0, $"end of stream after {total} bytes");
            total += read;
        }
        return result;
    }

    /// <summary>A single file with <see cref="Contents"/>, of which read binaries return what is asked for.</summary>
    private sealed class StubFileSystem(int fileLength) : IFileSystemStructured
    {
        private readonly FileInfo[] _path = [new StubFileInfo(fileLength)];

        public Queue<byte[]> Responses { get; } = new();

        public bool IsAlwaysEmpty { get; set; }

        public int ExtraBytes { get; set; }

        /// <summary>Whether the extra bytes may go beyond the end of the file (filled with 0xEE).</summary>
        public bool IgnoresFileLength { get; set; }

        public CardServiceException? Failure { get; set; }

        public int ReadBinaryCount { get; private set; }

        public void SelectFile(short fid)
        {
            // Only one file.
        }

        public byte[] ReadBinary(int offset, int length)
        {
            ReadBinaryCount++;
            if (Failure != null)
            {
                throw Failure;
            }
            if (Responses.Count > 0)
            {
                return Responses.Dequeue();
            }
            if (IsAlwaysEmpty)
            {
                return [];
            }
            if (IgnoresFileLength)
            {
                byte[] block = Enumerable.Repeat((byte)0xEE, length + ExtraBytes).ToArray();
                Array.Copy(Contents, offset, block, 0, Math.Min(block.Length, Contents.Length - offset));
                return block;
            }
            int count = Math.Min(length + ExtraBytes, Contents.Length - offset);
            return Contents.AsSpan(offset, count).ToArray();
        }

        public FileInfo[] GetSelectedPath() => _path;
    }

    private sealed class StubFileInfo(int fileLength) : FileInfo
    {
        public override short Fid => 0x0101;

        public override int FileLength => fileLength;
    }
}
