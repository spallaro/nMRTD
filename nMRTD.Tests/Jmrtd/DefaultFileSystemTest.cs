using nMRTD.SmartCards;

namespace nMRTD.Tests.Jmrtd;

/// <summary>Port of JMRTD's <c>org.jmrtd.DefaultFileSystemTest</c>.</summary>
public class DefaultFileSystemTest
{
    [Fact]
    public void readsAndCachesSelectedFile()
    {
        byte[] file = CreateTLVFile(0x61, 12);
        var service = new RecordingReadBinaryService();
        service.AddFile(PassportService.EF_DG1, PassportService.SFI_DG1, file);
        var fileSystem = new DefaultFileSystem(service, false);

        fileSystem.SelectFile(PassportService.EF_DG1);
        SmartCards.FileInfo[] selectedPath = fileSystem.GetSelectedPath();
        Assert.Single(selectedPath);
        Assert.Equal(PassportService.EF_DG1, selectedPath[0].Fid);
        Assert.Equal(file.Length, selectedPath[0].FileLength);

        Assert.Equal(file, fileSystem.ReadBinary(0, file.Length));
        Assert.Single(service.SelectedFIDs);
        Assert.Equal(2, service.Requests.Count);
        Assert.Equal(0, service.Requests[0].Offset);
        Assert.Equal(8, service.Requests[1].Offset);

        Assert.Equal(file, fileSystem.ReadBinary(0, file.Length));
        Assert.Equal(2, service.Requests.Count); // A buffered read should not result in another APDU
    }

    [Fact]
    public void usesSFIWithoutSelectingFile()
    {
        byte[] file = CreateTLVFile(0x61, 12);
        var service = new RecordingReadBinaryService();
        service.AddFile(PassportService.EF_DG1, PassportService.SFI_DG1, file);
        var fileSystem = new DefaultFileSystem(service, true);

        fileSystem.SelectFile(PassportService.EF_DG1);
        Assert.Equal(file, fileSystem.ReadBinary(0, file.Length));

        Assert.Empty(service.SelectedFIDs);
        Assert.Equal(2, service.Requests.Count);
        foreach (ReadRequest request in service.Requests)
        {
            Assert.True(request.IsSFIEnabled);
            Assert.Equal(0x80 | PassportService.SFI_DG1, request.Sfi);
            Assert.False(request.IsTLVEncodedOffsetNeeded);
        }
    }

    [Fact]
    public void returnsOnlyBytesActuallyReceivedFromCard()
    {
        byte[] file = CreateTLVFile(0x61, 12);
        var service = new RecordingReadBinaryService();
        service.AddFile(PassportService.EF_DG1, PassportService.SFI_DG1, file);
        var fileSystem = new DefaultFileSystem(service, false);
        fileSystem.SelectFile(PassportService.EF_DG1);

        service.MaximumResponseLength = 3;
        Assert.Equal(file[8..11], fileSystem.ReadBinary(8, 4));
        Assert.Equal(3, service.Requests[1].ResponseLength);
    }

    [Fact]
    public void fallsBackToShortReadsAfterWrongLengthStatus()
    {
        byte[] file = CreateTLVFile(0x61, 12);
        var service = new RecordingReadBinaryService();
        service.AddFile(PassportService.EF_DG1, PassportService.SFI_DG1, file);
        var fileSystem = new DefaultFileSystem(service, false);
        fileSystem.SelectFile(PassportService.EF_DG1);

        service.FailNextReadWithWrongLength = true;
        Assert.Equal(Array.Empty<byte>(), fileSystem.ReadBinary(8, 4));
        Assert.Equal(PassportService.DefaultMaxBlocksize, fileSystem.GetMaxReadBinaryLength());

        Assert.Equal(file[8..12], fileSystem.ReadBinary(8, 4));
    }

    /// <summary>On a 6700 the file system only switches to short reads; it never replaces the wrapper, also right
    /// after a new session (JMRTD 0.8.11, DefaultFileSystemTest.keepsWrapperAfterWrongLengthUnderSecureMessaging;
    /// SecureMessagingAPDUSender keeps the wrapper in step with the chip).</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void keepsWrapperAfterWrongLengthUnderSecureMessaging(bool isSfiEnabled)
    {
        byte[] file = CreateTLVFile(0x61, 300);
        var service = new RecordingReadBinaryService();
        service.AddFile(PassportService.EF_DG1, PassportService.SFI_DG1, file);
        var fileSystem = new DefaultFileSystem(service, isSfiEnabled);
        fileSystem.SetWrapper(nMRTD.Tests.Helpers.SecureMessagingFixtures.NewWrapper(false));
        fileSystem.SelectFile(PassportService.EF_DG1);
        var sessionWrapper = nMRTD.Tests.Helpers.SecureMessagingFixtures.NewWrapper(true); // a new session (CA)
        fileSystem.SetWrapper(sessionWrapper);

        service.FailNextReadWithWrongLength = true;
        Assert.Equal(Array.Empty<byte>(), fileSystem.ReadBinary(8, 292));
        Assert.Same(sessionWrapper, fileSystem.GetWrapper());

        Assert.Equal(file[8..(8 + PassportService.DefaultMaxBlocksize)], fileSystem.ReadBinary(8, 292));
        Assert.Same(sessionWrapper, fileSystem.GetWrapper());
    }

    [Fact]
    public void usesTLVEncodedReadForOffsetsAboveSignedShortRange()
    {
        byte[] file = CreateTLVFile(0x61, 40006);
        var service = new RecordingReadBinaryService();
        service.AddFile(PassportService.EF_DG1, PassportService.SFI_DG1, file);
        var fileSystem = new DefaultFileSystem(service, false);
        fileSystem.SelectFile(PassportService.EF_DG1);

        Assert.Equal(file[33000..33004], fileSystem.ReadBinary(33000, 4));
        Assert.True(service.Requests[1].IsTLVEncodedOffsetNeeded);
    }

    private static byte[] CreateTLVFile(int tag, int valueLength)
    {
        int lengthByteCount = valueLength < 128 ? 1 : valueLength < 256 ? 2 : 3;
        var result = new byte[1 + lengthByteCount + valueLength];
        result[0] = (byte)tag;
        if (lengthByteCount == 1)
        {
            result[1] = (byte)valueLength;
        }
        else if (lengthByteCount == 2)
        {
            result[1] = 0x81;
            result[2] = (byte)valueLength;
        }
        else
        {
            result[1] = 0x82;
            result[2] = (byte)(valueLength >> 8);
            result[3] = (byte)valueLength;
        }
        for (int i = 1 + lengthByteCount; i < result.Length; i++)
        {
            result[i] = (byte)i;
        }
        return result;
    }

    private sealed class RecordingReadBinaryService : IApduLevelReadBinaryCapable
    {
        private readonly Dictionary<short, byte[]> _filesByFID = [];
        private readonly Dictionary<int, byte[]> _filesBySFI = [];
        private short _selectedFID;

        public List<short> SelectedFIDs { get; } = [];

        public List<ReadRequest> Requests { get; } = [];

        public int MaximumResponseLength { get; set; } = int.MaxValue;

        public bool FailNextReadWithWrongLength { get; set; }

        public void AddFile(short fid, byte sfi, byte[] contents)
        {
            _filesByFID[fid] = (byte[])contents.Clone();
            _filesBySFI[0x80 | (sfi & 0xFF)] = (byte[])contents.Clone();
        }

        public void SendSelectApplet(IApduWrapper? wrapper, byte[] aid)
        {
            /* Not used by DefaultFileSystem. */
        }

        public void SendSelectMf()
        {
            /* Not used by DefaultFileSystem. */
        }

        public void SendSelectFile(IApduWrapper? wrapper, short fid)
        {
            if (!_filesByFID.ContainsKey(fid))
            {
                throw new CardServiceException("Unknown FID " + (fid & 0xFFFF).ToString("x"));
            }
            _selectedFID = fid;
            SelectedFIDs.Add(fid);
        }

        public byte[] SendReadBinary(IApduWrapper? wrapper, int sfi, int offset, int le, bool isSfiEnabled, bool isTlvEncodedOffsetNeeded)
        {
            if (FailNextReadWithWrongLength)
            {
                FailNextReadWithWrongLength = false;
                throw new CardServiceException("Wrong length", Iso7816.SwWrongLength);
            }

            byte[]? file = isSfiEnabled ? _filesBySFI.GetValueOrDefault(sfi) : _filesByFID.GetValueOrDefault(_selectedFID);
            if (file == null)
            {
                throw new CardServiceException("No file selected");
            }

            int responseLength = Math.Min(Math.Min(le, MaximumResponseLength), file.Length - offset);
            Requests.Add(new ReadRequest(sfi, offset, le, responseLength, isSfiEnabled, isTlvEncodedOffsetNeeded));
            return file[offset..(offset + responseLength)];
        }
    }

    private sealed class ReadRequest
    {
        public ReadRequest(int sfi, int offset, int requestedLength, int responseLength, bool isSFIEnabled, bool isTLVEncodedOffsetNeeded)
        {
            Sfi = sfi;
            Offset = offset;
            ResponseLength = responseLength;
            IsSFIEnabled = isSFIEnabled;
            IsTLVEncodedOffsetNeeded = isTLVEncodedOffsetNeeded;
            if (requestedLength < responseLength)
            {
                throw new ArgumentException("Response cannot exceed requested length");
            }
        }

        public int Sfi { get; }

        public int Offset { get; }

        public int ResponseLength { get; }

        public bool IsSFIEnabled { get; }

        public bool IsTLVEncodedOffsetNeeded { get; }
    }
}
