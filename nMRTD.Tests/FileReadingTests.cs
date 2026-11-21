using nMRTD.Lds;
using nMRTD.Protocol;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;

namespace nMRTD.Tests;

/// <summary>Reading files from a (simulated) card through PassportService and the READ BINARY sender.</summary>
public class FileReadingTests
{
    private static byte[] CardAccessBytes() =>
        new CardAccessFile([new PACEInfo(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, 2, PACEInfo.PARAM_ID_ECP_BRAINPOOL_P256_R1)])
            .GetEncoded()!;

    /// <summary>A card with one transparent file, answering SELECT and plain READ BINARY.</summary>
    private static FakeCard CardWithFile(byte[] file) => new(cmd =>
    {
        if (cmd.Ins == 0xA4) return [0x90, 0x00];
        if (cmd.Ins == 0xB0)
        {
            int offset = (cmd.P1 << 8) | cmd.P2;
            return file.Skip(offset).Take(cmd.Ne).Concat(new byte[] { 0x90, 0x00 }).ToArray();
        }
        return [0x6D, 0x00];
    });

    [Fact]
    public void PassportServiceReadsEfCardAccessFromTheCard()
    {
        byte[] efCardAccess = CardAccessBytes();
        var service = new PassportService(CardWithFile(efCardAccess), 256, PassportService.DefaultMaxBlocksize, false, true);

        using Stream stream = service.GetInputStream(PassportService.EF_CARD_ACCESS);
        Assert.Equal(efCardAccess.Length, stream.Length);
        var cardAccess = new CardAccessFile(stream);

        var paceInfo = Assert.IsType<PACEInfo>(Assert.Single(cardAccess.GetSecurityInfos()));
        Assert.Equal(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, paceInfo.GetObjectIdentifier());
        Assert.Equal(efCardAccess, cardAccess.GetEncoded());
    }

    [Fact]
    public void ExtendedReadBinaryStripsTheLongFormLengthOfDo53()
    {
        byte[] payload = Enumerable.Range(0, 200).Select(i => (byte)i).ToArray();
        var card = new FakeCard(cmd => cmd.Ins == 0xB1
            ? new byte[] { 0x53, 0x81, 0xC8 }.Concat(payload).Concat(new byte[] { 0x90, 0x00 }).ToArray()
            : [0x6D, 0x00]);
        var sender = new ReadBinaryAPDUSender(new SecureMessagingAPDUSender(card));

        byte[]? data = sender.SendReadBinary(null, 0, 40000, 200, false, true);

        Assert.Equal(payload, data);
    }

    [Fact]
    public void ReaderFailureIsKeptAsTheCauseOfNoResponseApdu()
    {
        var card = new FakeCard(_ => throw new CardServiceException("APDU transmit failed: The card is not responding", new TimeoutException()));
        var sender = new ReadBinaryAPDUSender(new SecureMessagingAPDUSender(card));

        var e = Assert.Throws<CardServiceException>(() => sender.SendReadBinary(null, 0x01, 0, 8, true, false));

        Assert.StartsWith("No response APDU", e.Message);
        Assert.Contains("The card is not responding", e.Message);
        var cause = Assert.IsType<CardServiceException>(e.InnerException);
        Assert.IsType<TimeoutException>(cause.InnerException);
        Assert.Equal(CardServiceException.SwNotSet, e.Sw);
    }

    [Fact]
    public void StreamRequiresASelectedFile()
    {
        Assert.Throws<CardServiceException>(() => new CardFileInputStream(100, new NothingSelectedFs()));
    }

    [Fact]
    public void CardErrorWhileReadingBecomesIOException()
    {
        var fs = new FailingFs();
        var stream = new CardFileInputStream(100, fs);

        Assert.Equal(500L, stream.Length);
        var e = Assert.Throws<IOException>(() => stream.ReadByte());
        Assert.IsType<CardServiceException>(e.InnerException);
    }

    private sealed class NothingSelectedFs : IFileSystemStructured
    {
        public SmartCards.FileInfo[] GetSelectedPath() => [];

        public void SelectFile(short fid) { }

        public byte[] ReadBinary(int offset, int length) => [];
    }

    private sealed class FailingFs : IFileSystemStructured
    {
        public SmartCards.FileInfo[] GetSelectedPath() => [new OneFile()];

        public void SelectFile(short fid) { }

        public byte[] ReadBinary(int offset, int length) => throw new CardServiceException("Security status not satisfied", 0x6982);

        private sealed class OneFile : SmartCards.FileInfo
        {
            public override short Fid => 0x0101;
            public override int FileLength => 500;
        }
    }
}
