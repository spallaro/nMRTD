using nMRTD.Lds;
using nMRTD.Lds.Icao;

namespace nMRTD.Tests;

/// <summary>
/// The lookup tables of <see cref="LDSFileUtil"/>: data group number, tag, file identifier (FID), short file
/// identifier (SFI) and file name agree with each other in both directions, and with ICAO Doc 9303-10 (SFI =
/// low byte of the FID for the data groups and EF.SOD).
/// </summary>
public class LdsFileTableTests
{
    public static TheoryData<int> DataGroups => new() { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

    [Theory]
    [MemberData(nameof(DataGroups))]
    public void DataGroupTablesAgree(int dataGroup)
    {
        int tag = LDSFileUtil.LookupTagByDataGroupNumber(dataGroup);
        short fid = LDSFileUtil.LookupFIDByDataGroupNumber(dataGroup);
        int sfi = LDSFileUtil.LookupSFIByFID(fid);

        Assert.Equal(0x0100 + dataGroup, fid); // EF.DGn = 01 0n
        Assert.Equal(dataGroup, sfi);           // SFI = low byte of the FID
        Assert.Equal(fid, LDSFileUtil.LookupFIDByTag(tag));
        Assert.Equal(tag, LDSFileUtil.LookupTagByFID(fid));
        Assert.Equal(fid, LDSFileUtil.LookupFIDBySFI((byte)sfi));
        Assert.Equal(dataGroup, LDSFileUtil.LookupDataGroupNumberByTag(tag));
        Assert.Equal(dataGroup, LDSFileUtil.LookupDataGroupNumberByFID(fid));
        Assert.Equal("EF_DG" + dataGroup, LDSFileUtil.LookupFileNameByFID(fid));
        Assert.Equal("EF_DG" + dataGroup, LDSFileUtil.LookupFileNameByTag(tag));
    }

    [Theory]
    [InlineData(PassportService.EF_COM, 0x60, 0x1E, "EF_COM")]
    [InlineData(PassportService.EF_SOD, 0x77, 0x1D, "EF_SOD")]
    public void ComAndSodTablesAgree(short fid, int tag, int sfi, string name)
    {
        Assert.Equal(tag, LDSFileUtil.LookupTagByFID(fid));
        Assert.Equal(fid, LDSFileUtil.LookupFIDByTag(tag));
        Assert.Equal(sfi, LDSFileUtil.LookupSFIByFID(fid));
        Assert.Equal(fid, LDSFileUtil.LookupFIDBySFI((byte)sfi));
        Assert.Equal(name, LDSFileUtil.LookupFileNameByFID(fid));
        Assert.Equal(name, LDSFileUtil.LookupFileNameByTag(tag));
    }

    [Fact]
    public void UnknownValuesAreRejected()
    {
        Assert.ThrowsAny<Exception>(() => LDSFileUtil.LookupFIDByTag(0x42));
        Assert.ThrowsAny<Exception>(() => LDSFileUtil.LookupTagByFID(0x0042));
        Assert.ThrowsAny<Exception>(() => LDSFileUtil.LookupSFIByFID(0x0042));
        Assert.ThrowsAny<Exception>(() => LDSFileUtil.LookupFIDBySFI(0x02 + 0x40));
        Assert.ThrowsAny<Exception>(() => LDSFileUtil.LookupTagByDataGroupNumber(17));
        Assert.ThrowsAny<Exception>(() => LDSFileUtil.LookupFIDByDataGroupNumber(0));
        Assert.ThrowsAny<Exception>(() => LDSFileUtil.LookupDataGroupNumberByTag(0x42));
    }

    [Theory]
    [InlineData(PassportService.EF_DG8)]
    [InlineData(PassportService.EF_DG9)]
    [InlineData(PassportService.EF_DG10)]
    [InlineData(PassportService.EF_DG13)]
    [InlineData(PassportService.EF_DG16)]
    public void DataGroupsWithoutAParserAreReportedAsUnsupported(short fid) =>
        Assert.Throws<NotSupportedException>(() => LDSFileUtil.GetLDSFile(fid, new MemoryStream([0x00])));

    [Fact]
    public void UnknownFileIsRejected() =>
        Assert.Throws<FormatException>(() => LDSFileUtil.GetLDSFile(0x0042, new MemoryStream([0x01, 0x02])));

    [Fact]
    public void DataGroupNumbersOfComSkipUnknownTags()
    {
        var com = new COMFile("1.7", "4.0.0", [0x61, 0x75, 0x6E, 0x42]); // DG1, DG2, DG14 and an unknown tag

        Assert.Equal([1, 2, 14], LDSFileUtil.GetDataGroupNumbers(com));
    }
}
