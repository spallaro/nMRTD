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

    /// <summary>Encoded files of every type <see cref="LDSFileUtil"/> parses, with the file identifier they belong to.</summary>
    public static TheoryData<short, Type> ParsedFiles => new()
    {
        { PassportService.EF_COM, typeof(COMFile) },
        { PassportService.EF_DG1, typeof(DG1File) },
        { PassportService.EF_DG2, typeof(DG2File) },
        { PassportService.EF_DG3, typeof(DG3File) },
        { PassportService.EF_DG4, typeof(DG4File) },
        { PassportService.EF_DG5, typeof(DG5File) },
        { PassportService.EF_DG6, typeof(DG6File) },
        { PassportService.EF_DG7, typeof(DG7File) },
        { PassportService.EF_DG11, typeof(DG11File) },
        { PassportService.EF_DG12, typeof(DG12File) },
        { PassportService.EF_DG14, typeof(DG14File) },
        { PassportService.EF_DG15, typeof(DG15File) },
        { PassportService.EF_SOD, typeof(SODFile) },
        { PassportService.EF_CVCA, typeof(CVCAFile) },
    };

    [Theory]
    [MemberData(nameof(ParsedFiles))]
    public void GetLdsFileParsesEachFileType(short fid, Type type)
    {
        byte[] encoded = Encode(fid);

        AbstractLDSFile file = LDSFileUtil.GetLDSFile(fid, new MemoryStream(encoded));

        Assert.IsType(type, file);
        Assert.Equal(encoded, file.GetEncoded());
    }

    [Theory]
    [MemberData(nameof(ParsedFiles))]
    public void TypedGettersParseEachFileType(short fid, Type type)
    {
        byte[] encoded = Encode(fid);
        Func<Stream, AbstractLDSFile> getter = fid switch
        {
            PassportService.EF_COM => LDSFileUtil.GetCOMFile,
            PassportService.EF_DG1 => LDSFileUtil.GetDG1File,
            PassportService.EF_DG2 => LDSFileUtil.GetDG2File,
            PassportService.EF_DG3 => LDSFileUtil.GetDG3File,
            PassportService.EF_DG4 => LDSFileUtil.GetDG4File,
            PassportService.EF_DG5 => LDSFileUtil.GetDG5File,
            PassportService.EF_DG6 => LDSFileUtil.GetDG6File,
            PassportService.EF_DG7 => LDSFileUtil.GetDG7File,
            PassportService.EF_DG11 => LDSFileUtil.GetDG11File,
            PassportService.EF_DG12 => LDSFileUtil.GetDG12File,
            PassportService.EF_DG14 => LDSFileUtil.GetDG14File,
            PassportService.EF_DG15 => LDSFileUtil.GetDG15File,
            PassportService.EF_SOD => LDSFileUtil.GetSODFile,
            _ => LDSFileUtil.GetCVCAFile,
        };

        Assert.IsType(type, getter(new MemoryStream(encoded)));
    }

    [Fact]
    public void CvcaFileUnderAnotherFidIsParsedByTheFallback()
    {
        const short fid = 0x0120; // an EF.CVCA under a FID given by the chip (not one of the LDS files)
        byte[] encoded = new CVCAFile(fid, "NLCVCA00001").GetEncoded()!;

        var file = Assert.IsType<CVCAFile>(LDSFileUtil.GetLDSFile(fid, new MemoryStream(encoded)));

        Assert.Equal(fid, file.GetFID());
    }

    [Fact]
    public void LookupsOfUnknownValuesFallBackOrFail()
    {
        Assert.Throws<FormatException>(() => LDSFileUtil.LookupDataGroupNumberByFID(0x0042));
        Assert.Equal("File with tag 0x42", LDSFileUtil.LookupFileNameByTag(0x42));
        Assert.Equal("File with FID 0x42", LDSFileUtil.LookupFileNameByFID(0x0042));
        Assert.Equal(PassportService.EF_CVCA, LDSFileUtil.LookupFIDBySFI(PassportService.SFI_CVCA));
    }

    [Fact]
    public void DataGroupNumbersOfMissingFilesAreEmpty()
    {
        Assert.Empty(LDSFileUtil.GetDataGroupNumbers((SODFile?)null));
        Assert.Empty(LDSFileUtil.GetDataGroupNumbers((COMFile?)null));
    }

    private static byte[] Encode(short fid) => fid switch
    {
        PassportService.EF_COM => Jmrtd.Lds.Icao.COMFileTest.CreateTestObject().GetEncoded()!,
        PassportService.EF_DG1 => Jmrtd.Lds.Icao.DG1FileTest.CreateTestObject().GetEncoded()!,
        PassportService.EF_DG2 => Jmrtd.Lds.Icao.DG2FileTest.CreateTestObject().GetEncoded()!,
        PassportService.EF_DG3 => Jmrtd.Lds.Icao.DG3FileTest.CreateTestObject().GetEncoded()!,
        PassportService.EF_DG4 => Jmrtd.Lds.Icao.DG4FileTest.CreateTestObject().GetEncoded()!,
        PassportService.EF_DG5 => new DG5File([new DisplayedImageInfo(ImageInfoTypes.TYPE_PORTRAIT, [0x01, 0x02])]).GetEncoded()!,
        PassportService.EF_DG6 => [0x66, 0x08, 0x02, 0x01, 0x01, 0x5F, 0x40, 0x02, 0x01, 0x02],
        PassportService.EF_DG7 => Jmrtd.Lds.Icao.DG7FileTest.CreateTestObject().GetEncoded()!,
        PassportService.EF_DG11 => Jmrtd.Lds.Icao.DG11FileTest.CreateTestObject().GetEncoded()!,
        PassportService.EF_DG12 => Jmrtd.Lds.Icao.DG12FileTest.CreateTestObject().GetEncoded()!,
        PassportService.EF_DG14 => new DG14File([new TerminalAuthenticationInfo()]).GetEncoded()!,
        PassportService.EF_DG15 => Jmrtd.Lds.Icao.DG15FileTest.CreateTestObject().GetEncoded()!,
        PassportService.EF_SOD => Jmrtd.Lds.SODFileTest.CreateTestObject("SHA-256", "SHA256WithRSA").GetEncoded()!,
        _ => new CVCAFile(PassportService.EF_CVCA, "NLCVCA00001").GetEncoded()!,
    };

    [Fact]
    public void DataGroupNumbersOfComSkipUnknownTags()
    {
        var com = new COMFile("1.7", "4.0.0", [0x61, 0x75, 0x6E, 0x42]); // DG1, DG2, DG14 and an unknown tag

        Assert.Equal([1, 2, 14], LDSFileUtil.GetDataGroupNumbers(com));
    }
}
