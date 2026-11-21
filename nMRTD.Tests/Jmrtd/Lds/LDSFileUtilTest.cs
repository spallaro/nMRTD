using System.Text;
using nMRTD.Cbeff;
using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.Lds.Iso19794;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using nMRTD.Tests.Jmrtd.Lds.Icao;
using nMRTD.Lds.Iso39794;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;

namespace nMRTD.Tests.Jmrtd.Lds;

/// <summary>Port of JMRTD's <c>org.jmrtd.lds.LDSFileUtilTest</c>.</summary>
/**
  * Tests some of the functionality provided by the {@code LDSFileUtil} class.
  *
  * @author The JMRTD team (info@jmrtd.org)
  *
  * @version $Revision$
  */
[Collection(nMRTD.Tests.Helpers.CbeffDataGroupCollection.Name)]
public class LDSFileUtilTest
{

    [Fact]
    public void testGetLDSFile()
    {

        COMFile comFile = COMFileTest.CreateTestObject();
        CheckGetLDSFile(PassportService.EF_COM, comFile.GetEncoded()!, comFile);

        DG1File dg1File = DG1FileTest.CreateTestObject();
        CheckGetLDSFile(PassportService.EF_DG1, dg1File.GetEncoded()!, dg1File);

        DG2File dg2File = DG2FileTest.CreateTestObject();
        CheckGetLDSFile(PassportService.EF_DG2, dg2File.GetEncoded()!, dg2File);

        DG3File dg3File = DG3FileTest.CreateTestObject();
        //    CheckGetLDSFile(PassportService.EF_DG3, dg3File.GetEncoded()!, dg3File); // FIXME

        DG4File dg4File = DG4FileTest.CreateTestObject();
        //      CheckGetLDSFile(PassportService.EF_DG4, dg4File.GetEncoded()!, dg4File); // FIXME

        DG14File dg14File = new DG14File(new MemoryStream(DG14FileTest.GetSpecSampleDG14File()));
        CheckGetLDSFile(PassportService.EF_DG14, dg14File.GetEncoded()!, dg14File);

        DG15File dg15File = DG15FileTest.CreateTestObject();
        CheckGetLDSFile(PassportService.EF_DG15, dg15File.GetEncoded()!, dg15File);

        SODFile sodFile = SODFileTest.CreateTestObject("SHA-256", "SHA256WithRSA");
        CheckGetLDSFile(PassportService.EF_SOD, sodFile.GetEncoded()!, sodFile);
    }

    internal static void CheckGetLDSFile(short fid, byte[] bytes, LDSFile expectedFile)
    {
        try
        {
            LDSFile actualFile = LDSFileUtil.GetLDSFile(fid, new MemoryStream(bytes));
            Assert.Equal(expectedFile, actualFile);
        }
        catch (Exception ioe) when (ioe is not Xunit.Sdk.XunitException) { Assert.Fail(ioe.Message); }
    }

    [Fact]
    public void testCompatibilityDataGroups()
    {
        for (int dgNumber = 1; dgNumber <= 16; dgNumber++)
        {
            CheckCompatibilityDataGroups(dgNumber);
        }
    }

    internal static void CheckCompatibilityDataGroups(int dgNumber)
    {
        int tag = LDSFileUtil.LookupTagByDataGroupNumber(dgNumber);
        int otherDGNumber = LDSFileUtil.LookupDataGroupNumberByTag(tag);
        Assert.Equal(dgNumber, otherDGNumber);

        int otherTag = LDSFileUtil.LookupTagByDataGroupNumber(dgNumber);
        Assert.Equal(tag, otherTag);

        short fidByDGNumber = LDSFileUtil.LookupFIDByDataGroupNumber(dgNumber);
        short fidByTag = LDSFileUtil.LookupFIDByTag(tag);
        Assert.Equal(fidByDGNumber, fidByTag);

        int tagByFID = LDSFileUtil.LookupTagByFID(fidByDGNumber);
        Assert.Equal(tag, tagByFID);

        int dgNumberByFID = LDSFileUtil.LookupDataGroupNumberByFID(fidByDGNumber);
        Assert.Equal(dgNumber, dgNumberByFID);

        int sfi = LDSFileUtil.LookupSFIByFID(fidByDGNumber);
        int fidBySFI = LDSFileUtil.LookupFIDBySFI((byte)sfi);
        Assert.Equal(fidByDGNumber, fidBySFI);

        string fileNameByTag = LDSFileUtil.LookupFileNameByTag(tag);
        string fileNameByFID = LDSFileUtil.LookupFileNameByFID(fidByDGNumber);
        Assert.Equal(fileNameByTag, fileNameByFID);
    }

    [Fact]
    public void testDGNumbers()
    {
        COMFile comFile = COMFileTest.CreateTestObject();
        List<int> dgNumbersFromCOM = LDSFileUtil.GetDataGroupNumbers(comFile);
        Assert.Equal(new List<int> { 1, 2, 15 }, dgNumbersFromCOM);

        SODFile sodFile = SODFileTest.CreateTestObject("SHA-256", "SHA256WithRSA");
        List<int> dgNumbersFromSOd = LDSFileUtil.GetDataGroupNumbers(sodFile);
        Assert.Equal(new List<int> { 1, 2 }, dgNumbersFromSOd);
    }
}
