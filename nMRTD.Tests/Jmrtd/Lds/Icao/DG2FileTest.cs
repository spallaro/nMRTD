using System.Text;
using nMRTD.Cbeff;
using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.Lds.Iso19794;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using nMRTD.Tests.Jmrtd.Lds.Iso19794;

namespace nMRTD.Tests.Jmrtd.Lds.Icao;

/// <summary>Port of JMRTD's <c>org.jmrtd.lds.icao.DG2FileTest</c>.</summary>
//import java.awt.image.BufferedImage;



public class DG2FileTest
{

    private const string BSI_TEST_FILE = "/lds/bsi2008/Datagroup2.bin";
    private const string LOES_TEST_FILE = "/lds/loes2006/ef0102.bin";

    private const bool SHOULD_SHOW_FRAME = false;

    [Fact]
    public void testConstruct()
    {
        DG2File dg2 = new DG2File(new List<FaceInfo> { });
    }

    [Fact]
    public void testReflexive()
    {
        CheckReflexive(GetTestObject(BSI_TEST_FILE));
        CheckReflexive(GetTestObject(LOES_TEST_FILE));
    }

    internal static void CheckReflexive(DG2File dg2File)
    {
        byte[] encoded = dg2File.GetEncoded()!;
        Assert.NotNull(encoded);
        MemoryStream input = new MemoryStream(encoded);
        DG2File copy = new DG2File(input);

        Assert.Equal(dg2File, copy);
        Assert.Equal(Hex.BytesToHexString(encoded), Hex.BytesToHexString(copy.GetEncoded()!));
    }

    [Fact]
    public void testWriteObject()
    {
        CheckDecodeEncode(GetTestObject(BSI_TEST_FILE), 2);
        CheckDecodeEncode(GetTestObject(LOES_TEST_FILE), 2);
    }

    /**
      * Tests if we can decode and then encode.
      *
      * @param dg2File
      * @param n number of times
      */
    internal static void CheckDecodeEncode(DG2File dg2File, int n)
    {
        byte[]? encoded = null;

        List<FaceInfo> records = dg2File.GetFaceInfos();
        int faceCount = records.Count;
        FaceInfo? record = faceCount == 0 ? null : records[0];
        List<FaceImageInfo> images = record!.GetFaceImageInfos();
        int faceImageCount = images.Count;
        FaceImageInfo? faceImage = faceImageCount == 0 ? null : images[0];
        int width = faceImageCount == 0 ? -1 : faceImage!.GetWidth(), height = faceImageCount == 0 ? -1 : faceImage!.GetHeight();

        for (int i = 0; i < n; i++)
        {
            encoded = dg2File.GetEncoded()!;
            dg2File = new DG2File(new MemoryStream(encoded));
        }

        List<FaceInfo> records1 = dg2File.GetFaceInfos();
        int faceCount1 = records1.Count;
        FaceInfo? record1 = faceCount1 == 0 ? null : records1[0];
        List<FaceImageInfo> images1 = record1!.GetFaceImageInfos();
        int faceImageCount1 = images1.Count;
        FaceImageInfo? faceImage1 = faceImageCount1 == 0 ? null : images1[0];
        int width1 = faceImageCount1 == 0 ? -1 : faceImage1!.GetWidth(), height1 = faceImageCount1 == 0 ? -1 : faceImage1!.GetHeight();

        Assert.Equal(width, width1);
        Assert.Equal(height, height1);
    }

    [Fact]
    public void testElements()
    {
        CheckElements(GetTestObject(BSI_TEST_FILE));
        CheckElements(GetTestObject(LOES_TEST_FILE));
    }

    internal static void CheckElements(DG2File dg2File)
    {
        CheckDecodeEncode(dg2File, 2);
        List<FaceInfo> faceInfos = dg2File.GetFaceInfos();
//    LOGGER.info("DEBUG: faceInfos: " + faceInfos.Count);
        foreach (FaceInfo faceInfo in faceInfos)
        {
            FaceInfoTest.CheckMandatorySBHFields(faceInfo);
            FaceInfoTest.CheckOptionalSBHFields(faceInfo);
            FaceInfoTest.CheckElements(faceInfo);
        }
    }

    [Fact]
    public void testImageBytes()
    {
        try
        {
            CheckImageBytes(GetTestObject(BSI_TEST_FILE));
            CheckImageBytes(GetTestObject(LOES_TEST_FILE));
        }
        catch (IOException ioe)
        {
            Assert.Fail(ioe.Message);
        }
    }

    internal static void CheckImageBytes(DG2File dg2)
    {
        FaceImageInfo i1 = dg2.GetFaceInfos()[0].GetFaceImageInfos()[0];
        int l1 = i1.GetImageLength();
        byte[] b1 = new byte[l1];
        (i1.GetImageInputStream()).ReadFully(b1);
    }

    [Fact]
    public void testImageBytes0()
    {
        CheckImageBytes0(BSI_TEST_FILE);
        CheckImageBytes0(LOES_TEST_FILE);
    }

    internal static void CheckImageBytes0(string testFile)
    {
        Stream inputStream = Fixtures.GetInputStream(testFile);

        DG2File dg2 = new DG2File(inputStream);
        FaceImageInfo i1 = dg2.GetFaceInfos()[0].GetFaceImageInfos()[0];
        int l1 = i1.GetImageLength();
        byte[] b1 = new byte[l1];
        (i1.GetImageInputStream()).ReadFully(b1);
    }

    [Fact]
    public void testCreate()
    {
        DG2File dg2 = CreateTestObject();
        byte[] header = new byte[256];
        Array.Copy(dg2.GetEncoded()!, 0, header, 0, header.Length);
        //			LOGGER.info(Hex.bytesToPrettyString(header));
    }

    [Fact]
    public void testTruncate()
    {
        DG2File dg2File = GetDefaultTestObject();
        byte[] dg2Bytes = dg2File.GetEncoded()!;
        byte[] partialBytes = new byte[(int)(0.8 * dg2Bytes.Length)];
        Array.Copy(dg2Bytes, 0, partialBytes, 0, partialBytes.Length);
        Assert.ThrowsAny<Exception>(() =>
        {
            new DG2File(new MemoryStream(partialBytes));
        });
    }

    public static DG2File CreateTestObject()
    {
        try
        {
            FaceInfo faceInfo = FaceInfoTest.CreateTestObject();
            DG2File dg2 = new DG2File(new List<FaceInfo> { faceInfo });
            return dg2;
        }
        catch (Exception e)
        {
            Assert.Fail(e.Message);
            return null;
        }
    }

    public static DG2File GetDefaultTestObject()
    {
        return GetTestObject(BSI_TEST_FILE);
    }

    public static DG2File GetTestObject(string fileName)
    {
        return new DG2File(Fixtures.GetInputStream(fileName));
    }

    internal static void CheckFile(Stream input)
    {
        try
        {
            CheckDecodeEncode(new DG2File(input), 3);
        }
        catch (IOException e)
        {
            Assert.Fail(e.Message);
        }
    }
}
