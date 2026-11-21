using System.Text;
using nMRTD.Cbeff;
using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.Lds.Iso19794;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using nMRTD.Tests.Jmrtd.Lds.Iso19794;

namespace nMRTD.Tests.Jmrtd.Lds.Icao;

/// <summary>Port of JMRTD's <c>org.jmrtd.lds.icao.DG4FileTest</c>.</summary>
[Collection(nMRTD.Tests.Helpers.CbeffDataGroupCollection.Name)]
public class DG4FileTest
{

    public static string TEST_FILE = "/lds/bsi2008/Datagroup4.bin";

    [Fact]
    public void testConstruct()
    {
        DG4File dg4 = new DG4File(new List<IrisInfo> { });
        Assert.NotNull(dg4.GetIrisInfos());
        Assert.True(dg4.GetIrisInfos().Count == 0);
    }

    [Fact]
    public void testReflexive()
    {
        DG4File dg4 = CreateTestObject();
        CheckReflexive(dg4);

        dg4 = GetTestObject();
        CheckReflexive(dg4);
    }

    internal static void CheckReflexive(DG4File dg4)
    {
        byte[] bytes = dg4.GetEncoded()!;
        Stream inputStream = new MemoryStream(bytes);
        DG4File copy = new DG4File(inputStream);
    }

    [Fact]
    public void testEncodeDecode()
    {
        DG4File dg4 = GetTestObject();
        CheckEncodeDecode(dg4);

        dg4 = CreateTestObject();
        CheckEncodeDecode(dg4);
    }

    internal static void CheckEncodeDecode(DG4File dg4)
    {
        byte[] dg4Bytes = dg4.GetEncoded()!;
        Assert.NotNull(dg4Bytes);

        DG4File copy = new DG4File(new MemoryStream(dg4Bytes));
        byte[] copyBytes = copy.GetEncoded()!;
        Assert.NotNull(copyBytes);

        Assert.True(Enumerable.SequenceEqual(dg4Bytes, copyBytes));
    }

    [Fact]
    public void testZeroInstanceTestObjectNotEquals()
    {
        DG4File dg4 = new DG4File(new List<IrisInfo>());
        byte[] dg4Bytes = dg4.GetEncoded()!;
        Assert.NotNull(dg4Bytes);

        DG4File anotherDG4 = new DG4File(new List<IrisInfo>());
        byte[] anotherDG4Bytes = anotherDG4.GetEncoded()!;
        Assert.NotNull(anotherDG4Bytes);

        Assert.False(Enumerable.SequenceEqual(dg4Bytes, anotherDG4Bytes));

        DG4File copy = new DG4File(new MemoryStream(dg4Bytes));
        byte[] copyBytes = copy.GetEncoded()!;
        Assert.NotNull(copyBytes);

        Assert.False(Enumerable.SequenceEqual(dg4Bytes, copyBytes));
    }

    [Fact]
    public void testFile()
    {
        DG4File dg4 = GetTestObject();
        List<IrisInfo> recordInfos = dg4.GetIrisInfos();
        int recordCount = recordInfos.Count;
        int recordNumber = 1;
//      LOGGER.info("DEBUG: Number of iris records = " + recordCount);
        foreach (IrisInfo record in recordInfos)
        {
            List<IrisBiometricSubtypeInfo> subtypeInfos = record.GetIrisBiometricSubtypeInfos();
            int subtypeInfoCount = subtypeInfos.Count;
//        LOGGER.info("DEBUG: Number of subtypes in iris record " + recordNumber + " is " + subtypeInfoCount);
            foreach (IrisBiometricSubtypeInfo subtypeInfo in subtypeInfos)
            {
                List<IrisImageInfo> imageInfos = subtypeInfo.GetIrisImageInfos();
                int imageInfoCount = imageInfos.Count;
//          LOGGER.info("DEBUG: Number of image infos in iris subtype record " + imageInfoNumber + " is " + imageInfoCount);
                foreach (IrisImageInfo imageInfo in imageInfos)
                {
                    int length = imageInfo.GetImageLength();
                    byte[] bytes = new byte[length];
                    Stream dataIn = (imageInfo.GetImageInputStream());
                    dataIn.ReadFully(bytes);
                }
                subtypeInfoCount ++;
            }
            recordNumber ++;
        }
    }

    public static DG4File CreateTestObject()
    {
        try
        {
            byte[] imageBytes = TestImages.TrivialJpeg; // Java: a blank 300x200 image, encoded with ImageIO

            int imageFormat = IrisInfo.IMAGEFORMAT_RGB_JPEG;
            IrisImageInfo irisImageInfo = new IrisImageInfo(0, 300, 200, new MemoryStream(imageBytes), imageBytes.Length, IrisInfo.IMAGEFORMAT_RGB_JPEG);

            int biometricSubtype = IrisBiometricSubtypeInfo.EYE_UNDEF;
            IrisBiometricSubtypeInfo irisBiometricSubtypeInfo = new IrisBiometricSubtypeInfo(biometricSubtype, imageFormat, new List<IrisImageInfo> { irisImageInfo });

            int captureDeviceId = IrisInfo.CAPTURE_DEVICE_UNDEF;
            int horizontalOrientation = IrisInfo.ORIENTATION_UNDEF;
            int verticalOrientation = IrisInfo.ORIENTATION_UNDEF;
            int scanType = IrisInfo.SCAN_TYPE_UNDEF;
            int irisOcclusion = IrisInfo.IROCC_UNDEF;
            int occlusionFilling = IrisInfo.IROCC_UNDEF;
            int boundaryExtraction = IrisInfo.IRBNDY_UNDEF;
            int irisDiameter = 167;
            int rawImageWidth = 300;
            int rawImageHeight = 200;
            int intensityDepth = 8;
            int imageTransformation = IrisInfo.TRANS_UNDEF;
            byte[] deviceUniqueId = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            IrisInfo irisInfo = new IrisInfo(
                    captureDeviceId,
                    horizontalOrientation,
                    verticalOrientation,
                    scanType,
                    irisOcclusion,
                    occlusionFilling,
                    boundaryExtraction,
                    irisDiameter,
                    imageFormat,
                    rawImageWidth,
                    rawImageHeight,
                    intensityDepth,
                    imageTransformation,
                    deviceUniqueId,
                    new List<IrisBiometricSubtypeInfo> { irisBiometricSubtypeInfo });
            DG4File dg4 = new DG4File(new List<IrisInfo> { irisInfo, IrisInfoTest.CreateTestObject() });
            return dg4;
        }
        catch (IOException ioe)
        {
            Assert.Fail(ioe.Message);
            return null;
        }
    }

    public static DG4File GetTestObject()
    {
        try
        {
            Stream input = Fixtures.GetInputStream(TEST_FILE);
            DG4File dg4 = new DG4File(input);
            return dg4;
        }
        catch (Exception)
        {
            return null!;
        }
    }
}
