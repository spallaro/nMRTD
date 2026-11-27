using System.Text;
using nMRTD.Cbeff;
using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.Lds.Iso19794;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;

namespace nMRTD.Tests.Jmrtd.Lds.Iso19794;

/// <summary>Port of JMRTD's <c>org.jmrtd.lds.iso19794.FingerInfoTest</c>.</summary>
public class FingerInfoTest
{

    [Fact]
    public void testToString()
    {
        FingerInfo imageInfo = CreateSingleRightIndexFingerTestObject();
        Assert.NotNull(imageInfo);
        string asString = imageInfo.ToString();
        Assert.NotNull(asString);
        Assert.StartsWith("FingerInfo [", asString);
    }

    [Fact]
    public void testEncodeDecode()
    {
        FingerInfo fingerInfo = CreateSingleRightIndexFingerTestObject();
        CheckEncodeDecode(fingerInfo);
    }

    [Fact]
    public void testReflexive()
    {
        FingerInfo fingerInfo = CreateSingleRightIndexFingerTestObject();
        CheckReflexiveReconstruct(fingerInfo);
    }

    [Fact]
    public void testElements()
    {
        FingerInfo fingerInfo = CreateSingleRightIndexFingerTestObject();
        CheckElements(fingerInfo);
    }

    /*
      * "FIR" + 0x00, big-endian, see Table 2 in Section 7.1 of ISO/IEC 19794-4.
      * Mirrors FingerInfo's private FORMAT_IDENTIFIER constant.
      */
    private const int FORMAT_IDENTIFIER = 0x46495200;

    /* "010" + 0x00. Mirrors FingerInfo's private VERSION_NUMBER constant. */
    private const int VERSION_NUMBER = 0x30313000;

    [Fact]
    public void testWrongMarkerThrows()
    {
        MemoryStream output = new MemoryStream();
        DataOutputStream dataOut = new DataOutputStream(output);
        dataOut.WriteInt(0x00000000); /* Not FORMAT_IDENTIFIER. */
        dataOut.WriteInt(VERSION_NUMBER);
        dataOut.Close();
        byte[] bytes = output.ToArray();

        ArgumentException exception = Assert.ThrowsAny<ArgumentException>(() => new FingerInfo(new MemoryStream(bytes)));
        Assert.True(exception.Message.Contains("FIR"), exception.Message);
    }

    [Fact]
    public void testWrongVersionThrows()
    {
        MemoryStream output = new MemoryStream();
        DataOutputStream dataOut = new DataOutputStream(output);
        dataOut.WriteInt(FORMAT_IDENTIFIER);
        dataOut.WriteInt(0x00000000); /* Not VERSION_NUMBER. */
        dataOut.Close();
        byte[] bytes = output.ToArray();

        ArgumentException exception = Assert.ThrowsAny<ArgumentException>(() => new FingerInfo(new MemoryStream(bytes)));
        Assert.True(exception.Message.Contains("version"), exception.Message);
    }

    [Fact]
    public void testFields()
    {
        FingerInfo fingerInfo = CreateSingleRightIndexFingerTestObject();
        CheckFieldsReasonable(fingerInfo);
        CheckFieldsSameAfterReconstruct(fingerInfo);
    }

    internal static void CheckEncodeDecode(FingerInfo fingerInfo)
    {
        byte[] encoded = fingerInfo.GetEncoded()!;
        FingerInfo fingerInfo2 = new FingerInfo(null, new MemoryStream(encoded));
        Assert.Equal(fingerInfo, fingerInfo2);
        CheckReflexiveReconstruct(fingerInfo2);
    }

    internal static void CheckReflexiveReconstruct(FingerInfo fingerInfo)
    {
        FingerInfo fingerInfo2 = new FingerInfo(fingerInfo.GetCaptureDeviceId(), fingerInfo.GetAcquisitionLevel(), fingerInfo.GetScaleUnits(), fingerInfo.GetHorizontalScanningResolution(), fingerInfo.GetVerticalScanningResolution(), fingerInfo.GetHorizontalImageResolution(), fingerInfo.GetVerticalImageResolution(), fingerInfo.GetDepth(), fingerInfo.GetCompressionAlgorithm(), fingerInfo.GetFingerImageInfos());
        Assert.Equal(fingerInfo, fingerInfo2);
    }

    internal static void CheckElements(FingerInfo fingerInfo)
    {
        List<FingerImageInfo> imageInfos = fingerInfo.GetFingerImageInfos();
        foreach (FingerImageInfo imageInfo in imageInfos)
        {
            FingerImageInfoTest.CheckEncodeDecode(imageInfo);
            FingerImageInfoTest.CheckViewCountAndNumber(imageInfo);
            FingerImageInfoTest.CheckValidType(imageInfo);
        }
    }

    internal static void CheckFieldsReasonable(FingerInfo fingerInfo)
    {
        int captureDeviceId = fingerInfo.GetCaptureDeviceId();
        int acquisitionLevel = fingerInfo.GetAcquisitionLevel();
        int scaleUnits = fingerInfo.GetScaleUnits();
        int scanResolutionHorizontal = fingerInfo.GetHorizontalScanningResolution();
        int scanResolutionVertical = fingerInfo.GetVerticalScanningResolution();
        int imageResolutionHorizontal = fingerInfo.GetHorizontalImageResolution();
        int imageResolutionVertical = fingerInfo.GetVerticalImageResolution();
        int depth = fingerInfo.GetDepth();
        int compressionAlgorithm = fingerInfo.GetCompressionAlgorithm();

        Assert.True(scaleUnits == FingerInfo.SCALE_UNITS_PPI || scaleUnits == FingerInfo.SCALE_UNITS_PPCM);
        Assert.True(scanResolutionHorizontal >= 0);
        Assert.True(scanResolutionVertical >= 0);
        Assert.True(imageResolutionHorizontal >= 0);
        Assert.True(imageResolutionVertical >= 0);

        /* FIXME: is there some relation between scanRes and imgRes? Is scanRes <= imgRes? */
        //		Assert.True(//				scanResolutionHorizontal >= imageResolutionHorizontal, "scanResolutionHorizontal == " + scanResolutionHorizontal
        //				+ ", imageResolutionHorizontal == " + imageResolutionHorizontal);
        //		Assert.True(//				scanResolutionVertical >= imageResolutionVertical, "scanResolutionVertical == " + scanResolutionVertical
        //				+ ", imageResolutionVertical == " + imageResolutionVertical);

        Assert.True(depth >= 0);
        Assert.True(compressionAlgorithm == FingerInfo.COMPRESSION_JPEG
                || compressionAlgorithm == FingerInfo.COMPRESSION_JPEG2000
                || compressionAlgorithm == FingerInfo.COMPRESSION_PNG
                || compressionAlgorithm == FingerInfo.COMPRESSION_UNCOMPRESSED_BIT_PACKED
                || compressionAlgorithm == FingerInfo.COMPRESSION_UNCOMPRESSED_NO_BIT_PACKING
                || compressionAlgorithm == FingerInfo.COMPRESSION_WSQ);
    }

    internal static void CheckFieldsSameAfterReconstruct(FingerInfo fingerInfo)
    {
        FingerInfo fingerInfo2 = new FingerInfo(fingerInfo.GetCaptureDeviceId(), fingerInfo.GetAcquisitionLevel(), fingerInfo.GetScaleUnits(), fingerInfo.GetHorizontalScanningResolution(), fingerInfo.GetVerticalScanningResolution(), fingerInfo.GetHorizontalImageResolution(), fingerInfo.GetVerticalImageResolution(), fingerInfo.GetDepth(), fingerInfo.GetCompressionAlgorithm(), fingerInfo.GetFingerImageInfos());
        int captureDeviceId = fingerInfo.GetCaptureDeviceId();
        int acquisitionLevel = fingerInfo.GetAcquisitionLevel();
        int scaleUnits = fingerInfo.GetScaleUnits();
        int scanResolutionHorizontal = fingerInfo.GetHorizontalScanningResolution();
        int scanResolutionVertical = fingerInfo.GetVerticalScanningResolution();
        int imageResolutionHorizontal = fingerInfo.GetHorizontalImageResolution();
        int imageResolutionVertical = fingerInfo.GetVerticalImageResolution();
        int depth = fingerInfo.GetDepth();
        int compressionAlgorithm = fingerInfo.GetCompressionAlgorithm();

        int captureDeviceId2 = fingerInfo2.GetCaptureDeviceId();
        int acquisitionLevel2 = fingerInfo2.GetAcquisitionLevel();
        int scaleUnits2 = fingerInfo2.GetScaleUnits();
        int scanResolutionHorizontal2 = fingerInfo2.GetHorizontalScanningResolution();
        int scanResolutionVertical2 = fingerInfo2.GetVerticalScanningResolution();
        int imageResolutionHorizontal2 = fingerInfo2.GetHorizontalImageResolution();
        int imageResolutionVertical2 = fingerInfo2.GetVerticalImageResolution();
        int depth2 = fingerInfo2.GetDepth();
        int compressionAlgorithm2 = fingerInfo2.GetCompressionAlgorithm();

        Assert.Equal(captureDeviceId, captureDeviceId2);
        Assert.Equal(acquisitionLevel,acquisitionLevel2);
        Assert.Equal(scaleUnits, scaleUnits2);
        Assert.Equal(scanResolutionHorizontal, scanResolutionHorizontal2);
        Assert.Equal(scanResolutionVertical, scanResolutionVertical2);
        Assert.Equal(imageResolutionHorizontal, imageResolutionHorizontal2);
        Assert.Equal(imageResolutionVertical, imageResolutionVertical2);
        Assert.Equal(depth, depth2);
        Assert.Equal(compressionAlgorithm, compressionAlgorithm2);

        Assert.NotNull(fingerInfo.GetFingerImageInfos());
        Assert.NotNull(fingerInfo2.GetFingerImageInfos());
        Assert.Equal(fingerInfo.GetFingerImageInfos(), fingerInfo2.GetFingerImageInfos());
    }

    [Fact]
    public void testSBHFields()
    {
        FingerInfo fingerInfo = CreateSingleRightIndexFingerTestObject();
        CheckMandatorySBHFields(fingerInfo);
        CheckOptionalSBHFields(fingerInfo);
    }

    /*
      * Doc 9303 says:
      * - Biometric type (Optional, but mandatory if subtype specified) // FIXME: is this true?
      * - Biometric subtype (Optional for DG2, mandatory for DG3, DG4.)
      * - Creation date and time (Optional)
      * - Validity period (from through) (Optional)
      * - Creator of the biometric reference data(PID) (Optional)
      * - Format owner (Mandatory)
      * - Format type (Mandatory)
      *
      * In practice this means: 0x81 (bio type), 0x82 (bio subtype),
      * 0x87 (format owner), 0x88 (format type) will be present.
      */
    internal static void CheckMandatorySBHFields(FingerInfo fingerInfo)
    {
        StandardBiometricHeader sbh = fingerInfo.GetStandardBiometricHeader();
        ICollection<int> tags = sbh.GetElements().Keys;
        Assert.Contains(0x81, tags); Assert.Contains(ISO781611.BIOMETRIC_TYPE_TAG, tags);
        Assert.Contains(0x82, tags); Assert.Contains(ISO781611.BIOMETRIC_SUBTYPE_TAG, tags);
        Assert.Contains(0x87, tags); Assert.Contains(ISO781611.FORMAT_OWNER_TAG, tags);
        Assert.Contains(0x88, tags); Assert.Contains(ISO781611.FORMAT_TYPE_TAG, tags);

        byte[] bioType = sbh.GetElements()[ISO781611.BIOMETRIC_TYPE_TAG];
        Assert.NotNull(bioType);
        Assert.Single(bioType);
        Assert.Equal(CBEFFBiometricTypes.BIOMETRIC_TYPE_FINGERPRINT, bioType[0]);
        Assert.Equal(8, bioType[0]);

        /* FIXME: is bio type really mandatory for DG3 (according to ICAO)? */
        byte[] bioSubType = sbh.GetElements()[ISO781611.BIOMETRIC_SUBTYPE_TAG];
        Assert.NotNull(bioSubType);
        Assert.Single(bioSubType);

        /* Possible subtypes for finger. */
        Assert.True(bioSubType[0] == 5
                || bioSubType[0] == 9
                || bioSubType[0] == 13
                || bioSubType[0] == 17
                || bioSubType[0] == 21
                || bioSubType[0] == 6
                || bioSubType[0] == 10
                || bioSubType[0] == 14
                || bioSubType[0] == 18
                || bioSubType[0] == 22, "Bio sub type = " + bioSubType[0]);
    }

    internal static void CheckOptionalSBHFields(FingerInfo fingerInfo)
    {
        int[] possibleTagsArray = { 0x81, 0x82, 0x83, /* 0x84, */ 0x85, 0x86, 0x87, 0x88 };
        ISet<int> possibleTags = new HashSet<int>(possibleTagsArray);
        StandardBiometricHeader sbh = fingerInfo.GetStandardBiometricHeader();
        ICollection<int> tags = sbh.GetElements().Keys;
        foreach (int tag in tags)
        {
            Assert.Contains(tag, possibleTags);
        }
    }

    [Fact]
    public void testBiometricSubType()
    {
        FingerInfo fingerInfo = CreateSingleRightIndexFingerTestObject();
        CheckBiometricSubType(fingerInfo);
    }

    internal static void CheckBiometricSubType(FingerInfo fingerInfo)
    {
        StandardBiometricHeader sbh = fingerInfo.GetStandardBiometricHeader();
        byte[] bioSubType = sbh.GetElements()[ISO781611.BIOMETRIC_SUBTYPE_TAG];
        /* bio sub type is mandatory in DG3 (Doc 9303). */
        Assert.NotNull(bioSubType);
        Assert.Single(bioSubType);
        List<FingerImageInfo> fingerImageInfos = fingerInfo.GetFingerImageInfos();
        foreach (FingerImageInfo fingerImageInfo in fingerImageInfos)
        {
            int position = fingerImageInfo.GetPosition();
            switch (bioSubType[0])
            {
                case 5: Assert.Equal(1, position); break;
                case 9: Assert.Equal(2, position); break;
                case 13: Assert.Equal(3, position); break;
                case 17: Assert.Equal(4, position); break;
                case 21: Assert.Equal(5, position); break;
                case 6: Assert.Equal(6, position); break;
                case 10: Assert.Equal(7, position); break;
                case 14: Assert.Equal(8, position); break;
                case 18: Assert.Equal(9, position); break;
                case 22: Assert.Equal(10, position); break;
                default: Assert.Fail("Unknown BHT coded bio type: " + bioSubType[0]); break;
            }
        }
    }

    public static FingerInfo CreateSingleRightIndexFingerTestObject()
    {
        List<FingerImageInfo> fingerImageInfos = new List<FingerImageInfo>();
        FingerImageInfo fingerImageInfo = FingerImageInfoTest.CreateRightIndexFingerTestObject();
        fingerImageInfos.Add(fingerImageInfo);
        FingerInfo fingerInfo = new FingerInfo(0,
                31, /* 31 if 500dpi, 41 if 1000dpi */
                FingerInfo.SCALE_UNITS_PPI,
                500,
                500,
                500,
                500,
                8,
                FingerInfo.COMPRESSION_WSQ,
                fingerImageInfos);
        return fingerInfo;
    }
}
