using System.Text;
using nMRTD.Cbeff;
using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.Lds.Iso19794;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;

namespace nMRTD.Tests.Jmrtd.Lds.Iso19794;

/// <summary>Port of JMRTD's <c>org.jmrtd.lds.iso19794.IrisInfoTest</c>.</summary>
public class IrisInfoTest
{

    /*
      * "IIR" + 0x00, big-endian. Mirrors IrisInfo's private FORMAT_IDENTIFIER constant.
      */
    private const int FORMAT_IDENTIFIER = 0x49495200;

    /* "010" + 0x00. Mirrors IrisInfo's private VERSION_NUMBER constant. */
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

        ArgumentException exception = Assert.ThrowsAny<ArgumentException>(() => new IrisInfo(new MemoryStream(bytes)));
        Assert.True(exception.Message.Contains("IIR"), exception.Message);
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

        ArgumentException exception = Assert.ThrowsAny<ArgumentException>(() => new IrisInfo(new MemoryStream(bytes)));
        Assert.True(exception.Message.Contains("version"), exception.Message);
    }

    /*
      * A third validation check specific to IrisInfo (beyond marker/version): the declared
      * record header length must be exactly 45 (see Section 5.2 of ISO/IEC 19794-6).
      */
    [Fact]
    public void testWrongRecordHeaderLengthThrows()
    {
        MemoryStream output = new MemoryStream();
        DataOutputStream dataOut = new DataOutputStream(output);
        dataOut.WriteInt(FORMAT_IDENTIFIER);
        dataOut.WriteInt(VERSION_NUMBER);
        dataOut.WriteInt(0); /* recordLength, irrelevant for this check. */
        dataOut.WriteShort(0); /* captureDeviceId, irrelevant. */
        dataOut.WriteByte(0); /* count, irrelevant. */
        dataOut.WriteShort(44); /* recordHeaderLength: anything but 45. */
        dataOut.Close();
        byte[] bytes = output.ToArray();

        ArgumentException exception = Assert.ThrowsAny<ArgumentException>(() => new IrisInfo(new MemoryStream(bytes)));
        Assert.True(exception.Message.Contains("header length"), exception.Message);
    }

    [Fact]
    public void testToString()
    {
        IrisInfo info = CreateTestObject();
        Assert.NotNull(info);
        string asString = info.ToString();
        Assert.NotNull(asString);
        Assert.StartsWith("IrisInfo", asString);
    }

    [Fact]
    public void testSBHFields()
    {
        IrisInfo irisInfo = CreateTestObject();
        CheckMandatorySBHFields(irisInfo);
        CheckOptionalSBHFields(irisInfo);
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
    internal static void CheckMandatorySBHFields(IrisInfo irisInfo)
    {
        StandardBiometricHeader sbh = irisInfo.GetStandardBiometricHeader();
        ICollection<int> tags = sbh.GetElements().Keys;
        Assert.Contains(0x81, tags); Assert.Contains(ISO781611.BIOMETRIC_TYPE_TAG, tags);
        Assert.Contains(0x82, tags); Assert.Contains(ISO781611.BIOMETRIC_SUBTYPE_TAG, tags);
        Assert.Contains(0x87, tags); Assert.Contains(ISO781611.FORMAT_OWNER_TAG, tags);
        Assert.Contains(0x88, tags); Assert.Contains(ISO781611.FORMAT_TYPE_TAG, tags);
    }

    internal static void CheckOptionalSBHFields(IrisInfo irisInfo)
    {
        int[] possibleTagsArray = { 0x81, 0x82, 0x83, /* 0x84, */ 0x85, 0x86, 0x87, 0x88 };
        ISet<int> possibleTags = new HashSet<int>(possibleTagsArray);
        StandardBiometricHeader sbh = irisInfo.GetStandardBiometricHeader();
        ICollection<int> tags = sbh.GetElements().Keys;
        foreach (int tag in tags)
        {
            Assert.Contains(tag, possibleTags);
        }
    }

    public static IrisInfo CreateTestObject()
    {
        IrisBiometricSubtypeInfo irisFeatureInfo = IrisBiometricSubtypeInfoTest.CreateTestObject();
        int captureDeviceId = IrisInfo.CAPTURE_DEVICE_UNDEF;
        int horizontalOrientation = IrisInfo.ORIENTATION_BASE;
        int verticalOrientation = IrisInfo.ORIENTATION_BASE;
        int scanType = IrisInfo.SCAN_TYPE_UNDEF;
        int irisOcclusion = IrisInfo.IROCC_UNDEF;
        int occlusionFilling = IrisInfo.IROCC_ZEROFILL;
        int boundaryExtraction = IrisInfo.IRBNDY_UNDEF;
        int irisDiameter = 200;
        int imageFormat = irisFeatureInfo.GetImageFormat();
        List<IrisImageInfo> imageInfos = irisFeatureInfo.GetIrisImageInfos();
        Assert.NotNull(imageInfos);
        Assert.Single(imageInfos);
        IrisImageInfo imageInfo = imageInfos[0];
        int rawImageWidth = imageInfo.GetWidth();
        int rawImageHeight = imageInfo.GetHeight();
        int intensityDepth = 24;
        int imageTransformation = IrisInfo.TRANS_UNDEF;
        byte[] deviceUniqueId = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

        List<IrisBiometricSubtypeInfo> irisFeatureInfos = new List<IrisBiometricSubtypeInfo> { irisFeatureInfo };
        IrisInfo irisInfo = new IrisInfo(captureDeviceId, horizontalOrientation, verticalOrientation,
                scanType, irisOcclusion, occlusionFilling, boundaryExtraction, irisDiameter, imageFormat,
                rawImageWidth, rawImageHeight, intensityDepth, imageTransformation, deviceUniqueId, irisFeatureInfos);
        return irisInfo;
    }
}
