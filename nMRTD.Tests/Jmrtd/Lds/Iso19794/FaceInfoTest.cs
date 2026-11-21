using System.Text;
using nMRTD.Cbeff;
using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.Lds.Iso19794;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using static nMRTD.Lds.Iso19794.FaceImageInfo;

namespace nMRTD.Tests.Jmrtd.Lds.Iso19794;

/// <summary>Port of JMRTD's <c>org.jmrtd.lds.iso19794.FaceInfoTest</c>.</summary>
public class FaceInfoTest
{

    [Fact]
    public void testToString()
    {
        FaceInfo info = CreateTestObject();
        Assert.NotNull(info);
        string asString = info.ToString();
        Assert.NotNull(asString);
    }

    [Fact]
    public void testElements()
    {
        FaceInfo faceInfo = CreateTestObject();
        CheckElements(faceInfo);
    }

    internal static void CheckElements(FaceInfo FaceInfo)
    {
        List<FaceImageInfo> imageInfos = FaceInfo.GetFaceImageInfos();
        foreach (FaceImageInfo imageInfo in imageInfos)
        {
            FaceImageInfoTest.CheckEncodeDecode(imageInfo);
        }
    }

    [Fact]
    public void testSBHFields()
    {
        FaceInfo faceInfo = CreateTestObject();
        CheckMandatorySBHFields(faceInfo);
        CheckOptionalSBHFields(faceInfo);

        byte[] faceInfoEncoded = faceInfo.GetEncoded()!;

        StandardBiometricHeader sbh = faceInfo.GetStandardBiometricHeader();
        Dictionary<int, byte[]> sbhElements = new Dictionary<int, byte[]>();
        sbhElements.Add(0x87, sbh.GetElements()[0x87]); // FORMAT_OWNER
        sbhElements.Add(0x88, sbh.GetElements()[0x88]); // FORMAT_TYPE

        FaceInfo faceInfoMinimalSBH = new FaceInfo(new StandardBiometricHeader(sbhElements), new MemoryStream(faceInfoEncoded));

        CheckMandatorySBHFields(faceInfoMinimalSBH);
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
    internal static void CheckMandatorySBHFields(FaceInfo faceInfo)
    {
        StandardBiometricHeader sbh = faceInfo.GetStandardBiometricHeader();
        ICollection<int> tags = sbh.GetElements().Keys;
        Assert.Contains(0x87, tags); Assert.Contains(ISO781611.FORMAT_OWNER_TAG, tags);
        Assert.Contains(0x88, tags); Assert.Contains(ISO781611.FORMAT_TYPE_TAG, tags);
    }

    internal static void CheckOptionalSBHFields(FaceInfo faceInfo)
    {
        int[] possibleTagsArray = { 0x81, 0x82, 0x83, /* 0x84, */ 0x85, 0x86, 0x87, 0x88 };
        ISet<int> possibleTags = new HashSet<int>(possibleTagsArray);
        StandardBiometricHeader sbh = faceInfo.GetStandardBiometricHeader();
        ICollection<int> tags = sbh.GetElements().Keys;
        foreach (int tag in tags)
        {
            Assert.Contains(tag, possibleTags);
        }
    }

    [Fact]
    public void testTruncate()
    {
        FaceInfo faceInfo = CreateTestObject();
        byte[] bytes = faceInfo.GetEncoded()!;
        byte[] partialBytes = new byte[(int)(0.8 * bytes.Length)];
        Array.Copy(bytes, 0, partialBytes, 0, partialBytes.Length);
        Assert.ThrowsAny<Exception>(() =>
        {
            new FaceInfo(new MemoryStream(partialBytes));
        });
    }

    /*
      * "FAC" + 0x00, big-endian, see Section 5.4/Table 2 of ISO/IEC 19794-5.
      * Mirrors FaceInfo's private FORMAT_IDENTIFIER constant.
      */
    private const int FORMAT_IDENTIFIER = 0x46414300;

    /* "010" + 0x00. Mirrors FaceInfo's private VERSION_NUMBER constant. */
    private const int VERSION_NUMBER = 0x30313000;

    [Fact]
    public void testWrongVersionThrows()
    {
        MemoryStream output = new MemoryStream();
        DataOutputStream dataOut = new DataOutputStream(output);
        dataOut.WriteInt(FORMAT_IDENTIFIER);
        dataOut.WriteInt(0x00000000); /* Not VERSION_NUMBER. */
        dataOut.Close();
        byte[] bytes = output.ToArray();

        ArgumentException exception = Assert.ThrowsAny<ArgumentException>(() => new FaceInfo(new MemoryStream(bytes)));
        Assert.True(exception.Message.Contains("version"), exception.Message);
    }

    /*
      * FaceInfo does not throw immediately on an unrecognized marker (unlike FingerInfo
      * and IrisInfo): it only logs a warning and falls through, except for one special-cased
      * legacy JP2 marker (0x0000000C, tested separately below). For any other wrong marker it
      * therefore ends up misreading the next 4 bytes as the version field, which then fails
      * the version check below -- this test pins down that (implicit) end result.
      */
    [Fact]
    public void testUnrecognizedMarkerFallsThroughToVersionCheck()
    {
        MemoryStream output = new MemoryStream();
        DataOutputStream dataOut = new DataOutputStream(output);
        dataOut.WriteInt(0x00000000); /* Not FORMAT_IDENTIFIER, not the special JP2 marker either. */
        dataOut.WriteInt(0x00000000); /* Not VERSION_NUMBER. */
        dataOut.Close();
        byte[] bytes = output.ToArray();

        ArgumentException exception = Assert.ThrowsAny<ArgumentException>(() => new FaceInfo(new MemoryStream(bytes)));
        Assert.True(exception.Message.Contains("version"), exception.Message);
    }

    /*
      * The one marker value FaceInfo treats as valid-but-different: a bare JP2 file instead of
      * a FAC record. 0x0000000C is the length of the JP2 signature box, which continues with "jP  ".
      * The image is the complete JP2 file, with nothing appended (the read buffer used to be
      * written in full, padding the image with zeros).
      */
    [Fact]
    public void testLegacyJP2MarkerParsesAsSingleImage()
    {
        byte[] jp2Bytes = TestData.Hex("0000000C 6A502020 0D0A870A 01020304");

        FaceInfo faceInfo = new FaceInfo(new MemoryStream(jp2Bytes));

        List<FaceImageInfo> faceImageInfos = faceInfo.GetFaceImageInfos();
        Assert.Single(faceImageInfos);
        FaceImageInfo faceImageInfo = faceImageInfos[0];
        Assert.Equal(jp2Bytes.Length, faceImageInfo.GetImageLength());
        byte[] imageBytes = new byte[faceImageInfo.GetImageLength()];
        Stream imageIn = (faceImageInfo.GetImageInputStream());
        imageIn.ReadFully(imageBytes);
        Assert.True(Enumerable.SequenceEqual(jp2Bytes, imageBytes));
        Assert.Equal(-1, imageIn.ReadByte());
    }

    [Fact]
    public void testEncoded()
    {
        FaceInfo faceInfo = CreateTestObject();
        byte[] encoded = faceInfo.GetEncoded()!;
        FaceInfo faceInfo2 = new FaceInfo(faceInfo.GetStandardBiometricHeader(), new MemoryStream(encoded));
        Assert.Equal(faceInfo, faceInfo2);
        Assert.Equal(faceInfo.ToString(), faceInfo2.ToString());
    }

    public static FaceInfo CreateTestObject()
    {
        List<FaceImageInfo> FaceImageInfos = new List<FaceImageInfo>();
        FaceImageInfo FaceImageInfo = FaceImageInfoTest.CreateTestObject();
        FaceImageInfos.Add(FaceImageInfo);
        FaceInfo FaceInfo = new FaceInfo(FaceImageInfos);
        return FaceInfo;
    }
}
