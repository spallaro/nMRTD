using System.Text;
using nMRTD.Cbeff;
using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.Lds.Iso19794;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;

namespace nMRTD.Tests.Jmrtd.Lds.Iso19794;

/// <summary>Port of JMRTD's <c>org.jmrtd.lds.iso19794.FingerImageInfoTest</c>.</summary>
public class FingerImageInfoTest
{

    [Fact]
    public void testToString()
    {
        FingerImageInfo imageInfo = CreateRightIndexFingerTestObject();
        Assert.NotNull(imageInfo);
        string asString = imageInfo.ToString();
        Assert.NotNull(asString);
    }

    [Fact]
    public void testNonNullEncoded()
    {
        FingerImageInfo imageInfo = CreateRightIndexFingerTestObject();
        Assert.NotNull(imageInfo);
        byte[] encoded = imageInfo.GetEncoded()!;
        Assert.NotNull(encoded);
    }

    [Fact]
    public void testEncodeDecode()
    {
        FingerImageInfo testObject = CreateRightIndexFingerTestObject();
        CheckEncodeDecode(testObject);
    }

    [Fact]
    public void testBSI()
    {
        byte[] imageBytes = Fixtures.GetBytes("/lds/wsq/fp.wsq");
        //			BufferedImage image = ImageIO.Read(new MemoryStream(imageBytes));
        //			LOGGER.info("DEBUG: image.GetWidth() = " + image.GetWidth());
        //			LOGGER.info("DEBUG: image.GetHeight() = " + image.GetHeight());
    }

    [Fact]
    public void testCreateExtract()
    {
        FingerImageInfo fingerImageInfo = CreateNonEmptyTestObject();
        Assert.True(fingerImageInfo.GetImageLength() > 0);
        Assert.True(fingerImageInfo.GetWidth() > 0);
        Assert.True(fingerImageInfo.GetHeight() > 0);
    }

    internal static void CheckEncodeDecode(FingerImageInfo original)
    {
        string? mimeType = original.GetMimeType();
        int compressionAlg = 0;

        if ("image/x-wsq".Equals(mimeType))
        {
            compressionAlg = FingerInfo.COMPRESSION_WSQ;
        }
        else if ("image/jpeg".Equals(mimeType))
        {
            compressionAlg = FingerInfo.COMPRESSION_JPEG;
        }
        else if ("image/jpeg2000".Equals(mimeType))
        {
            compressionAlg = FingerInfo.COMPRESSION_JPEG2000;
        }
        else
        {
            Assert.Fail("This test doesn't support this image data type " + mimeType);
        }
        byte[] encoded = original.GetEncoded()!;
        Assert.NotNull(encoded);
        MemoryStream input = new MemoryStream(encoded);
        FingerImageInfo copy = new FingerImageInfo(input, compressionAlg);
        Assert.Equal(original, copy);
        byte[] encodedCopy = copy.GetEncoded()!;
        Assert.NotNull(encodedCopy);
        Assert.Equal(Hex.BytesToHexString(encoded), Hex.BytesToHexString(encodedCopy));
    }

    [Fact]
    public void testWidthHeight()
    {
        FingerImageInfo imageInfo = CreateRightIndexFingerTestObject();
        //      LOGGER.info("DEBUG: imageInfo.GetWidth() = " + imageInfo.GetWidth());
        //      LOGGER.info("DEBUG: imageInfo.GetHeight() = " + imageInfo.GetHeight());
        string? mimeType = imageInfo.GetMimeType();
        Assert.NotNull(mimeType);
        Assert.True("image/x-wsq".Equals(mimeType) || "image/jpeg2000".Equals(mimeType) || "image/jpeg".Equals(mimeType));
    }

    [Fact]
    public void testViewCountAndNumber()
    {
        FingerImageInfo fingerImageInfo = CreateRightIndexFingerTestObject();
        CheckViewCountAndNumber(fingerImageInfo);
    }

    internal static void CheckViewCountAndNumber(FingerImageInfo fingerImageInfo)
    {
        int viewCount = fingerImageInfo.GetViewCount();
        int viewNumber = fingerImageInfo.GetViewCount();
        Assert.True(viewCount >= 1);
        Assert.True(viewNumber <= viewCount);
    }

    [Fact]
    public void testValidType()
    {
        FingerImageInfo portraitInfo = CreateRightIndexFingerTestObject();
        CheckValidType(portraitInfo);
    }

    internal static void CheckValidType(FingerImageInfo imageInfo)
    {
        int type = imageInfo.GetImageType();
        Assert.Equal(ImageInfo.TYPE_FINGER, type);
    }

    [Fact]
    public void testLength()
    {
        FingerImageInfo fingerImageInfo = CreateRightIndexFingerTestObject();
        int imageLength = fingerImageInfo.GetImageLength();
        int recordLength = (int)fingerImageInfo.GetRecordLength();
        Assert.True(imageLength < recordLength);
    }

    public static FingerImageInfo CreateNonEmptyTestObject()
    {
        return CreateNonEmptyTestObject(CreateTrivialJPGBytes(200, 200), 200, 200, "image/jpeg");
    }

    public static string
    JPEG_MIME_TYPE = "image/jpeg",
    JPEG2000_MIME_TYPE = "image/jp2",
    JPEG2000_ALT_MIME_TYPE = "image/jpeg2000",
    WSQ_MIME_TYPE = "image/x-wsq";

    public static FingerImageInfo CreateNonEmptyTestObject(byte[] imageBytes, int width, int height, string mimeType)
    {
        try
        {
            int position = FingerImageInfo.POSITION_RIGHT_INDEX_FINGER;
            int viewCount = 1;
            int viewNumber = 1;
            int quality = 69;
            int impressionType = FingerImageInfo.IMPRESSION_TYPE_LIVE_SCAN_PLAIN;
            int compressionType = -1;

            if (JPEG_MIME_TYPE.Equals(mimeType))
            {
                compressionType = FingerInfo.COMPRESSION_JPEG;
            }
            else if (WSQ_MIME_TYPE.Equals(mimeType))
            {
                compressionType = FingerInfo.COMPRESSION_WSQ;
            }
            else if (JPEG2000_MIME_TYPE.Equals(mimeType) || JPEG2000_ALT_MIME_TYPE.Equals(mimeType))
            {
                compressionType = FingerInfo.COMPRESSION_JPEG2000;
            }

            FingerImageInfo imageInfo = new FingerImageInfo(position, viewCount, viewNumber, quality, impressionType,
                    width, height, new MemoryStream(imageBytes), imageBytes.Length, compressionType);

            return imageInfo;
        }
        catch (IOException ioe)
        {
            Assert.Fail(ioe.Message);
            return null;
        }
    }

    /*
      * Encoding of a 545 x 622 WSQ image.
      */
    private static byte[] GetSampleWSQBytes()
    {
        try
        {
            return Fixtures.GetBytes("/lds/wsq/sample_image.wsq");
        }
        catch (Exception e)
        {
            Assert.Fail(e.Message);
            return null;
        }
    }

    //	/**
    //	 * FIXME: this appears to break j2wsq!
    //	 *
    //	 * @param width
    //	 * @param height
    //	 * @return
    //	 */
    //	private static byte[] createTrivialWSQBytes(int width, int height) {
    //		try {
    //			BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_BYTE_GRAY);
    //			MemoryStream output = new MemoryStream();
    //			// Images.writeImage(image, "image/x-wsq", output);
    //			ImageIO.Write(image, "wsq", output);
    //			output.Flush();
    //			byte[] bytes = output.ToArray();
    //			return bytes;
    //		} catch (Exception e) {
    //			Assert.Fail(e.Message);
    //			return null;
    //		}
    //	}

    /**
      * FIXME: this appears to break j2wsq!
      *
      * @param width
      * @param height
      * @return
      */
    private static byte[] CreateTrivialJPGBytes(int width, int height)
    {
        return TestImages.TrivialJpeg; // Java: a blank image of the given size, encoded with ImageIO
    }

    /*
      * A finger image object containing a WSQ image with position is right index finger.
      */
    public static FingerImageInfo CreateRightIndexFingerTestObject()
    {
        int width = 545;
        int height = 622;
        byte[] imageBytes = GetSampleWSQBytes();
        return CreateNonEmptyTestObject(imageBytes, width, height, WSQ_MIME_TYPE);
    }

    public static FingerImageInfo CreateBSITestObject()
    {
        try
        {
            DG3File dg3 = new DG3File(Fixtures.GetInputStream("/lds/bsi2008/Datagroup3.bin"));
            List<FingerInfo> fingerInfos = dg3.GetFingerInfos();
            FingerInfo fingerInfo = fingerInfos[1];
            List<FingerImageInfo> fingerImageInfos = fingerInfo.GetFingerImageInfos();
            return fingerImageInfos[0];
        }
        catch (Exception e)
        {
            Assert.Fail(e.Message);
            return null!;
        }
    }
}
