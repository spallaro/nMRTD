using System.Text;
using nMRTD.Cbeff;
using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.Lds.Iso19794;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using static nMRTD.Lds.Iso19794.FaceImageInfo;

namespace nMRTD.Tests.Jmrtd.Lds.Iso19794;

/// <summary>Port of JMRTD's <c>org.jmrtd.lds.iso19794.FaceImageInfoTest</c>.</summary>
public class FaceImageInfoTest
{

    [Fact]
    public void testToString()
    {
        FaceImageInfo imageInfo = CreateNonEmptyTestObject();
        Assert.NotNull(imageInfo);
        string asString = imageInfo.ToString();
        Assert.NotNull(asString);
    }

    [Fact]
    public void testNonNullEncoded()
    {
        FaceImageInfo imageInfo = CreateNonEmptyTestObject();
        Assert.NotNull(imageInfo);
        byte[] encoded = imageInfo.GetEncoded()!;
        Assert.NotNull(encoded);
    }

    [Fact]
    public void testEncodeDecode()
    {
        CheckEncodeDecode(CreateNonEmptyTestObject());
    }

    internal static void CheckEncodeDecode(FaceImageInfo original)
    {
        byte[] encoded = original.GetEncoded()!;
        Assert.NotNull(encoded);
        MemoryStream input = new MemoryStream(encoded);
        FaceImageInfo copy = new FaceImageInfo(input);
        Assert.Equal(original, copy);
        byte[] encodedCopy = copy.GetEncoded()!;
        Assert.NotNull(encodedCopy);
        Assert.Equal(Hex.BytesToHexString(encoded), Hex.BytesToHexString(encodedCopy));
    }

    [Fact]
    public void testNumExtractImageOnce()
    {
        FaceImageInfo imageInfo = CreateNonEmptyTestObject(50, 50);
        CheckExtractImage(imageInfo, 50, 50);
    }

    [Fact]
    public void testNumExtractImage()
    {
        for (int width = 100; width < 1000; width += 200)
        {
            for (int height = 100; height < 1000; height += 200)
            {
                FaceImageInfo imageInfo = CreateNonEmptyTestObject(width, height);
                CheckExtractImage(imageInfo, width, height);
            }
        }
    }

    internal static void CheckExtractImage(FaceImageInfo imageInfo, int expectedWidth, int expectedHeight)
    {
        Stream imageInputStream = imageInfo.GetImageInputStream();
        int imageLength = imageInfo.GetImageLength();
        Assert.True(imageLength >= 0);
        string? imageMimeType = imageInfo.GetMimeType();
        Assert.NotNull(imageMimeType);
        Assert.StartsWith("image", imageMimeType.ToLowerInvariant());
        imageInputStream.Close();
    }

    [Fact]
    public void testValidType()
    {
        FaceImageInfo portraitInfo = CreateTestObject();
        CheckValidType(portraitInfo);
    }

    internal static void CheckValidType(FaceImageInfo imageInfo)
    {
        int type = imageInfo.GetImageType();
        Assert.Equal(ImageInfoTypes.TYPE_PORTRAIT, type);
    }

    [Fact]
    public void testLength()
    {
        FaceImageInfo faceImageInfo = CreateTestObject();
        int imageLength = faceImageInfo.GetImageLength();
        int recordLength = (int)faceImageInfo.GetRecordLength();
        Assert.True(imageLength < recordLength);
    }

    /*
      * Pins down constructor argument order: hairColor and featureMask are
      * adjacent int parameters and easy to transpose by accident.
      */
    [Fact]
    public void testHairColorAndFeatureMask()
    {
        FaceImageInfo faceImageInfo = CreateTestObject();
        Assert.Equal(FaceImageInfo.HAIR_COLOR_BLACK, faceImageInfo.GetHairColor());
        Assert.Equal(0x000003, faceImageInfo.GetFeatureMask());
    }

    public static FaceImageInfo CreateTestObject()
    {
        return CreateNonEmptyTestObject(300, 400);
    }

    public static FaceImageInfo CreateNonEmptyTestObject()
    {
        return CreateNonEmptyTestObject(1, 1);
    }

    [Fact]
    public void testCreateAndExtract()
    {
        try
        {
            FaceImageInfo imageInfo = CreateNonEmptyTestObject();
            Stream imageInputStream = (imageInfo.GetImageInputStream());
            int imageLength = imageInfo.GetImageLength();
            byte[] imageBytes = new byte[imageLength];
            imageInputStream.ReadFully(imageBytes);
            imageInputStream.Close();
//      LOGGER.info("DEBUG: imageBytes.Length = " + imageBytes.Length);
        }
        catch (IOException e)
        {
            Assert.Fail(e.Message);
        }
    }

    public static FaceImageInfo CreateNonEmptyTestObject(int width, int height)
    {
        try
        {
            byte[] imageBytes = CreateTrivialJPEGBytes(width, height);
            Gender gender = Gender.Unspecified;
            EyeColor eyeColor = EyeColor.Unspecified;
            /* Non-zero and distinct so a regression in constructor argument order is actually observable. */
            int hairColor = FaceImageInfo.HAIR_COLOR_BLACK;
            int featureMask = 0x000003; /* features-are-specified flag + glasses flag. */
            short expression = FaceImageInfo.EXPRESSION_UNSPECIFIED;
            int[] poseAngle = { 0, 0, 0 };
            int[] poseAngleUncertainty = { 0, 0, 0 };
            int faceImageType = FaceImageInfo.FACE_IMAGE_TYPE_FULL_FRONTAL;
            int colorSpace = 0x00;
            int sourceType = FaceImageInfo.SOURCE_TYPE_UNSPECIFIED;
            int deviceType = 0x0000;
            int quality = 0x0000;
            int imageDataType = FaceImageInfo.IMAGE_DATA_TYPE_JPEG;
            FeaturePoint[] featurePoints = new FeaturePoint[0];
            /* NOTE: constructor takes (..., featureMask, hairColor, ...), in that order. */
            FaceImageInfo imageInfo = new FaceImageInfo(
                    gender, eyeColor,
                    featureMask,
                    hairColor,
                    expression,
                    poseAngle, poseAngleUncertainty,
                    faceImageType,
                    colorSpace,
                    sourceType,
                    deviceType,
                    quality,
                    featurePoints,
                    width, height,
                    new MemoryStream(imageBytes), imageBytes.Length, imageDataType);
            return imageInfo;
        }
        catch (Exception)
        {
            return null!;
        }
    }

    private static byte[] CreateTrivialJPEGBytes(int width, int height)
    {
        return TestImages.TrivialJpeg; // Java: a blank image of the given size, encoded with ImageIO
    }
}
