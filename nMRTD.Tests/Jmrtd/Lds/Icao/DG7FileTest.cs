using System.Text;
using nMRTD.Cbeff;
using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.Lds.Iso19794;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using nMRTD.Tests.Jmrtd.Lds.Iso19794;

namespace nMRTD.Tests.Jmrtd.Lds.Icao;

/// <summary>Port of JMRTD's <c>org.jmrtd.lds.icao.DG7FileTest</c>.</summary>
public class DG7FileTest
{

    [Fact]
    public void testToString()
    {
        CheckToString(CreateEmptyTestObject(), "DG7File []");
    }

    internal static void CheckToString(DG7File dg7File, string expectedResult)
    {
        Assert.NotNull(dg7File);
        Assert.Equal(dg7File.ToString(), expectedResult);
    }

    [Fact]
    public void testType()
    {
        CheckType(CreateEmptyTestObject());

        DG7File dg7 = CreateNumTestObject(1);
        CheckType(dg7);
    }

    internal static void CheckType(DG7File dg7File)
    {
        Assert.NotNull(dg7File);
        List<DisplayedImageInfo> displayedImageInfos = dg7File.GetImages();
        foreach (DisplayedImageInfo displayedImageInfo in displayedImageInfos)
        {
            Assert.Equal(ImageInfo.TYPE_SIGNATURE_OR_MARK, displayedImageInfo.GetImageType());
        }
    }

    [Fact]
    public void testNonNullEncoded()
    {
        DG7File dg7File = CreateEmptyTestObject();
        Assert.NotNull(dg7File);
        byte[] encoded = dg7File.GetEncoded()!;
        Assert.NotNull(encoded);
    }

    [Fact]
    public void testReflexive()
    {
        CheckEncodeDecode(CreateEmptyTestObject());
    }

    [Fact]
    public void testNum()
    {
        for (int n = 1; n < 10; n++)
        {
            DG7File dg7File = CreateNumTestObject(n);
            Assert.NotNull(dg7File);
            List<DisplayedImageInfo> imageInfos = dg7File.GetImages();
            Assert.NotNull(imageInfos);
            Assert.Equal(imageInfos.Count, n);
            CheckEncodeDecode(dg7File);
            CheckElements(dg7File);
        }
    }

    internal static void CheckElements(DG7File dg7File)
    {
        Assert.NotNull(dg7File);
        List<DisplayedImageInfo> imageInfos = dg7File.GetImages();
        foreach (DisplayedImageInfo imageInfo in imageInfos)
        {
            Assert.NotNull(imageInfo);
        }
    }

    internal static void CheckEncodeDecode(DG7File dg7File)
    {
        byte[] encoded = dg7File.GetEncoded()!;
        Assert.NotNull(encoded);
        MemoryStream input = new MemoryStream(encoded);
        DG7File copy = new DG7File(input);
        Assert.Equal(dg7File, copy);
        byte[] encodedCopy = copy.GetEncoded()!;
        Assert.NotNull(encodedCopy);
        Assert.Equal(Hex.BytesToHexString(encoded), Hex.BytesToHexString(encodedCopy));
    }

    [Fact]
    public void testCreate()
    {
        DG7File dg7 = CreateTestObject();
        byte[] header = new byte[256];
        Array.Copy(dg7.GetEncoded()!, 0, header, 0, header.Length);
//      LOGGER.info(Hex.bytesToPrettyString(header));
    }

    public static DG7File CreateEmptyTestObject()
    {
        List<DisplayedImageInfo> images = new List<DisplayedImageInfo>();
        return new DG7File(images);
    }

    public static DG7File CreateNumTestObject(int n)
    {
        List<DisplayedImageInfo> images = new List<DisplayedImageInfo>();
        for (int i = 0; i < n; i++)
        {
            byte[] imageBytes = new byte[0];
            DisplayedImageInfo imageInfo = new DisplayedImageInfo(ImageInfo.TYPE_SIGNATURE_OR_MARK, imageBytes);
            images.Add(imageInfo);
        }
        DG7File dg7File = new DG7File(images);
        return dg7File;
    }

    public static DG7File CreateTestObject()
    {
        byte[] image = CreateTrivialJPEGBytes(958, 208);
        DisplayedImageInfo imageInfo = new DisplayedImageInfo(ImageInfo.TYPE_SIGNATURE_OR_MARK, image);
        DG7File dg7File = new DG7File(new List<DisplayedImageInfo> { imageInfo });
        return dg7File;
    }

    internal static void CheckFile(Stream input)
    {
        CheckEncodeDecode(new DG7File(input));
    }

    private static byte[] CreateTrivialJPEGBytes(int width, int height)
    {
        try
        {
            return TestImages.TrivialJpeg; // Java: a blank image of the given size, encoded with ImageIO
        }
        catch (Exception e)
        {
            Assert.Fail(e.Message);
            return null;
        }
    }
}
