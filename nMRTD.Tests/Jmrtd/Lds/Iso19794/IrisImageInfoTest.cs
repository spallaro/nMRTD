using System.Text;
using nMRTD.Cbeff;
using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.Lds.Iso19794;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;

namespace nMRTD.Tests.Jmrtd.Lds.Iso19794;

/// <summary>Port of JMRTD's <c>org.jmrtd.lds.iso19794.IrisImageInfoTest</c>.</summary>
public class IrisImageInfoTest
{

    [Fact]
    public void testToString()
    {
        IrisImageInfo info = CreateTestObject();
        Assert.NotNull(info);
        string asString = info.ToString();
        Assert.NotNull(asString);
        Assert.StartsWith("IrisImageInfo", asString);
    }

    [Fact]
    public void testLength()
    {
        IrisImageInfo irisImageInfo = CreateTestObject();
        int imageLength = irisImageInfo.GetImageLength();
        int recordLength = (int)irisImageInfo.GetRecordLength();
        Assert.True(imageLength < recordLength);
    }

    public static IrisImageInfo CreateTestObject()
    {
        try
        {
            byte[] imageBytes = TestImages.TrivialJpeg; // Java: a blank 300x200 image, encoded with ImageIO
            IrisImageInfo irisImageInfo = new IrisImageInfo(1, 300, 200, new MemoryStream(imageBytes), imageBytes.Length, IrisInfo.IMAGEFORMAT_MONO_JPEG);
            return irisImageInfo;
        }
        catch (IOException e)
        {
            Assert.Fail(e.Message);
            return null!;
        }
    }
}
