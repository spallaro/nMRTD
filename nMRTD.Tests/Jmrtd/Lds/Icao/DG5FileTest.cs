using System.Text;
using nMRTD.Cbeff;
using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.Lds.Iso19794;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using nMRTD.Tests.Jmrtd.Lds.Iso19794;

namespace nMRTD.Tests.Jmrtd.Lds.Icao;

/// <summary>Port of JMRTD's <c>org.jmrtd.lds.icao.DG5FileTest</c>.</summary>
public class DG5FileTest
{

    [Fact]
    public void testDG5File()
    {
        byte[] imageBytes = { 0x01, 0x02 };
        DisplayedImageInfo image = new DisplayedImageInfo(ImageInfo.TYPE_PORTRAIT, imageBytes);
        List<DisplayedImageInfo> images = new List<DisplayedImageInfo> { image };
        DG5File dg5File = new DG5File(images);

        Assert.Equal(LDSFile.EF_DG5_TAG, dg5File.GetTag());
        Assert.Equal(new List<DisplayedImageInfo>(images), dg5File.GetImages());

        byte[] expectedEncoded = { 0x65, 0x08, 0x02, 0x01, 0x01, 0x5F, 0x40, 0x02, 0x01, 0x02 };

        Assert.True(Enumerable.SequenceEqual(expectedEncoded, dg5File.GetEncoded()!));
    }

    [Fact]
    public void testDG5FileDecode()
    {
        byte[] encoded = { 0x65, 0x08, 0x02, 0x01, 0x01, 0x5F, 0x40, 0x02, 0x01, 0x02 };
        DG5File dg5File = new DG5File(new MemoryStream(encoded));
        Assert.Equal(LDSFile.EF_DG5_TAG, dg5File.GetTag());

        byte[] imageBytes = { 0x01, 0x02 };
        DisplayedImageInfo image = new DisplayedImageInfo(ImageInfo.TYPE_PORTRAIT, imageBytes);
        List<DisplayedImageInfo> expectedImages = new List<DisplayedImageInfo> { image };
        Assert.Equal(new List<DisplayedImageInfo>(expectedImages), dg5File.GetImages());
    }

}
