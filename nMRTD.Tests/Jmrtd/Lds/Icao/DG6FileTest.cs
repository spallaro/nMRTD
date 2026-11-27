using System.Text;
using nMRTD.Cbeff;
using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.Lds.Iso19794;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using nMRTD.Tests.Jmrtd.Lds.Iso19794;

namespace nMRTD.Tests.Jmrtd.Lds.Icao;

/// <summary>Port of JMRTD's <c>org.jmrtd.lds.icao.DG6FileTest</c>.</summary>
public class DG6FileTest
{

    [Fact]
    public void testDG6File()
    {

        byte[] encoded = { 0x66, 0x08, 0x02, 0x01, 0x01, 0x5F, 0x40, 0x02, 0x01, 0x02 }; // NOTE: Uses 5F40, i.e. portrait. Not sure if DG6 is supposed to hold portrait images...
        DG6File dg6File = new DG6File(new MemoryStream(encoded));

        Assert.Equal(LDSFileTags.EF_DG6_TAG, dg6File.GetTag());

        byte[] imageBytes = { 0x01, 0x02 };
        DisplayedImageInfo image = new DisplayedImageInfo(ImageInfoTypes.TYPE_PORTRAIT, imageBytes);
        List<DisplayedImageInfo> expectedImages = new List<DisplayedImageInfo> { image };

        Assert.Equal(expectedImages, dg6File.GetImages());

    }
}
