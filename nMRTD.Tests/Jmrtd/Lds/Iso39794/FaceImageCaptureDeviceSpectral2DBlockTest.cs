using System.Text;
using nMRTD.Cbeff;
using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.Lds.Iso19794;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using nMRTD.Tests.Jmrtd.Lds.Icao;
using nMRTD.Lds.Iso39794;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;

namespace nMRTD.Tests.Jmrtd.Lds.Iso39794;

/// <summary>Port of JMRTD's <c>org.jmrtd.lds.iso39794.FaceImageCaptureDeviceSpectral2DBlockTest</c>.</summary>
public class FaceImageCaptureDeviceSpectral2DBlockTest
{

    /*
      * The Boolean fields are compared by value (they were compared with ==, which only
      * worked for the cached Boolean.TRUE and Boolean.FALSE instances).
      */
    [Fact]
    public void testEqualsComparesBooleanValues()
    {
        FaceImageCaptureDeviceSpectral2DBlock block = new FaceImageCaptureDeviceSpectral2DBlock(true, false, null);
        FaceImageCaptureDeviceSpectral2DBlock sameValues = new FaceImageCaptureDeviceSpectral2DBlock((bool?)true, (bool?)false, null);

        Assert.Equal(block, sameValues);
        Assert.Equal(block.GetHashCode(), sameValues.GetHashCode());
    }

    [Fact]
    public void testEqualsDistinguishesValues()
    {
        FaceImageCaptureDeviceSpectral2DBlock block = new FaceImageCaptureDeviceSpectral2DBlock(true, false, null);

        Assert.NotEqual(block, new FaceImageCaptureDeviceSpectral2DBlock(true, true, null));
        Assert.NotEqual(block, new FaceImageCaptureDeviceSpectral2DBlock(true, false, false));
    }
}
