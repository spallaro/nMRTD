using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.Lds.Iso39794;
using Org.BouncyCastle.Math;
using static nMRTD.Tests.Helpers.TestData;

namespace nMRTD.Tests;

public class Iso39794Tests
{
    /// <summary>Regression (review fix 7): the ISO/IEC 39794 block types must be public.</summary>
    [Fact]
    public void Dg2CanBeBuiltAndPhotoReadBackThroughPublicApi()
    {
        byte[] jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46];
        var info = new FaceImageInformation2DBlock(
            FaceImageInformation2DBlock.ImageDataFormatCode.Jpeg,
            FaceImageInformation2DBlock.FaceImageKind2DCode.Mrtd,
            null, null, null, null, null, null, null, null, null);
        var rep2d = new FaceImageRepresentation2DBlock(jpeg, info, null);
        var rep = new FaceImageRepresentationBlock(BigInteger.One, rep2d, null, null, null, null, null, null, null, null);
        var dataBlock = new FaceImageDataBlock(new VersionBlock(3, 2019), new List<FaceImageRepresentationBlock> { rep }, null);
        byte[] dg2 = DG2File.CreateISO39794DG2File(new List<FaceImageDataBlock> { dataBlock }).GetEncoded()!;

        var parsed = new DG2File(new MemoryStream(dg2));
        var block = Assert.IsType<FaceImageDataBlock>(parsed.GetSubRecords()[0]);
        Assert.Equal(3, block.GetVersionBlock().GetGeneration());
        ImageInfo image = block.GetRepresentationBlocks()[0];
        Assert.Equal("image/jpeg", image.GetMimeType());
        Assert.Equal(jpeg, ReadAll(image.GetImageInputStream()));
    }
}
