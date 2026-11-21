using System.Text;
using nMRTD.Cbeff;
using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.Lds.Iso19794;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using nMRTD.Tests.Jmrtd.Lds.Icao;
using nMRTD.Lds.Iso39794;
using static nMRTD.Lds.Iso39794.FaceImageCaptureDevice2DBlock;
using static nMRTD.Lds.Iso39794.FaceImageIdentityMetadataBlock;
using static nMRTD.Lds.Iso39794.FaceImageLandmarkKind;
using static nMRTD.Lds.Iso39794.FaceImagePoseAngleBlock;
using static nMRTD.Lds.Iso39794.PADDataBlock;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;

namespace nMRTD.Tests.Jmrtd.Lds.Icao;

/// <summary>Port of JMRTD's <c>org.jmrtd.lds.icao.ISO39794DG4FileTest</c>.</summary>




[Collection(nMRTD.Tests.Helpers.CbeffDataGroupCollection.Name)]
public class ISO39794DG4FileTest
{

    [Fact]
    public void testLegacyDG4FixtureContainsTwoIrisRecords()
    {
        DG4File dg4File = DG4FileTest.GetTestObject();
        Assert.Equal(2, dg4File.GetIrisInfos().Count);
    }

    [Fact]
    public void testISOSampleIrisImageDataBlock()
    {
        CheckIrisImageDataBlock("/lds/dg4/iso39794/sample-39794-6-ed-1-v1.der");
    }

    /*
      * toString shows the length of the image data (the null check was inverted, so it showed
      * "null" when there was image data).
      */
    [Fact]
    public void testIrisImageRepresentationBlockToStringShowsImageDataLength()
    {
        Stream inputStream = Fixtures.GetInputStream("/lds/dg4/iso39794/sample-39794-6-ed-1-v1.der");
        Assert.NotNull(inputStream);
        IrisImageDataBlock dataBlock = new IrisImageDataBlock(inputStream);
        Assert.True(dataBlock.GetRepresentationBlocks().Count > 0);
        foreach (IrisImageRepresentationBlock representationBlock in dataBlock.GetRepresentationBlocks())
        {
            Assert.NotNull(representationBlock.GetImageData());
            Assert.Contains("imageData: " + representationBlock.GetImageData()!.Length, representationBlock.ToString());
        }
    }

    internal static void CheckIrisImageDataBlock(string resource)
    {
        Stream inputStream = Fixtures.GetInputStream(resource);
        Assert.NotNull(inputStream);
        IrisImageDataBlock dataBlock = new IrisImageDataBlock(inputStream);
        CheckDecodeEncode(dataBlock);
    }

    internal static void CheckDecodeEncode(IrisImageDataBlock irisImageDataBlock)
    {
        byte[] encoded = irisImageDataBlock.GetEncoded()!;
        IrisImageDataBlock reconstructed = new IrisImageDataBlock(
                irisImageDataBlock.GetStandardBiometricHeader(), new MemoryStream(encoded));
        Assert.Equal(irisImageDataBlock, reconstructed);

        byte[] reEncoded = reconstructed.GetEncoded()!;
        Assert.Equal(encoded.Length, reEncoded.Length);
        Assert.Equal(encoded, reEncoded);
    }

    [Fact]
    public void testCreateISO39794DG4FileWithProfile()
    {
        Stream inputStream = Fixtures.GetInputStream("/lds/dg4/iso39794/sample-39794-6-ed-1-v1.der");
        Assert.NotNull(inputStream);
        IrisImageDataBlock dataBlock = new IrisImageDataBlock(inputStream);

        // Create DG4 file with ICAO profile
        DG4File dg4File = DG4File.CreateISO39794DG4File(
                [dataBlock],
                ISO39794EncodingProfile.Icao39794_5EmrtdV1
        );
        Assert.NotNull(dg4File);

        byte[] encoded = dg4File.GetEncoded()!;
        Assert.NotNull(encoded);

        // Parse it back
        DG4File reconstructed = new DG4File(new MemoryStream(encoded));
        Assert.Single(reconstructed.GetSubRecords());
        Assert.Equal(dataBlock, reconstructed.GetSubRecords()[0]);
    }
}
