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

/// <summary>Port of JMRTD's <c>org.jmrtd.lds.icao.ISO39794DG3FileTest</c>.</summary>




[Collection(nMRTD.Tests.Helpers.CbeffDataGroupCollection.Name)]
public class ISO39794DG3FileTest
{

    [Fact]
    public void testISOSampleFingerImageDataBlock()
    {
        CheckFingerImageDataBlock("/lds/dg3/iso39794/sample-39794-4-ed-1-v1.der");
    }

    /*
      * Each image data format has its MIME type (it was never assigned, so always null).
      */
    [Fact]
    public void testFingerImageDataFormatMimeTypes()
    {
        Assert.Equal("image/pgm", MimeTypeOf(FingerImageRepresentationBlock.ImageDataFormatCode.Pgm));
        Assert.Equal("image/x-wsq", MimeTypeOf(FingerImageRepresentationBlock.ImageDataFormatCode.Wsq));
        Assert.Equal("image/jp2", MimeTypeOf(FingerImageRepresentationBlock.ImageDataFormatCode.Jpeg2000Lossy));
        Assert.Equal("image/jp2", MimeTypeOf(FingerImageRepresentationBlock.ImageDataFormatCode.Jpeg2000Lossless));
        Assert.Equal("image/png", MimeTypeOf(FingerImageRepresentationBlock.ImageDataFormatCode.Png));

        Stream inputStream = Fixtures.GetInputStream("/lds/dg3/iso39794/sample-39794-4-ed-1-v1.der");
        Assert.NotNull(inputStream);
        FingerImageDataBlock dataBlock = new FingerImageDataBlock(inputStream);
        Assert.True(dataBlock.GetRepresentationBlocks().Count > 0);
        foreach (FingerImageRepresentationBlock representationBlock in dataBlock.GetRepresentationBlocks())
        {
            Assert.Equal(MimeTypeOf(representationBlock.GetImageDataFormat()!.Value), representationBlock.GetMimeType());
            Assert.NotNull(representationBlock.GetMimeType());
        }
    }

    internal static void CheckFingerImageDataBlock(string resource)
    {
        Stream inputStream = Fixtures.GetInputStream(resource);
        Assert.NotNull(inputStream);
        FingerImageDataBlock dataBlock = new FingerImageDataBlock(inputStream);
        CheckDecodeEncode(dataBlock);
    }

    internal static void CheckDecodeEncode(FingerImageDataBlock fingerImageDataBlock)
    {
        byte[] encoded = fingerImageDataBlock.GetEncoded()!;
        FingerImageDataBlock reconstructed = new FingerImageDataBlock(
                fingerImageDataBlock.GetStandardBiometricHeader(), new MemoryStream(encoded));
        Assert.Equal(fingerImageDataBlock, reconstructed);

        byte[] reEncoded = reconstructed.GetEncoded()!;
        Assert.Equal(encoded.Length, reEncoded.Length);
        Assert.Equal(encoded, reEncoded);
    }

    [Fact]
    public void testCreateISO39794DG3FileWithProfile()
    {
        Stream inputStream = Fixtures.GetInputStream("/lds/dg3/iso39794/sample-39794-4-ed-1-v1.der");
        Assert.NotNull(inputStream);
        FingerImageDataBlock dataBlock = new FingerImageDataBlock(inputStream);

        // Create DG3 file with ICAO profile
        DG3File dg3File = DG3File.CreateISO39794DG3File(
                [dataBlock],
                ISO39794EncodingProfile.Icao39794_5EmrtdV1
        );
        Assert.NotNull(dg3File);

        byte[] encoded = dg3File.GetEncoded()!;
        Assert.NotNull(encoded);

        // Parse it back
        DG3File reconstructed = new DG3File(new MemoryStream(encoded));
        Assert.Single(reconstructed.GetSubRecords());
        Assert.Equal(dataBlock, reconstructed.GetSubRecords()[0]);
    }

    /// <summary>Java's <c>ImageDataFormatCode.getMimeType()</c>; in nMRTD a private static helper of the block.</summary>
    private static string MimeTypeOf(FingerImageRepresentationBlock.ImageDataFormatCode code) =>
        (string)typeof(FingerImageRepresentationBlock)
            .GetMethod("GetMimeType", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static, [typeof(FingerImageRepresentationBlock.ImageDataFormatCode)])!
            .Invoke(null, [code])!;
}
