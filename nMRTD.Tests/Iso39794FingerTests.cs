using System.Text;
using nMRTD.Lds.Icao;
using nMRTD.Lds.Iso39794;
using Org.BouncyCastle.Asn1;
using static nMRTD.Lds.Iso39794.FingerImageRepresentationBlock;
using static nMRTD.Lds.Iso39794.PADDataBlock;

namespace nMRTD.Tests;

/// <summary>
/// ISO/IEC 39794-4 finger blocks with every optional element present: capture date and device,
/// quality, spatial sampling rate, position and rotation flags, segmentation with segments, annotations,
/// PAD data, comments and vendor specific data. Each must survive an encode and decode round trip, in
/// both encoding profiles, and keep the Equals and GetHashCode contract.
/// </summary>
public class Iso39794FingerTests
{
    private static FingerImageSegmentBlock Segment(FingerImagePositionCode position, int confidence) => new(
        position,
        [new CoordinateCartesian2DUnsignedShortBlock(10, 20), new CoordinateCartesian2DUnsignedShortBlock(110, 20),
         new CoordinateCartesian2DUnsignedShortBlock(110, 220), new CoordinateCartesian2DUnsignedShortBlock(10, 220)],
        15,
        [new QualityBlock(new RegistryIdBlock(257, 7), 70)],
        confidence);

    private static FingerImageSegmentationBlock Segmentation() => new(ASN1Util.EncodeTaggedObjects(new()
    {
        [0] = new RegistryIdBlock(257, 6).GetAsn1Object(),
        [1] = new DerSequence(Segment(FingerImagePositionCode.RightIndexFinger, 90).GetAsn1Object(),
            Segment(FingerImagePositionCode.RightMiddleFinger, -1).GetAsn1Object()),
    })!);

    private static FingerImageRepresentationBlock Full(byte[] imageData, int rotation = 12) => new(
        FingerImagePositionCode.RightIndexFinger,
        ImpressionCode.RolledContact,
        ImageDataFormatCode.Wsq,
        new DateTimeBlock(2026, 11, 22, 9, 8, 7, 6),
        new FingerImageCaptureDeviceBlock(new RegistryIdBlock(257, 1),
            FingerImageCaptureDeviceBlock.CaptureDeviceTechnologyIdCode.OpticalTirBrightField,
            [new RegistryIdBlock(257, 2), new RegistryIdBlock(257, 3)]),
        [new QualityBlock(new RegistryIdBlock(257, 4), 85), new QualityBlock(new RegistryIdBlock(257, 5), -1)],
        new FingerImageSpatialSamplingRateBlock(500, FingerImageSpatialSamplingRateBlock.UnitDimensionCode.Inch),
        true,
        rotation,
        false,
        true,
        [Segmentation()],
        [new FingerImageAnnotationBlock(FingerImagePositionCode.RightThumbFinger, FingerImageAnnotationBlock.AnnotationReasonCode.Amputated)],
        new PADDataBlock(PADDecisionCode.NoAttack, [new PADScoreBlock(new RegistryIdBlock(257, 8), 95)], null,
            PADCaptureContextCode.Verification, PADSupervisionLevelCode.Observed, 2, PADCriteriaCategoryCode.Common,
            null, [Encoding.ASCII.GetBytes("challenge")], null),
        imageData,
        ["first comment", "second comment"],
        [new ExtendedDataBlock(new RegistryIdBlock(257, 9), Encoding.ASCII.GetBytes("vendor data"))]);

    private static FingerImageDataBlock DataBlock(FingerImageRepresentationBlock representation) =>
        new(new VersionBlock(1, 2019), [representation], null);

    [Theory]
    [InlineData(ISO39794EncodingProfile.Base)]
    [InlineData(ISO39794EncodingProfile.Icao39794_5EmrtdV1)]
    public void DG3WithAllOptionalElementsRoundTrips(ISO39794EncodingProfile profile)
    {
        FingerImageDataBlock original = DataBlock(Full([0x01, 0x02, 0x03, 0x04]));
        DG3File dg3 = DG3File.CreateISO39794DG3File([original], profile);

        var copy = new DG3File(new MemoryStream(dg3.GetEncoded()!));

        var decoded = Assert.IsType<FingerImageDataBlock>(Assert.Single(copy.GetSubRecords()));
        Assert.Equal(original.GetRepresentationBlocks()[0], decoded.GetRepresentationBlocks()[0]);
        Assert.Equal(original.GetRepresentationBlocks()[0].GetHashCode(), decoded.GetRepresentationBlocks()[0].GetHashCode());
        Assert.Equal(dg3.GetEncoded(), DG3File.CreateISO39794DG3File([decoded], profile).GetEncoded());
    }

    [Fact]
    public void DecodedElementsAreTheOriginalOnes()
    {
        FingerImageRepresentationBlock original = Full([0x0A, 0x0B]);
        byte[] encoded = DataBlock(original).GetEncoded()!;

        FingerImageRepresentationBlock decoded = new FingerImageDataBlock(new MemoryStream(encoded)).GetRepresentationBlocks()[0];

        Assert.Equal(12, decoded.GetFingerRotation());
        Assert.Equal(["first comment", "second comment"], decoded.GetCommentBlocks()!);
        FingerImageSegmentationBlock segmentation = Assert.Single(decoded.GetSegmentationBlocks()!);
        Assert.Equal(new RegistryIdBlock(257, 6), segmentation.GetAlgorithmIdBlock());
        Assert.Equal(2, segmentation.GetSegmentBlocks().Count);
        Assert.Equal(4, segmentation.GetSegmentBlocks()[0].GetEnclosingCoordinatesBlock()!.Count);
        Assert.Equal(15, segmentation.GetSegmentBlocks()[0].GetOrientation());
        Assert.Equal(original.GetCaptureDeviceBlock(), decoded.GetCaptureDeviceBlock());
        Assert.Equal(original.GetSpatialSamplingRateBlock(), decoded.GetSpatialSamplingRateBlock());
        Assert.Equal(original.GetAnnotationBlocks(), decoded.GetAnnotationBlocks());
        Assert.Equal(original.GetPadDataBlock(), decoded.GetPadDataBlock());
        Assert.Contains("first comment", decoded.ToString());
    }

    [Fact]
    public void DifferentElementsAreNotEqual()
    {
        FingerImageRepresentationBlock block = Full([0x01]);

        Assert.Equal(block, Full([0x01]));
        Assert.Equal(block.GetHashCode(), Full([0x01]).GetHashCode());
        Assert.NotEqual(block, Full([0x02]));
        Assert.NotEqual(block, Full([0x01], rotation: 13));
        Assert.NotEqual(Segmentation().GetSegmentBlocks()[0], Segmentation().GetSegmentBlocks()[1]);
        Assert.Equal(Segmentation(), Segmentation());
        Assert.Equal(Segmentation().GetHashCode(), Segmentation().GetHashCode());
    }
}
