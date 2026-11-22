using System.Text;
using nMRTD.Lds.Icao;
using nMRTD.Lds.Iso39794;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Asn1;
using static nMRTD.Lds.Iso39794.PADDataBlock;

namespace nMRTD.Tests;

/// <summary>
/// ISO/IEC 39794-6 iris blocks with every optional element present: range, capture device, quality,
/// roll angle, iris localisation and PAD data. The JMRTD sample has none of them. Each block must decode
/// and encode back to the same bytes, and compare equal to a second decode.
/// </summary>
public class Iso39794IrisTests
{
    private const string Sample = "/lds/dg4/iso39794/sample-39794-6-ed-1-v1.der";

    private static Asn1Encodable Tagged(params (int Tag, Asn1Encodable Value)[] items) =>
        ASN1Util.EncodeTaggedObjects(items.ToDictionary(i => i.Tag, i => i.Value))!;

    private static Asn1Encodable Int(int value) => ASN1Util.EncodeInt(value);

    private static PADDataBlock PadData() => new(
        PADDecisionCode.NoAttack,
        [new PADScoreBlock(new RegistryIdBlock(1, 1), 99)],
        [new ExtendedDataBlock(new RegistryIdBlock(1, 1), Encoding.UTF8.GetBytes("extended"))],
        PADCaptureContextCode.Verification,
        PADSupervisionLevelCode.Assisted,
        3,
        PADCriteriaCategoryCode.Common,
        Encoding.UTF8.GetBytes("parameters"),
        [Encoding.UTF8.GetBytes("challenge")],
        new DateTimeBlock(2026, 11, 22, 10, 11, 12, 13));

    /// <summary>The sample's first representation block, with the optional elements [9]-[14] added.
    /// <paramref name="rangeOrError"/> is either a range ([0]) or a ranging error ([1]).</summary>
    private static Asn1Encodable FullRepresentationBlock((int Tag, int Value) rangeOrError)
    {
        var sample = new IrisImageDataBlock(Fixtures.GetInputStream(Sample));
        Dictionary<int, Asn1Encodable> elements = ASN1Util.DecodeTaggedObjects(sample.GetRepresentationBlocks()[0].GetAsn1Object());
        elements[9] = Tagged((rangeOrError.Tag, Int(rangeOrError.Value)));
        elements[10] = Tagged(
            (0, new RegistryIdBlock(257, 1).GetAsn1Object()),
            (1, ISO39794Util.EncodeCodeAsChoiceExtensionBlockFallback((int)IrisImageCaptureDeviceBlock.CaptureDeviceTechnologyIdCode.CmosCcd)),
            (2, new DerSequence(new RegistryIdBlock(257, 2).GetAsn1Object(), new RegistryIdBlock(257, 3).GetAsn1Object())));
        elements[11] = new DerSequence(new QualityBlock(new RegistryIdBlock(257, 4), 80).GetAsn1Object(),
            new QualityBlock(new RegistryIdBlock(257, 5), -1).GetAsn1Object());
        elements[12] = new IrisImageRepresentationBlock.RollAngleBlock(1234, 56).GetAsn1Object();
        elements[13] = Tagged((0, Int(300)), (1, Int(310)), (2, Int(200)), (3, Int(210)), (4, Int(120)), (5, Int(130)));
        elements[14] = PadData().GetAsn1Object();
        return ASN1Util.EncodeTaggedObjects(elements)!;
    }

    private static byte[] Der(Asn1Encodable asn1) => asn1.ToAsn1Object().GetDerEncoded();

    [Theory]
    [InlineData(0, 1500)] // range in mm
    [InlineData(1, (int)IrisImageRepresentationBlock.RangingErrorCode.Overflow)]
    public void RepresentationBlockWithAllOptionalElementsRoundTrips(int rangeTag, int value)
    {
        Asn1Encodable encoded = FullRepresentationBlock((rangeTag, value));

        var block = new IrisImageRepresentationBlock(encoded);
        var again = new IrisImageRepresentationBlock(Asn1Object.FromByteArray(Der(encoded)));

        Assert.Equal(Der(encoded), Der(block.GetAsn1Object()));
        Assert.Equal(block, again);
        Assert.Equal(block.GetHashCode(), again.GetHashCode());
        Assert.NotEqual(block, new IrisImageRepresentationBlock(FullRepresentationBlock((rangeTag, value + 1))));
        Assert.Contains("imageData", block.ToString());
    }

    [Fact]
    public void OptionalSubBlocksDecode()
    {
        var block = new IrisImageRepresentationBlock(FullRepresentationBlock((0, 1500)));
        Dictionary<int, Asn1Encodable> elements = ASN1Util.DecodeTaggedObjects(block.GetAsn1Object());

        var localisation = new IrisImageLocalisationBlock(elements[13]);
        Assert.Equal(300, localisation.GetIrisCenterXSmallest());
        Assert.Equal(310, localisation.GetIrisCenterXLargest());
        Assert.Equal(200, localisation.GetIrisCenterYSmallest());
        Assert.Equal(210, localisation.GetIrisCenterYLargest());
        Assert.Equal(120, localisation.GetIrisDiameterSmallest());
        Assert.Equal(130, localisation.GetIrisDiameterLargest());
        Assert.Equal(localisation, new IrisImageLocalisationBlock(localisation.GetAsn1Object()));
        Assert.Equal(localisation.GetHashCode(), new IrisImageLocalisationBlock(localisation.GetAsn1Object()).GetHashCode());
        Assert.Contains("310", localisation.ToString());

        var captureDevice = new IrisImageCaptureDeviceBlock(elements[10]);
        Assert.Equal(new RegistryIdBlock(257, 1), captureDevice.GetModel());
        Assert.Equal(IrisImageCaptureDeviceBlock.CaptureDeviceTechnologyIdCode.CmosCcd, captureDevice.GetCaptureDeviceTechnologyIdCode());
        Assert.Equal(2, captureDevice.GetCertifications()!.Count);
        Assert.Equal(captureDevice, new IrisImageCaptureDeviceBlock(captureDevice.GetAsn1Object()));
        Assert.Equal(captureDevice.GetHashCode(), new IrisImageCaptureDeviceBlock(captureDevice.GetAsn1Object()).GetHashCode());
        Assert.NotEqual(captureDevice, new IrisImageCaptureDeviceBlock(Tagged((0, new RegistryIdBlock(257, 1).GetAsn1Object()))));
        Assert.Contains("CmosCcd", captureDevice.ToString());
    }

    /// <summary>A whole DG4 with the full block, in both encoding profiles.</summary>
    [Theory]
    [InlineData(ISO39794EncodingProfile.Base)]
    [InlineData(ISO39794EncodingProfile.Icao39794_5EmrtdV1)]
    public void DG4WithAllOptionalElementsRoundTrips(ISO39794EncodingProfile profile)
    {
        var sample = new IrisImageDataBlock(Fixtures.GetInputStream(Sample));
        Dictionary<int, Asn1Encodable> dataBlock = ASN1Util.DecodeTaggedObjects(
            ASN1Util.CheckTag(sample.GetAsn1Object(), Asn1Tags.Application, 6));
        dataBlock[1] = new DerSequence(FullRepresentationBlock((0, 1500)).ToAsn1Object());
        byte[] encoded = new DerTaggedObject(false, Asn1Tags.Application, 6,
            (Asn1Encodable)ASN1Util.EncodeTaggedObjects(dataBlock)!).GetEncoded(Asn1Encodable.Der);
        var full = new IrisImageDataBlock(new MemoryStream(encoded));

        DG4File dg4 = DG4File.CreateISO39794DG4File([full], profile);
        var copy = new DG4File(new MemoryStream(dg4.GetEncoded()!));

        var decoded = Assert.IsType<IrisImageDataBlock>(Assert.Single(copy.GetSubRecords()));
        Assert.Equal(full, decoded);
        Assert.Equal(full.GetHashCode(), decoded.GetHashCode());
        // The profile is not recorded in the data, so a decoded file re-encodes with the default
        // profile; encoding the decoded block with the same profile gives the same bytes.
        Assert.Equal(dg4.GetEncoded(), DG4File.CreateISO39794DG4File([decoded], profile).GetEncoded());
    }
}
