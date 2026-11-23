using nMRTD.Lds.Icao;
using nMRTD.Lds.Iso19794;
using nMRTD.Tests.Helpers;

namespace nMRTD.Tests;

/// <summary>
/// ISO/IEC 19794-6 iris records: every header field takes part in equality, and a record with
/// non-default values survives an encode and decode round trip through DG4.
/// </summary>
public class Iso19794IrisTests
{
    // captureDeviceId, horizontalOrientation, verticalOrientation, scanType, irisOcclusion, occlusionFilling,
    // boundaryExtraction, irisDiameter, imageFormat, rawImageWidth, rawImageHeight, intensityDepth, imageTransformation
    private static readonly int[] Fields =
    [
        7, IrisInfo.ORIENTATION_BASE, IrisInfo.ORIENTATION_FLIPPED, IrisInfo.SCAN_TYPE_PROGRESSIVE, IrisInfo.IROCC_PROCESSED,
        IrisInfo.IROC_UNITFILL, IrisInfo.IRBNDY_PROCESSED, 210, IrisInfo.IMAGEFORMAT_MONO_JPEG, 640, 480, 8, IrisInfo.TRANS_STD,
    ];

    private static readonly byte[] DeviceUniqueId = [.. "D0123456789ABCDE"u8];

    private static IrisInfo Iris(int[] fields, byte[]? deviceUniqueId = null)
    {
        byte[] image = TestImages.TrivialJpeg;
        var subtype = new IrisBiometricSubtypeInfo(IrisBiometricSubtypeInfo.EYE_RIGHT, fields[8],
            [new IrisImageInfo(1, 90, 300, 200, 300, 200, new MemoryStream(image), image.Length, fields[8])]);
        return new IrisInfo(fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6], fields[7],
            fields[8], fields[9], fields[10], fields[11], fields[12], deviceUniqueId ?? DeviceUniqueId, [subtype]);
    }

    [Fact]
    public void RecordRoundTripsThroughDG4()
    {
        IrisInfo iris = Iris(Fields);

        var copy = new DG4File(new MemoryStream(new DG4File([iris]).GetEncoded()!));

        IrisInfo decoded = Assert.Single(copy.GetIrisInfos());
        Assert.Equal(iris, decoded);
        Assert.Equal(iris.GetHashCode(), decoded.GetHashCode());
        Assert.Equal(DeviceUniqueId, decoded.GetDeviceUniqueId());
        Assert.Equal(210, decoded.GetIrisDiameter());
        Assert.NotNull(decoded.ToString());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(7)]
    [InlineData(9)]
    [InlineData(10)]
    [InlineData(11)]
    [InlineData(12)]
    public void EachHeaderFieldTakesPartInEquality(int field)
    {
        int[] changed = [.. Fields];
        changed[field] ^= 0x01;

        Assert.NotEqual(Iris(Fields), Iris(changed));
    }

    [Fact]
    public void ImageFormatAndDeviceIdTakePartInEquality()
    {
        int[] otherFormat = [.. Fields];
        otherFormat[8] = IrisInfo.IMAGEFORMAT_RGB_JPEG;

        Assert.NotEqual(Iris(Fields), Iris(otherFormat));
        Assert.NotEqual(Iris(Fields), Iris(Fields, [.. "D0123456789ABCDF"u8]));
        Assert.Equal(Iris(Fields), Iris(Fields));
        Assert.False(Iris(Fields).Equals(null));
    }

    [Fact]
    public void MissingSubtypeListIsRejected() =>
        Assert.Throws<ArgumentException>(() => new IrisInfo(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, DeviceUniqueId, null));
}
