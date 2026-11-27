using nMRTD.Cbeff;
using nMRTD.Lds;
using nMRTD.Lds.Iso39794;

namespace nMRTD.Tests;

#pragma warning disable CS0618 // The obsolete forwarders are what is tested.

/// <summary>
/// The constants and static methods that were on interfaces (<see cref="LDSFile"/>, <see cref="ImageInfo"/>,
/// <see cref="CBEFFInfo{R}"/>, <see cref="FaceImageLandmarkCoordinates"/>) moved to static classes, because .NET
/// Framework does not allow static members in interfaces. On the other targets the old members are kept as
/// obsolete forwarders, with the same values.
/// </summary>
public class ObsoleteForwardersTests
{
#if !NETFRAMEWORK
    [Fact]
    public void LdsFileTagsAreForwarded()
    {
        Assert.Equal(LDSFileTags.EF_COM_TAG, LDSFile.EF_COM_TAG);
        Assert.Equal(LDSFileTags.EF_DG1_TAG, LDSFile.EF_DG1_TAG);
        Assert.Equal(LDSFileTags.EF_DG2_TAG, LDSFile.EF_DG2_TAG);
        Assert.Equal(LDSFileTags.EF_DG16_TAG, LDSFile.EF_DG16_TAG);
        Assert.Equal(LDSFileTags.EF_SOD_TAG, LDSFile.EF_SOD_TAG);

        // Still constants, so existing switch statements compile.
        int tag = 0x61;
        switch (tag)
        {
            case LDSFile.EF_DG1_TAG:
                break;
            default:
                Assert.Fail("not a constant");
                break;
        }
    }

    [Fact]
    public void ImageInfoTypesAreForwarded()
    {
        Assert.Equal(ImageInfoTypes.JPEG_MIME_TYPE, ImageInfo.JPEG_MIME_TYPE);
        Assert.Equal(ImageInfoTypes.JPEG2000_MIME_TYPE, ImageInfo.JPEG2000_MIME_TYPE);
        Assert.Equal(ImageInfoTypes.WSQ_MIME_TYPE, ImageInfo.WSQ_MIME_TYPE);
        Assert.Equal(ImageInfoTypes.TYPE_PORTRAIT, ImageInfo.TYPE_PORTRAIT);
        Assert.Equal(ImageInfoTypes.TYPE_IRIS, ImageInfo.TYPE_IRIS);
    }

    [Fact]
    public void CbeffBiometricTypesAreForwarded()
    {
        Assert.Equal(CBEFFBiometricTypes.BIOMETRIC_TYPE_FACIAL_FEATURES, CBEFFInfo<BiometricDataBlock>.BIOMETRIC_TYPE_FACIAL_FEATURES);
        Assert.Equal(CBEFFBiometricTypes.BIOMETRIC_TYPE_FINGERPRINT, CBEFFInfo<BiometricDataBlock>.BIOMETRIC_TYPE_FINGERPRINT);
        Assert.Equal(CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_LITTLE_FINGER, CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_LITTLE_FINGER);
    }

    [Fact]
    public void LandmarkCoordinatesCodecIsForwarded()
    {
        var coordinates = new CoordinateCartesian2DUnsignedShortBlock(12, 34);

        var encoded = FaceImageLandmarkCoordinates.EncodeLandmarkCoordinates(coordinates);

        Assert.Equal(FaceImageLandmarkCoordinatesCodec.EncodeLandmarkCoordinates(coordinates).ToAsn1Object(), encoded.ToAsn1Object());
        Assert.Equal(coordinates, FaceImageLandmarkCoordinates.DecodeLandmarkCoordinates(encoded));
    }
#endif
}
