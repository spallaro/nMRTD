/*
 * nMRTD - A .Net API for accessing Machine Readable Travel Documents.
 *
 * Copyright (C) Sebastiano Pallaro.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * This is a porting from jMRTD, Copyright (C) The jMRTD Team (https://jmrtd.org/).
 *
 * Distributed under the terms of GNU LGPL v3.
 * See LICENSE for more information.
 */

using Org.BouncyCastle.Asn1;
using BigInteger = Org.BouncyCastle.Math.BigInteger;

namespace nMRTD.Lds.Iso39794;

//  ImageInformation2DBlock ::= SEQUENCE {
//    imageDataFormat [0] ImageDataFormat,
//    faceImageKind2D [1] FaceImageKind2D OPTIONAL,
//    postAcquisitionProcessingBlock [2] PostAcquisitionProcessingBlock OPTIONAL,
//    lossyTransformationAttempts [3] LossyTransformationAttempts OPTIONAL,
//    cameraToSubjectDistance [4] CameraToSubjectDistance OPTIONAL,
//    sensorDiagonal [5] SensorDiagonal OPTIONAL,
//    lensFocalLength [6] LensFocalLength OPTIONAL,
//    imageSizeBlock [7] ImageSizeBlock OPTIONAL,
//    imageFaceMeasurementsBlock [8] ImageFaceMeasurementsBlock OPTIONAL,
//    imageColourSpace [9] ImageColourSpace OPTIONAL,
//    referenceColourMappingBlock [10] ReferenceColourMappingBlock OPTIONAL,
//    ...
//  }

/// <summary>
/// Port of <c>org.jmrtd.lds.iso39794.FaceImageInformation2DBlock</c>. Java's <c>Serializable</c> marker is
/// dropped (no reflection-based serialization is needed in this port).
///
/// <see cref="ImageDataFormatCode"/>, <see cref="GetImageDataFormatCode"/>, <see cref="FaceImageKind2DCode"/>
/// and <see cref="GetFaceImageKind2DCode"/> are also used by
/// <see cref="ISO39794EncodingProfileExtensions.Validate"/>.
/// </summary>
public class FaceImageInformation2DBlock : Block
{
    /// <summary>
    /// ADAPTATION: Java's version is <c>enum ImageDataFormatCode implements
    /// EncodableEnum&lt;ImageDataFormatCode&gt;</c>, using reflection-based <c>EncodableEnum.fromCode</c>
    /// lookup keyed on each constant's own <c>getCode()</c> (note codes are not contiguous -- <c>1</c> is
    /// skipped). Ported as a plain enum with explicit numeric values matching each Java constant's
    /// <c>getCode()</c>. Java's version additionally carries a per-constant <c>mimeType</c> string, exposed
    /// via <c>getMimeType()</c>/the package-private static <c>toMimeType(ImageDataFormatCode)</c> helper --
    /// C# enums cannot carry members, so those are ported as the static <see cref="GetMimeType"/> and
    /// <see cref="ToMimeType"/> methods on this class instead (used by
    /// <c>FaceImageRepresentation2DBlock.GetRepresentationData2DInputMimeType</c>). See
    /// <see cref="FromCode{T}"/> for the shared "decode from code" replacement and
    /// <c>ScoreOrError.ScoringErrorCode</c>'s doc comment for the fuller rationale.
    /// </summary>
    public enum ImageDataFormatCode
    {
        Unknown = 0,
        Jpeg = 2,
        Jpeg2000Lossy = 3,
        Jpeg2000Lossless = 4,
    }

    public enum FaceImageKind2DCode
    {
        Mrtd = 0,
        GeneralPurpose = 1,
    }

    public enum LossyTransformationAttemptsCode
    {
        Unknown = 0,
        Zero = 1,
        One = 2,
        MoreThanOne = 3,
    }

    public enum ImageColourSpaceCode
    {
        Unknown = 0,
        Other = 1,
        Rgb24Bit = 2,
        Rgb48Bit = 3,
        Yuv422 = 4,
        Greyscale8Bit = 5,
        Greyscale16Bit = 6,
    }

    //  ImageSizeBlock ::= SEQUENCE {
    //    width [0] ImageSize,
    //    height [1] ImageSize
    //  }

    /// <summary>
    /// Port of <c>org.jmrtd.lds.iso39794.FaceImageInformation2DBlock.ImageSizeBlock</c>.
    ///
    /// ADAPTATION: Java's version is a nested <c>public static class ImageSizeBlock extends Block</c>; ported as a public nested class.
    /// </summary>
    public class ImageSizeBlock : Block
    {
        private readonly int _width;
        private readonly int _height;

        public ImageSizeBlock(int width, int height)
        {
            _width = width;
            _height = height;
        }

        internal ImageSizeBlock(Asn1Encodable asn1Encodable)
        {
            if (asn1Encodable is not Asn1Sequence)
            {
                throw new ArgumentException("Cannot decode!");
            }

            Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
            _width = ASN1Util.DecodeInt(taggedObjects[0]);
            _height = ASN1Util.DecodeInt(taggedObjects[1]);
        }

        public int GetWidth() => _width;

        public int GetHeight() => _height;

        public override int GetHashCode() => HashCode.Combine(_height, _width);

        public override bool Equals(object? other)
        {
            if (ReferenceEquals(this, other))
            {
                return true;
            }
            if (other == null || GetType() != other.GetType())
            {
                return false;
            }

            var otherBlock = (ImageSizeBlock)other;
            return _height == otherBlock._height && _width == otherBlock._width;
        }

        public override string ToString() => $"ImageSizeBlock [width: {_width}, height: {_height}]";

        internal override Asn1Encodable GetAsn1Object()
        {
            var taggedObjects = new Dictionary<int, Asn1Encodable>
            {
                [0] = ASN1Util.EncodeInt(_width),
                [1] = ASN1Util.EncodeInt(_height),
            };
            return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
        }
    }

    /// <summary>
    /// Port of <c>org.jmrtd.lds.iso39794.FaceImageInformation2DBlock.ImageFaceMeasurementsBlock</c>.
    ///
    /// ADAPTATION: Java's version is a nested <c>public static class ImageFaceMeasurementsBlock extends
    /// Block</c>; ported as a public nested class. Java's fields are <c>java.math.BigInteger</c>; ported using this project's established
    /// <c>Org.BouncyCastle.Math.BigInteger</c> alias (see <c>ASN1Util.cs</c>), matching
    /// <c>ASN1Util.DecodeBigInteger</c>/<c>EncodeBigInteger</c>'s own type.
    /// </summary>
    public class ImageFaceMeasurementsBlock : Block
    {
        private readonly BigInteger? _imageHeadWidth;
        private readonly BigInteger? _imageInterEyeDistance;
        private readonly BigInteger? _imageEyeToMouthDistance;
        private readonly BigInteger? _imageHeadLength;

        public ImageFaceMeasurementsBlock(BigInteger? imageHeadWidth, BigInteger? imageInterEyeDistance,
            BigInteger? imageEyeToMouthDistance, BigInteger? imageHeadLength)
        {
            _imageHeadWidth = imageHeadWidth;
            _imageInterEyeDistance = imageInterEyeDistance;
            _imageEyeToMouthDistance = imageEyeToMouthDistance;
            _imageHeadLength = imageHeadLength;
        }

        internal ImageFaceMeasurementsBlock(Asn1Encodable asn1Encodable)
        {
            Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
            if (taggedObjects.TryGetValue(0, out Asn1Encodable? headWidthObject))
            {
                _imageHeadWidth = ASN1Util.DecodeBigInteger(headWidthObject);
            }
            if (taggedObjects.TryGetValue(1, out Asn1Encodable? interEyeDistanceObject))
            {
                _imageInterEyeDistance = ASN1Util.DecodeBigInteger(interEyeDistanceObject);
            }
            if (taggedObjects.TryGetValue(2, out Asn1Encodable? eyeToMouthDistanceObject))
            {
                _imageEyeToMouthDistance = ASN1Util.DecodeBigInteger(eyeToMouthDistanceObject);
            }
            if (taggedObjects.TryGetValue(3, out Asn1Encodable? headLengthObject))
            {
                _imageHeadLength = ASN1Util.DecodeBigInteger(headLengthObject);
            }
        }

        public BigInteger? GetImageHeadWidth() => _imageHeadWidth;

        public BigInteger? GetImageInterEyeDistance() => _imageInterEyeDistance;

        public BigInteger? GetImageEyeToMouthDistance() => _imageEyeToMouthDistance;

        public BigInteger? GetImageHeadLength() => _imageHeadLength;

        public override int GetHashCode() =>
            HashCode.Combine(_imageEyeToMouthDistance, _imageHeadLength, _imageHeadWidth, _imageInterEyeDistance);

        public override bool Equals(object? other)
        {
            if (ReferenceEquals(this, other))
            {
                return true;
            }
            if (other == null || GetType() != other.GetType())
            {
                return false;
            }

            var otherBlock = (ImageFaceMeasurementsBlock)other;
            return Equals(_imageEyeToMouthDistance, otherBlock._imageEyeToMouthDistance)
                && Equals(_imageHeadLength, otherBlock._imageHeadLength)
                && Equals(_imageHeadWidth, otherBlock._imageHeadWidth)
                && Equals(_imageInterEyeDistance, otherBlock._imageInterEyeDistance);
        }

        public override string ToString() =>
            "ImageFaceMeasurementsBlock ["
            + $"imageHeadWidth: {_imageHeadWidth}"
            + $", imageInterEyeDistance: {_imageInterEyeDistance}"
            + $", imageEyeToMouthDistance: {_imageEyeToMouthDistance}"
            + $", imageHeadLength: {_imageHeadLength}"
            + "]";

        /* PACKAGE */

        internal override Asn1Encodable GetAsn1Object()
        {
            var taggedObjects = new Dictionary<int, Asn1Encodable>();
            if (_imageHeadWidth != null)
            {
                taggedObjects[0] = ASN1Util.EncodeBigInteger(_imageHeadWidth);
            }
            if (_imageInterEyeDistance != null)
            {
                taggedObjects[1] = ASN1Util.EncodeBigInteger(_imageInterEyeDistance);
            }
            if (_imageEyeToMouthDistance != null)
            {
                taggedObjects[2] = ASN1Util.EncodeBigInteger(_imageEyeToMouthDistance);
            }
            if (_imageHeadLength != null)
            {
                taggedObjects[3] = ASN1Util.EncodeBigInteger(_imageHeadLength);
            }
            return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
        }
    }

    /// <summary>Shared "decode from code" replacement for Java's reflection-based
    /// <c>EncodableEnum.fromCode(int, Class&lt;T&gt;)</c>: an <see cref="Enum.IsDefined(Type, object)"/>
    /// validity check plus a direct cast, returning <see langword="null"/> for an unrecognized code exactly
    /// like the Java original (which never throws from <c>fromCode</c> itself).</summary>
    private static T? FromCode<T>(int code) where T : struct, Enum =>
        Enum.IsDefined(typeof(T), code) ? (T)(object)code : null;

    private static string GetMimeType(ImageDataFormatCode code) => code switch
    {
        ImageDataFormatCode.Jpeg => "image/jpeg",
        ImageDataFormatCode.Jpeg2000Lossy => "image/jp2",
        ImageDataFormatCode.Jpeg2000Lossless => "image/jp2",
        _ => "image/raw",
    };

    /// <summary>Port of the package-private static <c>ImageDataFormatCode.toMimeType</c> helper.</summary>
    internal static string ToMimeType(ImageDataFormatCode? imageDataFormatCode) =>
        imageDataFormatCode == null ? "image/raw" : GetMimeType(imageDataFormatCode.Value);

    private readonly ImageSizeBlock? _imageSizeBlock;
    private readonly ImageDataFormatCode? _imageDataFormatCode;
    private readonly FaceImageKind2DCode? _faceImageKind2DCode;
    private readonly FaceImagePostAcquisitionProcessingBlock? _postAcquisitionProcessingBlock;
    private readonly LossyTransformationAttemptsCode? _lossyTransformationAttemptsCode;
    private readonly int? _cameraToSubjectDistance;
    private readonly int? _sensorDiagonal;
    private readonly int? _lensFocalLength;
    private readonly ImageFaceMeasurementsBlock? _imageFaceMeasurementsBlock;
    private readonly ImageColourSpaceCode? _imageColourSpaceCode;
    private readonly FaceImageReferenceColourMappingBlock? _referenceColourMappingBlock;

    public FaceImageInformation2DBlock(ImageDataFormatCode? imageDataFormatCode,
        FaceImageKind2DCode? faceImageKind2DCode, FaceImagePostAcquisitionProcessingBlock? postAcquisitionProcessingBlock,
        LossyTransformationAttemptsCode? lossyTransformationAttemptsCode, int? cameraToSubjectDistance,
        int? sensorDiagonal, int? lensFocalLength, ImageSizeBlock? imageSizeBlock,
        ImageFaceMeasurementsBlock? imageFaceMeasurementsBlock, ImageColourSpaceCode? imageColourSpaceCode,
        FaceImageReferenceColourMappingBlock? referenceColourMappingBlock)
    {
        _imageDataFormatCode = imageDataFormatCode;
        _faceImageKind2DCode = faceImageKind2DCode;
        _postAcquisitionProcessingBlock = postAcquisitionProcessingBlock;
        _lossyTransformationAttemptsCode = lossyTransformationAttemptsCode;
        _cameraToSubjectDistance = cameraToSubjectDistance;
        _sensorDiagonal = sensorDiagonal;
        _lensFocalLength = lensFocalLength;
        _imageSizeBlock = imageSizeBlock;
        _imageFaceMeasurementsBlock = imageFaceMeasurementsBlock;
        _imageColourSpaceCode = imageColourSpaceCode;
        _referenceColourMappingBlock = referenceColourMappingBlock;
    }

    /// <summary>NOTE: preserved Java quirk -- like the mandatory-but-guarded fields elsewhere in this port
    /// (see <c>IrisImageCaptureDeviceBlock</c>'s doc comment), <see cref="_imageDataFormatCode"/> is nullable
    /// even though it is conceptually mandatory: Java's decode constructor only assigns it when tag 0 is
    /// present, and the encoder (<see cref="GetAsn1Object(ISO39794EncodingProfile)"/>) unconditionally calls
    /// <c>imageDataFormatCode.getCode()</c> without a null check, so re-encoding a value decoded without tag 0
    /// throws (Java NPE, reproduced here as <see cref="InvalidOperationException"/> via <c>!.Value</c>). See
    /// the identical established pattern in <c>PADDataBlock.cs</c>/<c>IrisImageRepresentationBlock.cs</c>.
    /// </summary>
    internal FaceImageInformation2DBlock(Asn1Encodable? asn1Encodable)
    {
        if (asn1Encodable is not Asn1Sequence && asn1Encodable is not Asn1TaggedObject)
        {
            throw new ArgumentException("Cannot decode!");
        }

        Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
        if (taggedObjects.TryGetValue(0, out Asn1Encodable? imageDataFormatObject))
        {
            _imageDataFormatCode = FromCode<ImageDataFormatCode>(ISO39794Util.DecodeCodeFromChoiceExtensionBlockFallback(imageDataFormatObject)!.Value);
        }
        if (taggedObjects.TryGetValue(1, out Asn1Encodable? faceImageKind2DObject))
        {
            _faceImageKind2DCode = FromCode<FaceImageKind2DCode>(ISO39794Util.DecodeCodeFromChoiceExtensionBlockFallback(faceImageKind2DObject)!.Value);
        }
        if (taggedObjects.TryGetValue(2, out Asn1Encodable? postAcquisitionProcessingObject))
        {
            _postAcquisitionProcessingBlock = new FaceImagePostAcquisitionProcessingBlock(postAcquisitionProcessingObject);
        }
        if (taggedObjects.TryGetValue(3, out Asn1Encodable? lossyTransformationAttemptsObject))
        {
            _lossyTransformationAttemptsCode = FromCode<LossyTransformationAttemptsCode>(ISO39794Util.DecodeCodeFromChoiceExtensionBlockFallback(lossyTransformationAttemptsObject)!.Value);
        }
        if (taggedObjects.TryGetValue(4, out Asn1Encodable? cameraToSubjectDistanceObject))
        {
            _cameraToSubjectDistance = ASN1Util.DecodeInt(cameraToSubjectDistanceObject);
        }
        if (taggedObjects.TryGetValue(5, out Asn1Encodable? sensorDiagonalObject))
        {
            _sensorDiagonal = ASN1Util.DecodeInt(sensorDiagonalObject);
        }
        if (taggedObjects.TryGetValue(6, out Asn1Encodable? lensFocalLengthObject))
        {
            _lensFocalLength = ASN1Util.DecodeInt(lensFocalLengthObject);
        }
        if (taggedObjects.TryGetValue(7, out Asn1Encodable? imageSizeObject))
        {
            _imageSizeBlock = new ImageSizeBlock(imageSizeObject);
        }
        if (taggedObjects.TryGetValue(8, out Asn1Encodable? imageFaceMeasurementsObject))
        {
            _imageFaceMeasurementsBlock = new ImageFaceMeasurementsBlock(imageFaceMeasurementsObject);
        }
        if (taggedObjects.TryGetValue(9, out Asn1Encodable? imageColourSpaceObject))
        {
            _imageColourSpaceCode = FromCode<ImageColourSpaceCode>(ISO39794Util.DecodeCodeFromChoiceExtensionBlockFallback(imageColourSpaceObject)!.Value);
        }
        if (taggedObjects.TryGetValue(10, out Asn1Encodable? referenceColourMappingObject))
        {
            _referenceColourMappingBlock = new FaceImageReferenceColourMappingBlock(referenceColourMappingObject);
        }
    }

    /// <summary>Returns the image data format. One of <see cref="ImageDataFormatCode.Jpeg"/>,
    /// <see cref="ImageDataFormatCode.Jpeg2000Lossy"/>, or <see cref="ImageDataFormatCode.Jpeg2000Lossless"/>.
    ///
    /// ADAPTATION: Java's version returns the (reference-typed, so nullable at runtime) enum directly;
    /// ported as a non-nullable <see cref="ImageDataFormatCode"/> return specifically because
    /// <see cref="ISO39794EncodingProfileExtensions.Validate"/> (the already-committed contract in
    /// <c>ISO39794EncodingProfile.cs</c>) assigns this call's result to a non-nullable local, requiring a
    /// non-nullable return shape here. A block decoded without tag 0 therefore throws
    /// <see cref="InvalidOperationException"/> from this accessor (via <c>!.Value</c>) rather than silently
    /// yielding a Java-style <see langword="null"/> -- consistent with this port's established convention for
    /// every other "mandatory-but-guarded-on-decode" field (see <c>PADDataBlock.cs</c>'s doc comment).
    /// </summary>
    public ImageDataFormatCode GetImageDataFormatCode() => _imageDataFormatCode!.Value;

    public FaceImageKind2DCode? GetFaceImageKind2DCode() => _faceImageKind2DCode;

    public FaceImagePostAcquisitionProcessingBlock? GetPostAcquisitionProcessingBlock() => _postAcquisitionProcessingBlock;

    public LossyTransformationAttemptsCode? GetLossyTransformationAttemptsCode() => _lossyTransformationAttemptsCode;

    public int? GetCameraToSubjectDistance() => _cameraToSubjectDistance;

    public int? GetSensorDiagonal() => _sensorDiagonal;

    public int? GetLensFocalLength() => _lensFocalLength;

    public ImageSizeBlock? GetImageSizeBlock() => _imageSizeBlock;

    public ImageFaceMeasurementsBlock? GetImageFaceMeasurementsBlock() => _imageFaceMeasurementsBlock;

    public ImageColourSpaceCode? GetImageColourSpaceCode() => _imageColourSpaceCode;

    public FaceImageReferenceColourMappingBlock? GetReferenceColourMappingBlock() => _referenceColourMappingBlock;

    public override int GetHashCode() =>
        HashCode.Combine(
            HashCode.Combine(_cameraToSubjectDistance, _faceImageKind2DCode, _imageColourSpaceCode, _imageDataFormatCode,
                _imageFaceMeasurementsBlock, _imageSizeBlock, _lensFocalLength, _lossyTransformationAttemptsCode),
            _postAcquisitionProcessingBlock, _referenceColourMappingBlock, _sensorDiagonal);

    public override bool Equals(object? other)
    {
        if (ReferenceEquals(this, other))
        {
            return true;
        }
        if (other == null || GetType() != other.GetType())
        {
            return false;
        }

        var otherBlock = (FaceImageInformation2DBlock)other;
        return _cameraToSubjectDistance == otherBlock._cameraToSubjectDistance
            && _faceImageKind2DCode == otherBlock._faceImageKind2DCode
            && _imageColourSpaceCode == otherBlock._imageColourSpaceCode
            && _imageDataFormatCode == otherBlock._imageDataFormatCode
            && Equals(_imageFaceMeasurementsBlock, otherBlock._imageFaceMeasurementsBlock)
            && Equals(_imageSizeBlock, otherBlock._imageSizeBlock)
            && _lensFocalLength == otherBlock._lensFocalLength
            && _lossyTransformationAttemptsCode == otherBlock._lossyTransformationAttemptsCode
            && Equals(_postAcquisitionProcessingBlock, otherBlock._postAcquisitionProcessingBlock)
            && Equals(_referenceColourMappingBlock, otherBlock._referenceColourMappingBlock)
            && _sensorDiagonal == otherBlock._sensorDiagonal;
    }

    public override string ToString() =>
        "FaceImageInformation2DBlock ["
        + $"imageSizeBlock: {_imageSizeBlock}"
        + $", imageDataFormatCode: {_imageDataFormatCode}"
        + $", faceImageKind2DCode: {_faceImageKind2DCode}"
        + $", postAcquisitionProcessingBlock: {_postAcquisitionProcessingBlock}"
        + $", lossyTransformationAttemptsCode: {_lossyTransformationAttemptsCode}"
        + $", cameraToSubjectDistance: {_cameraToSubjectDistance}"
        + $", sensorDiagonal: {_sensorDiagonal}"
        + $", lensFocalLength: {_lensFocalLength}"
        + $", imageFaceMeasurementsBlock: {_imageFaceMeasurementsBlock}"
        + $", imageColourSpaceCode: {_imageColourSpaceCode}"
        + $", referenceColourMappingBlock: {_referenceColourMappingBlock}"
        + "]";

    /* PACKAGE */

    internal override Asn1Encodable GetAsn1Object() => GetAsn1Object(ISO39794EncodingProfile.Base);

    internal override Asn1Encodable GetAsn1Object(ISO39794EncodingProfile profile)
    {
        var taggedObjects = new Dictionary<int, Asn1Encodable>
        {
            [0] = ISO39794Util.EncodeCodeAsChoiceExtensionBlockFallback((int)_imageDataFormatCode!.Value),
        };
        if (_faceImageKind2DCode != null)
        {
            taggedObjects[1] = ISO39794Util.EncodeCodeAsChoiceExtensionBlockFallback((int)_faceImageKind2DCode.Value, profile, ChoiceType.FaceImageKind2D);
        }
        if (_postAcquisitionProcessingBlock != null)
        {
            taggedObjects[2] = _postAcquisitionProcessingBlock.GetAsn1Object();
        }
        if (_lossyTransformationAttemptsCode != null)
        {
            taggedObjects[3] = ISO39794Util.EncodeCodeAsChoiceExtensionBlockFallback((int)_lossyTransformationAttemptsCode.Value, profile, ChoiceType.LossyTransformationAttempts);
        }
        if (_cameraToSubjectDistance != null)
        {
            taggedObjects[4] = ASN1Util.EncodeInt(_cameraToSubjectDistance.Value);
        }
        if (_sensorDiagonal != null)
        {
            taggedObjects[5] = ASN1Util.EncodeInt(_sensorDiagonal.Value);
        }
        if (_lensFocalLength != null)
        {
            taggedObjects[6] = ASN1Util.EncodeInt(_lensFocalLength.Value);
        }
        if (_imageSizeBlock != null)
        {
            taggedObjects[7] = _imageSizeBlock.GetAsn1Object();
        }
        if (_imageFaceMeasurementsBlock != null)
        {
            taggedObjects[8] = _imageFaceMeasurementsBlock.GetAsn1Object();
        }
        if (_imageColourSpaceCode != null)
        {
            taggedObjects[9] = ISO39794Util.EncodeCodeAsChoiceExtensionBlockFallback((int)_imageColourSpaceCode.Value, profile, ChoiceType.ImageColourSpace);
        }
        if (_referenceColourMappingBlock != null)
        {
            taggedObjects[10] = _referenceColourMappingBlock.GetAsn1Object();
        }
        return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
    }
}
