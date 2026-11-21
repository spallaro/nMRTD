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
using nMRTD.Cbeff;
using nMRTD.Lds;

namespace nMRTD.Lds.Iso39794;

//  RepresentationBlock ::= SEQUENCE {
//    position [0] Position,
//    impression [1] Impression,
//    imageDataFormat [2] ImageDataFormat,
//    imageData [3] OCTET STRING,
//    captureDateTimeBlock [4] CaptureDateTimeBlock OPTIONAL,
//    captureDeviceBlock [5] CaptureDeviceBlock OPTIONAL,
//    qualityBlocks [6] QualityBlocks OPTIONAL,
//    spatialSamplingRateBlock [7] SpatialSamplingRateBlock OPTIONAL,
//    positionComputedByCaptureSystem [8] BOOLEAN OPTIONAL,
//    originalRotation [9] FingerRotation OPTIONAL,
//    imageRotatedToVertical [10] BOOLEAN OPTIONAL,
//    imageHasBeenLossilyCompressed [11] BOOLEAN OPTIONAL,
//    segmentationBlocks [12] SegmentationBlocks OPTIONAL,
//    annotationBlocks [13] AnnotationBlocks OPTIONAL,
//    pADDataBlock [14] PADDataBlock OPTIONAL,
//    commentBlocks [15] CommentBlocks OPTIONAL,
//    vendorSpecificDataBlocks [16] VendorSpecificDataBlocks OPTIONAL,
//    ...
//  }

/// <summary>
/// Port of <c>org.jmrtd.lds.iso39794.FingerImageRepresentationBlock</c>. Java's <c>Serializable</c> marker
/// is dropped (no reflection-based serialization is needed in this port).
/// A <see langword="public"/> interface (<see cref="ImageInfo"/>, via Java's <c>implements ImageInfo</c>)
/// may still be implemented by an <see langword="internal"/> class in C#, so that part of the shape carries
/// over directly; <c>Block</c>'s own <c>GetEncoded()</c> already satisfies <see cref="ImageInfo"/>'s
/// (Java's <c>LDSElement</c>'s) <c>GetEncoded()</c> requirement.
/// </summary>
public class FingerImageRepresentationBlock : Block, ImageInfo
{
    /// <summary>
    /// ADAPTATION: Java's version is <c>enum ImpressionCode implements EncodableEnum&lt;ImpressionCode&gt;</c>,
    /// using reflection-based <c>EncodableEnum.fromCode</c> lookup keyed on each constant's own
    /// <c>getCode()</c>. Ported as a plain enum with explicit numeric values matching each Java constant's
    /// <c>getCode()</c> exactly -- declaration order and code do NOT coincide here (<c>OTHER_IMPRESSION</c>
    /// is 28 and <c>UNKNOWN_IMPRESSION</c> is 29, both declared after the higher-numbered
    /// <c>MOVING_SUBJECT_CONTACTLESS_*</c> constants); see <c>ScoreOrError.ScoringErrorCode</c>'s doc
    /// comment for the fuller rationale and <see cref="FromCode"/> for the shared "decode from code"
    /// replacement.
    /// </summary>
    public enum ImpressionCode
    {
        PlainContact = 0,
        RolledContact = 1,
        LatentImage = 4,
        SwipeContact = 8,
        StationarySubjectContactlessPlain = 24,
        StationarySubjectContactlessRolled = 25,
        MovingSubjectContactlessPlain = 41,
        MovingSubjectContactlessRolled = 42,
        OtherImpression = 28,
        UnknownImpression = 29,
    }

    private static ImpressionCode? FromCode(int code) =>
        Enum.IsDefined(typeof(ImpressionCode), code) ? (ImpressionCode)code : null;

    /// <summary>
    /// ADAPTATION: Java's version is <c>enum ImageDataFormatCode implements
    /// EncodableEnum&lt;ImageDataFormatCode&gt;</c>, using reflection-based <c>EncodableEnum.fromCode</c>
    /// lookup keyed on each constant's own <c>getCode()</c>. Ported as a plain enum with explicit numeric
    /// values matching each Java constant's <c>getCode()</c> (declaration order and code happen to coincide
    /// here); see <c>ScoreOrError.ScoringErrorCode</c>'s doc comment for the fuller rationale and
    /// <see cref="FromCode"/> for the shared "decode from code" replacement.
    ///
    /// Java's version additionally carries a per-constant <c>mimeType</c> string; C# enums cannot carry
    /// members, so that mapping is <see cref="GetMimeType(ImageDataFormatCode)"/> below instead.
    /// </summary>
    public enum ImageDataFormatCode
    {
        Pgm = 0,
        Wsq = 1,
        Jpeg2000Lossy = 2,
        Jpeg2000Lossless = 3,
        Png = 4,
    }

    private static string GetMimeType(ImageDataFormatCode code) => code switch
    {
        ImageDataFormatCode.Pgm => "image/pgm",
        ImageDataFormatCode.Wsq => "image/x-wsq",
        ImageDataFormatCode.Jpeg2000Lossy => "image/jp2",
        ImageDataFormatCode.Jpeg2000Lossless => "image/jp2",
        ImageDataFormatCode.Png => "image/png",
        _ => throw new ArgumentOutOfRangeException(nameof(code), code, null),
    };

    private static ImageDataFormatCode? FromImageDataFormatCode(int code) =>
        Enum.IsDefined(typeof(ImageDataFormatCode), code) ? (ImageDataFormatCode)code : null;

    private readonly FingerImagePositionCode? _position;

    private readonly ImpressionCode? _impression;

    private readonly ImageDataFormatCode? _imageDataFormat;

    private readonly DateTimeBlock? _captureDateTimeBlock;

    private readonly FingerImageCaptureDeviceBlock? _captureDeviceBlock;

    private readonly List<QualityBlock>? _qualityBlocks;

    private readonly FingerImageSpatialSamplingRateBlock? _spatialSamplingRateBlock;

    private readonly bool? _isPositionComputedByCaptureSystem;

    /// <summary>INTEGER (0..359)</summary>
    private readonly int? _fingerRotation;

    private readonly bool? _isImageRotatedToVertical;

    private readonly bool? _isImageHasBeenLossilyCompressed;

    private readonly List<FingerImageSegmentationBlock>? _segmentationBlocks;

    private readonly List<FingerImageAnnotationBlock>? _annotationBlocks;

    private readonly PADDataBlock? _padDataBlock;

    private readonly byte[] _imageData;

    private readonly List<string>? _commentBlocks;

    private readonly List<ExtendedDataBlock>? _vendorSpecificDataBlocks;

    public FingerImageRepresentationBlock(FingerImagePositionCode? position, ImpressionCode? impression,
        ImageDataFormatCode? imageDataFormat, DateTimeBlock? captureDateTimeBlock,
        FingerImageCaptureDeviceBlock? captureDeviceBlock, List<QualityBlock>? qualityBlocks,
        FingerImageSpatialSamplingRateBlock? spatialSamplingRateBlock, bool? isPositionComputedByCaptureSystem,
        int? fingerRotation, bool? isImageRotatedToVertical, bool? isImageHasBeenLossilyCompressed,
        List<FingerImageSegmentationBlock>? segmentationBlocks, List<FingerImageAnnotationBlock>? annotationBlocks,
        PADDataBlock? padDataBlock, byte[] imageData, List<string>? commentBlocks,
        List<ExtendedDataBlock>? vendorSpecificDataBlocks)
    {
        _position = position;
        _impression = impression;
        _imageDataFormat = imageDataFormat;
        _captureDateTimeBlock = captureDateTimeBlock;
        _captureDeviceBlock = captureDeviceBlock;
        _qualityBlocks = qualityBlocks;
        _spatialSamplingRateBlock = spatialSamplingRateBlock;
        _isPositionComputedByCaptureSystem = isPositionComputedByCaptureSystem;
        _fingerRotation = fingerRotation;
        _isImageRotatedToVertical = isImageRotatedToVertical;
        _isImageHasBeenLossilyCompressed = isImageHasBeenLossilyCompressed;
        _segmentationBlocks = segmentationBlocks;
        _annotationBlocks = annotationBlocks;
        _padDataBlock = padDataBlock;
        _imageData = imageData;
        _commentBlocks = commentBlocks;
        _vendorSpecificDataBlocks = vendorSpecificDataBlocks;
    }

    internal FingerImageRepresentationBlock(Asn1Encodable? asn1Encodable)
    {
        if (asn1Encodable == null)
        {
            throw new ArgumentException("Cannot decode!");
        }

        Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
        _position = FingerImagePositionCodeExtensions.FromCode(ISO39794Util.DecodeCodeFromChoiceExtensionBlockFallback(taggedObjects[0])!.Value);
        _impression = FromCode(ISO39794Util.DecodeCodeFromChoiceExtensionBlockFallback(taggedObjects[1])!.Value);
        _imageDataFormat = FromImageDataFormatCode(ISO39794Util.DecodeCodeFromChoiceExtensionBlockFallback(taggedObjects[2])!.Value);
        _imageData = Asn1OctetString.GetInstance(taggedObjects[3]).GetOctets();
        if (taggedObjects.TryGetValue(4, out Asn1Encodable? captureDateTimeObject))
        {
            _captureDateTimeBlock = new DateTimeBlock(captureDateTimeObject);
        }
        if (taggedObjects.TryGetValue(5, out Asn1Encodable? captureDeviceObject))
        {
            _captureDeviceBlock = new FingerImageCaptureDeviceBlock(captureDeviceObject);
        }
        if (taggedObjects.TryGetValue(6, out Asn1Encodable? qualityBlocksObject))
        {
            _qualityBlocks = QualityBlock.DecodeQualityBlocks(qualityBlocksObject);
        }
        if (taggedObjects.TryGetValue(7, out Asn1Encodable? spatialSamplingRateObject))
        {
            _spatialSamplingRateBlock = new FingerImageSpatialSamplingRateBlock(spatialSamplingRateObject);
        }
        if (taggedObjects.TryGetValue(8, out Asn1Encodable? positionComputedObject))
        {
            _isPositionComputedByCaptureSystem = ASN1Util.DecodeBoolean(positionComputedObject);
        }
        if (taggedObjects.TryGetValue(9, out Asn1Encodable? fingerRotationObject))
        {
            _fingerRotation = ASN1Util.DecodeInt(fingerRotationObject);
        }
        if (taggedObjects.TryGetValue(10, out Asn1Encodable? rotatedToVerticalObject))
        {
            _isImageRotatedToVertical = ASN1Util.DecodeBoolean(rotatedToVerticalObject);
        }
        if (taggedObjects.TryGetValue(11, out Asn1Encodable? lossilyCompressedObject))
        {
            _isImageHasBeenLossilyCompressed = ASN1Util.DecodeBoolean(lossilyCompressedObject);
        }
        if (taggedObjects.TryGetValue(12, out Asn1Encodable? segmentationBlocksObject))
        {
            _segmentationBlocks = FingerImageSegmentationBlock.DecodeFingerImageSegmentationBlocks(segmentationBlocksObject);
        }
        if (taggedObjects.TryGetValue(13, out Asn1Encodable? annotationBlocksObject))
        {
            _annotationBlocks = FingerImageAnnotationBlock.DecodeFingerImageAnnotationBlocks(annotationBlocksObject);
        }
        if (taggedObjects.TryGetValue(14, out Asn1Encodable? padDataObject))
        {
            _padDataBlock = new PADDataBlock(padDataObject);
        }
        if (taggedObjects.TryGetValue(15, out Asn1Encodable? commentBlocksObject))
        {
            _commentBlocks = DecodeCommentBlocks(commentBlocksObject);
        }
        if (taggedObjects.TryGetValue(16, out Asn1Encodable? vendorSpecificObject))
        {
            _vendorSpecificDataBlocks = ExtendedDataBlock.DecodeExtendedDataBlocks(vendorSpecificObject);
        }
    }

    public FingerImagePositionCode? GetPosition() => _position;

    public ImpressionCode? GetImpression() => _impression;

    public FingerImageCaptureDeviceBlock? GetCaptureDeviceBlock() => _captureDeviceBlock;

    public DateTimeBlock? GetCaptureDateTimeBlock() => _captureDateTimeBlock;

    public ImageDataFormatCode? GetImageDataFormat() => _imageDataFormat;

    public List<QualityBlock>? GetQualityBlocks() => _qualityBlocks;

    public FingerImageSpatialSamplingRateBlock? GetSpatialSamplingRateBlock() => _spatialSamplingRateBlock;

    public bool? IsPositionComputedByCaptureSystem() => _isPositionComputedByCaptureSystem;

    public int? GetFingerRotation() => _fingerRotation;

    public bool? GetIsImageRotatedToVertical() => _isImageRotatedToVertical;

    public bool? GetIsImageHasBeenLossilyCompressed() => _isImageHasBeenLossilyCompressed;

    public List<FingerImageSegmentationBlock>? GetSegmentationBlocks() => _segmentationBlocks;

    public PADDataBlock? GetPadDataBlock() => _padDataBlock;

    public List<FingerImageAnnotationBlock>? GetAnnotationBlocks() => _annotationBlocks;

    public List<string>? GetCommentBlocks() => _commentBlocks;

    public List<ExtendedDataBlock>? GetVendorSpecificDataBlocks() => _vendorSpecificDataBlocks;

    public byte[] GetImageData() => _imageData;

    /// <summary>Misspelled, use <see cref="GetImageData"/> instead.</summary>
    [Obsolete("Misspelled, use GetImageData() instead.")]
    public byte[] GeImageData() => GetImageData();

    public override int GetHashCode()
    {
        const int prime = 31;
        int result = 1;
        result = (prime * result) + JavaArrayHashCode(_imageData);
        result = (prime * result) + JavaObjectsHash(
            JavaListHashCode(_annotationBlocks),
            _captureDateTimeBlock?.GetHashCode() ?? 0,
            _captureDeviceBlock?.GetHashCode() ?? 0,
            JavaListHashCode(_commentBlocks),
            _fingerRotation?.GetHashCode() ?? 0,
            _imageDataFormat?.GetHashCode() ?? 0,
            _impression?.GetHashCode() ?? 0,
            _isImageHasBeenLossilyCompressed?.GetHashCode() ?? 0,
            _isImageRotatedToVertical?.GetHashCode() ?? 0,
            _isPositionComputedByCaptureSystem?.GetHashCode() ?? 0,
            _padDataBlock?.GetHashCode() ?? 0,
            _position?.GetHashCode() ?? 0,
            JavaListHashCode(_qualityBlocks),
            JavaListHashCode(_segmentationBlocks),
            _spatialSamplingRateBlock?.GetHashCode() ?? 0,
            JavaListHashCode(_vendorSpecificDataBlocks));
        return result;
    }

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

        var otherBlock = (FingerImageRepresentationBlock)other;
        return ListEquals(_annotationBlocks, otherBlock._annotationBlocks)
            && Equals(_captureDateTimeBlock, otherBlock._captureDateTimeBlock)
            && Equals(_captureDeviceBlock, otherBlock._captureDeviceBlock)
            && ListEquals(_commentBlocks, otherBlock._commentBlocks)
            && _fingerRotation == otherBlock._fingerRotation
            && _imageData.SequenceEqual(otherBlock._imageData)
            && _imageDataFormat == otherBlock._imageDataFormat
            && _impression == otherBlock._impression
            && _isImageHasBeenLossilyCompressed == otherBlock._isImageHasBeenLossilyCompressed
            && _isImageRotatedToVertical == otherBlock._isImageRotatedToVertical
            && _isPositionComputedByCaptureSystem == otherBlock._isPositionComputedByCaptureSystem
            && Equals(_padDataBlock, otherBlock._padDataBlock)
            && _position == otherBlock._position
            && ListEquals(_qualityBlocks, otherBlock._qualityBlocks)
            && ListEquals(_segmentationBlocks, otherBlock._segmentationBlocks)
            && Equals(_spatialSamplingRateBlock, otherBlock._spatialSamplingRateBlock)
            && ListEquals(_vendorSpecificDataBlocks, otherBlock._vendorSpecificDataBlocks);
    }

    public override string ToString() =>
        "FingerImageRepresentationBlock ["
        + $"position: {ToStringOrNull(_position)}"
        + $", impression: {ToStringOrNull(_impression)}"
        + $", imageDataFormat: {ToStringOrNull(_imageDataFormat)}"
        + $", captureDateTimeBlock: {_captureDateTimeBlock}"
        + $", captureDeviceBlock: {_captureDeviceBlock}"
        + $", qualityBlocks: {JavaListToString(_qualityBlocks)}"
        + $", spatialSamplingRateBlock: {_spatialSamplingRateBlock}"
        + $", isPositionComputedByCaptureSystem: {ToStringOrNull(_isPositionComputedByCaptureSystem)}"
        + $", fingerRotation: {ToStringOrNull(_fingerRotation)}"
        + $", isImageRotatedToVertical: {ToStringOrNull(_isImageRotatedToVertical)}"
        + $", isImageHasBeenLossilyCompressed: {ToStringOrNull(_isImageHasBeenLossilyCompressed)}"
        + $", segmentationBlocks: {JavaListToString(_segmentationBlocks)}"
        + $", annotationBlocks: {JavaListToString(_annotationBlocks)}"
        + $", padDataBlock: {_padDataBlock}"
        + $", imageData: {_imageData.Length}"
        + $", commentBlocks: {JavaListToString(_commentBlocks)}"
        + $", vendorSpecificDataBlocks: {JavaListToString(_vendorSpecificDataBlocks)}"
        + "]";

    /* ImageInfo (LDSElement) */

    public int GetImageType() => ImageInfo.TYPE_FINGER;

    public string? GetMimeType() => _imageDataFormat == null ? "image/raw" : GetMimeType(_imageDataFormat.Value);

    public int GetWidth() => 0;

    public int GetHeight() => 0;

    public long GetRecordLength() => 0;

    public int GetImageLength() => _imageData.Length;

    public Stream GetImageInputStream() => new MemoryStream(_imageData);

    /* PACKAGE */

    /// <summary>Returns the biometric sub-type: the ICAO/CBEFF (BHT) biometric sub-type.</summary>
    internal int GetBiometricSubtype() => ToBiometricSubtype(_position);

    internal override Asn1Encodable GetAsn1Object() => GetAsn1Object(ISO39794EncodingProfile.Base);

    internal override Asn1Encodable GetAsn1Object(ISO39794EncodingProfile profile)
    {
        var taggedObjects = new Dictionary<int, Asn1Encodable>
        {
            [0] = ISO39794Util.EncodeCodeAsChoiceExtensionBlockFallback((int)_position!.Value),
            [1] = ISO39794Util.EncodeCodeAsChoiceExtensionBlockFallback((int)_impression!.Value),
            [2] = ISO39794Util.EncodeCodeAsChoiceExtensionBlockFallback((int)_imageDataFormat!.Value),
            [3] = new DerOctetString(_imageData),
        };
        if (_captureDateTimeBlock != null)
        {
            taggedObjects[4] = _captureDateTimeBlock.GetAsn1Object();
        }
        if (_captureDeviceBlock != null)
        {
            taggedObjects[5] = _captureDeviceBlock.GetAsn1Object();
        }
        if (_qualityBlocks != null)
        {
            taggedObjects[6] = ISO39794Util.EncodeBlocks([.. _qualityBlocks.Cast<Block>()], profile)!;
        }
        if (_spatialSamplingRateBlock != null)
        {
            taggedObjects[7] = _spatialSamplingRateBlock.GetAsn1Object();
        }
        if (_isPositionComputedByCaptureSystem != null)
        {
            taggedObjects[8] = ASN1Util.EncodeBoolean(_isPositionComputedByCaptureSystem.Value);
        }
        if (_fingerRotation != null)
        {
            taggedObjects[9] = ASN1Util.EncodeInt(_fingerRotation.Value);
        }
        if (_isImageRotatedToVertical != null)
        {
            taggedObjects[10] = ASN1Util.EncodeBoolean(_isImageRotatedToVertical.Value);
        }
        if (_isImageHasBeenLossilyCompressed != null)
        {
            taggedObjects[11] = ASN1Util.EncodeBoolean(_isImageHasBeenLossilyCompressed.Value);
        }
        if (_segmentationBlocks != null)
        {
            taggedObjects[12] = ISO39794Util.EncodeBlocks([.. _segmentationBlocks.Cast<Block>()], profile)!;
        }
        if (_annotationBlocks != null)
        {
            taggedObjects[13] = ISO39794Util.EncodeBlocks([.. _annotationBlocks.Cast<Block>()], profile)!;
        }
        if (_padDataBlock != null)
        {
            taggedObjects[14] = _padDataBlock.GetAsn1Object(profile);
        }
        if (_commentBlocks != null)
        {
            taggedObjects[15] = EncodeCommentBlocks(_commentBlocks);
        }
        if (_vendorSpecificDataBlocks != null)
        {
            taggedObjects[16] = ISO39794Util.EncodeBlocks([.. _vendorSpecificDataBlocks.Cast<Block>()], profile)!;
        }
        return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
    }

    internal static List<FingerImageRepresentationBlock> DecodeRepresentationBlocks(Asn1Encodable asn1Encodable)
    {
        var blocks = new List<FingerImageRepresentationBlock>();
        if (ASN1Util.IsSequenceOfSequences(asn1Encodable))
        {
            List<Asn1Encodable> blockAsn1Objects = ASN1Util.List(asn1Encodable)!;
            foreach (Asn1Encodable blockAsn1Object in blockAsn1Objects)
            {
                blocks.Add(new FingerImageRepresentationBlock(blockAsn1Object));
            }
        }
        else
        {
            blocks.Add(new FingerImageRepresentationBlock(asn1Encodable));
        }

        return blocks;
    }

    /* PRIVATE */

    /// <summary>NOTE: Java logs a warning "Cannot decode comment blocks!" and returns <see langword="null"/>
    /// when the input is neither a sequence nor a single visible string; the warning is omitted per the
    /// non-essential-warning-omission precedent (see <c>AbstractLDSFile.cs</c>), the <see langword="null"/>
    /// return is preserved.</summary>
    private static List<string>? DecodeCommentBlocks(Asn1Encodable asn1Encodable)
    {
        if (asn1Encodable is Asn1Sequence)
        {
            List<Asn1Encodable> blockAsn1Objects = ASN1Util.List(asn1Encodable)!;
            var blocks = new List<string>(blockAsn1Objects.Count);
            foreach (Asn1Encodable blockAsn1Object in blockAsn1Objects)
            {
                blocks.Add(DerVisibleString.GetInstance(blockAsn1Object).GetString());
            }
            return blocks;
        }
        else if (asn1Encodable is DerVisibleString)
        {
            return [DerVisibleString.GetInstance(asn1Encodable).GetString()];
        }

        return null;
    }

    private static Asn1Encodable EncodeCommentBlocks(List<string> comments)
    {
        var asn1Objects = new List<Asn1Encodable>(comments.Count);
        foreach (string comment in comments)
        {
            asn1Objects.Add(new DerVisibleString(comment));
        }
        return new DerSequence(asn1Objects.ToArray());
    }

    /// <summary>Converts from 39794-4 position coding to 7816-11 (BHT) coding.</summary>
    /// <param name="position">an ISO 39794-4 finger position code</param>
    /// <returns>an ISO7816-11 biometric subtype mask combination</returns>
    private static int ToBiometricSubtype(FingerImagePositionCode? position)
    {
        if (position == null)
        {
            return CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_NONE;
        }

        return position.Value switch
        {
            FingerImagePositionCode.UnknownPosition => CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_NONE,
            FingerImagePositionCode.RightThumbFinger => CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_RIGHT | CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_THUMB,
            FingerImagePositionCode.RightIndexFinger => CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_RIGHT | CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_POINTER_FINGER,
            FingerImagePositionCode.RightMiddleFinger => CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_RIGHT | CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_MIDDLE_FINGER,
            FingerImagePositionCode.RightRingFinger => CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_RIGHT | CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_RING_FINGER,
            FingerImagePositionCode.RightLittleFinger => CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_RIGHT | CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_LITTLE_FINGER,
            FingerImagePositionCode.LeftThumbFinger => CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_LEFT | CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_THUMB,
            FingerImagePositionCode.LeftIndexFinger => CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_LEFT | CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_POINTER_FINGER,
            FingerImagePositionCode.LeftMiddleFinger => CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_LEFT | CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_MIDDLE_FINGER,
            FingerImagePositionCode.LeftRingFinger => CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_LEFT | CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_RING_FINGER,
            FingerImagePositionCode.LeftLittleFinger => CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_LEFT | CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_LITTLE_FINGER,
            FingerImagePositionCode.RightFourFingers => CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_RIGHT,
            FingerImagePositionCode.LeftFourFingers => CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_LEFT,
            FingerImagePositionCode.BothThumbFingers => CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_THUMB,
            FingerImagePositionCode.UnknownPalm => CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_NONE,
            FingerImagePositionCode.RightFullPalm => CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_RIGHT,
            FingerImagePositionCode.RightWritersPalm => CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_NONE,
            FingerImagePositionCode.LeftFullPalm => CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_LEFT,
            FingerImagePositionCode.LeftWritersPalm => CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_LEFT,
            FingerImagePositionCode.RightLowerPalm => CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_RIGHT,
            FingerImagePositionCode.RightUpperPalm => CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_RIGHT,
            FingerImagePositionCode.LeftLowerPalm => CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_LEFT,
            FingerImagePositionCode.LeftUpperPalm => CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_LEFT,
            FingerImagePositionCode.RightInterdigital => CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_RIGHT,
            FingerImagePositionCode.RightThenar => CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_RIGHT,
            FingerImagePositionCode.RightHypothenar => CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_RIGHT,
            FingerImagePositionCode.LeftInterdigital => CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_LEFT,
            FingerImagePositionCode.LeftThenar => CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_LEFT,
            FingerImagePositionCode.LeftHypothenar => CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_LEFT,
            FingerImagePositionCode.OtherPosition => CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_NONE,
            _ => CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_NONE,
        };
    }

    private static string ToStringOrNull<T>(T? value) where T : struct => value?.ToString() ?? "null";

    private static string JavaListToString<T>(List<T>? list) => list == null ? "null" : $"[{string.Join(", ", list)}]";

    private static bool ListEquals<T>(List<T>? list1, List<T>? list2)
    {
        if (ReferenceEquals(list1, list2))
        {
            return true;
        }
        if (list1 == null || list2 == null)
        {
            return false;
        }

        return list1.SequenceEqual(list2);
    }

    private static int JavaListHashCode<T>(List<T>? list)
    {
        if (list == null)
        {
            return 0;
        }

        int hash = 1;
        foreach (T? element in list)
        {
            hash = (31 * hash) + (element?.GetHashCode() ?? 0);
        }

        return hash;
    }

    /// <summary>Java-style <c>Arrays.hashCode</c> for a byte array; see this port's established pattern
    /// (e.g. <c>PaceKeySpec.cs</c>, <c>PACECAMResult.cs</c>) for why this isn't just <c>byte[].GetHashCode()</c>.</summary>
    private static int JavaArrayHashCode(byte[] array)
    {
        int result = 1;
        foreach (byte b in array)
        {
            result = (31 * result) + (sbyte)b;
        }

        return result;
    }

    /// <summary>Java-style <c>Objects.hash(Object...)</c> (== <c>Arrays.hashCode(Object[])</c>): 1, then
    /// <c>31*hash + elementHash</c> per already-computed element hash, in order.</summary>
    private static int JavaObjectsHash(params int[] elementHashes)
    {
        int result = 1;
        foreach (int elementHash in elementHashes)
        {
            result = (31 * result) + elementHash;
        }

        return result;
    }
}
