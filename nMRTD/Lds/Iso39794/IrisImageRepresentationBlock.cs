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
using nMRTD.Lds;

namespace nMRTD.Lds.Iso39794;

//  RepresentationBlock ::= SEQUENCE {
//    eyeLabelCode              [0]          EyeLabelCode,
//    irisImageKind             [1]          IrisImageKind,
//    bitDepth                  [2]          INTEGER (8..24),
//    imageDataFormat           [3]          ImageDataFormat,
//    horizontalOrientationCode [4]          HorizontalOrientationCode,
//    verticalOrientationCode   [5]          VerticalOrientationCode,
//    compressionHistoryCode    [6]          CompressionHistoryCode,
//    captureDateTimeBlock      [7]          CaptureDateTimeBlock,
//    irisImageData             [8]          OCTET STRING,
//    range                     [9]          RangeOrError                   OPTIONAL,
//    captureDeviceBlock        [10]         CaptureDeviceBlock             OPTIONAL,
//    qualityBlocks             [11]         QualityBlocks                  OPTIONAL,
//    rollAngleBlock            [12]         RollAngleBlock                 OPTIONAL,
//    localisationBlock         [13]         LocalisationBlock              OPTIONAL,
//    pADDataBlock              [14]         PADDataBlock                   OPTIONAL,
//    ...
//  }

//  RangeOrError ::= CHOICE {
//    range   [0]     INTEGER (2..65533),
//    errorCode       [1]     RangingErrorCode
//  }

/// <summary>
/// Port of <c>org.jmrtd.lds.iso39794.IrisImageRepresentationBlock</c>. Java's <c>Serializable</c> marker is
/// dropped (no reflection-based serialization is needed in this port).
/// Java's version also <c>implements ImageInfo</c> (<c>org.jmrtd.lds.ImageInfo</c>); this port implements
/// <see cref="nMRTD.Lds.ImageInfo"/> (<c>nMRTD.Lds.LDSElement.GetEncoded</c> is already satisfied by
/// <see cref="Block.GetEncoded()"/>), so the image bytes, MIME type and size are available through it.
/// </summary>
public class IrisImageRepresentationBlock : Block, ImageInfo
{
    /// <summary>
    /// ADAPTATION: Java's version is <c>enum EyeLabelCode implements EncodableEnum&lt;EyeLabelCode&gt;</c>,
    /// using reflection-based <c>EncodableEnum.fromCode</c> lookup keyed on each constant's own
    /// <c>getCode()</c>. Ported as a plain enum with explicit numeric values matching each Java constant's
    /// <c>getCode()</c> (declaration order and code coincide here); see <see cref="FromCode{T}"/> for the
    /// shared "decode from code" replacement and <c>ScoreOrError.ScoringErrorCode</c>'s doc comment for the
    /// fuller rationale.
    /// </summary>
    public enum EyeLabelCode
    {
        Unknown = 0,
        RightIris = 1,
        LeftIris = 2,
    }

    public enum IrisImageKindCode
    {
        Uncropped = 1,
        Vga = 2,
        Cropped = 3,
        CroppedAndMasked = 7,
    }

    /// <summary>
    /// ADAPTATION: Java's version additionally carries a per-constant <c>mimeType</c> string, exposed via
    /// <c>getMimeType()</c> -- C# enums cannot carry members, so that mapping is <see cref="GetMimeType(ImageDataFormatCode)"/>
    /// below instead (a plain switch expression keyed on the enum value, analogous to how this port's other
    /// coded enums replace Java's reflection-based <c>fromCode</c> with <see cref="FromCode{T}"/>).
    /// </summary>
    public enum ImageDataFormatCode
    {
        Pgm = 0,
        Ppm = 1,
        Png = 2,
        Jpeg2000Lossless = 3,
        Jpeg2000Lossy = 4,
    }

    public enum HorizontalOrientationCode
    {
        Undefined = 0,
        LeftToRight = 1,
        RightToLeft = 2,
    }

    public enum VerticalOrientationCode
    {
        Undefined = 0,
        TopToBottom = 1,
        BottomToTop = 2,
    }

    public enum CompressionHistoryCode
    {
        Undefined = 0,
        LosslessOrNone = 1,
        Lossy = 2,
    }

    public enum RangingErrorCode
    {
        Unassigned = 0,
        Failed = 1,
        Overflow = 2,
    }

    /// <summary>Shared "decode from code" replacement for Java's reflection-based
    /// <c>EncodableEnum.fromCode(int, Class&lt;T&gt;)</c>: an <see cref="Enum.IsDefined(Type, object)"/>
    /// validity check plus a direct cast, returning <see langword="null"/> for an unrecognized code exactly
    /// like the Java original (which never throws from <c>fromCode</c> itself).</summary>
    private static T? FromCode<T>(int code) where T : struct, Enum =>
        Enum.IsDefined(typeof(T), code) ? (T)(object)code : null;

    private static string GetMimeType(ImageDataFormatCode code) => code switch
    {
        ImageDataFormatCode.Pgm => "image/pgm",
        ImageDataFormatCode.Ppm => "image/ppm",
        ImageDataFormatCode.Png => "image/png",
        ImageDataFormatCode.Jpeg2000Lossless => "image/jp2",
        ImageDataFormatCode.Jpeg2000Lossy => "image/jp2",
        _ => "image/raw",
    };

    /// <summary>
    /// Port of <c>org.jmrtd.lds.iso39794.IrisImageRepresentationBlock.RollAngleBlock</c>.
    ///
    /// ADAPTATION: Java's version is a nested <c>public static class RollAngleBlock extends Block</c>; ported as a public nested class.
    /// Java's version has no <c>toString()</c> override (it falls back to <c>Object.toString()</c>); this
    /// port likewise leaves <see cref="object.ToString"/> un-overridden here, matching that Java has no
    /// requirement to override it (only <c>GetHashCode</c>/<c>Equals</c> are abstract on <see cref="Block"/>).
    /// </summary>
    public class RollAngleBlock : Block
    {
        private readonly int _angle;
        private readonly int _uncertainty;

        public RollAngleBlock(int angle, int uncertainty)
        {
            _angle = angle;
            _uncertainty = uncertainty;
        }

        internal RollAngleBlock(Asn1Encodable asn1Encodable)
        {
            Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
            _angle = ASN1Util.DecodeInt(taggedObjects[0]);
            _uncertainty = ASN1Util.DecodeInt(taggedObjects[1]);
        }

        public int GetAngle() => _angle;

        public int GetUncertainty() => _uncertainty;

        public override int GetHashCode() => HashCode.Combine(_angle, _uncertainty);

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

            var otherBlock = (RollAngleBlock)other;
            return _angle == otherBlock._angle && _uncertainty == otherBlock._uncertainty;
        }

        internal override Asn1Encodable GetAsn1Object()
        {
            var taggedObjects = new Dictionary<int, Asn1Encodable>
            {
                [0] = ASN1Util.EncodeInt(_angle),
                [1] = ASN1Util.EncodeInt(_uncertainty),
            };
            return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
        }
    }

    private readonly EyeLabelCode? _eyeLabelCode;

    private readonly IrisImageKindCode? _irisImageKind;

    private readonly int _bitDepth;

    private readonly ImageDataFormatCode? _imageDataFormatCode;

    private readonly HorizontalOrientationCode? _horizontalOrientationCode;

    private readonly VerticalOrientationCode? _verticalOrientationCode;

    private readonly CompressionHistoryCode? _compressionHistoryCode;

    private readonly byte[] _imageData;

    /// <summary>INTEGER (2..65533), is <see langword="null"/> iff <see cref="_rangingErrorCode"/> is not
    /// <see langword="null"/>.</summary>
    private readonly int? _range;
    private readonly RangingErrorCode? _rangingErrorCode;

    private readonly DateTimeBlock _captureDateTimeBlock;

    private readonly IrisImageCaptureDeviceBlock? _captureDeviceBlock;

    private readonly List<QualityBlock>? _qualityBlocks;

    private readonly RollAngleBlock? _rollAngleBlock;

    private readonly IrisImageLocalisationBlock? _localisationBlock;

    private readonly PADDataBlock? _padDataBlock;

    /// <summary>
    /// NOTE: preserved Java quirk -- like the mandatory-but-guarded fields elsewhere in this port (see
    /// <c>IrisImageCaptureDeviceBlock</c>'s doc comment), the mandatory coded fields below
    /// (<see cref="_eyeLabelCode"/>, <see cref="_irisImageKind"/>, <see cref="_imageDataFormatCode"/>,
    /// <see cref="_horizontalOrientationCode"/>, <see cref="_verticalOrientationCode"/>,
    /// <see cref="_compressionHistoryCode"/>) are all nullable: Java's <c>EncodableEnum.fromCode</c> quietly
    /// returns <see langword="null"/> (never throws) for an unrecognized code, and since Java enums are
    /// reference types, that <see langword="null"/> flows straight into the (non-<c>Optional</c>,
    /// non-primitive) instance field without any unboxing exception -- unlike the CHOICE-with-extension-block
    /// fields elsewhere in this package, where the *code itself* being absent (rather than merely
    /// unrecognized) throws via <c>int</c> auto-unboxing. This port's encoder (<see cref="GetAsn1Object()"/>)
    /// reproduces the resulting "NPE on re-encoding a value carrying an unrecognized code" behavior via an
    /// explicit <c>!.Value</c> non-null assertion (<see cref="InvalidOperationException"/> instead of Java's
    /// NPE) rather than silently tolerating it.
    /// </summary>
    public IrisImageRepresentationBlock(Asn1Encodable? asn1Encodable)
    {
        if (asn1Encodable == null)
        {
            throw new ArgumentException("Cannot decode!");
        }

        Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
        _eyeLabelCode = FromCode<EyeLabelCode>(ASN1Util.DecodeInt(taggedObjects[0]));
        _irisImageKind = FromCode<IrisImageKindCode>(ISO39794Util.DecodeCodeFromChoiceExtensionBlockFallback(taggedObjects[1])!.Value);
        _bitDepth = ASN1Util.DecodeInt(taggedObjects[2]);
        _imageDataFormatCode = FromCode<ImageDataFormatCode>(ISO39794Util.DecodeCodeFromChoiceExtensionBlockFallback(taggedObjects[3])!.Value);
        _horizontalOrientationCode = FromCode<HorizontalOrientationCode>(ASN1Util.DecodeInt(taggedObjects[4]));
        _verticalOrientationCode = FromCode<VerticalOrientationCode>(ASN1Util.DecodeInt(taggedObjects[5]));
        _compressionHistoryCode = FromCode<CompressionHistoryCode>(ASN1Util.DecodeInt(taggedObjects[6]));
        _captureDateTimeBlock = new DateTimeBlock(taggedObjects[7]);
        _imageData = Asn1OctetString.GetInstance(taggedObjects[8]).GetOctets();
        if (taggedObjects.TryGetValue(9, out Asn1Encodable? rangeOrErrorObject))
        {
            (_range, _rangingErrorCode) = DecodeRangeOrError(rangeOrErrorObject);
        }
        if (taggedObjects.TryGetValue(10, out Asn1Encodable? captureDeviceObject))
        {
            _captureDeviceBlock = new IrisImageCaptureDeviceBlock(captureDeviceObject);
        }
        if (taggedObjects.TryGetValue(11, out Asn1Encodable? qualityBlocksObject))
        {
            _qualityBlocks = QualityBlock.DecodeQualityBlocks(qualityBlocksObject);
        }
        if (taggedObjects.TryGetValue(12, out Asn1Encodable? rollAngleObject))
        {
            _rollAngleBlock = new RollAngleBlock(rollAngleObject);
        }
        if (taggedObjects.TryGetValue(13, out Asn1Encodable? localisationObject))
        {
            _localisationBlock = new IrisImageLocalisationBlock(localisationObject);
        }
        if (taggedObjects.TryGetValue(14, out Asn1Encodable? padDataObject))
        {
            _padDataBlock = new PADDataBlock(padDataObject);
        }
    }

    public EyeLabelCode? GetEyeLabelCode() => _eyeLabelCode;

    public IrisImageKindCode? GetIrisImageKind() => _irisImageKind;

    public int GetBitDepth() => _bitDepth;

    public ImageDataFormatCode? GetImageDataFormat() => _imageDataFormatCode;

    public HorizontalOrientationCode? GetHorizontalOrientationCode() => _horizontalOrientationCode;

    public VerticalOrientationCode? GetVerticalOrientationCode() => _verticalOrientationCode;

    public CompressionHistoryCode? GetCompressionHistoryCode() => _compressionHistoryCode;

    public byte[] GetImageData() => _imageData;

    /// <summary>Misspelled, use <see cref="GetImageData"/> instead.</summary>
    [Obsolete("Misspelled, use GetImageData() instead.")]
    public byte[] GeImageData() => GetImageData();

    public IrisImageCaptureDeviceBlock? GetCaptureDeviceBlock() => _captureDeviceBlock;

    public List<QualityBlock>? GetQualityBlocks() => _qualityBlocks;

    public RollAngleBlock? GetRollAngleBlock() => _rollAngleBlock;

    public IrisImageLocalisationBlock? GetLocalisationBlock() => _localisationBlock;

    public PADDataBlock? GetPADDataBlock() => _padDataBlock;

    /* PACKAGE */

    public override int GetHashCode()
    {
        const int prime = 31;
        int result = 1;
        result = (prime * result) + JavaArrayHashCode(_imageData);
        result = (prime * result) + JavaObjectsHash(
            _bitDepth,
            _captureDateTimeBlock.GetHashCode(),
            _captureDeviceBlock?.GetHashCode() ?? 0,
            _compressionHistoryCode?.GetHashCode() ?? 0,
            _eyeLabelCode?.GetHashCode() ?? 0,
            _horizontalOrientationCode?.GetHashCode() ?? 0,
            _imageDataFormatCode?.GetHashCode() ?? 0,
            _irisImageKind?.GetHashCode() ?? 0,
            _localisationBlock?.GetHashCode() ?? 0,
            _padDataBlock?.GetHashCode() ?? 0,
            JavaListHashCode(_qualityBlocks),
            _range?.GetHashCode() ?? 0,
            _rangingErrorCode?.GetHashCode() ?? 0,
            _rollAngleBlock?.GetHashCode() ?? 0,
            _verticalOrientationCode?.GetHashCode() ?? 0);
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

        var otherBlock = (IrisImageRepresentationBlock)other;
        return _bitDepth == otherBlock._bitDepth
            && Equals(_captureDateTimeBlock, otherBlock._captureDateTimeBlock)
            && Equals(_captureDeviceBlock, otherBlock._captureDeviceBlock)
            && _compressionHistoryCode == otherBlock._compressionHistoryCode
            && _eyeLabelCode == otherBlock._eyeLabelCode
            && _horizontalOrientationCode == otherBlock._horizontalOrientationCode
            && ByteArraysEqual(_imageData, otherBlock._imageData)
            && _imageDataFormatCode == otherBlock._imageDataFormatCode
            && _irisImageKind == otherBlock._irisImageKind
            && Equals(_localisationBlock, otherBlock._localisationBlock)
            && Equals(_padDataBlock, otherBlock._padDataBlock)
            && ListEquals(_qualityBlocks, otherBlock._qualityBlocks)
            && _range == otherBlock._range
            && _rangingErrorCode == otherBlock._rangingErrorCode
            && Equals(_rollAngleBlock, otherBlock._rollAngleBlock)
            && _verticalOrientationCode == otherBlock._verticalOrientationCode;
    }

    public override string ToString() =>
        "IrisImageRepresentationBlock ["
        + $"eyeLabelCode: {ToStringOrNull(_eyeLabelCode)}"
        + $", irisImageKind: {ToStringOrNull(_irisImageKind)}"
        + $", bitDepth: {_bitDepth}"
        + $", imageDataFormat: {ToStringOrNull(_imageDataFormatCode)}"
        + $", horizontalOrientationCode: {ToStringOrNull(_horizontalOrientationCode)}"
        + $", verticalOrientationCode: {ToStringOrNull(_verticalOrientationCode)}"
        + $", compressionHistoryCode: {ToStringOrNull(_compressionHistoryCode)}"
        + $", imageData: {(_imageData == null ? "null" : _imageData.Length.ToString())}"
        + $", range: {(_range != null ? _range.Value.ToString() : ToStringOrNull(_rangingErrorCode))}"
        + $", captureDateTimeBlock: {_captureDateTimeBlock}"
        + $", captureDeviceBlock: {_captureDeviceBlock?.ToString() ?? "null"}"
        + $", qualityBlocks: {JavaListToString(_qualityBlocks)}"
        + $", rollAngleBlock: {_rollAngleBlock?.ToString() ?? "null"}"
        + $", localisationBlock: {_localisationBlock?.ToString() ?? "null"}"
        + $", padDataBlock: {_padDataBlock?.ToString() ?? "null"}"
        + "]";

    public int GetImageType() => ImageInfoTypes.TYPE_IRIS;

    public string? GetMimeType() => _imageDataFormatCode == null ? "image/raw" : GetMimeType(_imageDataFormatCode.Value);

    public int GetWidth() => 0;

    public int GetHeight() => 0;

    public long GetRecordLength() => 0;

    public int GetImageLength() => _imageData.Length;

    public Stream GetImageInputStream() => new MemoryStream(_imageData);

    internal override Asn1Encodable GetAsn1Object() => GetAsn1Object(ISO39794EncodingProfile.Base);

    internal override Asn1Encodable GetAsn1Object(ISO39794EncodingProfile profile)
    {
        var taggedObjects = new Dictionary<int, Asn1Encodable>
        {
            [0] = ASN1Util.EncodeInt((int)_eyeLabelCode!.Value),
            [1] = ISO39794Util.EncodeCodeAsChoiceExtensionBlockFallback((int)_irisImageKind!.Value),
            [2] = ASN1Util.EncodeInt(_bitDepth),
            [3] = ISO39794Util.EncodeCodeAsChoiceExtensionBlockFallback((int)_imageDataFormatCode!.Value),
            [4] = ASN1Util.EncodeInt((int)_horizontalOrientationCode!.Value),
            [5] = ASN1Util.EncodeInt((int)_verticalOrientationCode!.Value),
            [6] = ASN1Util.EncodeInt((int)_compressionHistoryCode!.Value),
            [7] = _captureDateTimeBlock.GetAsn1Object(),
            [8] = new DerOctetString(_imageData),
        };
        if (_range != null || _rangingErrorCode != null)
        {
            taggedObjects[9] = EncodeRangeOrError();
        }
        if (_captureDeviceBlock != null)
        {
            taggedObjects[10] = _captureDeviceBlock.GetAsn1Object();
        }
        if (_qualityBlocks != null)
        {
            taggedObjects[11] = ISO39794Util.EncodeBlocks([.. _qualityBlocks.Cast<Block>()], profile)!;
        }
        if (_rollAngleBlock != null)
        {
            taggedObjects[12] = _rollAngleBlock.GetAsn1Object();
        }
        if (_localisationBlock != null)
        {
            taggedObjects[13] = _localisationBlock.GetAsn1Object();
        }
        if (_padDataBlock != null)
        {
            taggedObjects[14] = _padDataBlock.GetAsn1Object(profile);
        }
        return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
    }

    internal static List<IrisImageRepresentationBlock> DecodeRepresentationBlocks(Asn1Encodable asn1Encodable)
    {
        var result = new List<IrisImageRepresentationBlock>();
        if (ASN1Util.IsSequenceOfSequences(asn1Encodable))
        {
            List<Asn1Encodable> representationBlockAsn1Objects = ASN1Util.List(asn1Encodable)!;
            foreach (Asn1Encodable representationBlockAsn1Object in representationBlockAsn1Objects)
            {
                result.Add(new IrisImageRepresentationBlock(representationBlockAsn1Object));
            }
        }
        else
        {
            result.Add(new IrisImageRepresentationBlock(asn1Encodable));
        }

        return result;
    }

    /// <summary>NOTE: 39795-6 code value happens to be consistent with 19794-6 defined subtype.</summary>
    internal int GetBiometricSubtype() => _eyeLabelCode == null ? (int)EyeLabelCode.Unknown : (int)_eyeLabelCode.Value;

    /* PRIVATE */

    private static (int? Range, RangingErrorCode? ErrorCode) DecodeRangeOrError(Asn1Encodable asn1Encodable)
    {
        Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
        if (taggedObjects.TryGetValue(0, out Asn1Encodable? rangeObject))
        {
            return (ASN1Util.DecodeInt(rangeObject), null);
        }
        if (taggedObjects.TryGetValue(1, out Asn1Encodable? errorObject))
        {
            return (null, FromCode<RangingErrorCode>(ASN1Util.DecodeInt(errorObject)));
        }

        return (null, null);
    }

    private Asn1Encodable EncodeRangeOrError()
    {
        var taggedObjects = new Dictionary<int, Asn1Encodable>();
        if (_range != null)
        {
            taggedObjects[0] = ASN1Util.EncodeInt(_range.Value);
        }
        else if (_rangingErrorCode != null)
        {
            taggedObjects[1] = ASN1Util.EncodeInt((int)_rangingErrorCode.Value);
        }
        return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
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

    private static bool ByteArraysEqual(byte[]? array1, byte[]? array2)
    {
        if (array1 == null || array2 == null)
        {
            return array1 == array2;
        }

        return array1.SequenceEqual(array2);
    }

    /// <summary>Java-style <c>Arrays.hashCode(byte[])</c> for a (possibly <see langword="null"/>) byte
    /// array -- see the established pattern in e.g. <c>PADDataBlock.cs</c>.</summary>
    private static int JavaArrayHashCode(byte[]? array)
    {
        if (array == null)
        {
            return 0;
        }

        int result = 1;
        foreach (byte b in array)
        {
            result = (31 * result) + (sbyte)b;
        }

        return result;
    }

    /// <summary>Java-style content-based <c>List.hashCode()</c> (the <c>AbstractList</c> contract).</summary>
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
