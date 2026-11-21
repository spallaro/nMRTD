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

namespace nMRTD.Lds.Iso39794;

/// <summary>
/// Port of <c>org.jmrtd.lds.iso39794.FaceImagePostAcquisitionProcessingBlock</c>. Java's <c>Serializable</c>
/// marker is dropped (no reflection-based serialization is needed in this port).
/// Java's decode constructor is unusually declared <c>public</c> (most sibling blocks in this package use a
/// package-private decode constructor); it is <c>public</c> here too.
/// </summary>
public class FaceImagePostAcquisitionProcessingBlock : Block
{
    //  PostAcquisitionProcessingBlock ::= SEQUENCE {
    //    rotated [0] BOOLEAN OPTIONAL,
    //    cropped [1] BOOLEAN OPTIONAL,
    //    downSampled [2] BOOLEAN OPTIONAL,
    //    whiteBalanceAdjusted [3] BOOLEAN OPTIONAL,
    //    multiplyCompressed [4] BOOLEAN OPTIONAL,
    //    interpolated [5] BOOLEAN OPTIONAL,
    //    contrastStretched [6] BOOLEAN OPTIONAL,
    //    poseCorrected [7] BOOLEAN OPTIONAL,
    //    multiViewImage [8] BOOLEAN OPTIONAL,
    //    ageProgressed [9] BOOLEAN OPTIONAL,
    //    superResolutionProcessed [10] BOOLEAN OPTIONAL,
    //    normalised [11] BOOLEAN OPTIONAL,
    //    ...
    //  }

    private readonly bool? _isRotated;
    private readonly bool? _isCropped;
    private readonly bool? _isDownSampled;
    private readonly bool? _isWhiteBalanceAdjusted;
    private readonly bool? _isMultiplyCompressed;
    private readonly bool? _isInterpolated;
    private readonly bool? _isContrastStretched;
    private readonly bool? _isPoseCorrected;
    private readonly bool? _isMultiViewImage;
    private readonly bool? _isAgeProgressed;
    private readonly bool? _isSuperResolutionProcessed;
    private readonly bool? _isNormalised;

    public FaceImagePostAcquisitionProcessingBlock(bool? isRotated, bool? isCropped, bool? isDownSampled,
        bool? isWhiteBalanceAdjusted, bool? isMultiplyCompressed, bool? isInterpolated, bool? isContrastStretched,
        bool? isPoseCorrected, bool? isMultiViewImage, bool? isAgeProgressed, bool? isSuperResolutionProcessed,
        bool? isNormalised)
    {
        _isRotated = isRotated;
        _isCropped = isCropped;
        _isDownSampled = isDownSampled;
        _isWhiteBalanceAdjusted = isWhiteBalanceAdjusted;
        _isMultiplyCompressed = isMultiplyCompressed;
        _isInterpolated = isInterpolated;
        _isContrastStretched = isContrastStretched;
        _isPoseCorrected = isPoseCorrected;
        _isMultiViewImage = isMultiViewImage;
        _isAgeProgressed = isAgeProgressed;
        _isSuperResolutionProcessed = isSuperResolutionProcessed;
        _isNormalised = isNormalised;
    }

    public FaceImagePostAcquisitionProcessingBlock(Asn1Encodable asn1Encodable)
    {
        Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
        if (taggedObjects.TryGetValue(0, out Asn1Encodable? rotatedObject))
        {
            _isRotated = ASN1Util.DecodeBoolean(rotatedObject);
        }
        if (taggedObjects.TryGetValue(1, out Asn1Encodable? croppedObject))
        {
            _isCropped = ASN1Util.DecodeBoolean(croppedObject);
        }
        if (taggedObjects.TryGetValue(2, out Asn1Encodable? downSampledObject))
        {
            _isDownSampled = ASN1Util.DecodeBoolean(downSampledObject);
        }
        if (taggedObjects.TryGetValue(3, out Asn1Encodable? whiteBalanceAdjustedObject))
        {
            _isWhiteBalanceAdjusted = ASN1Util.DecodeBoolean(whiteBalanceAdjustedObject);
        }
        if (taggedObjects.TryGetValue(4, out Asn1Encodable? multiplyCompressedObject))
        {
            _isMultiplyCompressed = ASN1Util.DecodeBoolean(multiplyCompressedObject);
        }
        if (taggedObjects.TryGetValue(5, out Asn1Encodable? interpolatedObject))
        {
            _isInterpolated = ASN1Util.DecodeBoolean(interpolatedObject);
        }
        if (taggedObjects.TryGetValue(6, out Asn1Encodable? contrastStretchedObject))
        {
            _isContrastStretched = ASN1Util.DecodeBoolean(contrastStretchedObject);
        }
        if (taggedObjects.TryGetValue(7, out Asn1Encodable? poseCorrectedObject))
        {
            _isPoseCorrected = ASN1Util.DecodeBoolean(poseCorrectedObject);
        }
        if (taggedObjects.TryGetValue(8, out Asn1Encodable? multiViewImageObject))
        {
            _isMultiViewImage = ASN1Util.DecodeBoolean(multiViewImageObject);
        }
        if (taggedObjects.TryGetValue(9, out Asn1Encodable? ageProgressedObject))
        {
            _isAgeProgressed = ASN1Util.DecodeBoolean(ageProgressedObject);
        }
        if (taggedObjects.TryGetValue(10, out Asn1Encodable? superResolutionProcessedObject))
        {
            _isSuperResolutionProcessed = ASN1Util.DecodeBoolean(superResolutionProcessedObject);
        }
        if (taggedObjects.TryGetValue(11, out Asn1Encodable? normalisedObject))
        {
            _isNormalised = ASN1Util.DecodeBoolean(normalisedObject);
        }
    }

    public bool? IsRotated() => _isRotated;

    public bool? IsCropped() => _isCropped;

    public bool? IsDownSampled() => _isDownSampled;

    public bool? IsWhiteBalanceAdjusted() => _isWhiteBalanceAdjusted;

    public bool? IsMultiplyCompressed() => _isMultiplyCompressed;

    public bool? IsInterpolated() => _isInterpolated;

    public bool? IsContrastStretched() => _isContrastStretched;

    public bool? IsPoseCorrected() => _isPoseCorrected;

    public bool? IsMultiViewImage() => _isMultiViewImage;

    public bool? IsAgeProgressed() => _isAgeProgressed;

    public bool? IsSuperResolutionProcessed() => _isSuperResolutionProcessed;

    public bool? IsNormalised() => _isNormalised;

    public override int GetHashCode() =>
        HashCode.Combine(
            HashCode.Combine(_isAgeProgressed, _isContrastStretched, _isCropped, _isDownSampled, _isInterpolated, _isMultiViewImage),
            HashCode.Combine(_isMultiplyCompressed, _isNormalised, _isPoseCorrected, _isRotated, _isSuperResolutionProcessed, _isWhiteBalanceAdjusted));

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

        var otherBlock = (FaceImagePostAcquisitionProcessingBlock)other;
        return _isAgeProgressed == otherBlock._isAgeProgressed
            && _isContrastStretched == otherBlock._isContrastStretched
            && _isCropped == otherBlock._isCropped
            && _isDownSampled == otherBlock._isDownSampled
            && _isInterpolated == otherBlock._isInterpolated
            && _isMultiViewImage == otherBlock._isMultiViewImage
            && _isMultiplyCompressed == otherBlock._isMultiplyCompressed
            && _isNormalised == otherBlock._isNormalised
            && _isPoseCorrected == otherBlock._isPoseCorrected
            && _isRotated == otherBlock._isRotated
            && _isSuperResolutionProcessed == otherBlock._isSuperResolutionProcessed
            && _isWhiteBalanceAdjusted == otherBlock._isWhiteBalanceAdjusted;
    }

    public override string ToString() =>
        "FaceImagePostAcquisitionProcessingBlock ["
        + $"isRotated: {_isRotated}"
        + $", isCropped: {_isCropped}"
        + $", isDownSampled: {_isDownSampled}"
        + $", isWhiteBalanceAdjusted: {_isWhiteBalanceAdjusted}"
        + $", isMultiplyCompressed: {_isMultiplyCompressed}"
        + $", isInterpolated: {_isInterpolated}"
        + $", isContrastStretched: {_isContrastStretched}"
        + $", isPoseCorrected: {_isPoseCorrected}"
        + $", isMultiViewImage: {_isMultiViewImage}"
        + $", isAgeProgressed: {_isAgeProgressed}"
        + $", isSuperResolutionProcessed: {_isSuperResolutionProcessed}"
        + $", isNormalised: {_isNormalised}"
        + "]";

    /* PACKAGE */

    internal override Asn1Encodable GetAsn1Object()
    {
        var taggedObjects = new Dictionary<int, Asn1Encodable>();
        if (_isRotated != null)
        {
            taggedObjects[0] = ASN1Util.EncodeBoolean(_isRotated.Value);
        }
        if (_isCropped != null)
        {
            taggedObjects[1] = ASN1Util.EncodeBoolean(_isCropped.Value);
        }
        if (_isDownSampled != null)
        {
            taggedObjects[2] = ASN1Util.EncodeBoolean(_isDownSampled.Value);
        }
        if (_isWhiteBalanceAdjusted != null)
        {
            taggedObjects[3] = ASN1Util.EncodeBoolean(_isWhiteBalanceAdjusted.Value);
        }
        if (_isMultiplyCompressed != null)
        {
            taggedObjects[4] = ASN1Util.EncodeBoolean(_isMultiplyCompressed.Value);
        }
        if (_isInterpolated != null)
        {
            taggedObjects[5] = ASN1Util.EncodeBoolean(_isInterpolated.Value);
        }
        if (_isContrastStretched != null)
        {
            taggedObjects[6] = ASN1Util.EncodeBoolean(_isContrastStretched.Value);
        }
        if (_isPoseCorrected != null)
        {
            taggedObjects[7] = ASN1Util.EncodeBoolean(_isPoseCorrected.Value);
        }
        if (_isMultiViewImage != null)
        {
            taggedObjects[8] = ASN1Util.EncodeBoolean(_isMultiViewImage.Value);
        }
        if (_isAgeProgressed != null)
        {
            taggedObjects[9] = ASN1Util.EncodeBoolean(_isAgeProgressed.Value);
        }
        if (_isSuperResolutionProcessed != null)
        {
            taggedObjects[10] = ASN1Util.EncodeBoolean(_isSuperResolutionProcessed.Value);
        }
        if (_isNormalised != null)
        {
            taggedObjects[11] = ASN1Util.EncodeBoolean(_isNormalised.Value);
        }
        return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
    }
}
