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

//  ExpressionBlock ::= SEQUENCE {
//    neutral [0] BOOLEAN OPTIONAL,
//    smile [1] BOOLEAN OPTIONAL,
//    raisedEyebrows [2] BOOLEAN OPTIONAL,
//    eyesLookingAwayFromTheCamera [3] BOOLEAN OPTIONAL,
//    squinting [4] BOOLEAN OPTIONAL,
//    frowning [5] BOOLEAN OPTIONAL,
//    ...
//  }

/// <summary>
/// Port of <c>org.jmrtd.lds.iso39794.FaceImageExpressionBlock</c>. Java's <c>Serializable</c> marker is
/// dropped (no reflection-based serialization is needed in this port).
/// </summary>
public class FaceImageExpressionBlock : Block
{
    private readonly bool? _isNeutral;
    private readonly bool? _isSmile;
    private readonly bool? _isRaisedEyebrows;
    private readonly bool? _isEyesLookingAwayFromTheCamera;
    private readonly bool? _isSquinting;
    private readonly bool? _isFrowning;

    public FaceImageExpressionBlock(bool? isNeutral, bool? isSmile, bool? isRaisedEyebrows,
        bool? isEyesLookingAwayFromTheCamera, bool? isSquinting, bool? isFrowning)
    {
        _isNeutral = isNeutral;
        _isSmile = isSmile;
        _isRaisedEyebrows = isRaisedEyebrows;
        _isEyesLookingAwayFromTheCamera = isEyesLookingAwayFromTheCamera;
        _isSquinting = isSquinting;
        _isFrowning = isFrowning;
    }

    internal FaceImageExpressionBlock(Asn1Encodable asn1Encodable)
    {
        Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
        if (taggedObjects.TryGetValue(0, out Asn1Encodable? neutralObject))
        {
            _isNeutral = ASN1Util.DecodeBoolean(neutralObject);
        }
        if (taggedObjects.TryGetValue(1, out Asn1Encodable? smileObject))
        {
            _isSmile = ASN1Util.DecodeBoolean(smileObject);
        }
        if (taggedObjects.TryGetValue(2, out Asn1Encodable? raisedEyebrowsObject))
        {
            _isRaisedEyebrows = ASN1Util.DecodeBoolean(raisedEyebrowsObject);
        }
        if (taggedObjects.TryGetValue(3, out Asn1Encodable? eyesLookingAwayObject))
        {
            _isEyesLookingAwayFromTheCamera = ASN1Util.DecodeBoolean(eyesLookingAwayObject);
        }
        if (taggedObjects.TryGetValue(4, out Asn1Encodable? squintingObject))
        {
            _isSquinting = ASN1Util.DecodeBoolean(squintingObject);
        }
        if (taggedObjects.TryGetValue(5, out Asn1Encodable? frowningObject))
        {
            _isFrowning = ASN1Util.DecodeBoolean(frowningObject);
        }
    }

    public bool? IsNeutral() => _isNeutral;

    public bool? IsSmile() => _isSmile;

    public bool? IsRaisedEyebrows() => _isRaisedEyebrows;

    public bool? IsEyesLookingAwayFromTheCamera() => _isEyesLookingAwayFromTheCamera;

    public bool? IsSquinting() => _isSquinting;

    public bool? IsFrowning() => _isFrowning;

    public override int GetHashCode() =>
        HashCode.Combine(_isEyesLookingAwayFromTheCamera, _isFrowning, _isNeutral, _isRaisedEyebrows, _isSmile, _isSquinting);

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

        var otherBlock = (FaceImageExpressionBlock)other;
        return _isEyesLookingAwayFromTheCamera == otherBlock._isEyesLookingAwayFromTheCamera
            && _isFrowning == otherBlock._isFrowning
            && _isNeutral == otherBlock._isNeutral
            && _isRaisedEyebrows == otherBlock._isRaisedEyebrows
            && _isSmile == otherBlock._isSmile
            && _isSquinting == otherBlock._isSquinting;
    }

    public override string ToString() =>
        "FaceImageExpressionBlock ["
        + $"isNeutral: {_isNeutral}"
        + $", isSmile: {_isSmile}"
        + $", isRaisedEyebrows: {_isRaisedEyebrows}"
        + $", isEyesLookingAwayFromTheCamera: {_isEyesLookingAwayFromTheCamera}"
        + $", isSquinting: {_isSquinting}"
        + $", isFrowning: {_isFrowning}"
        + "]";

    /* PACKAGE */

    internal override Asn1Encodable GetAsn1Object()
    {
        var taggedObjects = new Dictionary<int, Asn1Encodable>();
        if (_isNeutral != null)
        {
            taggedObjects[0] = ASN1Util.EncodeBoolean(_isNeutral.Value);
        }
        if (_isSmile != null)
        {
            taggedObjects[1] = ASN1Util.EncodeBoolean(_isSmile.Value);
        }
        if (_isRaisedEyebrows != null)
        {
            taggedObjects[2] = ASN1Util.EncodeBoolean(_isRaisedEyebrows.Value);
        }
        if (_isEyesLookingAwayFromTheCamera != null)
        {
            taggedObjects[3] = ASN1Util.EncodeBoolean(_isEyesLookingAwayFromTheCamera.Value);
        }
        if (_isSquinting != null)
        {
            taggedObjects[4] = ASN1Util.EncodeBoolean(_isSquinting.Value);
        }
        if (_isFrowning != null)
        {
            taggedObjects[5] = ASN1Util.EncodeBoolean(_isFrowning.Value);
        }
        return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
    }
}
