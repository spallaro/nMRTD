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

//  PoseAngleBlock ::= SEQUENCE {
//    yawAngleBlock [0] AngleDataBlock OPTIONAL,
//    pitchAngleBlock [1] AngleDataBlock OPTIONAL,
//    rollAngleBlock [2] AngleDataBlock OPTIONAL
//  }

/// <summary>
/// Port of <c>org.jmrtd.lds.iso39794.FaceImagePoseAngleBlock</c>. Java's <c>Serializable</c> marker is
/// dropped (no reflection-based serialization is needed in this port). Java's
/// <c>public static long getSerialversionuid()</c> accessor (a leftover artifact exposing the dropped
/// <c>serialVersionUID</c> field) is omitted entirely, matching this port's blanket dropping of
/// <c>Serializable</c>-related surface.
/// </summary>
public class FaceImagePoseAngleBlock : Block
{
    /// <summary>
    /// ADAPTATION: Java's version is a nested <c>public static class AngleDataBlock extends Block</c>; ported as a public nested class.
    /// </summary>
    public class AngleDataBlock : Block
    {
        /// <summary>INTEGER (-180..180).</summary>
        private readonly int _angleValue;

        /// <summary>INTEGER (0..180).</summary>
        private readonly int _angleUncertainty;

        public AngleDataBlock(int angleValue, int angleUncertainty)
        {
            _angleValue = angleValue;
            _angleUncertainty = angleUncertainty;
        }

        internal AngleDataBlock(Asn1Encodable asn1Encodable)
        {
            Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
            _angleValue = ASN1Util.DecodeInt(taggedObjects[0]);
            _angleUncertainty = taggedObjects.TryGetValue(1, out Asn1Encodable? uncertaintyObject)
                ? ASN1Util.DecodeInt(uncertaintyObject)
                : -1;
        }

        public int GetAngleValue() => _angleValue;

        public int GetAngleUncertainty() => _angleUncertainty;

        public override int GetHashCode() => HashCode.Combine(_angleUncertainty, _angleValue);

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

            var otherBlock = (AngleDataBlock)other;
            return _angleUncertainty == otherBlock._angleUncertainty && _angleValue == otherBlock._angleValue;
        }

        public override string ToString() =>
            $"AngleDataBlock [angleValue: {_angleValue}, angleUncertainty: {_angleUncertainty}]";

        internal override Asn1Encodable GetAsn1Object()
        {
            var taggedObjects = new Dictionary<int, Asn1Encodable>
            {
                [0] = ASN1Util.EncodeInt(_angleValue),
            };
            if (_angleUncertainty >= 0)
            {
                taggedObjects[1] = ASN1Util.EncodeInt(_angleUncertainty);
            }
            return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
        }
    }

    private readonly AngleDataBlock? _yawAngleDataBlock;
    private readonly AngleDataBlock? _pitchAngleDataBlock;
    private readonly AngleDataBlock? _rollAngleDataBlock;

    public FaceImagePoseAngleBlock(AngleDataBlock? yawAngleDataBlock, AngleDataBlock? pitchAngleDataBlock,
        AngleDataBlock? rollAngleDataBlock)
    {
        _yawAngleDataBlock = yawAngleDataBlock;
        _pitchAngleDataBlock = pitchAngleDataBlock;
        _rollAngleDataBlock = rollAngleDataBlock;
    }

    internal FaceImagePoseAngleBlock(Asn1Encodable asn1Encodable)
    {
        Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
        if (taggedObjects.TryGetValue(0, out Asn1Encodable? yawObject))
        {
            _yawAngleDataBlock = new AngleDataBlock(yawObject);
        }
        if (taggedObjects.TryGetValue(1, out Asn1Encodable? pitchObject))
        {
            _pitchAngleDataBlock = new AngleDataBlock(pitchObject);
        }
        if (taggedObjects.TryGetValue(2, out Asn1Encodable? rollObject))
        {
            _rollAngleDataBlock = new AngleDataBlock(rollObject);
        }
    }

    public AngleDataBlock? GetYawAngleDataBlock() => _yawAngleDataBlock;

    public AngleDataBlock? GetPitchAngleDataBlock() => _pitchAngleDataBlock;

    public AngleDataBlock? GetRollAngleDataBlock() => _rollAngleDataBlock;

    public override int GetHashCode() => HashCode.Combine(_pitchAngleDataBlock, _rollAngleDataBlock, _yawAngleDataBlock);

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

        var otherBlock = (FaceImagePoseAngleBlock)other;
        return Equals(_pitchAngleDataBlock, otherBlock._pitchAngleDataBlock)
            && Equals(_rollAngleDataBlock, otherBlock._rollAngleDataBlock)
            && Equals(_yawAngleDataBlock, otherBlock._yawAngleDataBlock);
    }

    public override string ToString() =>
        $"FaceImagePoseAngleBlock [yawAngleDataBlock: {_yawAngleDataBlock}, pitchAngleDataBlock: {_pitchAngleDataBlock}, rollAngleDataBlock: {_rollAngleDataBlock}]";

    /* PACKAGE */

    internal override Asn1Encodable GetAsn1Object()
    {
        var taggedObjects = new Dictionary<int, Asn1Encodable>();
        if (_yawAngleDataBlock != null)
        {
            taggedObjects[0] = _yawAngleDataBlock.GetAsn1Object();
        }
        if (_pitchAngleDataBlock != null)
        {
            taggedObjects[1] = _pitchAngleDataBlock.GetAsn1Object();
        }
        if (_rollAngleDataBlock != null)
        {
            taggedObjects[2] = _rollAngleDataBlock.GetAsn1Object();
        }
        return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
    }
}
