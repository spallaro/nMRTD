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

//  CoordinateCartesian3DUnsignedShortBlock ::= SEQUENCE {
//    x               [0] INTEGER (0..65535),
//    y               [1] INTEGER (0..65535),
//    z               [2] INTEGER (0..65535)
//  }

/// <summary>
/// Port of <c>org.jmrtd.lds.iso39794.CoordinateCartesian3DUnsignedShortBlock</c>. Java's
/// <c>Serializable</c> marker is dropped (no reflection-based serialization is needed in this port).
/// Implements <see cref="FaceImageLandmarkCoordinates"/> (a marker interface consumed by
/// <c>FaceImageLandmarkBlock</c>/<c>FaceImageCoordinateTextureImageBlock</c>), matching Java's
/// <c>implements FaceImageLandmarkCoordinates</c>.
/// </summary>
public class CoordinateCartesian3DUnsignedShortBlock : Block, FaceImageLandmarkCoordinates
{
    private readonly int _x;
    private readonly int _y;
    private readonly int _z;

    public CoordinateCartesian3DUnsignedShortBlock(int x, int y, int z)
    {
        _x = x;
        _y = y;
        _z = z;
    }

    internal CoordinateCartesian3DUnsignedShortBlock(Asn1Encodable asn1Encodable)
    {
        Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
        _x = ASN1Util.DecodeInt(taggedObjects[0]);
        _y = ASN1Util.DecodeInt(taggedObjects[1]);
        _z = ASN1Util.DecodeInt(taggedObjects[2]);
    }

    public int GetX() => _x;

    public int GetY() => _y;

    public int GetZ() => _z;

    public override int GetHashCode() => HashCode.Combine(_x, _y, _z);

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

        var otherBlock = (CoordinateCartesian3DUnsignedShortBlock)other;
        return _x == otherBlock._x && _y == otherBlock._y && _z == otherBlock._z;
    }

    public override string ToString() =>
        $"CoordinateCartesian3DUnsignedShortBlock [x: {_x}, y: {_y}, z: {_z}]";

    /* PACKAGE */

    internal override Asn1Encodable GetAsn1Object()
    {
        var taggedObjects = new Dictionary<int, Asn1Encodable>
        {
            [0] = ASN1Util.EncodeInt(_x),
            [1] = ASN1Util.EncodeInt(_y),
            [2] = ASN1Util.EncodeInt(_z),
        };
        return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
    }
}
