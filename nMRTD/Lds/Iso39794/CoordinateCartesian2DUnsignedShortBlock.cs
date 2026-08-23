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

//  CoordinateCartesian2DUnsignedShortBlock ::= SEQUENCE {
//    x               [0] INTEGER (0..65535),
//    y               [1] INTEGER (0..65535)
//  }

/// <summary>
/// Port of <c>org.jmrtd.lds.iso39794.CoordinateCartesian2DUnsignedShortBlock</c>. Java's
/// <c>Serializable</c> marker is dropped (no reflection-based serialization is needed in this port).
///
/// ADAPTATION: Java's version is also a top-level <c>public class</c>, but this is <c>internal</c> since its
/// base class <see cref="Block"/> is <c>internal</c> in this port (see <c>VersionBlock</c>'s doc comment).
/// Implements <see cref="FaceImageLandmarkCoordinates"/> (a marker interface consumed by
/// <c>FaceImageLandmarkBlock</c>/<c>FaceImageCoordinateTextureImageBlock</c>), matching Java's
/// <c>implements FaceImageLandmarkCoordinates</c>.
/// </summary>
internal class CoordinateCartesian2DUnsignedShortBlock : Block, FaceImageLandmarkCoordinates
{
    private readonly int _x;
    private readonly int _y;

    public CoordinateCartesian2DUnsignedShortBlock(int x, int y)
    {
        _x = x;
        _y = y;
    }

    internal CoordinateCartesian2DUnsignedShortBlock(Asn1Encodable asn1Encodable)
    {
        Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
        _x = ASN1Util.DecodeInt(taggedObjects[0]);
        _y = ASN1Util.DecodeInt(taggedObjects[1]);
    }

    public int GetX() => _x;

    public int GetY() => _y;

    public override int GetHashCode() => HashCode.Combine(_x, _y);

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

        var otherBlock = (CoordinateCartesian2DUnsignedShortBlock)other;
        return _x == otherBlock._x && _y == otherBlock._y;
    }

    public override string ToString() =>
        $"CoordinateCartesian2DUnsignedShortBlock [x: {_x}, y: {_y}]";

    /* PACKAGE */

    internal static List<CoordinateCartesian2DUnsignedShortBlock> DecodeCoordinateCartesian2DUnsignedShortBlocks(Asn1Encodable asn1Encodable)
    {
        if (ASN1Util.IsSequenceOfSequences(asn1Encodable))
        {
            List<Asn1Encodable> blockAsn1Objects = ASN1Util.List(asn1Encodable)!;
            var blocks = new List<CoordinateCartesian2DUnsignedShortBlock>(blockAsn1Objects.Count);
            foreach (Asn1Encodable blockAsn1Object in blockAsn1Objects)
            {
                blocks.Add(new CoordinateCartesian2DUnsignedShortBlock(blockAsn1Object));
            }

            return blocks;
        }

        return [new CoordinateCartesian2DUnsignedShortBlock(asn1Encodable)];
    }

    internal override Asn1Encodable GetAsn1Object()
    {
        var taggedObjects = new Dictionary<int, Asn1Encodable>
        {
            [0] = ASN1Util.EncodeInt(_x),
            [1] = ASN1Util.EncodeInt(_y),
        };
        return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
    }
}
