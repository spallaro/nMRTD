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

//  CoordinateTextureImageBlock ::= SEQUENCE {
//    uInPixel [0] INTEGER (0..MAX),
//    vInPixel [1] INTEGER (0..MAX)
//  }

/// <summary>
/// Port of <c>org.jmrtd.lds.iso39794.FaceImageCoordinateTextureImageBlock</c>. Java's <c>Serializable</c>
/// marker is dropped (no reflection-based serialization is needed in this port).
/// Java's <c>uInPixel</c>/<c>vInPixel</c> are <c>java.math.BigInteger</c>; kept here as BouncyCastle's own
/// <c>Org.BouncyCastle.Math.BigInteger</c> (rather than this port's usual <c>System.Numerics.BigInteger</c>
/// convention for Java <c>BigInteger</c> -- see <c>docs\porting-conventions.md</c>) in order to interoperate
/// directly with <see cref="ASN1Util.DecodeBigInteger"/>/<see cref="ASN1Util.EncodeBigInteger"/>, which are
/// themselves already typed against BouncyCastle's <c>BigInteger</c> throughout this package.
/// </summary>
public class FaceImageCoordinateTextureImageBlock : Block, FaceImageLandmarkCoordinates
{
    private readonly BigInteger _uInPixel;
    private readonly BigInteger _vInPixel;

    public FaceImageCoordinateTextureImageBlock(BigInteger uInPixel, BigInteger vInPixel)
    {
        _uInPixel = uInPixel;
        _vInPixel = vInPixel;
    }

    internal FaceImageCoordinateTextureImageBlock(Asn1Encodable asn1Encodable)
    {
        Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
        _uInPixel = ASN1Util.DecodeBigInteger(taggedObjects[0]);
        _vInPixel = ASN1Util.DecodeBigInteger(taggedObjects[1]);
    }

    public BigInteger GetUInPixel() => _uInPixel;

    public BigInteger GetVInPixel() => _vInPixel;

    public override int GetHashCode() => HashCode.Combine(_uInPixel, _vInPixel);

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

        var otherBlock = (FaceImageCoordinateTextureImageBlock)other;
        return Equals(_uInPixel, otherBlock._uInPixel) && Equals(_vInPixel, otherBlock._vInPixel);
    }

    public override string ToString() =>
        $"CoordinateTextureImageBlock [uInPixel: {_uInPixel}, vInPixel: {_vInPixel}]";

    /* PACKAGE */

    internal override Asn1Encodable GetAsn1Object()
    {
        var taggedObjects = new Dictionary<int, Asn1Encodable>
        {
            [0] = ASN1Util.EncodeBigInteger(_uInPixel),
            [1] = ASN1Util.EncodeBigInteger(_vInPixel),
        };
        return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
    }
}
