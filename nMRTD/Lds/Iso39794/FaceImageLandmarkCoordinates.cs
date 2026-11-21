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

//  LandmarkCoordinates ::= CHOICE {
//    base [0] LandmarkCoordinatesBase,
//    extensionBlock [1] LandmarkCoordinatesExtensionBlock
//  }
//
//  LandmarkCoordinatesBase ::= CHOICE {
//    coordinateCartesian2DBlock [0] CoordinateCartesian2DUnsignedShortBlock,
//    coordinateTextureImageBlock [1] CoordinateTextureImageBlock,
//    coordinateCartesian3DBlock [2] CoordinateCartesian3DUnsignedShortBlock
//  }

/// <summary>
/// Port of <c>org.jmrtd.lds.iso39794.FaceImageLandmarkCoordinates</c>: a marker interface for the three
/// concrete "landmark coordinates" block shapes -- <see cref="CoordinateCartesian2DUnsignedShortBlock"/>,
/// <see cref="FaceImageCoordinateTextureImageBlock"/>, and <see cref="CoordinateCartesian3DUnsignedShortBlock"/>
/// -- plus the CHOICE-with-extension-block-fallback decode/encode dispatch shared by all three.
///
/// ADAPTATION: Java's version declares <c>hashCode()</c>/<c>equals(Object)</c> purely as documentation
/// (every Java <c>Object</c> already has them); omitted here since every C# object has the same guarantee.
/// Java's <c>Serializable</c> super-interface is dropped for the same reason as elsewhere in this port.
/// Java's version is a top-level <c>public interface</c>, and so is this one.
///
/// The two static factory methods (<c>decodeLandmarkCoordinates</c>/<c>encodeLandmarkCoordinates</c>) are
/// ported as C# static interface members with a body (supported since C# 8, fully available on .NET 8),
/// matching Java's own placement of this dispatch logic directly on the interface rather than as
/// free-standing helpers in a separate utility class.
/// </summary>
public interface FaceImageLandmarkCoordinates
{
    static FaceImageLandmarkCoordinates? DecodeLandmarkCoordinates(Asn1Encodable asn1Encodable)
    {
        Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
        if (taggedObjects.TryGetValue(0, out Asn1Encodable? baseObject))
        {
            Dictionary<int, Asn1Encodable> baseTaggedObjects = ASN1Util.DecodeTaggedObjects(baseObject);
            if (baseTaggedObjects.TryGetValue(0, out Asn1Encodable? coordinateCartesian2D))
            {
                return new CoordinateCartesian2DUnsignedShortBlock(coordinateCartesian2D);
            }

            if (baseTaggedObjects.TryGetValue(1, out Asn1Encodable? coordinateTextureImage))
            {
                return new FaceImageCoordinateTextureImageBlock(coordinateTextureImage);
            }

            if (baseTaggedObjects.TryGetValue(2, out Asn1Encodable? coordinateCartesian3D))
            {
                return new CoordinateCartesian3DUnsignedShortBlock(coordinateCartesian3D);
            }
        }

        return null;
    }

    static Asn1Encodable EncodeLandmarkCoordinates(FaceImageLandmarkCoordinates landmarkCoordinates)
    {
        var baseTaggedObjects = new Dictionary<int, Asn1Encodable>();
        switch (landmarkCoordinates)
        {
            case CoordinateCartesian2DUnsignedShortBlock block2D:
                baseTaggedObjects[0] = block2D.GetAsn1Object();
                break;
            case FaceImageCoordinateTextureImageBlock textureImage:
                baseTaggedObjects[1] = textureImage.GetAsn1Object();
                break;
            case CoordinateCartesian3DUnsignedShortBlock block3D:
                baseTaggedObjects[2] = block3D.GetAsn1Object();
                break;
        }

        var taggedObjects = new Dictionary<int, Asn1Encodable>
        {
            [0] = ASN1Util.EncodeTaggedObjects(baseTaggedObjects)!,
        };
        return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
    }
}
