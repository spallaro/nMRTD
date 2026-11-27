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
/// The CHOICE-with-extension-block decode and encode of <see cref="FaceImageLandmarkCoordinates"/> (Java's static
/// <c>decodeLandmarkCoordinates</c>/<c>encodeLandmarkCoordinates</c> on the interface, where .NET Framework cannot
/// have them).
/// </summary>
public static class FaceImageLandmarkCoordinatesCodec
{
    public static FaceImageLandmarkCoordinates? DecodeLandmarkCoordinates(Asn1Encodable asn1Encodable)
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

    public static Asn1Encodable EncodeLandmarkCoordinates(FaceImageLandmarkCoordinates landmarkCoordinates)
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
