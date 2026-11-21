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

//  LandmarkBlock ::= SEQUENCE {
//    landmarkKind [0] LandmarkKind,
//    landmarkCoordinates [1] LandmarkCoordinates OPTIONAL,
//    ...
//  }

/// <summary>
/// Port of <c>org.jmrtd.lds.iso39794.FaceImageLandmarkBlock</c>. Java's <c>Serializable</c> marker is
/// dropped (no reflection-based serialization is needed in this port).
/// </summary>
public class FaceImageLandmarkBlock : Block
{
    private readonly FaceImageLandmarkKind? _landmarkKind;
    private readonly FaceImageLandmarkCoordinates? _landmarkCoordinates;

    public FaceImageLandmarkBlock(FaceImageLandmarkKind? landmarkKind, FaceImageLandmarkCoordinates? landmarkCoordinates)
    {
        _landmarkKind = landmarkKind;
        _landmarkCoordinates = landmarkCoordinates;
    }

    internal FaceImageLandmarkBlock(Asn1Encodable asn1Encodable)
    {
        Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
        _landmarkKind = FaceImageLandmarkKind.DecodeLandmarkKind(taggedObjects[0]);
        if (taggedObjects.TryGetValue(1, out Asn1Encodable? coordinatesObject))
        {
            _landmarkCoordinates = FaceImageLandmarkCoordinates.DecodeLandmarkCoordinates(coordinatesObject);
        }
    }

    public FaceImageLandmarkKind? GetLandmarkKind() => _landmarkKind;

    public FaceImageLandmarkCoordinates? GetLandmarkCoordinates() => _landmarkCoordinates;

    public override int GetHashCode() => HashCode.Combine(_landmarkCoordinates, _landmarkKind);

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

        var otherBlock = (FaceImageLandmarkBlock)other;
        return Equals(_landmarkCoordinates, otherBlock._landmarkCoordinates) && Equals(_landmarkKind, otherBlock._landmarkKind);
    }

    public override string ToString() =>
        $"FaceImageLandmarkBlock [landmarkKind: {_landmarkKind}, landmarkCoordinates: {_landmarkCoordinates}]";

    /* PACKAGE */

    internal override Asn1Encodable GetAsn1Object() => GetAsn1Object(ISO39794EncodingProfile.Base);

    internal override Asn1Encodable GetAsn1Object(ISO39794EncodingProfile profile)
    {
        var taggedObjects = new Dictionary<int, Asn1Encodable>
        {
            [0] = FaceImageLandmarkKind.EncodeLandmarkKind(_landmarkKind, profile),
        };
        if (_landmarkCoordinates != null)
        {
            taggedObjects[1] = FaceImageLandmarkCoordinates.EncodeLandmarkCoordinates(_landmarkCoordinates);
        }
        return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
    }

    internal static List<FaceImageLandmarkBlock> DecodeLandmarkBlocks(Asn1Encodable asn1Encodable)
    {
        if (ASN1Util.IsSequenceOfSequences(asn1Encodable))
        {
            List<Asn1Encodable> blockAsn1Objects = ASN1Util.List(asn1Encodable)!;
            var blocks = new List<FaceImageLandmarkBlock>(blockAsn1Objects.Count);
            foreach (Asn1Encodable blockAsn1Object in blockAsn1Objects)
            {
                blocks.Add(new FaceImageLandmarkBlock(blockAsn1Object));
            }

            return blocks;
        }

        return [new FaceImageLandmarkBlock(asn1Encodable)];
    }
}
