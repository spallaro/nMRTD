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
using BigInteger = Org.BouncyCastle.Math.BigInteger;

namespace nMRTD.Lds.Iso39794;

//  RepresentationBlock ::= SEQUENCE {
//    representationId [0] INTEGER (0..MAX),
//    imageRepresentation [1] ImageRepresentation,
//    captureDateTimeBlock [2] CaptureDateTimeBlock OPTIONAL,
//    qualityBlocks [3] QualityBlocks OPTIONAL,
//    padDataBlock [4] PADDataBlock OPTIONAL,
//    sessionId [5] INTEGER (0..MAX) OPTIONAL,
//    derivedFrom [6] INTEGER (0..MAX) OPTIONAL,
//    captureDeviceBlock [7] CaptureDeviceBlock OPTIONAL,
//    identityMetadataBlock [8] IdentityMetadataBlock OPTIONAL,
//    landmarkBlocks [9] LandmarkBlocks OPTIONAL,
//    ...
//  }

//  ImageRepresentation ::= CHOICE {
//    base [0] ImageRepresentationBase,
//    extensionBlock [1] ImageRepresentationExtensionBlock
//  }
//
//  ImageRepresentationBase ::= CHOICE {
//    imageRepresentation2DBlock [0] ImageRepresentation2DBlock
//  }
//
//  ImageRepresentationExtensionBlock ::= SEQUENCE {
//    ...
//  }

/// <summary>
/// Port of <c>org.jmrtd.lds.iso39794.FaceImageRepresentationBlock</c>. Java's <c>Serializable</c> marker is
/// dropped (no reflection-based serialization is needed in this port).
///
/// ADAPTATION: Java's version is also a top-level <c>public class</c>, but this is <c>internal</c> since its
/// base class <see cref="Block"/> is <c>internal</c> in this port (see <c>VersionBlock</c>'s doc comment). It
/// is however required to expose exactly <see cref="GetImageRepresentation2DBlock"/>,
/// <see cref="GetPadDataBlocks"/>, and <see cref="GetIdentityMetadataBlock"/>, referenced by
/// <see cref="ISO39794EncodingProfileExtensions.Validate"/> in the already-committed
/// <c>ISO39794EncodingProfile.cs</c> -- an established contract this class must satisfy exactly. Java's
/// version also <c>implements ImageInfo</c> (<c>org.jmrtd.lds.ImageInfo</c>); this port implements
/// <see cref="nMRTD.Lds.ImageInfo"/> the same way regardless of this class's own reduced (<c>internal</c>)
/// visibility, matching <c>IrisImageRepresentationBlock</c>'s own established precedent.
/// </summary>
internal class FaceImageRepresentationBlock : Block, ImageInfo
{
    private readonly BigInteger _representationId;
    private readonly FaceImageRepresentation2DBlock? _imageRepresentation2DBlock;
    private readonly DateTimeBlock? _captureDateTimeBlock;
    private readonly List<QualityBlock>? _qualityBlocks;
    private readonly List<PADDataBlock>? _padDataBlocks;
    private readonly BigInteger? _sessionId;
    private readonly BigInteger? _derivedFrom;
    private readonly FaceImageCaptureDeviceBlock? _captureDeviceBlock;
    private readonly FaceImageIdentityMetadataBlock? _identityMetadataBlock;
    private readonly List<FaceImageLandmarkBlock>? _landmarkBlocks;

    public FaceImageRepresentationBlock(BigInteger representationId,
        FaceImageRepresentation2DBlock? imageRepresentation2DBlock, DateTimeBlock? captureDateTimeBlock,
        List<QualityBlock>? qualityBlocks, List<PADDataBlock>? padDataBlocks, BigInteger? sessionId,
        BigInteger? derivedFrom, FaceImageCaptureDeviceBlock? captureDeviceBlock,
        FaceImageIdentityMetadataBlock? identityMetadataBlock, List<FaceImageLandmarkBlock>? landmarkBlocks)
    {
        _representationId = representationId;
        _imageRepresentation2DBlock = imageRepresentation2DBlock;
        _captureDateTimeBlock = captureDateTimeBlock;
        _qualityBlocks = qualityBlocks;
        _padDataBlocks = padDataBlocks;
        _sessionId = sessionId;
        _derivedFrom = derivedFrom;
        _captureDeviceBlock = captureDeviceBlock;
        _identityMetadataBlock = identityMetadataBlock;
        _landmarkBlocks = landmarkBlocks;
    }

    /// <summary>NOTE: preserved Java quirk -- unlike every other decode constructor in this package, Java's
    /// version has no leading type check on <paramref name="asn1Encodable"/> at all; it goes straight to
    /// <c>ASN1Util.decodeTaggedObjects</c>, which itself tolerates a <see langword="null"/> input by returning
    /// an empty map (see <c>ASN1Util.DecodeTaggedObjects</c>). Kept as-is.</summary>
    internal FaceImageRepresentationBlock(Asn1Encodable? asn1Encodable)
    {
        Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
        _representationId = ASN1Util.DecodeBigInteger(taggedObjects[0]);
        _imageRepresentation2DBlock = DecodeImageRepresentation2DBlock(
            taggedObjects.TryGetValue(1, out Asn1Encodable? imageRepresentationObject) ? imageRepresentationObject : null);
        if (taggedObjects.TryGetValue(2, out Asn1Encodable? captureDateTimeObject))
        {
            _captureDateTimeBlock = new DateTimeBlock(captureDateTimeObject);
        }
        if (taggedObjects.TryGetValue(3, out Asn1Encodable? qualityBlocksObject))
        {
            _qualityBlocks = QualityBlock.DecodeQualityBlocks(qualityBlocksObject);
        }
        if (taggedObjects.TryGetValue(4, out Asn1Encodable? padDataBlocksObject))
        {
            _padDataBlocks = PADDataBlock.DecodePADDataBlocks(padDataBlocksObject);
        }
        if (taggedObjects.TryGetValue(5, out Asn1Encodable? sessionIdObject))
        {
            _sessionId = ASN1Util.DecodeBigInteger(sessionIdObject);
        }
        if (taggedObjects.TryGetValue(6, out Asn1Encodable? derivedFromObject))
        {
            _derivedFrom = ASN1Util.DecodeBigInteger(derivedFromObject);
        }
        if (taggedObjects.TryGetValue(7, out Asn1Encodable? captureDeviceObject))
        {
            _captureDeviceBlock = new FaceImageCaptureDeviceBlock(captureDeviceObject);
        }
        if (taggedObjects.TryGetValue(8, out Asn1Encodable? identityMetadataObject))
        {
            _identityMetadataBlock = new FaceImageIdentityMetadataBlock(identityMetadataObject);
        }
        if (taggedObjects.TryGetValue(9, out Asn1Encodable? landmarkBlocksObject))
        {
            _landmarkBlocks = FaceImageLandmarkBlock.DecodeLandmarkBlocks(landmarkBlocksObject);
        }
    }

    public BigInteger GetRepresentationId() => _representationId;

    public FaceImageRepresentation2DBlock? GetImageRepresentation2DBlock() => _imageRepresentation2DBlock;

    public FaceImageIdentityMetadataBlock? GetIdentityMetadataBlock() => _identityMetadataBlock;

    public List<FaceImageLandmarkBlock>? GetLandmarkBlocks() => _landmarkBlocks;

    public FaceImageCaptureDeviceBlock? GetCaptureDeviceBlock() => _captureDeviceBlock;

    public DateTimeBlock? GetCaptureDateTimeBlock() => _captureDateTimeBlock;

    public List<QualityBlock>? GetQualityBlocks() => _qualityBlocks;

    public List<PADDataBlock>? GetPadDataBlocks() => _padDataBlocks;

    public BigInteger? GetSessionId() => _sessionId;

    public BigInteger? GetDerivedFrom() => _derivedFrom;

    public override int GetHashCode() =>
        JavaObjectsHash(
            _captureDateTimeBlock?.GetHashCode() ?? 0,
            _captureDeviceBlock?.GetHashCode() ?? 0,
            _derivedFrom?.GetHashCode() ?? 0,
            _identityMetadataBlock?.GetHashCode() ?? 0,
            _imageRepresentation2DBlock?.GetHashCode() ?? 0,
            JavaListHashCode(_landmarkBlocks),
            JavaListHashCode(_padDataBlocks),
            JavaListHashCode(_qualityBlocks),
            _representationId.GetHashCode(),
            _sessionId?.GetHashCode() ?? 0);

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

        var otherBlock = (FaceImageRepresentationBlock)other;
        return Equals(_captureDateTimeBlock, otherBlock._captureDateTimeBlock)
            && Equals(_captureDeviceBlock, otherBlock._captureDeviceBlock)
            && Equals(_derivedFrom, otherBlock._derivedFrom)
            && Equals(_identityMetadataBlock, otherBlock._identityMetadataBlock)
            && Equals(_imageRepresentation2DBlock, otherBlock._imageRepresentation2DBlock)
            && ListEquals(_landmarkBlocks, otherBlock._landmarkBlocks)
            && ListEquals(_padDataBlocks, otherBlock._padDataBlocks)
            && ListEquals(_qualityBlocks, otherBlock._qualityBlocks)
            && Equals(_representationId, otherBlock._representationId)
            && Equals(_sessionId, otherBlock._sessionId);
    }

    public override string ToString() =>
        "FaceImageRepresentationBlock ["
        + $"representationId: {_representationId}"
        + $", imageRepresentation: {_imageRepresentation2DBlock}"
        + $", captureDateTimeBlock: {_captureDateTimeBlock}"
        + $", qualityBlocks: {JavaListToString(_qualityBlocks)}"
        + $", padDataBlocks: {JavaListToString(_padDataBlocks)}"
        + $", sessionId: {_sessionId}"
        + $", derivedFrom: {_derivedFrom}"
        + $", captureDeviceBlock: {_captureDeviceBlock}"
        + $", identityMetadataBlock: {_identityMetadataBlock}"
        + $", landmarkBlocks: {JavaListToString(_landmarkBlocks)}"
        + "]";

    public int GetImageType() => ImageInfo.TYPE_PORTRAIT;

    public string? GetMimeType() =>
        _imageRepresentation2DBlock == null ? "image/raw" : _imageRepresentation2DBlock.GetRepresentationData2DInputMimeType();

    public int GetWidth()
    {
        if (_imageRepresentation2DBlock == null)
        {
            return 0;
        }

        FaceImageInformation2DBlock? information2DBlock = _imageRepresentation2DBlock.GetImageInformation2DBlock();
        if (information2DBlock == null)
        {
            return 0;
        }

        FaceImageInformation2DBlock.ImageSizeBlock? imageSizeBlock = information2DBlock.GetImageSizeBlock();
        return imageSizeBlock == null ? 0 : imageSizeBlock.GetWidth();
    }

    public int GetHeight()
    {
        if (_imageRepresentation2DBlock == null)
        {
            return 0;
        }

        FaceImageInformation2DBlock? information2DBlock = _imageRepresentation2DBlock.GetImageInformation2DBlock();
        if (information2DBlock == null)
        {
            return 0;
        }

        FaceImageInformation2DBlock.ImageSizeBlock? imageSizeBlock = information2DBlock.GetImageSizeBlock();
        return imageSizeBlock == null ? 0 : imageSizeBlock.GetHeight();
    }

    public long GetRecordLength() => 0;

    public int GetImageLength() =>
        _imageRepresentation2DBlock == null ? 0 : (int)_imageRepresentation2DBlock.GetRepresentationData2DInputLength();

    /// <summary>NOTE: preserved Java quirk -- like Java's own <c>getImageInputStream()</c>, this returns
    /// <see langword="null"/> when there is no 2D representation, even though
    /// <see cref="nMRTD.Lds.ImageInfo.GetImageInputStream"/> is declared non-nullable (matching Java's own
    /// non-<c>@Nullable</c>-annotated <c>InputStream</c> return type, which JMRTD nonetheless returns
    /// <see langword="null"/> from here).</summary>
    public Stream GetImageInputStream() =>
        _imageRepresentation2DBlock == null ? null! : _imageRepresentation2DBlock.GetRepresentationData2DInputStream();

    /* PACKAGE */

    internal override Asn1Encodable GetAsn1Object() => GetAsn1Object(ISO39794EncodingProfile.Base);

    internal override Asn1Encodable GetAsn1Object(ISO39794EncodingProfile profile)
    {
        var taggedObjects = new Dictionary<int, Asn1Encodable>
        {
            [0] = ASN1Util.EncodeBigInteger(_representationId),
            [1] = EncodeImageRepresentation2DBlock(_imageRepresentation2DBlock, profile),
        };
        if (_captureDateTimeBlock != null)
        {
            taggedObjects[2] = _captureDateTimeBlock.GetAsn1Object();
        }
        if (_qualityBlocks != null)
        {
            taggedObjects[3] = ISO39794Util.EncodeBlocks([.. _qualityBlocks.Cast<Block>()], profile)!;
        }
        if (_padDataBlocks != null)
        {
            if (profile == ISO39794EncodingProfile.Icao39794_5EmrtdV1 && _padDataBlocks.Count == 1)
            {
                taggedObjects[4] = _padDataBlocks[0].GetAsn1Object(profile);
            }
            else
            {
                taggedObjects[4] = ISO39794Util.EncodeBlocks([.. _padDataBlocks.Cast<Block>()], profile)!;
            }
        }
        if (_sessionId != null)
        {
            taggedObjects[5] = ASN1Util.EncodeBigInteger(_sessionId);
        }
        if (_derivedFrom != null)
        {
            taggedObjects[6] = ASN1Util.EncodeBigInteger(_derivedFrom);
        }
        if (_captureDeviceBlock != null)
        {
            taggedObjects[7] = _captureDeviceBlock.GetAsn1Object();
        }
        if (_identityMetadataBlock != null)
        {
            taggedObjects[8] = _identityMetadataBlock.GetAsn1Object(profile);
        }
        if (_landmarkBlocks != null)
        {
            taggedObjects[9] = ISO39794Util.EncodeBlocks([.. _landmarkBlocks.Cast<Block>()], profile)!;
        }
        return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
    }

    // RepresentationBlocks ::= SEQUENCE SIZE (1) OF RepresentationBlock

    internal static List<FaceImageRepresentationBlock> DecodeRepresentationBlocks(Asn1Encodable asn1Encodable)
    {
        var blocks = new List<FaceImageRepresentationBlock>();
        if (ASN1Util.IsSequenceOfSequences(asn1Encodable))
        {
            List<Asn1Encodable> blockAsn1Objects = ASN1Util.List(asn1Encodable)!;
            foreach (Asn1Encodable blockAsn1Object in blockAsn1Objects)
            {
                blocks.Add(new FaceImageRepresentationBlock(blockAsn1Object));
            }
        }
        else
        {
            blocks.Add(new FaceImageRepresentationBlock(asn1Encodable));
        }

        return blocks;
    }

    /* PRIVATE */

    private static FaceImageRepresentation2DBlock? DecodeImageRepresentation2DBlock(Asn1Encodable? asn1Encodable)
    {
        Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
        if (taggedObjects.TryGetValue(0, out Asn1Encodable? baseObject))
        {
            Dictionary<int, Asn1Encodable> baseTaggedObjects = ASN1Util.DecodeTaggedObjects(baseObject);
            if (baseTaggedObjects.TryGetValue(0, out Asn1Encodable? representation2DObject))
            {
                return new FaceImageRepresentation2DBlock(representation2DObject);
            }

            /* NOTE: Not supporting [1] ShapeRepresentation3DBlock... */
        }

        return null;
    }

    private static Asn1Encodable EncodeImageRepresentation2DBlock(FaceImageRepresentation2DBlock? faceImageRepresentation2DBlock,
        ISO39794EncodingProfile profile)
    {
        var baseTaggedObjects = new Dictionary<int, Asn1Encodable>
        {
            [0] = faceImageRepresentation2DBlock!.GetAsn1Object(profile),
        };

        var taggedObjects = new Dictionary<int, Asn1Encodable>
        {
            [0] = ASN1Util.EncodeTaggedObjects(baseTaggedObjects)!,
        };
        return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
    }

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

    private static string JavaListToString<T>(List<T>? list) => list == null ? "null" : $"[{string.Join(", ", list)}]";

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
