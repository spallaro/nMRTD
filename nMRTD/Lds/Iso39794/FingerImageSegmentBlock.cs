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

//    SegmentBlock ::= SEQUENCE {
//      position [0] Position,
//      enclosingCoordinatesBlock [1] CoordinatesBlock,
//      orientation [2] INTEGER (0..255) OPTIONAL,
//      qualityBlocks [3] QualityBlocks OPTIONAL,
//      confidence [4] ScoreOrError OPTIONAL,
//      ...
//  }

/// <summary>
/// Port of <c>org.jmrtd.lds.iso39794.FingerImageSegmentBlock</c>. Java's <c>Serializable</c> marker is
/// dropped (no reflection-based serialization is needed in this port).
///
/// ADAPTATION: Java's version is a top-level <c>public class</c>, but this is <c>internal</c> since its
/// base class <see cref="Block"/> is <c>internal</c> in this port (see <c>VersionBlock</c>'s doc comment).
/// </summary>
internal class FingerImageSegmentBlock : Block
{
    private readonly FingerImagePositionCode? _positionCode;
    private readonly List<CoordinateCartesian2DUnsignedShortBlock>? _enclosingCoordinatesBlock; // SIZE(2..MAX)
    private readonly int? _orientation;
    private readonly List<QualityBlock>? _qualityBlocks;
    private readonly ScoreOrError? _confidence;

    public FingerImageSegmentBlock(FingerImagePositionCode? positionCode,
        List<CoordinateCartesian2DUnsignedShortBlock>? enclosingCoordinatesBlock, int? orientation,
        List<QualityBlock>? qualityBlocks, int confidence)
        : this(positionCode, enclosingCoordinatesBlock, orientation, qualityBlocks,
            confidence >= 0 ? new ScoreOrError(confidence) : null)
    {
    }

    public FingerImageSegmentBlock(FingerImagePositionCode? positionCode,
        List<CoordinateCartesian2DUnsignedShortBlock>? enclosingCoordinatesBlock, int? orientation,
        List<QualityBlock>? qualityBlocks, ScoreOrError? confidence)
    {
        _positionCode = positionCode;
        _enclosingCoordinatesBlock = enclosingCoordinatesBlock;
        _orientation = orientation;
        _qualityBlocks = qualityBlocks;
        _confidence = confidence;
    }

    internal FingerImageSegmentBlock(Asn1Encodable asn1Encodable)
    {
        Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
        _positionCode = FingerImagePositionCodeExtensions.FromCode(ISO39794Util.DecodeCodeFromChoiceExtensionBlockFallback(taggedObjects[0])!.Value);
        _enclosingCoordinatesBlock = CoordinateCartesian2DUnsignedShortBlock.DecodeCoordinateCartesian2DUnsignedShortBlocks(taggedObjects[1]);
        if (taggedObjects.TryGetValue(2, out Asn1Encodable? orientationObject))
        {
            _orientation = ASN1Util.DecodeInt(orientationObject);
        }
        if (taggedObjects.TryGetValue(3, out Asn1Encodable? qualityBlocksObject))
        {
            _qualityBlocks = QualityBlock.DecodeQualityBlocks(qualityBlocksObject);
        }
        if (taggedObjects.TryGetValue(4, out Asn1Encodable? confidenceObject))
        {
            _confidence = new ScoreOrError(confidenceObject);
        }
    }

    public FingerImagePositionCode? GetPositionCode() => _positionCode;

    public List<CoordinateCartesian2DUnsignedShortBlock>? GetEnclosingCoordinatesBlock() => _enclosingCoordinatesBlock;

    public int? GetOrientation() => _orientation;

    public List<QualityBlock>? GetQualityBlocks() => _qualityBlocks;

    public int GetConfidence()
    {
        if (_confidence == null)
        {
            return -1;
        }
        return _confidence.IsScore() ? _confidence.GetScore()!.Value : -1;
    }

    public ScoreOrError? GetConfidenceScoreOrError() => _confidence;

    public override int GetHashCode() =>
        HashCode.Combine(_confidence, JavaListHashCode(_enclosingCoordinatesBlock), _orientation, _positionCode, JavaListHashCode(_qualityBlocks));

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

        var otherBlock = (FingerImageSegmentBlock)other;
        return Equals(_confidence, otherBlock._confidence)
            && ListEquals(_enclosingCoordinatesBlock, otherBlock._enclosingCoordinatesBlock)
            && _orientation == otherBlock._orientation && _positionCode == otherBlock._positionCode
            && ListEquals(_qualityBlocks, otherBlock._qualityBlocks);
    }

    public override string ToString() =>
        "FingerImageSegmentBlock ["
        + $"positionCode: {ToStringOrNull(_positionCode)}"
        + $", enclosingCoordinatesBlock: {JavaListToString(_enclosingCoordinatesBlock)}"
        + $", orientation: {ToStringOrNull(_orientation)}"
        + $", qualityBlocks: {JavaListToString(_qualityBlocks)}"
        + $", confidence: {_confidence}"
        + "]";

    /* PACKAGE */

    internal static List<FingerImageSegmentBlock> DecodeFingerImageSegmentBlocks(Asn1Encodable asn1Encodable)
    {
        if (ASN1Util.IsSequenceOfSequences(asn1Encodable))
        {
            List<Asn1Encodable> blockAsn1Objects = ASN1Util.List(asn1Encodable)!;
            var blocks = new List<FingerImageSegmentBlock>(blockAsn1Objects.Count);
            foreach (Asn1Encodable blockAsn1Object in blockAsn1Objects)
            {
                blocks.Add(new FingerImageSegmentBlock(blockAsn1Object));
            }
            return blocks;
        }
        else
        {
            return [new FingerImageSegmentBlock(asn1Encodable)];
        }
    }

    internal override Asn1Encodable GetAsn1Object()
    {
        var taggedObjects = new Dictionary<int, Asn1Encodable>
        {
            [0] = ISO39794Util.EncodeCodeAsChoiceExtensionBlockFallback((int)_positionCode!.Value),
            [1] = ISO39794Util.EncodeBlocks([.. _enclosingCoordinatesBlock!.Cast<Block>()])!,
        };
        if (_orientation != null)
        {
            taggedObjects[2] = ASN1Util.EncodeInt(_orientation.Value);
        }
        if (_qualityBlocks != null)
        {
            taggedObjects[3] = ISO39794Util.EncodeBlocks([.. _qualityBlocks.Cast<Block>()])!;
        }
        if (_confidence != null)
        {
            taggedObjects[4] = _confidence.GetAsn1Object();
        }
        return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
    }

    /* PRIVATE */

    private static string ToStringOrNull<T>(T? value) where T : struct => value?.ToString() ?? "null";

    private static string JavaListToString<T>(List<T>? list) => list == null ? "null" : $"[{string.Join(", ", list)}]";

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
}
