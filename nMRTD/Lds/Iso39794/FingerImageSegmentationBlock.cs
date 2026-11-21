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

//  SegmentationBlock ::= SEQUENCE {
//    algorithmIdBlock [0] RegistryIdBlock,
//    segmentBlocks [1] SegmentBlocks,
//    ...
//  }

/// <summary>
/// Port of <c>org.jmrtd.lds.iso39794.FingerImageSegmentationBlock</c>. Java's <c>Serializable</c> marker
/// is dropped (no reflection-based serialization is needed in this port).
///
/// NOTE: preserved Java quirk -- Java's version has no public constructor at all (only the package-private
/// decode constructor below), so instances can only be produced by decoding ASN.1 data; this port keeps
/// that same shape rather than adding a public constructor Java does not have.
/// </summary>
public class FingerImageSegmentationBlock : Block
{
    private readonly RegistryIdBlock _algorithmIdBlock;

    private readonly List<FingerImageSegmentBlock> _segmentBlocks;

    internal FingerImageSegmentationBlock(Asn1Encodable asn1Encodable)
    {
        Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
        _algorithmIdBlock = new RegistryIdBlock(taggedObjects[0]);
        _segmentBlocks = FingerImageSegmentBlock.DecodeFingerImageSegmentBlocks(taggedObjects[1]);
    }

    public RegistryIdBlock GetAlgorithmIdBlock() => _algorithmIdBlock;

    public List<FingerImageSegmentBlock> GetSegmentBlocks() => _segmentBlocks;

    public override int GetHashCode() => HashCode.Combine(_algorithmIdBlock, JavaListHashCode(_segmentBlocks));

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

        var otherBlock = (FingerImageSegmentationBlock)other;
        return Equals(_algorithmIdBlock, otherBlock._algorithmIdBlock)
            && ListEquals(_segmentBlocks, otherBlock._segmentBlocks);
    }

    public override string ToString() =>
        "FingerImageSegmentationBlock ["
        + $"algorithmIdBlock: {_algorithmIdBlock}"
        + $", segmentBlocks: {JavaListToString(_segmentBlocks)}"
        + "]";

    /* PACKAGE */

    internal static List<FingerImageSegmentationBlock> DecodeFingerImageSegmentationBlocks(Asn1Encodable asn1Encodable)
    {
        if (ASN1Util.IsSequenceOfSequences(asn1Encodable))
        {
            List<Asn1Encodable> blockAsn1Objects = ASN1Util.List(asn1Encodable)!;
            var blocks = new List<FingerImageSegmentationBlock>(blockAsn1Objects.Count);
            foreach (Asn1Encodable blockAsn1Object in blockAsn1Objects)
            {
                blocks.Add(new FingerImageSegmentationBlock(blockAsn1Object));
            }
            return blocks;
        }
        else
        {
            return [new FingerImageSegmentationBlock(asn1Encodable)];
        }
    }

    internal override Asn1Encodable GetAsn1Object()
    {
        var taggedObjects = new Dictionary<int, Asn1Encodable>
        {
            [0] = _algorithmIdBlock.GetAsn1Object(),
            [1] = ISO39794Util.EncodeBlocks([.. _segmentBlocks.Cast<Block>()])!,
        };
        return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
    }

    /* PRIVATE */

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
