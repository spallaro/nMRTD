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
using nMRTD.SmartCards;

namespace nMRTD.Lds.Iso39794;

//  ReferenceColourMappingBlock ::= SEQUENCE {
//    referenceColourSchema [0] OCTET STRING OPTIONAL,
//    referenceColourDefinitionAndValueBlocks [1] ReferenceColourDefinitionAndValueBlocks OPTIONAL,
//    ...
//  }

/// <summary>
/// Port of <c>org.jmrtd.lds.iso39794.FaceImageReferenceColourMappingBlock</c>. Java's <c>Serializable</c>
/// marker is dropped (no reflection-based serialization is needed in this port).
/// </summary>
public class FaceImageReferenceColourMappingBlock : Block
{
    //  ReferenceColourDefinitionAndValueBlock ::= SEQUENCE {
    //          referenceColourDefinition [0] OCTET STRING OPTIONAL,
    //          referenceColourValue [1] OCTET STRING OPTIONAL,
    //          ...
    //  }

    /// <summary>
    /// ADAPTATION: Java's version is a nested <c>public static class ReferenceColourDefinitionAndValueBlock
    /// extends Block</c>; ported as a public nested class.
    /// </summary>
    public class ReferenceColourDefinitionAndValueBlock : Block
    {
        private readonly byte[]? _referenceColourDefinition;
        private readonly byte[]? _referenceColourValue;

        public ReferenceColourDefinitionAndValueBlock(byte[]? referenceColourDefinition, byte[]? referenceColourValue)
        {
            _referenceColourDefinition = referenceColourDefinition;
            _referenceColourValue = referenceColourValue;
        }

        internal ReferenceColourDefinitionAndValueBlock(Asn1Encodable asn1Encodable)
        {
            Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
            if (taggedObjects.TryGetValue(0, out Asn1Encodable? definitionObject))
            {
                _referenceColourDefinition = Asn1OctetString.GetInstance(definitionObject).GetOctets();
            }
            if (taggedObjects.TryGetValue(1, out Asn1Encodable? valueObject))
            {
                _referenceColourValue = Asn1OctetString.GetInstance(valueObject).GetOctets();
            }
        }

        public byte[]? GetReferenceColourDefinition() => _referenceColourDefinition;

        public byte[]? GetReferenceColourValue() => _referenceColourValue;

        public override int GetHashCode()
        {
            const int prime = 31;
            int result = 1;
            result = (prime * result) + JavaArrayHashCode(_referenceColourDefinition);
            result = (prime * result) + JavaArrayHashCode(_referenceColourValue);
            return result;
        }

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

            var otherBlock = (ReferenceColourDefinitionAndValueBlock)other;
            return ByteArraysEqual(_referenceColourDefinition, otherBlock._referenceColourDefinition)
                && ByteArraysEqual(_referenceColourValue, otherBlock._referenceColourValue);
        }

        public override string ToString() =>
            $"ReferenceColourDefinitionAndValueBlock [referenceColourDefinition: {HexOrNull(_referenceColourDefinition)}, referenceColourValue: {HexOrNull(_referenceColourValue)}]";

        /* PACKAGE */

        internal static List<ReferenceColourDefinitionAndValueBlock> DecodeReferenceColourDefinitionAndValueBlocks(Asn1Encodable asn1Encodable)
        {
            if (ASN1Util.IsSequenceOfSequences(asn1Encodable))
            {
                List<Asn1Encodable> blockAsn1Objects = ASN1Util.List(asn1Encodable)!;
                var blocks = new List<ReferenceColourDefinitionAndValueBlock>(blockAsn1Objects.Count);
                foreach (Asn1Encodable blockAsn1Object in blockAsn1Objects)
                {
                    blocks.Add(new ReferenceColourDefinitionAndValueBlock(blockAsn1Object));
                }

                return blocks;
            }

            return [new ReferenceColourDefinitionAndValueBlock(asn1Encodable)];
        }

        internal override Asn1Encodable GetAsn1Object()
        {
            var taggedObjects = new Dictionary<int, Asn1Encodable>();
            if (_referenceColourDefinition != null)
            {
                taggedObjects[0] = new DerOctetString(_referenceColourDefinition);
            }
            if (_referenceColourValue != null)
            {
                taggedObjects[1] = new DerOctetString(_referenceColourValue);
            }
            return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
        }
    }

    private readonly byte[]? _referenceColourSchema;
    private readonly List<ReferenceColourDefinitionAndValueBlock>? _referenceColourDefinitionAndValueBlocks;

    public FaceImageReferenceColourMappingBlock(byte[]? referenceColourSchema,
        List<ReferenceColourDefinitionAndValueBlock>? referenceColourDefinitionAndValueBlocks)
    {
        _referenceColourSchema = referenceColourSchema;
        _referenceColourDefinitionAndValueBlocks = referenceColourDefinitionAndValueBlocks;
    }

    internal FaceImageReferenceColourMappingBlock(Asn1Encodable asn1Encodable)
    {
        Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
        if (taggedObjects.TryGetValue(0, out Asn1Encodable? schemaObject))
        {
            _referenceColourSchema = Asn1OctetString.GetInstance(schemaObject).GetOctets();
        }
        if (taggedObjects.TryGetValue(1, out Asn1Encodable? blocksObject))
        {
            _referenceColourDefinitionAndValueBlocks = ReferenceColourDefinitionAndValueBlock.DecodeReferenceColourDefinitionAndValueBlocks(blocksObject);
        }
    }

    public byte[]? GetReferenceColourSchema() => _referenceColourSchema;

    public List<ReferenceColourDefinitionAndValueBlock>? GetReferenceColourDefinitionAndValueBlocks() => _referenceColourDefinitionAndValueBlocks;

    public override int GetHashCode()
    {
        const int prime = 31;
        int result = 1;
        result = (prime * result) + JavaArrayHashCode(_referenceColourSchema);
        result = (prime * result) + JavaObjectsHash(JavaListHashCode(_referenceColourDefinitionAndValueBlocks));
        return result;
    }

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

        var otherBlock = (FaceImageReferenceColourMappingBlock)other;
        return ListEquals(_referenceColourDefinitionAndValueBlocks, otherBlock._referenceColourDefinitionAndValueBlocks)
            && ByteArraysEqual(_referenceColourSchema, otherBlock._referenceColourSchema);
    }

    public override string ToString() =>
        $"FaceImageReferenceColourMappingBlock [referenceColourSchema: {HexOrNull(_referenceColourSchema)}, referenceColourDefinitionAndValueBlocks: {JavaListToString(_referenceColourDefinitionAndValueBlocks)}]";

    /* PACKAGE */

    internal override Asn1Encodable GetAsn1Object()
    {
        var taggedObjects = new Dictionary<int, Asn1Encodable>();
        if (_referenceColourSchema != null)
        {
            taggedObjects[0] = new DerOctetString(_referenceColourSchema);
        }
        if (_referenceColourDefinitionAndValueBlocks != null)
        {
            taggedObjects[1] = ISO39794Util.EncodeBlocks([.. _referenceColourDefinitionAndValueBlocks.Cast<Block>()])!;
        }
        return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
    }

    /* PRIVATE */

    /// <summary>Renders a byte array as hex, or the literal <c>"null"</c> string when absent -- matches
    /// Java's own <c>Hex.bytesToHexString(null)</c> plus string-concatenation-of-null convention (rather
    /// than this port's <see cref="Hex.BytesToHexString"/>, which throws on <see langword="null"/>); see
    /// the identical established pattern in <c>PADDataBlock.cs</c>.</summary>
    private static string HexOrNull(byte[]? bytes) => bytes == null ? "null" : Hex.BytesToHexString(bytes);

    /// <summary>Java-style <c>Arrays.hashCode(byte[])</c> for a (possibly <see langword="null"/>) byte
    /// array -- see the established pattern in e.g. <c>PADDataBlock.cs</c>/<c>PaceKeySpec.cs</c>.</summary>
    private static int JavaArrayHashCode(byte[]? array)
    {
        if (array == null)
        {
            return 0;
        }

        int result = 1;
        foreach (byte b in array)
        {
            result = (31 * result) + (sbyte)b;
        }

        return result;
    }

    /// <summary>Java-style content-based <c>List.hashCode()</c> (the <c>AbstractList</c> contract: 1, then
    /// <c>31*hash + element.hashCode()</c> per element, 0 for a <see langword="null"/> element or list).
    /// See the established pattern in <c>PADDataBlock.cs</c>.</summary>
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

    private static bool ByteArraysEqual(byte[]? array1, byte[]? array2)
    {
        if (array1 == null || array2 == null)
        {
            return array1 == array2;
        }

        return array1.SequenceEqual(array2);
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
}
