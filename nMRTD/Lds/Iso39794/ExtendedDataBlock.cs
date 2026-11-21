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

//  ExtendedDataBlock ::= SEQUENCE {
//    dataTypeIdBlock         [0] RegistryIdBlock,
//    data                    [1] OCTET STRING
//  }

/// <summary>
/// Port of <c>org.jmrtd.lds.iso39794.ExtendedDataBlock</c>. Java's <c>Serializable</c> marker is dropped
/// (no reflection-based serialization is needed in this port).
/// </summary>
public class ExtendedDataBlock : Block
{
    private readonly RegistryIdBlock _dataTypeIdBlock;
    private readonly byte[] _data;

    public ExtendedDataBlock(RegistryIdBlock dataTypeIdBlock, byte[] data)
    {
        _dataTypeIdBlock = dataTypeIdBlock;
        _data = data;
    }

    internal ExtendedDataBlock(Asn1Encodable asn1Encodable)
    {
        Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
        _dataTypeIdBlock = new RegistryIdBlock(taggedObjects[0]);
        _data = Asn1OctetString.GetInstance(taggedObjects[1]).GetOctets();
    }

    public RegistryIdBlock GetDataTypeIdBlock() => _dataTypeIdBlock;

    public byte[] GetData() => _data;

    /// <summary>Java-style <c>Arrays.hashCode</c> for a byte array; see this port's established pattern
    /// (e.g. <c>PaceKeySpec.cs</c>, <c>PACECAMResult.cs</c>) for why this isn't just <c>byte[].GetHashCode()</c>.</summary>
    private static int JavaArrayHashCode(byte[] array)
    {
        int result = 1;
        foreach (byte b in array)
        {
            result = (31 * result) + (sbyte)b;
        }

        return result;
    }

    public override int GetHashCode()
    {
        const int prime = 31;
        int result = 1;
        result = (prime * result) + JavaArrayHashCode(_data);
        result = (prime * result) + HashCode.Combine(_dataTypeIdBlock);
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

        var otherBlock = (ExtendedDataBlock)other;
        return _data.SequenceEqual(otherBlock._data) && Equals(_dataTypeIdBlock, otherBlock._dataTypeIdBlock);
    }

    public override string ToString() =>
        $"ExtendedDataBlock [dataTypeIdBlock: {_dataTypeIdBlock}, data: {_data.Length}]";

    /* PACKAGE */

    internal static List<ExtendedDataBlock> DecodeExtendedDataBlocks(Asn1Encodable asn1Encodable)
    {
        if (ASN1Util.IsSequenceOfSequences(asn1Encodable))
        {
            List<Asn1Encodable> blockAsn1Objects = ASN1Util.List(asn1Encodable)!;
            var blocks = new List<ExtendedDataBlock>(blockAsn1Objects.Count);
            foreach (Asn1Encodable blockAsn1Object in blockAsn1Objects)
            {
                blocks.Add(new ExtendedDataBlock(blockAsn1Object));
            }

            return blocks;
        }

        return [new ExtendedDataBlock(asn1Encodable)];
    }

    internal override Asn1Encodable GetAsn1Object()
    {
        var taggedObjects = new Dictionary<int, Asn1Encodable>
        {
            [0] = _dataTypeIdBlock.GetAsn1Object(),
            [1] = new DerOctetString(_data),
        };
        return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
    }
}
