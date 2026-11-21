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

// RegistryId ::= INTEGER (1..65535)
//
// RegistryIdBlock ::= SEQUENCE {
//        organization            [0] RegistryId,
//        id                      [1] RegistryId
// }

// CertificationIdBlock ::= RegistryIdBlock
//
// CertificationIdBlocks ::= SEQUENCE OF CertificationIdBlock

/// <summary>
/// Port of <c>org.jmrtd.lds.iso39794.RegistryIdBlock</c>. Java's <c>Serializable</c> marker is dropped (no
/// reflection-based serialization is needed in this port).
/// </summary>
public class RegistryIdBlock : Block
{
    private readonly int _organization;
    private readonly int _id;

    public RegistryIdBlock(int organization, int id)
    {
        _organization = organization;
        _id = id;
    }

    internal RegistryIdBlock(Asn1Encodable asn1Encodable)
    {
        if (asn1Encodable is not Asn1Sequence)
        {
            throw new ArgumentException("Cannot decode!");
        }

        Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
        _organization = ASN1Util.DecodeInt(taggedObjects[0]);
        _id = ASN1Util.DecodeInt(taggedObjects[1]);
    }

    public int GetOrganization() => _organization;

    public int GetId() => _id;

    public override int GetHashCode() => HashCode.Combine(_id, _organization);

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

        var otherBlock = (RegistryIdBlock)other;
        return _id == otherBlock._id && _organization == otherBlock._organization;
    }

    public override string ToString() =>
        $"RegistryIdBlock[organization: {_organization}, id: {_id}]";

    internal override Asn1Encodable GetAsn1Object()
    {
        var taggedObjects = new Dictionary<int, Asn1Encodable>
        {
            [0] = ASN1Util.EncodeInt(_organization),
            [1] = ASN1Util.EncodeInt(_id),
        };
        return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
    }

    /* PACKAGE */

    internal static List<RegistryIdBlock> DecodeRegistryIdBlocks(Asn1Encodable asn1Encodable)
    {
        if (ASN1Util.IsSequenceOfSequences(asn1Encodable))
        {
            List<Asn1Encodable> blockAsn1Objects = ASN1Util.List(asn1Encodable)!;
            var blocks = new List<RegistryIdBlock>(blockAsn1Objects.Count);
            foreach (Asn1Encodable blockAsn1Object in blockAsn1Objects)
            {
                blocks.Add(new RegistryIdBlock(blockAsn1Object));
            }

            return blocks;
        }

        return [new RegistryIdBlock(asn1Encodable)];
    }
}
