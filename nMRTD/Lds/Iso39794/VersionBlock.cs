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

//  VersionBlock ::= SEQUENCE {
//    generation              [0] VersionGeneration,
//    year                    [1] VersionYear,
//    ...
//  }

/// <summary>
/// Port of <c>org.jmrtd.lds.iso39794.VersionBlock</c>. Java's <c>Serializable</c> marker is dropped (no
/// reflection-based serialization is needed in this port).
/// </summary>
public class VersionBlock : Block
{
    private readonly int _generation;
    private readonly int _year;

    public VersionBlock(int generation, int year)
    {
        _generation = generation;
        _year = year;
    }

    internal VersionBlock(Asn1Encodable asn1Encodable)
    {
        if (asn1Encodable is not Asn1Sequence)
        {
            throw new ArgumentException("Cannot decode!");
        }

        Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
        _generation = ASN1Util.DecodeInt(taggedObjects[0]);
        _year = ASN1Util.DecodeInt(taggedObjects[1]);
    }

    public int GetGeneration() => _generation;

    public int GetYear() => _year;

    public override int GetHashCode() => HashCode.Combine(_generation, _year);

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

        var otherBlock = (VersionBlock)other;
        return _generation == otherBlock._generation && _year == otherBlock._year;
    }

    public override string ToString() =>
        $"VersionBlock [generation: {_generation}, year: {_year}]";

    internal override Asn1Encodable GetAsn1Object()
    {
        var taggedObjects = new Dictionary<int, Asn1Encodable>
        {
            [0] = ASN1Util.EncodeInt(_generation),
            [1] = ASN1Util.EncodeInt(_year),
        };
        return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
    }
}
