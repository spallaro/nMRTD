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

//  Coordinate ::=  INTEGER (1..65535)
//  Diameter ::=    INTEGER (1..65535)

//  LocalisationBlock ::= SEQUENCE {
//    irisCenterXSmallest [0]                 Coordinate                                      OPTIONAL,
//    irisCenterXLargest [1]                  Coordinate                                      OPTIONAL,
//    irisCenterYSmallest [2]                 Coordinate                                      OPTIONAL,
//    irisCenterYLargest [3]                  Coordinate                                      OPTIONAL,
//    irisDiameterSmallest [4]                Diameter                                        OPTIONAL,
//    irisDiameterLargest [5]                 Diameter                                        OPTIONAL
//  }

/// <summary>
/// Port of <c>org.jmrtd.lds.iso39794.IrisImageLocalisationBlock</c>. Java's <c>Serializable</c> marker is
/// dropped (no reflection-based serialization is needed in this port).
///
/// NOTE: preserved Java quirk -- Java only ever assigns these six <c>int</c> fields from its decode
/// constructor (there is no field-values constructor at all), so a field left unset by the decoder keeps
/// Java's implicit primitive default of <c>0</c>. The encoder then guards each field with a <c>&gt;= 0</c>
/// check -- which a genuine value of <c>0</c> would also pass, even though <c>0</c> is outside this field's
/// own <c>1..65535</c> ASN.1 range and was never actually decoded. This is the same "0-used-as-a-would-be
/// -1-sentinel" round-trip bug already preserved verbatim in <c>PADDataBlock.cs</c>'s <c>_riskLevel</c>
/// (see its doc comment) -- kept here rather than "fixed", and for the same reason Java's fields stay plain
/// <c>int</c> here rather than <c>int?</c>.
///
/// ADAPTATION: Java's version is a top-level <c>public class</c>, but this is <c>internal</c> since its
/// base class <see cref="Block"/> is <c>internal</c> in this port (see <c>VersionBlock</c>'s doc comment).
/// </summary>
internal class IrisImageLocalisationBlock : Block
{
    private readonly int _irisCenterXSmallest;
    private readonly int _irisCenterXLargest;

    private readonly int _irisCenterYSmallest;
    private readonly int _irisCenterYLargest;

    private readonly int _irisDiameterSmallest;
    private readonly int _irisDiameterLargest;

    internal IrisImageLocalisationBlock(Asn1Encodable asn1Encodable)
    {
        Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
        if (taggedObjects.TryGetValue(0, out Asn1Encodable? xSmallest))
        {
            _irisCenterXSmallest = ASN1Util.DecodeInt(xSmallest);
        }
        if (taggedObjects.TryGetValue(1, out Asn1Encodable? xLargest))
        {
            _irisCenterXLargest = ASN1Util.DecodeInt(xLargest);
        }
        if (taggedObjects.TryGetValue(2, out Asn1Encodable? ySmallest))
        {
            _irisCenterYSmallest = ASN1Util.DecodeInt(ySmallest);
        }
        if (taggedObjects.TryGetValue(3, out Asn1Encodable? yLargest))
        {
            _irisCenterYLargest = ASN1Util.DecodeInt(yLargest);
        }
        if (taggedObjects.TryGetValue(4, out Asn1Encodable? diameterSmallest))
        {
            _irisDiameterSmallest = ASN1Util.DecodeInt(diameterSmallest);
        }
        if (taggedObjects.TryGetValue(5, out Asn1Encodable? diameterLargest))
        {
            _irisDiameterLargest = ASN1Util.DecodeInt(diameterLargest);
        }
    }

    public int GetIrisCenterXSmallest() => _irisCenterXSmallest;

    public int GetIrisCenterXLargest() => _irisCenterXLargest;

    public int GetIrisCenterYSmallest() => _irisCenterYSmallest;

    public int GetIrisCenterYLargest() => _irisCenterYLargest;

    public int GetIrisDiameterSmallest() => _irisDiameterSmallest;

    public int GetIrisDiameterLargest() => _irisDiameterLargest;

    public override int GetHashCode() =>
        HashCode.Combine(_irisCenterXLargest, _irisCenterXSmallest, _irisCenterYLargest, _irisCenterYSmallest,
            _irisDiameterLargest, _irisDiameterSmallest);

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

        var otherBlock = (IrisImageLocalisationBlock)other;
        return _irisCenterXLargest == otherBlock._irisCenterXLargest
            && _irisCenterXSmallest == otherBlock._irisCenterXSmallest
            && _irisCenterYLargest == otherBlock._irisCenterYLargest
            && _irisCenterYSmallest == otherBlock._irisCenterYSmallest
            && _irisDiameterLargest == otherBlock._irisDiameterLargest
            && _irisDiameterSmallest == otherBlock._irisDiameterSmallest;
    }

    public override string ToString() =>
        "IrisImageLocalisationBlock ["
        + $"irisCenterXSmallest: {_irisCenterXSmallest}"
        + $", irisCenterXLargest: {_irisCenterXLargest}"
        + $", irisCenterYSmallest: {_irisCenterYSmallest}"
        + $", irisCenterYLargest: {_irisCenterYLargest}"
        + $", irisDiameterSmallest: {_irisDiameterSmallest}"
        + $", irisDiameterLargest: {_irisDiameterLargest}"
        + "]";

    /* PACKAGE */

    internal override Asn1Encodable GetAsn1Object()
    {
        var taggedObjects = new Dictionary<int, Asn1Encodable>();
        if (_irisCenterXSmallest >= 0)
        {
            taggedObjects[0] = ASN1Util.EncodeInt(_irisCenterXSmallest);
        }
        if (_irisCenterXLargest >= 0)
        {
            taggedObjects[1] = ASN1Util.EncodeInt(_irisCenterXLargest);
        }
        if (_irisCenterYSmallest >= 0)
        {
            taggedObjects[2] = ASN1Util.EncodeInt(_irisCenterYSmallest);
        }
        if (_irisCenterYLargest >= 0)
        {
            taggedObjects[3] = ASN1Util.EncodeInt(_irisCenterYLargest);
        }
        if (_irisDiameterSmallest >= 0)
        {
            taggedObjects[4] = ASN1Util.EncodeInt(_irisDiameterSmallest);
        }
        if (_irisDiameterLargest >= 0)
        {
            taggedObjects[5] = ASN1Util.EncodeInt(_irisDiameterLargest);
        }
        return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
    }
}
