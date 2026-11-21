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

//  SpatialSamplingRateBlock ::= SEQUENCE {
//    samplesPerUnit [0] INTEGER (0..65535),
//    unitDimension [1] UnitDimensionCode
//  }

//  UnitDimensionCode ::= ENUMERATED {
//    inch(0),
//    cm(1)
//  }

/// <summary>
/// Port of <c>org.jmrtd.lds.iso39794.FingerImageSpatialSamplingRateBlock</c>. Java's <c>Serializable</c>
/// marker is dropped (no reflection-based serialization is needed in this port).
/// </summary>
public class FingerImageSpatialSamplingRateBlock : Block
{
    /// <summary>
    /// ADAPTATION: Java's version is <c>enum UnitDimensionCode implements
    /// EncodableEnum&lt;UnitDimensionCode&gt;</c>, using reflection-based <c>EncodableEnum.fromCode</c>
    /// lookup keyed on each constant's own <c>getCode()</c>. Ported as a plain enum with explicit numeric
    /// values matching each Java constant's <c>getCode()</c> (declaration order and code happen to
    /// coincide here); see <c>ScoreOrError.ScoringErrorCode</c>'s doc comment for the fuller rationale and
    /// <see cref="FromCode"/> for the shared "decode from code" replacement.
    /// </summary>
    public enum UnitDimensionCode
    {
        Inch = 0,
        Cm = 1,
    }

    private static UnitDimensionCode? FromCode(int code) =>
        Enum.IsDefined(typeof(UnitDimensionCode), code) ? (UnitDimensionCode)code : null;

    private readonly int _samplesPerUnit;
    private readonly UnitDimensionCode _unitDimension;

    public FingerImageSpatialSamplingRateBlock(int samplesPerUnit, UnitDimensionCode unitDimension)
    {
        _samplesPerUnit = samplesPerUnit;
        _unitDimension = unitDimension;
    }

    internal FingerImageSpatialSamplingRateBlock(Asn1Encodable asn1Encodable)
    {
        Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
        _samplesPerUnit = ASN1Util.DecodeInt(taggedObjects[0]);
        _unitDimension = FromCode(ASN1Util.DecodeInt(taggedObjects[1]))!.Value;
    }

    public int GetSamplesPerUnit() => _samplesPerUnit;

    public UnitDimensionCode GetUnitDimension() => _unitDimension;

    public override int GetHashCode() => HashCode.Combine(_samplesPerUnit, _unitDimension);

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

        var otherBlock = (FingerImageSpatialSamplingRateBlock)other;
        return _samplesPerUnit == otherBlock._samplesPerUnit && _unitDimension == otherBlock._unitDimension;
    }

    public override string ToString() =>
        "FingerImageSpatialSamplingRateBlock ["
        + $"samplesPerUnit: {_samplesPerUnit}"
        + $", unitDimension: {_unitDimension}"
        + "]";

    /* PACKAGE */

    internal override Asn1Encodable GetAsn1Object()
    {
        var taggedObjects = new Dictionary<int, Asn1Encodable>
        {
            [0] = ASN1Util.EncodeInt(_samplesPerUnit),
            [1] = ASN1Util.EncodeInt((int)_unitDimension),
        };
        return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
    }
}
