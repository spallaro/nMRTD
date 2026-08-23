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

//  AnnotationBlock ::= SEQUENCE {
//    position [0] Position,
//    reason [1] AnnotationReason,
//    ...
//  }

/// <summary>
/// Port of <c>org.jmrtd.lds.iso39794.FingerImageAnnotationBlock</c>. Java's <c>Serializable</c> marker is
/// dropped (no reflection-based serialization is needed in this port) -- this also means Java's
/// <c>getSerialversionuid()</c> static accessor (a pure serialization artifact) has no counterpart here.
///
/// ADAPTATION: Java's version is a top-level <c>public class</c>, but this is <c>internal</c> since its
/// base class <see cref="Block"/> is <c>internal</c> in this port (see <c>VersionBlock</c>'s doc comment).
/// </summary>
internal class FingerImageAnnotationBlock : Block
{
    /// <summary>
    /// ADAPTATION: Java's version is <c>enum AnnotationReasonCode implements
    /// EncodableEnum&lt;AnnotationReasonCode&gt;</c>, using reflection-based <c>EncodableEnum.fromCode</c>
    /// lookup keyed on each constant's own <c>getCode()</c>. Ported as a plain enum with explicit numeric
    /// values matching each Java constant's <c>getCode()</c> (declaration order and code happen to coincide
    /// here); see <c>ScoreOrError.ScoringErrorCode</c>'s doc comment for the fuller rationale and
    /// <see cref="FromCode"/> for the shared "decode from code" replacement.
    /// </summary>
    public enum AnnotationReasonCode
    {
        Unknown = 0,
        Other = 1,
        Amputated = 2,
        UnableToPrint = 3,
        Bandaged = 4,
        PhysicallyChallenged = 5,
        Diseased = 6,
    }

    private static AnnotationReasonCode? FromCode(int code) =>
        Enum.IsDefined(typeof(AnnotationReasonCode), code) ? (AnnotationReasonCode)code : null;

    private readonly FingerImagePositionCode? _positionCode;

    private readonly AnnotationReasonCode? _reasonCode;

    public FingerImageAnnotationBlock(FingerImagePositionCode? positionCode, AnnotationReasonCode? reasonCode)
    {
        _positionCode = positionCode;
        _reasonCode = reasonCode;
    }

    internal FingerImageAnnotationBlock(Asn1Encodable asn1Encodable)
    {
        Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
        _positionCode = FingerImagePositionCodeExtensions.FromCode(ISO39794Util.DecodeCodeFromChoiceExtensionBlockFallback(taggedObjects[0])!.Value);
        _reasonCode = FromCode(ISO39794Util.DecodeCodeFromChoiceExtensionBlockFallback(taggedObjects[1])!.Value);
    }

    public FingerImagePositionCode? GetPositionCode() => _positionCode;

    public AnnotationReasonCode? GetReasonCode() => _reasonCode;

    public override int GetHashCode() => HashCode.Combine(_positionCode, _reasonCode);

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

        var otherBlock = (FingerImageAnnotationBlock)other;
        return _positionCode == otherBlock._positionCode && _reasonCode == otherBlock._reasonCode;
    }

    public override string ToString() =>
        "FingerImageAnnotationBlock ["
        + $"positionCode: {_positionCode}"
        + $", reasonCode: {_reasonCode}"
        + "]";

    /* PACKAGE */

    internal static List<FingerImageAnnotationBlock> DecodeFingerImageAnnotationBlocks(Asn1Encodable asn1Encodable)
    {
        if (ASN1Util.IsSequenceOfSequences(asn1Encodable))
        {
            List<Asn1Encodable> blockAsn1Objects = ASN1Util.List(asn1Encodable)!;
            var blocks = new List<FingerImageAnnotationBlock>(blockAsn1Objects.Count);
            foreach (Asn1Encodable blockAsn1Object in blockAsn1Objects)
            {
                blocks.Add(new FingerImageAnnotationBlock(blockAsn1Object));
            }
            return blocks;
        }
        else
        {
            return [new FingerImageAnnotationBlock(asn1Encodable)];
        }
    }

    internal override Asn1Encodable GetAsn1Object()
    {
        var taggedObjects = new Dictionary<int, Asn1Encodable>
        {
            [0] = ISO39794Util.EncodeCodeAsChoiceExtensionBlockFallback((int)_positionCode!.Value),
            [1] = ISO39794Util.EncodeCodeAsChoiceExtensionBlockFallback((int)_reasonCode!.Value),
        };
        return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
    }
}
