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

using System.Runtime.CompilerServices;
using Org.BouncyCastle.Asn1;
using nMRTD.SmartCards;

namespace nMRTD.Lds.Iso39794;

//  PADDataBlock ::= SEQUENCE {
//    decision              [0] PADDecision            OPTIONAL,
//    scoreBlocks           [1] PADScoreBlocks         OPTIONAL,
//    extendedDataBlocks    [2] PADExtendedDataBlocks  OPTIONAL,
//    captureContext        [3] PADCaptureContext      OPTIONAL,
//    supervisionLevel      [4] PADSupervisionLevel    OPTIONAL,
//    riskLevel             [5] PADRiskLevel           OPTIONAL,
//    criteriaCategory      [6] PADCriteriaCategory    OPTIONAL,
//    parameter             [7] OCTET STRING           OPTIONAL,
//    challenges            [8] PADChallenges          OPTIONAL,
//    captureDateTimeBlock  [9] CaptureDateTimeBlock   OPTIONAL,
//    ...
//  }

/// <summary>
/// Port of <c>org.jmrtd.lds.iso39794.PADDataBlock</c>. Java's <c>Serializable</c> marker is dropped (no
/// reflection-based serialization is needed in this port).
/// </summary>
public class PADDataBlock : Block
{
    /// <summary>
    /// ADAPTATION: Java's four nested "PAD ... Code" enums here each <c>implement EncodableEnum&lt;T&gt;</c>
    /// with reflection-based <c>fromCode</c> lookup. Ported as plain enums with explicit numeric values
    /// matching each Java constant's own <c>getCode()</c> (declaration order and code coincide for all four
    /// of these); see <see cref="FromCode{T}"/> for the shared "decode from code" replacement and
    /// <see cref="ScoreOrError.ScoringErrorCode"/>'s doc comment for the fuller rationale.
    /// </summary>
    public enum PADDecisionCode
    {
        NoAttack = 0,
        Attack = 1,
        FailureToAssess = 2,
    }

    public enum PADCaptureContextCode
    {
        Enrolment = 0,
        Verification = 1,
        Identification = 2,
    }

    public enum PADSupervisionLevelCode
    {
        Unknown = 0,
        Controlled = 1,
        Assisted = 2,
        Observed = 3,
        Unattended = 4,
    }

    public enum PADCriteriaCategoryCode
    {
        Unknown = 0,
        Individual = 1,
        Common = 2,
    }

    /// <summary>Shared "decode from code" replacement for Java's reflection-based
    /// <c>EncodableEnum.fromCode(int, Class&lt;T&gt;)</c>: an <see cref="Enum.IsDefined(Type, object)"/>
    /// validity check plus a direct cast, returning <see langword="null"/> for an unrecognized code exactly
    /// like the Java original (which never throws from <c>fromCode</c> itself -- callers decide whether a
    /// <see langword="null"/> result is acceptable).</summary>
    private static T? FromCode<T>(int code) where T : struct, Enum =>
        Enum.IsDefined(typeof(T), code) ? (T)(object)code : null;

    private readonly PADDecisionCode? _padDecisionCode;
    private readonly List<PADScoreBlock>? _padScoreBlocks;
    private readonly List<ExtendedDataBlock>? _padExtendedDataBlocks;
    private readonly PADCaptureContextCode? _padCaptureContextCode;
    private readonly PADSupervisionLevelCode? _padSupervisionLevelCode;

    /// <summary>INTEGER (0..100).
    /// NOTE: preserved Java quirk -- like Java's primitive <c>int riskLevel</c> field, this stays an
    /// unconditional (non-nullable) <c>int</c> rather than <c>int?</c>. Java's decode constructor only ever
    /// assigns it when tag 5 is present; when absent, the field keeps Java's implicit default of
    /// <c>0</c> -- not <c>-1</c>, even though the encoder's own <c>riskLevel &gt;= 0</c> guard implies
    /// <c>-1</c> was meant to signal "absent". A <see cref="PADDataBlock"/> decoded without a risk level
    /// therefore reports <c>GetRiskLevel() == 0</c> (indistinguishable from an actual risk level of zero),
    /// and re-encoding it would emit tag 5 with value 0 where the original had none -- a genuine round-trip
    /// bug in the original JMRTD code, preserved here rather than "fixed".</summary>
    private readonly int _riskLevel;

    private readonly PADCriteriaCategoryCode? _padCriteriaCategoryCode;
    private readonly byte[]? _parameter;
    private readonly List<byte[]>? _challenges;
    private readonly DateTimeBlock? _captureDateTimeBlock;

    public PADDataBlock(PADDecisionCode? padDecisionCode, List<PADScoreBlock>? padScoreBlocks,
        List<ExtendedDataBlock>? padExtendedDataBlocks, PADCaptureContextCode? padCaptureContextCode,
        PADSupervisionLevelCode? padSupervisionLevelCode, int riskLevel, PADCriteriaCategoryCode? padCriteriaCategoryCode,
        byte[]? parameter, List<byte[]>? challenges, DateTimeBlock? captureDateTimeBlock)
    {
        _padDecisionCode = padDecisionCode;
        _padScoreBlocks = padScoreBlocks;
        _padExtendedDataBlocks = padExtendedDataBlocks;
        _padCaptureContextCode = padCaptureContextCode;
        _padSupervisionLevelCode = padSupervisionLevelCode;
        _riskLevel = riskLevel;
        _padCriteriaCategoryCode = padCriteriaCategoryCode;
        _parameter = parameter;
        _challenges = challenges;
        _captureDateTimeBlock = captureDateTimeBlock;
    }

    /// <summary>NOTE: preserved Java quirk -- for each of the four "choice/extension-block" coded fields
    /// below, <c>ISO39794Util.DecodeCodeFromChoiceExtensionBlockFallback</c> returns a nullable code (it can
    /// legitimately find neither the direct nor the extension-block tag and return nothing). Java passes
    /// that boxed <c>Integer</c> straight into <c>fromCode(int)</c>, so a malformed inner CHOICE throws an
    /// (unchecked) <c>NullPointerException</c> there via auto-unboxing. This port's direct <c>.Value</c>
    /// access on the <see langword="int?"/> reproduces the same "throw on malformed input" behavior
    /// (<see cref="InvalidOperationException"/> instead of Java's NPE) rather than silently swallowing it.</summary>
    internal PADDataBlock(Asn1Encodable asn1Encodable)
    {
        Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
        if (taggedObjects.TryGetValue(0, out Asn1Encodable? decisionObject))
        {
            _padDecisionCode = FromCode<PADDecisionCode>(ISO39794Util.DecodeCodeFromChoiceExtensionBlockFallback(decisionObject)!.Value);
        }
        if (taggedObjects.TryGetValue(1, out Asn1Encodable? scoreBlocksObject))
        {
            _padScoreBlocks = PADScoreBlock.DecodePADScoreBlocks(scoreBlocksObject);
        }
        if (taggedObjects.TryGetValue(2, out Asn1Encodable? extendedDataBlocksObject))
        {
            _padExtendedDataBlocks = ExtendedDataBlock.DecodeExtendedDataBlocks(extendedDataBlocksObject);
        }
        if (taggedObjects.TryGetValue(3, out Asn1Encodable? captureContextObject))
        {
            _padCaptureContextCode = FromCode<PADCaptureContextCode>(ISO39794Util.DecodeCodeFromChoiceExtensionBlockFallback(captureContextObject)!.Value);
        }
        if (taggedObjects.TryGetValue(4, out Asn1Encodable? supervisionLevelObject))
        {
            _padSupervisionLevelCode = FromCode<PADSupervisionLevelCode>(ISO39794Util.DecodeCodeFromChoiceExtensionBlockFallback(supervisionLevelObject)!.Value);
        }
        if (taggedObjects.TryGetValue(5, out Asn1Encodable? riskLevelObject))
        {
            _riskLevel = ASN1Util.DecodeInt(riskLevelObject);
        }
        if (taggedObjects.TryGetValue(6, out Asn1Encodable? criteriaCategoryObject))
        {
            _padCriteriaCategoryCode = FromCode<PADCriteriaCategoryCode>(ISO39794Util.DecodeCodeFromChoiceExtensionBlockFallback(criteriaCategoryObject)!.Value);
        }
        if (taggedObjects.TryGetValue(7, out Asn1Encodable? parameterObject))
        {
            _parameter = Asn1OctetString.GetInstance(parameterObject).GetOctets();
        }
        if (taggedObjects.TryGetValue(8, out Asn1Encodable? challengesObject))
        {
            _challenges = DecodePADChallenges(challengesObject);
        }
        if (taggedObjects.TryGetValue(9, out Asn1Encodable? captureDateTimeObject))
        {
            _captureDateTimeBlock = new DateTimeBlock(captureDateTimeObject);
        }
    }

    public PADDecisionCode? GetPADDecisionCode() => _padDecisionCode;

    public List<PADScoreBlock>? GetPadScoreBlocks() => _padScoreBlocks;

    public List<ExtendedDataBlock>? GetPadExtendedDataBlocks() => _padExtendedDataBlocks;

    public PADCaptureContextCode? GetPADCaptureContextCode() => _padCaptureContextCode;

    public PADSupervisionLevelCode? GetPADSupervisionLevelCode() => _padSupervisionLevelCode;

    public int GetRiskLevel() => _riskLevel;

    public PADCriteriaCategoryCode? GetPADCriteriaCategoryCode() => _padCriteriaCategoryCode;

    public byte[]? GetParameter() => _parameter;

    public List<byte[]>? GetChallenges() => _challenges;

    public DateTimeBlock? GetCaptureDateTimeBlock() => _captureDateTimeBlock;

    public override int GetHashCode()
    {
        const int prime = 31;
        int result = 1;
        result = (prime * result) + JavaArrayHashCode(_parameter);
        result = (prime * result) + JavaObjectsHash(
            _captureDateTimeBlock?.GetHashCode() ?? 0,
            JavaChallengesHashCode(_challenges),
            _padCaptureContextCode?.GetHashCode() ?? 0,
            _padCriteriaCategoryCode?.GetHashCode() ?? 0,
            _padDecisionCode?.GetHashCode() ?? 0,
            JavaListHashCode(_padExtendedDataBlocks),
            JavaListHashCode(_padScoreBlocks),
            _padSupervisionLevelCode?.GetHashCode() ?? 0,
            _riskLevel);
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

        var otherBlock = (PADDataBlock)other;
        return Equals(_captureDateTimeBlock, otherBlock._captureDateTimeBlock)
            && EqualBytes(_challenges, otherBlock._challenges)
            && _padCaptureContextCode == otherBlock._padCaptureContextCode
            && _padCriteriaCategoryCode == otherBlock._padCriteriaCategoryCode
            && _padDecisionCode == otherBlock._padDecisionCode
            && ListEquals(_padExtendedDataBlocks, otherBlock._padExtendedDataBlocks)
            && ListEquals(_padScoreBlocks, otherBlock._padScoreBlocks)
            && _padSupervisionLevelCode == otherBlock._padSupervisionLevelCode
            && ByteArraysEqual(_parameter, otherBlock._parameter)
            && _riskLevel == otherBlock._riskLevel;
    }

    public override string ToString() =>
        "PADDataBlock ["
        + $"padDecisionCode: {ToStringOrNull(_padDecisionCode)}"
        + $", padScoreBlocks: {JavaListToString(_padScoreBlocks)}"
        + $", padExtendedDataBlocks: {JavaListToString(_padExtendedDataBlocks)}"
        + $", padCaptureContextCode: {ToStringOrNull(_padCaptureContextCode)}"
        + $", padSupervisionLevelCode: {ToStringOrNull(_padSupervisionLevelCode)}"
        + $", riskLevel: {_riskLevel}"
        + $", padCriteriaCategoryCode: {ToStringOrNull(_padCriteriaCategoryCode)}"
        + $", parameter: {ParameterToString(_parameter)}"
        + $", challenges: {ChallengesToString(_challenges)}"
        + $", captureDateTimeBlock: {_captureDateTimeBlock?.ToString() ?? "null"}"
        + "]";

    /* PACKAGE */

    internal static List<PADDataBlock> DecodePADDataBlocks(Asn1Encodable asn1Encodable)
    {
        if (ASN1Util.IsSequenceOfSequences(asn1Encodable))
        {
            List<Asn1Encodable> blockAsn1Objects = ASN1Util.List(asn1Encodable)!;
            var blocks = new List<PADDataBlock>(blockAsn1Objects.Count);
            foreach (Asn1Encodable blockAsn1Object in blockAsn1Objects)
            {
                blocks.Add(new PADDataBlock(blockAsn1Object));
            }

            return blocks;
        }

        return [new PADDataBlock(asn1Encodable)];
    }

    internal override Asn1Encodable GetAsn1Object() => GetAsn1Object(ISO39794EncodingProfile.Base);

    internal override Asn1Encodable GetAsn1Object(ISO39794EncodingProfile profile)
    {
        var taggedObjects = new Dictionary<int, Asn1Encodable>();
        if (_padDecisionCode != null)
        {
            taggedObjects[0] = ISO39794Util.EncodeCodeAsChoiceExtensionBlockFallback((int)_padDecisionCode.Value, profile, ChoiceType.PadDecision);
        }
        if (_padScoreBlocks != null)
        {
            taggedObjects[1] = ISO39794Util.EncodeBlocks([.. _padScoreBlocks.Cast<Block>()], profile)!;
        }
        if (_padExtendedDataBlocks != null)
        {
            taggedObjects[2] = ISO39794Util.EncodeBlocks([.. _padExtendedDataBlocks.Cast<Block>()])!;
        }
        if (_padCaptureContextCode != null)
        {
            taggedObjects[3] = ISO39794Util.EncodeCodeAsChoiceExtensionBlockFallback((int)_padCaptureContextCode.Value, profile, ChoiceType.PadCaptureContext);
        }
        if (_padSupervisionLevelCode != null)
        {
            taggedObjects[4] = ISO39794Util.EncodeCodeAsChoiceExtensionBlockFallback((int)_padSupervisionLevelCode.Value, profile, ChoiceType.PadSupervisionLevel);
        }
        if (_riskLevel >= 0)
        {
            taggedObjects[5] = ASN1Util.EncodeInt(_riskLevel);
        }
        if (_padCriteriaCategoryCode != null)
        {
            taggedObjects[6] = ISO39794Util.EncodeCodeAsChoiceExtensionBlockFallback((int)_padCriteriaCategoryCode.Value, profile, ChoiceType.PadCriteriaCategory);
        }
        if (_parameter != null)
        {
            taggedObjects[7] = new DerOctetString(_parameter);
        }
        if (_challenges != null)
        {
            taggedObjects[8] = EncodePADChallenges(_challenges);
        }
        if (_captureDateTimeBlock != null)
        {
            taggedObjects[9] = _captureDateTimeBlock.GetAsn1Object();
        }
        return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
    }

    /* PRIVATE */

    private static List<byte[]> DecodePADChallenges(Asn1Encodable asn1Encodable)
    {
        List<Asn1Encodable> challengeAsn1Objects = ASN1Util.List(asn1Encodable)!;
        var padChallenges = new List<byte[]>(challengeAsn1Objects.Count);
        foreach (Asn1Encodable challengeAsn1Object in challengeAsn1Objects)
        {
            padChallenges.Add(Asn1OctetString.GetInstance(challengeAsn1Object).GetOctets());
        }

        return padChallenges;
    }

    private static DerSequence EncodePADChallenges(List<byte[]> padChallenges)
    {
        var asn1Encodables = new List<Asn1Encodable>(padChallenges.Count);
        foreach (byte[] padChallenge in padChallenges)
        {
            asn1Encodables.Add(new DerOctetString(padChallenge));
        }

        return new DerSequence(asn1Encodables.ToArray());
    }

    private static bool EqualBytes(List<byte[]>? challenges1, List<byte[]>? challenges2)
    {
        if (ReferenceEquals(challenges1, challenges2))
        {
            return true;
        }
        if (challenges1 == null || challenges2 == null)
        {
            return false;
        }
        if (challenges1.Count != challenges2.Count)
        {
            return false;
        }

        int length = challenges1.Count;
        for (int i = 0; i < length; i++)
        {
            if (!challenges1[i].SequenceEqual(challenges2[i]))
            {
                return false;
            }
        }

        return true;
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

    private static bool ByteArraysEqual(byte[]? array1, byte[]? array2)
    {
        if (array1 == null || array2 == null)
        {
            return array1 == array2;
        }

        return array1.SequenceEqual(array2);
    }

    private static string ToStringOrNull<T>(T? value) where T : struct => value?.ToString() ?? "null";

    private static string JavaListToString<T>(List<T>? list) => list == null ? "null" : $"[{string.Join(", ", list)}]";

    /// <summary>Renders <c>parameter</c> as hex, or the literal <c>"null"</c> string when absent -- matches
    /// Java's own <c>Hex.bytesToHexString(null)</c> plus string-concatenation-of-null convention (rather
    /// than this port's <c>Hex.BytesToHexString</c>, which throws on <see langword="null"/>).</summary>
    private static string ParameterToString(byte[]? parameter) => parameter == null ? "null" : Hex.BytesToHexString(parameter);

    private static string ChallengesToString(List<byte[]>? challenges)
    {
        if (challenges == null)
        {
            return "null";
        }

        bool isFirst = true;
        var stringBuilder = new System.Text.StringBuilder("[");
        foreach (byte[] challenge in challenges)
        {
            if (isFirst)
            {
                isFirst = false;
            }
            else
            {
                stringBuilder.Append(", ");
            }
            stringBuilder.Append(Hex.BytesToHexString(challenge));
        }

        return stringBuilder.Append(']').ToString();
    }

    /// <summary>Java-style <c>Arrays.hashCode(byte[])</c> for a (possibly <see langword="null"/>) byte
    /// array -- see the established pattern in e.g. <c>PaceKeySpec.cs</c>/<c>PACECAMResult.cs</c>. Unlike
    /// those single-purpose copies, this one accepts <see langword="null"/> directly (matching
    /// <c>Arrays.hashCode(null) == 0</c>) since <c>parameter</c> is OPTIONAL here.</summary>
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
    /// Needed because C#'s <c>List&lt;T&gt;.GetHashCode()</c> is reference-identity-based, unlike Java's,
    /// while <see cref="Equals(object?)"/> above compares these same fields by content
    /// (<see cref="ListEquals{T}"/>) -- so the default identity-based hash would violate the
    /// equals/hashCode contract if used here instead.</summary>
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

    /// <summary>
    /// NOTE: preserved Java quirk -- Java's <c>List&lt;byte[]&gt;.hashCode()</c> (via <c>AbstractList</c>)
    /// sums each element's <c>hashCode()</c>, and <c>byte[]</c> doesn't override <c>hashCode()</c> in Java
    /// (identity-based), so <c>challenges</c>' contribution to <see cref="GetHashCode"/> is array-identity-
    /// based even though <see cref="Equals(object?)"/> compares <c>challenges</c> by content
    /// (<c>Arrays.equals</c> per element via <see cref="EqualBytes"/>) -- a real equals/hashCode contract
    /// violation in the original JMRTD code (two content-equal instances can hash differently), preserved
    /// here rather than "fixed", matching the identical quirk already documented in
    /// <c>StandardBiometricHeader.cs</c>.
    /// </summary>
    private static int JavaChallengesHashCode(List<byte[]>? challenges)
    {
        if (challenges == null)
        {
            return 0;
        }

        int hash = 1;
        foreach (byte[] challenge in challenges)
        {
            hash = (31 * hash) + RuntimeHelpers.GetHashCode(challenge);
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
