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

//  IdentityMetadataBlock ::= SEQUENCE {
//    gender [0] Gender OPTIONAL,
//    eyeColour [1] EyeColour OPTIONAL,
//    hairColour [2] HairColour OPTIONAL,
//    subjectHeight [3] SubjectHeight OPTIONAL,
//    propertiesBlock [4] PropertiesBlock OPTIONAL,
//    expressionBlock [5] ExpressionBlock OPTIONAL,
//    poseAngleBlock [6] PoseAngleBlock OPTIONAL,
//    ...
//  }

/// <summary>
/// Port of <c>org.jmrtd.lds.iso39794.FaceImageIdentityMetadataBlock</c>. Java's <c>Serializable</c> marker
/// is dropped (no reflection-based serialization is needed in this port).
///
/// ADAPTATION: Java's version is also a top-level <c>public class</c>, but this is <c>internal</c> since its
/// base class <see cref="Block"/> is <c>internal</c> in this port (see <c>VersionBlock</c>'s doc comment).
/// It is however required to expose exactly the members referenced by
/// <see cref="ISO39794EncodingProfileExtensions.Validate"/> (<see cref="GenderCode"/> and
/// <see cref="GetGenderCode"/>) unchanged, since that method (in the already-committed
/// <c>ISO39794EncodingProfile.cs</c>) is an established contract this class must satisfy exactly.
/// </summary>
internal class FaceImageIdentityMetadataBlock : Block
{
    /// <summary>
    /// ADAPTATION: Java's version is <c>enum GenderCode implements EncodableEnum&lt;GenderCode&gt;</c>, using
    /// reflection-based <c>EncodableEnum.fromCode</c> lookup keyed on each constant's own <c>getCode()</c>.
    /// Ported as a plain enum with explicit numeric values matching each Java constant's <c>getCode()</c>
    /// (declaration order and code coincide here). See <see cref="FromCode{T}"/> for the shared "decode from
    /// code" replacement and <c>ScoreOrError.ScoringErrorCode</c>'s doc comment for the fuller rationale.
    /// </summary>
    public enum GenderCode
    {
        Unknown = 0,
        Other = 1,
        Male = 2,
        Female = 3,
    }

    public enum EyeColourCode
    {
        Unknown = 0,
        Other = 1,
        Black = 2,
        Blue = 3,
        Brown = 4,
        Grey = 5,
        Green = 6,
        Hazel = 7,
        MultiColoured = 8,
        Pink = 9,
    }

    /// <summary>NOTE: preserved Java quirk verbatim -- the last constant is named <c>KNOWN_COLOURED</c> in the
    /// Java original (evidently meant to be <c>MULTI_COLOURED</c>, mirroring <see cref="EyeColourCode"/>'s own
    /// last constant, but not spelled that way). Ported as <see cref="KnownColoured"/> to match the Java
    /// identifier faithfully rather than "fixing" the apparent typo.</summary>
    public enum HairColourCode
    {
        Unknown = 0,
        Other = 1,
        Bald = 2,
        Black = 3,
        Blonde = 4,
        Brown = 5,
        Grey = 6,
        White = 7,
        Red = 8,
        KnownColoured = 9,
    }

    /// <summary>Shared "decode from code" replacement for Java's reflection-based
    /// <c>EncodableEnum.fromCode(int, Class&lt;T&gt;)</c>: an <see cref="Enum.IsDefined(Type, object)"/>
    /// validity check plus a direct cast, returning <see langword="null"/> for an unrecognized code exactly
    /// like the Java original (which never throws from <c>fromCode</c> itself).</summary>
    private static T? FromCode<T>(int code) where T : struct, Enum =>
        Enum.IsDefined(typeof(T), code) ? (T)(object)code : null;

    private readonly GenderCode? _genderCode;
    private readonly EyeColourCode? _eyeColourCode;
    private readonly HairColourCode? _hairColourCode;

    /// <summary>NOTE: preserved Java quirk -- like <c>PADDataBlock</c>'s <c>riskLevel</c>, this stays an
    /// unconditional (non-nullable) <c>int</c> rather than <c>int?</c>, matching Java's primitive
    /// <c>int subjectHeight</c> field. When tag 3 is absent on decode, this keeps Java's implicit default of
    /// <c>0</c> (not <c>-1</c>), even though the encoder's own <c>subjectHeight &gt;= 0</c> guard implies
    /// <c>-1</c> was meant to signal "absent" -- a genuine round-trip quirk in the original JMRTD code,
    /// preserved here rather than "fixed".</summary>
    private readonly int _subjectHeight;

    private readonly FaceImagePropertiesBlock? _propertiesBlock;
    private readonly FaceImageExpressionBlock? _expressionBlock;
    private readonly FaceImagePoseAngleBlock? _poseAngleBlock;

    public FaceImageIdentityMetadataBlock(GenderCode? genderCode, EyeColourCode? eyeColourCode,
        HairColourCode? hairColourCode, int subjectHeight, FaceImagePropertiesBlock? propertiesBlock,
        FaceImageExpressionBlock? expressionBlock, FaceImagePoseAngleBlock? poseAngleBlock)
    {
        _genderCode = genderCode;
        _eyeColourCode = eyeColourCode;
        _hairColourCode = hairColourCode;
        _subjectHeight = subjectHeight;
        _propertiesBlock = propertiesBlock;
        _expressionBlock = expressionBlock;
        _poseAngleBlock = poseAngleBlock;
    }

    /// <summary>NOTE: preserved Java quirk -- for each of the three "choice/extension-block" coded fields
    /// below, <c>ISO39794Util.DecodeCodeFromChoiceExtensionBlockFallback</c> returns a nullable code (it can
    /// legitimately find neither the direct nor the extension-block tag and return nothing). Java passes that
    /// boxed <c>Integer</c> straight into <c>fromCode(int)</c>, so a malformed inner CHOICE throws an
    /// (unchecked) <c>NullPointerException</c> there via auto-unboxing. This port's direct <c>.Value</c>
    /// access on the <see langword="int?"/> reproduces the same "throw on malformed input" behavior
    /// (<see cref="InvalidOperationException"/> instead of Java's NPE) rather than silently swallowing it. See
    /// the identical established pattern in <c>PADDataBlock.cs</c>.</summary>
    internal FaceImageIdentityMetadataBlock(Asn1Encodable? asn1Encodable)
    {
        if (asn1Encodable == null)
        {
            throw new ArgumentException("Cannot decode null!");
        }
        if (asn1Encodable is not Asn1Sequence && asn1Encodable is not Asn1TaggedObject)
        {
            throw new ArgumentException("Cannot decode!");
        }

        Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
        if (taggedObjects.TryGetValue(0, out Asn1Encodable? genderObject))
        {
            _genderCode = FromCode<GenderCode>(ISO39794Util.DecodeCodeFromChoiceExtensionBlockFallback(genderObject)!.Value);
        }
        if (taggedObjects.TryGetValue(1, out Asn1Encodable? eyeColourObject))
        {
            _eyeColourCode = FromCode<EyeColourCode>(ISO39794Util.DecodeCodeFromChoiceExtensionBlockFallback(eyeColourObject)!.Value);
        }
        if (taggedObjects.TryGetValue(2, out Asn1Encodable? hairColourObject))
        {
            _hairColourCode = FromCode<HairColourCode>(ISO39794Util.DecodeCodeFromChoiceExtensionBlockFallback(hairColourObject)!.Value);
        }
        if (taggedObjects.TryGetValue(3, out Asn1Encodable? subjectHeightObject))
        {
            _subjectHeight = ASN1Util.DecodeInt(subjectHeightObject);
        }
        if (taggedObjects.TryGetValue(4, out Asn1Encodable? propertiesObject))
        {
            _propertiesBlock = new FaceImagePropertiesBlock(propertiesObject);
        }
        if (taggedObjects.TryGetValue(5, out Asn1Encodable? expressionObject))
        {
            _expressionBlock = new FaceImageExpressionBlock(expressionObject);
        }
        if (taggedObjects.TryGetValue(6, out Asn1Encodable? poseAngleObject))
        {
            _poseAngleBlock = new FaceImagePoseAngleBlock(poseAngleObject);
        }
    }

    public GenderCode? GetGenderCode() => _genderCode;

    public EyeColourCode? GetEyeColourCode() => _eyeColourCode;

    public HairColourCode? GetHairColourCode() => _hairColourCode;

    public int GetSubjectHeight() => _subjectHeight;

    public FaceImagePropertiesBlock? GetPropertiesBlock() => _propertiesBlock;

    public FaceImageExpressionBlock? GetExpressionBlock() => _expressionBlock;

    public FaceImagePoseAngleBlock? GetPoseAngleBlock() => _poseAngleBlock;

    public override int GetHashCode() =>
        HashCode.Combine(_expressionBlock, _eyeColourCode, _genderCode, _hairColourCode, _poseAngleBlock,
            _propertiesBlock, _subjectHeight);

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

        var otherBlock = (FaceImageIdentityMetadataBlock)other;
        return Equals(_expressionBlock, otherBlock._expressionBlock)
            && _eyeColourCode == otherBlock._eyeColourCode
            && _genderCode == otherBlock._genderCode
            && _hairColourCode == otherBlock._hairColourCode
            && Equals(_poseAngleBlock, otherBlock._poseAngleBlock)
            && Equals(_propertiesBlock, otherBlock._propertiesBlock)
            && _subjectHeight == otherBlock._subjectHeight;
    }

    public override string ToString() =>
        "FaceImageIdentityMetadataBlock ["
        + $"genderCode: {_genderCode}"
        + $", eyeColourCode: {_eyeColourCode}"
        + $", hairColourCode: {_hairColourCode}"
        + $", subjectHeight: {_subjectHeight}"
        + $", propertiesBlock: {_propertiesBlock}"
        + $", expressionBlock: {_expressionBlock}"
        + $", poseAngleBlock: {_poseAngleBlock}"
        + "]";

    /* PACKAGE */

    internal override Asn1Encodable GetAsn1Object() => GetAsn1Object(ISO39794EncodingProfile.Base);

    internal override Asn1Encodable GetAsn1Object(ISO39794EncodingProfile profile)
    {
        var taggedObjects = new Dictionary<int, Asn1Encodable>();
        if (_genderCode != null)
        {
            taggedObjects[0] = ISO39794Util.EncodeCodeAsChoiceExtensionBlockFallback((int)_genderCode.Value, profile, ChoiceType.Gender);
        }
        if (_eyeColourCode != null)
        {
            taggedObjects[1] = ISO39794Util.EncodeCodeAsChoiceExtensionBlockFallback((int)_eyeColourCode.Value, profile, ChoiceType.EyeColour);
        }
        if (_hairColourCode != null)
        {
            taggedObjects[2] = ISO39794Util.EncodeCodeAsChoiceExtensionBlockFallback((int)_hairColourCode.Value, profile, ChoiceType.HairColour);
        }
        if (_subjectHeight >= 0)
        {
            taggedObjects[3] = ASN1Util.EncodeInt(_subjectHeight);
        }
        if (_propertiesBlock != null)
        {
            taggedObjects[4] = _propertiesBlock.GetAsn1Object();
        }
        if (_expressionBlock != null)
        {
            taggedObjects[5] = _expressionBlock.GetAsn1Object();
        }
        if (_poseAngleBlock != null)
        {
            taggedObjects[6] = _poseAngleBlock.GetAsn1Object();
        }
        return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
    }
}
