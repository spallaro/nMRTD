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

//  LandmarkKind ::= CHOICE {
//    base [0] LandmarkKindBase,
//    extensionBlock [1] LandmarkKindExtensionBlock
//  }
//
//  LandmarkKindBase ::= CHOICE {
//    mpeg4FeaturePoint [0] MPEG4FeaturePoint,
//    anthropometricLandmark [1] AnthropometricLandmark
//  }
//
//  AnthropometricLandmark ::= CHOICE {
//    base [0] AnthropometricLandmarkBase,
//    extensionBlock [1] AnthropometricLandmarkExtensionBlock
//  }
//
//  AnthropometricLandmarkBase ::= CHOICE {
//    anthropometricLandmarkName [0] AnthropometricLandmarkName,
//    anthropometricLandmarkPointName [1] AnthropometricLandmarkPointName,
//    anthropometricLandmarkPointId [2] AnthropometricLandmarkPointId
//  }

/// <summary>
/// Port of <c>org.jmrtd.lds.iso39794.FaceImageLandmarkKind</c>: identifies a facial landmark, either as an
/// MPEG-4 feature point or as one of three flavors of anthropometric landmark.
///
/// ADAPTATION: Java's version is a <c>public interface FaceImageLandmarkKind</c> implemented directly by
/// four nested <c>enum ... implements EncodableEnum&lt;T&gt;, FaceImageLandmarkKind</c> declarations, so
/// each Java enum CONSTANT is itself a polymorphic <c>FaceImageLandmarkKind</c> value (Java dispatches on
/// <c>instanceof</c> in <c>encodeLandmarkKind</c>/<c>encodeAnthropmetricLandmark</c>). C# enums cannot
/// implement interfaces, and per this port's established EncodableEnum-replacement convention (see
/// <see cref="ScoreOrError.ScoringErrorCode"/>'s doc comment) each of those four Java enums is ported here
/// as a plain nested enum with explicit numeric values matching each Java constant's own <c>getCode()</c>
/// (all four happen to number their constants in strict declaration order, so code == ordinal for every
/// one -- verified against the Java source, not assumed).
///
/// Since a plain C# enum member can no longer double as a polymorphic <c>FaceImageLandmarkKind</c> value,
/// this whole type is ported not as an interface but as a single sealed "tagged union" class: exactly one
/// of its four nullable properties is non-null for any given instance (enforced by the four constructor
/// overloads below), and <see cref="GetCode"/> stands in for Java's interface method of the same name. This
/// is the one file in this wave where the Java design does not translate mechanically to a like-for-like C#
/// shape -- see this wave's report for the fuller rationale.
/// </summary>
public sealed class FaceImageLandmarkKind
{
    public enum MPEGFeaturePointCode
    {
        Mpeg4PointCode_02_01 = 0,
        Mpeg4PointCode_02_02 = 1,
        Mpeg4PointCode_02_03 = 2,
        Mpeg4PointCode_02_04 = 3,
        Mpeg4PointCode_02_05 = 4,
        Mpeg4PointCode_02_06 = 5,
        Mpeg4PointCode_02_07 = 6,
        Mpeg4PointCode_02_08 = 7,
        Mpeg4PointCode_02_09 = 8,
        Mpeg4PointCode_02_10 = 9,
        Mpeg4PointCode_02_11 = 10,
        Mpeg4PointCode_02_12 = 11,
        Mpeg4PointCode_02_13 = 12,
        Mpeg4PointCode_02_14 = 13,
        Mpeg4PointCode_03_01 = 14,
        Mpeg4PointCode_03_02 = 15,
        Mpeg4PointCode_03_03 = 16,
        Mpeg4PointCode_03_04 = 17,
        Mpeg4PointCode_03_05 = 18,
        Mpeg4PointCode_03_06 = 19,
        Mpeg4PointCode_03_07 = 20,
        Mpeg4PointCode_03_08 = 21,
        Mpeg4PointCode_03_09 = 22,
        Mpeg4PointCode_03_10 = 23,
        Mpeg4PointCode_03_11 = 24,
        Mpeg4PointCode_03_12 = 25,
        Mpeg4PointCode_03_13 = 26,
        Mpeg4PointCode_03_14 = 27,
        Mpeg4PointCode_04_01 = 28,
        Mpeg4PointCode_04_02 = 29,
        Mpeg4PointCode_04_03 = 30,
        Mpeg4PointCode_04_04 = 31,
        Mpeg4PointCode_04_05 = 32,
        Mpeg4PointCode_04_06 = 33,
        Mpeg4PointCode_05_01 = 34,
        Mpeg4PointCode_05_02 = 35,
        Mpeg4PointCode_05_03 = 36,
        Mpeg4PointCode_05_04 = 37,
        Mpeg4PointCode_06_01 = 38,
        Mpeg4PointCode_06_02 = 39,
        Mpeg4PointCode_06_03 = 40,
        Mpeg4PointCode_06_04 = 41,
        Mpeg4PointCode_07_01 = 42,
        Mpeg4PointCode_08_01 = 43,
        Mpeg4PointCode_08_02 = 44,
        Mpeg4PointCode_08_03 = 45,
        Mpeg4PointCode_08_04 = 46,
        Mpeg4PointCode_08_05 = 47,
        Mpeg4PointCode_08_06 = 48,
        Mpeg4PointCode_08_07 = 49,
        Mpeg4PointCode_08_08 = 50,
        Mpeg4PointCode_08_09 = 51,
        Mpeg4PointCode_08_10 = 52,
        Mpeg4PointCode_09_01 = 53,
        Mpeg4PointCode_09_02 = 54,
        Mpeg4PointCode_09_03 = 55,
        Mpeg4PointCode_09_04 = 56,
        Mpeg4PointCode_09_05 = 57,
        Mpeg4PointCode_09_06 = 58,
        Mpeg4PointCode_09_07 = 59,
        Mpeg4PointCode_09_08 = 60,
        Mpeg4PointCode_09_09 = 61,
        Mpeg4PointCode_09_10 = 62,
        Mpeg4PointCode_09_11 = 63,
        Mpeg4PointCode_09_12 = 64,
        Mpeg4PointCode_09_13 = 65,
        Mpeg4PointCode_09_14 = 66,
        Mpeg4PointCode_09_15 = 67,
        Mpeg4PointCode_10_01 = 68,
        Mpeg4PointCode_10_02 = 69,
        Mpeg4PointCode_10_03 = 70,
        Mpeg4PointCode_10_04 = 71,
        Mpeg4PointCode_10_05 = 72,
        Mpeg4PointCode_10_06 = 73,
        Mpeg4PointCode_10_07 = 74,
        Mpeg4PointCode_10_08 = 75,
        Mpeg4PointCode_10_09 = 76,
        Mpeg4PointCode_10_10 = 77,
        Mpeg4PointCode_11_01 = 78,
        Mpeg4PointCode_11_02 = 79,
        Mpeg4PointCode_11_03 = 80,
        Mpeg4PointCode_11_04 = 81,
        Mpeg4PointCode_11_05 = 82,
        Mpeg4PointCode_11_06 = 83,
        Mpeg4PointCode_12_01 = 84,
        Mpeg4PointCode_12_02 = 85,
        Mpeg4PointCode_12_03 = 86,
        Mpeg4PointCode_12_04 = 87,
    }

    public enum AnthropometricLandmarkNameCode
    {
        Vertex = 0,
        Glabella = 1,
        Opisthocranion = 2,
        EurionLeft = 3,
        EurionRight = 4,
        FrontotemporaleLeft = 5,
        FrontotemporaleRight = 6,
        Trichion = 7,
        ZygionLeft = 8,
        ZygionRight = 9,
        GonionLeft = 10,
        GonionRight = 11,
        Sublabiale = 12,
        Pogonion = 13,
        Menton = 14,
        CondylionLateraleLeft = 15,
        CondylionLateraleRight = 16,
        EndocanthionLeft = 17,
        EndocanthionRight = 18,
        ExocanthionLeft = 19,
        ExocanthionRight = 20,
        CenterPointOfPupilLeft = 21,
        CenterPointOfPupilRight = 22,
        OrbitaleLeft = 23,
        OrbitaleRight = 24,
        PalpebraleSuperiusLeft = 25,
        PalpebraleSuperiusRight = 26,
        PalpebraleInferiusLeft = 27,
        PalpebraleInferiusRight = 28,
        OrbitaleSuperiusLeft = 29,
        OrbitaleSuperiusRight = 30,
        SuperciliareLeft = 31,
        SuperciliareRight = 32,
        Nasion = 33,
        Sellion = 34,
        AlareLeft = 35,
        AlareRight = 36,
        Pronasale = 37,
        Subnasale = 38,
        Subalare = 39,
        AlarCurvatureLeft = 40,
        AlarCurvatureRight = 41,
        Maxillofrontale = 42,
        ChristaPhiltraLandmarkLeft = 43,
        ChristaPhiltraLandmarkRight = 44,
        LabialeSuperius = 45,
        LabialeInferius = 46,
        CheilionLeft = 47,
        CheilionRight = 48,
        Stomion = 49,
        SuperauraleLeft = 50,
        SuperauraleRight = 51,
        SubauraleLeft = 52,
        SubauraleRight = 53,
        Preaurale = 54,
        Postaurale = 55,
        OtobasionSuperiusLeft = 56,
        OtobasionSuperiusRight = 57,
        OtobasionInferius = 58,
        Porion = 59,
        Tragion = 60,
    }

    public enum AnthropometricLandmarkPointNameCode
    {
        PointCode_01_01 = 0,
        PointCode_01_02 = 1,
        PointCode_01_05 = 2,
        PointCode_01_06 = 3,
        PointCode_01_07 = 4,
        PointCode_01_08 = 5,
        PointCode_01_09 = 6,
        PointCode_02_01 = 7,
        PointCode_02_02 = 8,
        PointCode_02_03 = 9,
        PointCode_02_04 = 10,
        PointCode_02_05 = 11,
        PointCode_02_06 = 12,
        PointCode_02_07 = 13,
        PointCode_02_09 = 14,
        PointCode_02_10 = 15,
        PointCode_03_01 = 16,
        PointCode_03_02 = 17,
        PointCode_03_03 = 18,
        PointCode_03_04 = 19,
        PointCode_03_05 = 20,
        PointCode_03_06 = 21,
        PointCode_03_07 = 22,
        PointCode_03_08 = 23,
        PointCode_03_09 = 24,
        PointCode_03_10 = 25,
        PointCode_03_11 = 26,
        PointCode_03_12 = 27,
        PointCode_04_01 = 28,
        PointCode_04_02 = 29,
        PointCode_04_03 = 30,
        PointCode_04_04 = 31,
        PointCode_05_01 = 32,
        PointCode_05_02 = 33,
        PointCode_05_03 = 34,
        PointCode_05_04 = 35,
        PointCode_05_06 = 36,
    }

    public enum AnthropometricLandmarkPointIdCode
    {
        V = 0,
        G = 1,
        Op = 2,
        EuLeft = 3,
        EuRight = 4,
        FtLeft = 5,
        FtRight = 6,
        Tr = 7,
        ZyLeft = 8,
        ZyRight = 9,
        GoLeft = 10,
        GoRight = 11,
        Sl = 12,
        Pg = 13,
        Gn = 14,
        CdlLeft = 15,
        CdlRight = 16,
        EnLeft = 17,
        EnRight = 18,
        ExLeft = 19,
        ExRight = 20,
        PLeft = 21,
        PRight = 22,
        OrLeft = 23,
        OrRight = 24,
        PsLeft = 25,
        PsRight = 26,
        PiLeft = 27,
        PiRight = 28,
        OsLeft = 29,
        OsRight = 30,
        SciLeft = 31,
        SciRight = 32,
        N = 33,
        Se = 34,
        AlLeft = 35,
        AlRight = 36,
        Prn = 37,
        Sn = 38,
        Sbal = 39,
        AcLeft = 40,
        AcRight = 41,
        MfLeft = 42,
        MfRight = 43,
        CphLeft = 44,
        CphRight = 45,
        Ls = 46,
        Li = 47,
        ChLeft = 48,
        ChRight = 49,
        Sto = 50,
        SaLeft = 51,
        SaRight = 52,
        SbaLeft = 53,
        SbaRight = 54,
        PraLeft = 55,
        PraRight = 56,
        Pa = 57,
        ObsLeft = 58,
        ObsRight = 59,
        Obi = 60,
        Po = 61,
        T = 62,
    }

    private readonly MPEGFeaturePointCode? _mpegFeaturePointCode;
    private readonly AnthropometricLandmarkNameCode? _anthropometricLandmarkNameCode;
    private readonly AnthropometricLandmarkPointNameCode? _anthropometricLandmarkPointNameCode;
    private readonly AnthropometricLandmarkPointIdCode? _anthropometricLandmarkPointIdCode;

    public FaceImageLandmarkKind(MPEGFeaturePointCode code) => _mpegFeaturePointCode = code;

    public FaceImageLandmarkKind(AnthropometricLandmarkNameCode code) => _anthropometricLandmarkNameCode = code;

    public FaceImageLandmarkKind(AnthropometricLandmarkPointNameCode code) => _anthropometricLandmarkPointNameCode = code;

    public FaceImageLandmarkKind(AnthropometricLandmarkPointIdCode code) => _anthropometricLandmarkPointIdCode = code;

    public MPEGFeaturePointCode? GetMPEGFeaturePointCode() => _mpegFeaturePointCode;

    public AnthropometricLandmarkNameCode? GetAnthropometricLandmarkNameCode() => _anthropometricLandmarkNameCode;

    public AnthropometricLandmarkPointNameCode? GetAnthropometricLandmarkPointNameCode() => _anthropometricLandmarkPointNameCode;

    public AnthropometricLandmarkPointIdCode? GetAnthropometricLandmarkPointIdCode() => _anthropometricLandmarkPointIdCode;

    /// <summary>Stands in for Java's <c>FaceImageLandmarkKind.getCode()</c> interface method: returns
    /// whichever of the four codes above this instance carries.</summary>
    public int GetCode()
    {
        if (_mpegFeaturePointCode != null)
        {
            return (int)_mpegFeaturePointCode.Value;
        }
        if (_anthropometricLandmarkNameCode != null)
        {
            return (int)_anthropometricLandmarkNameCode.Value;
        }
        if (_anthropometricLandmarkPointNameCode != null)
        {
            return (int)_anthropometricLandmarkPointNameCode.Value;
        }
        if (_anthropometricLandmarkPointIdCode != null)
        {
            return (int)_anthropometricLandmarkPointIdCode.Value;
        }

        throw new InvalidOperationException("No landmark kind code set");
    }

    public override int GetHashCode() =>
        HashCode.Combine(_mpegFeaturePointCode, _anthropometricLandmarkNameCode, _anthropometricLandmarkPointNameCode, _anthropometricLandmarkPointIdCode);

    public override bool Equals(object? other)
    {
        if (ReferenceEquals(this, other))
        {
            return true;
        }
        if (other is not FaceImageLandmarkKind otherKind)
        {
            return false;
        }

        return _mpegFeaturePointCode == otherKind._mpegFeaturePointCode
            && _anthropometricLandmarkNameCode == otherKind._anthropometricLandmarkNameCode
            && _anthropometricLandmarkPointNameCode == otherKind._anthropometricLandmarkPointNameCode
            && _anthropometricLandmarkPointIdCode == otherKind._anthropometricLandmarkPointIdCode;
    }

    public override string ToString()
    {
        if (_mpegFeaturePointCode != null)
        {
            return _mpegFeaturePointCode.Value.ToString();
        }
        if (_anthropometricLandmarkNameCode != null)
        {
            return _anthropometricLandmarkNameCode.Value.ToString();
        }
        if (_anthropometricLandmarkPointNameCode != null)
        {
            return _anthropometricLandmarkPointNameCode.Value.ToString();
        }
        if (_anthropometricLandmarkPointIdCode != null)
        {
            return _anthropometricLandmarkPointIdCode.Value.ToString();
        }

        return "null";
    }

    /* PACKAGE */

    internal static FaceImageLandmarkKind? DecodeLandmarkKind(Asn1Encodable asn1Encodable)
    {
        Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
        if (taggedObjects.TryGetValue(0, out Asn1Encodable? baseObject))
        {
            Dictionary<int, Asn1Encodable> baseTaggedObjects = ASN1Util.DecodeTaggedObjects(baseObject);
            if (baseTaggedObjects.TryGetValue(0, out Asn1Encodable? mpegObject))
            {
                int code = ISO39794Util.DecodeCodeFromChoiceExtensionBlockFallback(mpegObject)!.Value;
                return new FaceImageLandmarkKind((MPEGFeaturePointCode)code);
            }

            if (baseTaggedObjects.TryGetValue(1, out Asn1Encodable? anthropometricObject))
            {
                return DecodeAnthropometricLandmark(anthropometricObject);
            }
        }

        return null;
    }

    internal static FaceImageLandmarkKind? DecodeAnthropometricLandmark(Asn1Encodable asn1Encodable)
    {
        Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
        if (taggedObjects.TryGetValue(0, out Asn1Encodable? baseObject))
        {
            Dictionary<int, Asn1Encodable> baseTaggedObjects = ASN1Util.DecodeTaggedObjects(baseObject);
            if (baseTaggedObjects.TryGetValue(0, out Asn1Encodable? nameObject))
            {
                int code = ISO39794Util.DecodeCodeFromChoiceExtensionBlockFallback(nameObject)!.Value;
                return new FaceImageLandmarkKind((AnthropometricLandmarkNameCode)code);
            }

            if (baseTaggedObjects.TryGetValue(1, out Asn1Encodable? pointNameObject))
            {
                int code = ISO39794Util.DecodeCodeFromChoiceExtensionBlockFallback(pointNameObject)!.Value;
                return new FaceImageLandmarkKind((AnthropometricLandmarkPointNameCode)code);
            }

            if (baseTaggedObjects.TryGetValue(2, out Asn1Encodable? pointIdObject))
            {
                int code = ISO39794Util.DecodeCodeFromChoiceExtensionBlockFallback(pointIdObject)!.Value;
                return new FaceImageLandmarkKind((AnthropometricLandmarkPointIdCode)code);
            }
        }

        return null;
    }

    internal static Asn1Encodable EncodeLandmarkKind(FaceImageLandmarkKind? landmarkKind) =>
        EncodeLandmarkKind(landmarkKind, ISO39794EncodingProfile.Base);

    internal static Asn1Encodable EncodeLandmarkKind(FaceImageLandmarkKind? landmarkKind, ISO39794EncodingProfile profile)
    {
        var baseTaggedObjects = new Dictionary<int, Asn1Encodable>();
        if (landmarkKind?._mpegFeaturePointCode != null)
        {
            baseTaggedObjects[0] = ISO39794Util.EncodeCodeAsChoiceExtensionBlockFallback(
                (int)landmarkKind._mpegFeaturePointCode.Value, profile, ChoiceType.Mpeg4FeaturePoint);
        }
        else
        {
            /* NOTE: preserved Java quirk -- Java's encodeLandmarkKind unconditionally falls into the
             * "anthropometric landmark" branch whenever landmarkKind is not an MPEGFeaturePointCode
             * instance, even if landmarkKind is null. Mirrored here rather than special-cased. */
            baseTaggedObjects[1] = EncodeAnthropometricLandmark(landmarkKind, profile);
        }

        var taggedObjects = new Dictionary<int, Asn1Encodable>
        {
            [0] = ASN1Util.EncodeTaggedObjects(baseTaggedObjects)!,
        };
        return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
    }

    internal static Asn1Encodable EncodeAnthropometricLandmark(FaceImageLandmarkKind? landmarkKind) =>
        EncodeAnthropometricLandmark(landmarkKind, ISO39794EncodingProfile.Base);

    internal static Asn1Encodable EncodeAnthropometricLandmark(FaceImageLandmarkKind? landmarkKind, ISO39794EncodingProfile profile)
    {
        var baseTaggedObjects = new Dictionary<int, Asn1Encodable>();
        if (landmarkKind?._anthropometricLandmarkNameCode != null)
        {
            baseTaggedObjects[0] = ISO39794Util.EncodeCodeAsChoiceExtensionBlockFallback(
                (int)landmarkKind._anthropometricLandmarkNameCode.Value, profile, ChoiceType.AnthropometricLandmarkName);
        }
        else if (landmarkKind?._anthropometricLandmarkPointNameCode != null)
        {
            baseTaggedObjects[1] = ISO39794Util.EncodeCodeAsChoiceExtensionBlockFallback(
                (int)landmarkKind._anthropometricLandmarkPointNameCode.Value, profile, ChoiceType.AnthropometricLandmarkPointName);
        }
        else if (landmarkKind?._anthropometricLandmarkPointIdCode != null)
        {
            baseTaggedObjects[2] = ISO39794Util.EncodeCodeAsChoiceExtensionBlockFallback(
                (int)landmarkKind._anthropometricLandmarkPointIdCode.Value, profile, ChoiceType.AnthropometricLandmarkPointId);
        }

        var taggedObjects = new Dictionary<int, Asn1Encodable>
        {
            [0] = ASN1Util.EncodeTaggedObjects(baseTaggedObjects)!,
        };
        return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
    }
}
