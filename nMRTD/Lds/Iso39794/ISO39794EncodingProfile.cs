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

namespace nMRTD.Lds.Iso39794;

/// <summary>
/// Port of <c>org.jmrtd.lds.iso39794.ISO39794EncodingProfile</c>: encoding profiles for ISO/IEC 39794
/// data. Decoding deliberately does not use a profile: this port, like JMRTD, accepts both base-standard
/// and application-profile encodings.
///
/// ADAPTATION: Java's version is a <c>public enum</c> carrying instance methods
/// (<c>usesExtensionBlockFallback</c>, <c>validate</c>); C# enums cannot carry methods, so those live in
/// <see cref="ISO39794EncodingProfileExtensions"/> as extension methods instead, matching this port's
/// established pattern for Java enums with associated logic (see e.g.
/// <c>nMRTD.Cbeff.BiometricEncodingTypeCodec</c>). Java's nested <c>ChoiceType</c> enum cannot be ported as
/// a nested type of a C# <c>enum</c> either (enums cannot contain nested types in C#), so it is a sibling
/// top-level <see cref="ChoiceType"/> in this same file instead -- both are package-private in Java, so the
/// exact qualified path used to reach it from other files is not part of any external contract.
/// </summary>
public enum ISO39794EncodingProfile
{
    /// <summary>The unconstrained ISO/IEC 39794 base-standard encoding.</summary>
    Base,

    /// <summary>ISO/IEC 39794-5 Application Profile for eMRTDs, version 1.0.</summary>
    Icao39794_5EmrtdV1,
}

/// <summary>See <see cref="ISO39794EncodingProfile"/>'s doc comment for why this exists.</summary>
internal enum ChoiceType
{
    ScoringError,
    PadDecision,
    PadCaptureContext,
    PadSupervisionLevel,
    PadCriteriaCategory,
    Gender,
    EyeColour,
    HairColour,
    Mpeg4FeaturePoint,
    AnthropometricLandmarkName,
    AnthropometricLandmarkPointName,
    AnthropometricLandmarkPointId,
    CaptureDeviceTechnology2D,
    FaceImageKind2D,
    LossyTransformationAttempts,
    ImageColourSpace,
}

/// <summary>See <see cref="ISO39794EncodingProfile"/>'s doc comment for why this exists.</summary>
internal static class ISO39794EncodingProfileExtensions
{
    internal static bool UsesExtensionBlockFallback(this ISO39794EncodingProfile profile, ChoiceType choiceType) =>
        profile == ISO39794EncodingProfile.Icao39794_5EmrtdV1;

    internal static void Validate(this ISO39794EncodingProfile profile, FaceImageDataBlock dataBlock)
    {
        if (profile != ISO39794EncodingProfile.Icao39794_5EmrtdV1)
        {
            return;
        }

        List<FaceImageRepresentationBlock>? representations = dataBlock.GetRepresentationBlocks();
        if (representations == null || representations.Count != 1)
        {
            throw new ArgumentException("ICAO ISO/IEC 39794-5 profile requires exactly one representation");
        }

        FaceImageRepresentationBlock representation = representations[0];
        if (representation == null || representation.GetImageRepresentation2DBlock() == null)
        {
            throw new ArgumentException("ICAO ISO/IEC 39794-5 profile requires a 2D face representation");
        }

        if (representation.GetPadDataBlocks() != null && representation.GetPadDataBlocks()!.Count > 1)
        {
            throw new ArgumentException("ICAO ISO/IEC 39794-5 profile permits at most one PAD data block");
        }

        FaceImageInformation2DBlock? information = representation.GetImageRepresentation2DBlock()!.GetImageInformation2DBlock();
        if (information == null)
        {
            throw new ArgumentException("ICAO ISO/IEC 39794-5 profile requires 2D image information");
        }

        FaceImageInformation2DBlock.ImageDataFormatCode format = information.GetImageDataFormatCode();
        if (format != FaceImageInformation2DBlock.ImageDataFormatCode.Jpeg
            && format != FaceImageInformation2DBlock.ImageDataFormatCode.Jpeg2000Lossy
            && format != FaceImageInformation2DBlock.ImageDataFormatCode.Jpeg2000Lossless)
        {
            throw new ArgumentException($"Image format is not permitted by the ICAO ISO/IEC 39794-5 profile: {format}");
        }

        FaceImageInformation2DBlock.FaceImageKind2DCode? kind = information.GetFaceImageKind2DCode();
        if (kind != null && kind != FaceImageInformation2DBlock.FaceImageKind2DCode.Mrtd)
        {
            throw new ArgumentException($"Face image kind is not permitted by the ICAO ISO/IEC 39794-5 profile: {kind}");
        }

        FaceImageIdentityMetadataBlock? identity = representation.GetIdentityMetadataBlock();
        if (identity != null && identity.GetGenderCode() == FaceImageIdentityMetadataBlock.GenderCode.Unknown)
        {
            throw new ArgumentException("UNKNOWN gender is not permitted by the ICAO ISO/IEC 39794-5 profile");
        }
    }
}
