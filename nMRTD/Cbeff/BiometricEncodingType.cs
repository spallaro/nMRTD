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

namespace nMRTD.Cbeff;

/// <summary>
/// Port of <c>org.jmrtd.cbeff.BiometricEncodingType</c>: specifies what encoding (ISO/IEC-19794 or
/// ISO/IEC-39794) was used for biometric data blocks.
/// </summary>
public enum BiometricEncodingType
{
    /// <summary>Unknown encoding.</summary>
    Unknown,

    /// <summary>Uses ISO-19794 records BDB.</summary>
    Iso19794,

    /// <summary>Uses ISO-39794 records BDB.</summary>
    Iso39794,
}

/// <summary>
/// Port of the static <c>fromBDBTag</c>/<c>toBDBTag</c> methods of Java's
/// <c>org.jmrtd.cbeff.BiometricEncodingType</c> enum. C# enums cannot carry methods, so these live in a
/// companion static class here, matching this port's established pattern for Java enums with associated
/// logic (see e.g. <c>PACEInfo.ToMappingType</c> for its nested <c>MappingType</c> enum).
/// </summary>
public static class BiometricEncodingTypeCodec
{
    /// <summary>Maps tag to encoding type.</summary>
    /// <param name="bioDataBlockTag">either <c>0x5F2E</c> or <c>0x7F2E</c></param>
    /// <returns>the corresponding type</returns>
    public static BiometricEncodingType FromBDBTag(int bioDataBlockTag)
    {
        return bioDataBlockTag switch
        {
            ISO781611.BIOMETRIC_DATA_BLOCK_TAG => BiometricEncodingType.Iso19794,
            ISO781611.BIOMETRIC_DATA_BLOCK_CONSTRUCTED_TAG => BiometricEncodingType.Iso39794,
            _ => BiometricEncodingType.Unknown,
        };
    }

    /// <summary>Maps encoding type to tag. Defaults to ISO-19794 (<c>0x5F2E</c>).</summary>
    /// <param name="encodingType">one of the enum values</param>
    /// <returns>either <c>0x5F2E</c> or <c>0x7F2E</c></returns>
    public static int ToBDBTag(BiometricEncodingType encodingType)
    {
        return encodingType switch
        {
            BiometricEncodingType.Iso39794 => ISO781611.BIOMETRIC_DATA_BLOCK_CONSTRUCTED_TAG,
            /* Iso19794 falls through to the default, same as the Java switch. */
            _ => ISO781611.BIOMETRIC_DATA_BLOCK_TAG,
        };
    }
}
