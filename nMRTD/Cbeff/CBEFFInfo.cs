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
/// Port of <c>org.jmrtd.cbeff.CBEFFInfo</c>: CBEFF according to ISO 19785-1 (version 2.0) and NISTIR
/// 6529-A (version 1.1). Java's version is a "constants interface" (it declares no abstract methods at
/// all) that <see cref="SimpleCBEFFInfo{B}"/> and <see cref="ComplexCBEFFInfo{R}"/> implement purely to
/// share a common, generically-typed supertype (so a list can hold a heterogeneous mix of simple and
/// complex sub-records) -- ported the same way here as an empty behavioral-contract interface holding
/// the biometric type/subtype constants. Kept as the bare Java name (no <c>I</c> prefix): this codebase
/// is inconsistent about the prefix across porting sessions, and <c>org.jmrtd.lds.CBEFFDataGroup</c> (an
/// earlier wave) already forward-references this type by its bare name, which settles it here.
/// </summary>
/// <typeparam name="R">the type of biometric data block referenced by this CBEFF info</typeparam>
public interface CBEFFInfo<R> where R : BiometricDataBlock
{
    /*
     * Biometric type value, based on
     * Section 5.2.1.5 and Table 4 in NISTIR-6529A,
     * Table C.2 in ISO/IEC 7816-11,
     * Section 6.5.6 of ISO/IEC 19785-1.
     */
    /// <summary>Biometric type value.</summary>
    public const int BIOMETRIC_TYPE_NO_INFORMATION_GIVEN = 0x000000;

    /// <summary>Biometric type value.</summary>
    public const int BIOMETRIC_TYPE_MULTIPLE_BIOMETRICS_USED = 0x000001;

    /// <summary>Biometric type value.</summary>
    public const int BIOMETRIC_TYPE_FACIAL_FEATURES = 0x000002;

    /// <summary>Biometric type value.</summary>
    public const int BIOMETRIC_TYPE_VOICE = 0x000004;

    /// <summary>Biometric type value.</summary>
    public const int BIOMETRIC_TYPE_FINGERPRINT = 0x000008;

    /// <summary>Biometric type value.</summary>
    public const int BIOMETRIC_TYPE_IRIS = 0x000010;

    /// <summary>Biometric type value.</summary>
    public const int BIOMETRIC_TYPE_RETINA = 0x000020;

    /// <summary>Biometric type value.</summary>
    public const int BIOMETRIC_TYPE_HAND_GEOMETRY = 0x000040;

    /// <summary>Biometric type value.</summary>
    public const int BIOMETRIC_TYPE_SIGNATURE_DYNAMICS = 0x000080;

    /// <summary>Biometric type value.</summary>
    public const int BIOMETRIC_TYPE_KEYSTROKE_DYNAMICS = 0x000100;

    /// <summary>Biometric type value.</summary>
    public const int BIOMETRIC_TYPE_LIP_MOVEMENT = 0x000200;

    /// <summary>Biometric type value.</summary>
    public const int BIOMETRIC_TYPE_THERMAL_FACE_IMAGE = 0x000400;

    /// <summary>Biometric type value.</summary>
    public const int BIOMETRIC_TYPE_THERMAL_HAND_IMAGE = 0x000800;

    /// <summary>Biometric type value.</summary>
    public const int BIOMETRIC_TYPE_GAIT = 0x001000;

    /// <summary>Biometric type value.</summary>
    public const int BIOMETRIC_TYPE_BODY_ODOR = 0x002000;

    /// <summary>Biometric type value.</summary>
    public const int BIOMETRIC_TYPE_DNA = 0x004000;

    /// <summary>Biometric type value.</summary>
    public const int BIOMETRIC_TYPE_EAR_SHAPE = 0x008000;

    /// <summary>Biometric type value.</summary>
    public const int BIOMETRIC_TYPE_FINGER_GEOMETRY = 0x010000;

    /// <summary>Biometric type value.</summary>
    public const int BIOMETRIC_TYPE_PALM_PRINT = 0x020000;

    /// <summary>Biometric type value.</summary>
    public const int BIOMETRIC_TYPE_VEIN_PATTERN = 0x040000;

    /// <summary>Biometric type value.</summary>
    public const int BIOMETRIC_TYPE_FOOT_PRINT = 0x080000;

    /*
     * Biometric subtype, based on
     * Section 5.1.2.6 and Table 6 in NISTIR-6529A,
     * Table C.3 in ISO/IEC 7816-11,
     * Section 6.5.7 of ISO/IEC 19785-1.
     */
    /// <summary>Biometric subtype.</summary>
    public const int BIOMETRIC_SUBTYPE_NONE = 0x00; /* 00000000 */

    /// <summary>Biometric subtype.</summary>
    public const int BIOMETRIC_SUBTYPE_MASK_RIGHT = 0x01; /* xxxxxx01 */

    /// <summary>Biometric subtype.</summary>
    public const int BIOMETRIC_SUBTYPE_MASK_LEFT = 0x02; /* xxxxxx10 */

    /// <summary>Biometric subtype.</summary>
    public const int BIOMETRIC_SUBTYPE_MASK_THUMB = 0x04; /* xxx001xx */

    /// <summary>Biometric subtype.</summary>
    public const int BIOMETRIC_SUBTYPE_MASK_POINTER_FINGER = 0x08; /* xxx010xx */

    /// <summary>Biometric subtype.</summary>
    public const int BIOMETRIC_SUBTYPE_MASK_MIDDLE_FINGER = 0x0C; /* xxx011xx */

    /// <summary>Biometric subtype.</summary>
    public const int BIOMETRIC_SUBTYPE_MASK_RING_FINGER = 0x10; /* xxx100xx */

    /// <summary>Biometric subtype.</summary>
    public const int BIOMETRIC_SUBTYPE_MASK_LITTLE_FINGER = 0x14; /* xxx101xx */
}
