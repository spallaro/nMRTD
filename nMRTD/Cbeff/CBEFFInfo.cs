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
#if !NETFRAMEWORK
    // The constants are in CBEFFBiometricTypes: .NET Framework does not allow static members in interfaces.
    // These forwarders keep existing code compiling on the other targets.

    /// <summary>Biometric type value.</summary>
    [Obsolete("Use CBEFFBiometricTypes.BIOMETRIC_TYPE_NO_INFORMATION_GIVEN.")]
    public const int BIOMETRIC_TYPE_NO_INFORMATION_GIVEN = CBEFFBiometricTypes.BIOMETRIC_TYPE_NO_INFORMATION_GIVEN;

    /// <summary>Biometric type value.</summary>
    [Obsolete("Use CBEFFBiometricTypes.BIOMETRIC_TYPE_MULTIPLE_BIOMETRICS_USED.")]
    public const int BIOMETRIC_TYPE_MULTIPLE_BIOMETRICS_USED = CBEFFBiometricTypes.BIOMETRIC_TYPE_MULTIPLE_BIOMETRICS_USED;

    /// <summary>Biometric type value.</summary>
    [Obsolete("Use CBEFFBiometricTypes.BIOMETRIC_TYPE_FACIAL_FEATURES.")]
    public const int BIOMETRIC_TYPE_FACIAL_FEATURES = CBEFFBiometricTypes.BIOMETRIC_TYPE_FACIAL_FEATURES;

    /// <summary>Biometric type value.</summary>
    [Obsolete("Use CBEFFBiometricTypes.BIOMETRIC_TYPE_VOICE.")]
    public const int BIOMETRIC_TYPE_VOICE = CBEFFBiometricTypes.BIOMETRIC_TYPE_VOICE;

    /// <summary>Biometric type value.</summary>
    [Obsolete("Use CBEFFBiometricTypes.BIOMETRIC_TYPE_FINGERPRINT.")]
    public const int BIOMETRIC_TYPE_FINGERPRINT = CBEFFBiometricTypes.BIOMETRIC_TYPE_FINGERPRINT;

    /// <summary>Biometric type value.</summary>
    [Obsolete("Use CBEFFBiometricTypes.BIOMETRIC_TYPE_IRIS.")]
    public const int BIOMETRIC_TYPE_IRIS = CBEFFBiometricTypes.BIOMETRIC_TYPE_IRIS;

    /// <summary>Biometric type value.</summary>
    [Obsolete("Use CBEFFBiometricTypes.BIOMETRIC_TYPE_RETINA.")]
    public const int BIOMETRIC_TYPE_RETINA = CBEFFBiometricTypes.BIOMETRIC_TYPE_RETINA;

    /// <summary>Biometric type value.</summary>
    [Obsolete("Use CBEFFBiometricTypes.BIOMETRIC_TYPE_HAND_GEOMETRY.")]
    public const int BIOMETRIC_TYPE_HAND_GEOMETRY = CBEFFBiometricTypes.BIOMETRIC_TYPE_HAND_GEOMETRY;

    /// <summary>Biometric type value.</summary>
    [Obsolete("Use CBEFFBiometricTypes.BIOMETRIC_TYPE_SIGNATURE_DYNAMICS.")]
    public const int BIOMETRIC_TYPE_SIGNATURE_DYNAMICS = CBEFFBiometricTypes.BIOMETRIC_TYPE_SIGNATURE_DYNAMICS;

    /// <summary>Biometric type value.</summary>
    [Obsolete("Use CBEFFBiometricTypes.BIOMETRIC_TYPE_KEYSTROKE_DYNAMICS.")]
    public const int BIOMETRIC_TYPE_KEYSTROKE_DYNAMICS = CBEFFBiometricTypes.BIOMETRIC_TYPE_KEYSTROKE_DYNAMICS;

    /// <summary>Biometric type value.</summary>
    [Obsolete("Use CBEFFBiometricTypes.BIOMETRIC_TYPE_LIP_MOVEMENT.")]
    public const int BIOMETRIC_TYPE_LIP_MOVEMENT = CBEFFBiometricTypes.BIOMETRIC_TYPE_LIP_MOVEMENT;

    /// <summary>Biometric type value.</summary>
    [Obsolete("Use CBEFFBiometricTypes.BIOMETRIC_TYPE_THERMAL_FACE_IMAGE.")]
    public const int BIOMETRIC_TYPE_THERMAL_FACE_IMAGE = CBEFFBiometricTypes.BIOMETRIC_TYPE_THERMAL_FACE_IMAGE;

    /// <summary>Biometric type value.</summary>
    [Obsolete("Use CBEFFBiometricTypes.BIOMETRIC_TYPE_THERMAL_HAND_IMAGE.")]
    public const int BIOMETRIC_TYPE_THERMAL_HAND_IMAGE = CBEFFBiometricTypes.BIOMETRIC_TYPE_THERMAL_HAND_IMAGE;

    /// <summary>Biometric type value.</summary>
    [Obsolete("Use CBEFFBiometricTypes.BIOMETRIC_TYPE_GAIT.")]
    public const int BIOMETRIC_TYPE_GAIT = CBEFFBiometricTypes.BIOMETRIC_TYPE_GAIT;

    /// <summary>Biometric type value.</summary>
    [Obsolete("Use CBEFFBiometricTypes.BIOMETRIC_TYPE_BODY_ODOR.")]
    public const int BIOMETRIC_TYPE_BODY_ODOR = CBEFFBiometricTypes.BIOMETRIC_TYPE_BODY_ODOR;

    /// <summary>Biometric type value.</summary>
    [Obsolete("Use CBEFFBiometricTypes.BIOMETRIC_TYPE_DNA.")]
    public const int BIOMETRIC_TYPE_DNA = CBEFFBiometricTypes.BIOMETRIC_TYPE_DNA;

    /// <summary>Biometric type value.</summary>
    [Obsolete("Use CBEFFBiometricTypes.BIOMETRIC_TYPE_EAR_SHAPE.")]
    public const int BIOMETRIC_TYPE_EAR_SHAPE = CBEFFBiometricTypes.BIOMETRIC_TYPE_EAR_SHAPE;

    /// <summary>Biometric type value.</summary>
    [Obsolete("Use CBEFFBiometricTypes.BIOMETRIC_TYPE_FINGER_GEOMETRY.")]
    public const int BIOMETRIC_TYPE_FINGER_GEOMETRY = CBEFFBiometricTypes.BIOMETRIC_TYPE_FINGER_GEOMETRY;

    /// <summary>Biometric type value.</summary>
    [Obsolete("Use CBEFFBiometricTypes.BIOMETRIC_TYPE_PALM_PRINT.")]
    public const int BIOMETRIC_TYPE_PALM_PRINT = CBEFFBiometricTypes.BIOMETRIC_TYPE_PALM_PRINT;

    /// <summary>Biometric type value.</summary>
    [Obsolete("Use CBEFFBiometricTypes.BIOMETRIC_TYPE_VEIN_PATTERN.")]
    public const int BIOMETRIC_TYPE_VEIN_PATTERN = CBEFFBiometricTypes.BIOMETRIC_TYPE_VEIN_PATTERN;

    /// <summary>Biometric type value.</summary>
    [Obsolete("Use CBEFFBiometricTypes.BIOMETRIC_TYPE_FOOT_PRINT.")]
    public const int BIOMETRIC_TYPE_FOOT_PRINT = CBEFFBiometricTypes.BIOMETRIC_TYPE_FOOT_PRINT;

    /// <summary>Biometric subtype.</summary>
    [Obsolete("Use CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_NONE.")]
    public const int BIOMETRIC_SUBTYPE_NONE = CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_NONE;

    /// <summary>Biometric subtype.</summary>
    [Obsolete("Use CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_RIGHT.")]
    public const int BIOMETRIC_SUBTYPE_MASK_RIGHT = CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_RIGHT;

    /// <summary>Biometric subtype.</summary>
    [Obsolete("Use CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_LEFT.")]
    public const int BIOMETRIC_SUBTYPE_MASK_LEFT = CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_LEFT;

    /// <summary>Biometric subtype.</summary>
    [Obsolete("Use CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_THUMB.")]
    public const int BIOMETRIC_SUBTYPE_MASK_THUMB = CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_THUMB;

    /// <summary>Biometric subtype.</summary>
    [Obsolete("Use CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_POINTER_FINGER.")]
    public const int BIOMETRIC_SUBTYPE_MASK_POINTER_FINGER = CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_POINTER_FINGER;

    /// <summary>Biometric subtype.</summary>
    [Obsolete("Use CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_MIDDLE_FINGER.")]
    public const int BIOMETRIC_SUBTYPE_MASK_MIDDLE_FINGER = CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_MIDDLE_FINGER;

    /// <summary>Biometric subtype.</summary>
    [Obsolete("Use CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_RING_FINGER.")]
    public const int BIOMETRIC_SUBTYPE_MASK_RING_FINGER = CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_RING_FINGER;

    /// <summary>Biometric subtype.</summary>
    [Obsolete("Use CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_LITTLE_FINGER.")]
    public const int BIOMETRIC_SUBTYPE_MASK_LITTLE_FINGER = CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_LITTLE_FINGER;
#endif
}
