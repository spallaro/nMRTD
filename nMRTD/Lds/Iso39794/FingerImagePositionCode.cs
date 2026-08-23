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
/// Port of <c>org.jmrtd.lds.iso39794.FingerImagePositionCode</c>.
///
/// ADAPTATION: Java's version is <c>enum FingerImagePositionCode implements
/// EncodableEnum&lt;FingerImagePositionCode&gt;</c>, using reflection-based <c>EncodableEnum.fromCode</c>
/// lookup keyed on each constant's own <c>getCode()</c>. Ported as a plain enum with explicit numeric
/// values matching each Java constant's <c>getCode()</c> exactly (declaration order and code do NOT
/// coincide here -- the codes skip several values, e.g. 11/12/39/56-59); see
/// <c>ScoreOrError.ScoringErrorCode</c>'s doc comment for the fuller rationale and <see cref="FromCode"/>
/// for the shared "decode from code" replacement.
///
/// Java's version is a top-level <c>public enum</c>; ported as <c>internal</c> since it is only ever used
/// as a field type on other <c>internal</c> block types in this port (see <c>VersionBlock</c>'s doc
/// comment for why those are internal).
/// </summary>
internal enum FingerImagePositionCode
{
    UnknownPosition = 0,
    RightThumbFinger = 1,
    RightIndexFinger = 2,
    RightMiddleFinger = 3,
    RightRingFinger = 4,
    RightLittleFinger = 5,
    LeftThumbFinger = 6,
    LeftIndexFinger = 7,
    LeftMiddleFinger = 8,
    LeftRingFinger = 9,
    LeftLittleFinger = 10,
    RightFourFingers = 13,
    LeftFourFingers = 14,
    BothThumbFingers = 15,
    RightExtraDigitFinger = 16,
    LeftExtraDigitFinger = 17,
    UnknownFrictionRidge = 18,
    EntireJointImage = 19,
    UnknownPalm = 20,
    RightFullPalm = 21,
    RightWritersPalm = 22,
    RightLowerPalm = 23,
    RightUpperPalm = 24,
    RightOtherPalm = 25,
    RightInterdigital = 26,
    RightThenar = 27,
    RightHypothenar = 28,
    LeftFullPalm = 29,
    LeftWritersPalm = 30,
    LeftLowerPalm = 31,
    LeftUpperPalm = 32,
    LeftOtherPalm = 33,
    LeftInterdigital = 34,
    LeftThenar = 35,
    LeftHypothenar = 36,
    RightGrasp = 37,
    LeftGrasp = 38,
    RightIndexMiddleFingers = 40,
    RightMiddleRingFingers = 41,
    RightRingLittleFingers = 42,
    LeftIndexMiddleFingers = 43,
    LeftMiddleRingFingers = 44,
    LeftRingLittleFingers = 45,
    RightIndexLeftIndexFingers = 46,
    RightIndexMiddleRingFingers = 47,
    RightMiddleRingLittleFingers = 48,
    LeftIndexMiddleRingFingers = 49,
    LeftMiddleRingLittleFingers = 50,
    RightFourFingertips = 51,
    LeftFourFingertips = 52,
    RightFingertips = 53,
    LeftFingertips = 54,
    LeftMiddleIndexRightIndexMiddleFingers = 55,
    UnknownSole = 60,
    RightSole = 61,
    LeftSole = 62,
    UnknownToe = 63,
    RightBigToe = 64,
    RightSecondToe = 65,
    RightMiddleToe = 66,
    RightFourthToe = 67,
    RightLittleToe = 68,
    LeftBigToe = 69,
    LeftSecondToe = 70,
    LeftMiddleToe = 71,
    LeftFourthToe = 72,
    LeftLittleToe = 73,
    RightFrontBallFoot = 74,
    RightBackHeelFoot = 75,
    LeftFrontBallFoot = 76,
    LeftBackHeelFoot = 77,
    RightMiddleFoot = 78,
    LeftMiddleFoot = 79,
    RightCarpalDelta = 81,
    LeftCarpalDelta = 82,
    RightFullWithWriterPalm = 83,
    LeftFullWithWriterPalm = 84,
    RightBracelet = 85,
    LeftBracelet = 86,
    OtherPosition = 999,
}

/// <summary>See <see cref="FingerImagePositionCode"/>'s doc comment for why this exists.</summary>
internal static class FingerImagePositionCodeExtensions
{
    internal static FingerImagePositionCode? FromCode(int code) =>
        Enum.IsDefined(typeof(FingerImagePositionCode), code) ? (FingerImagePositionCode)code : null;
}
