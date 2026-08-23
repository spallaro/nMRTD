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

namespace nMRTD.SmartCards;

/// <summary>
/// Port of <c>net.sf.scuba.data.Gender</c>. Originally used by MRZ parsing to map the MRZ sex character
/// (<c>M</c>/<c>F</c>/<c>&lt;</c> or <c>X</c>) to a value (only <see cref="Male"/>, <see cref="Female"/>,
/// <see cref="Unknown"/> needed there). <see cref="Unspecified"/> was added when porting
/// <c>org.jmrtd.lds.iso19794.FaceImageInfo</c>, which also references <c>Gender.UNSPECIFIED</c> (ISO/IEC
/// 19794-5 Section 5.5.3 has a distinct "unspecified" gender code, 0x00, separate from "unknown", 0xFF).
/// Real scuba's <c>Gender.getInstance(int)</c>/<c>toInt()</c> round-trip methods are not ported onto this
/// enum itself (scuba source is not vendored in this repo to port them faithfully from); the ISO 19794-5
/// int-code mapping FaceImageInfo needs is instead a small private helper local to that file, scoped to
/// that one spec's code values rather than asserted as this enum's general contract.
/// </summary>
public enum Gender
{
    Male,
    Female,
    Unknown,
    Unspecified
}
