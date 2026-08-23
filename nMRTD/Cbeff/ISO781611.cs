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
/// Port of <c>org.jmrtd.cbeff.ISO781611</c>: constants representing ISO7816-11. Java's version is a
/// "constants interface" (declares no abstract methods, only <c>static final int</c> fields) that
/// <see cref="ISO781611Encoder{B}"/> and <see cref="ISO781611Decoder{B}"/> implement purely to bring the
/// constants into scope unqualified. C# has no equivalent "implement an interface just for its constants"
/// idiom, so this is ported as a plain static constants holder (same pattern as
/// <c>nMRTD.SmartCards.Iso7816</c>) referenced via <c>ISO781611.SOME_TAG</c> at call sites, rather than as
/// an interface. Constant names are kept identical to the Java source (matching this port's convention for
/// the sibling <see cref="CBEFFInfo{R}"/> and <see cref="StandardBiometricHeader"/> constants) rather than
/// renamed to PascalCase, for cross-reference traceability with JMRTD/ISO 7816-11/CBEFF spec text.
/// </summary>
public static class ISO781611
{
    public const int BIOMETRIC_INFORMATION_GROUP_TEMPLATE_TAG = 0x7F61;
    public const int BIOMETRIC_INFORMATION_TEMPLATE_TAG = 0x7F60;

    public const int BIOMETRIC_INFO_COUNT_TAG = 0x02;
    public const int BIOMETRIC_HEADER_TEMPLATE_BASE_TAG = 0xA1;
    public const int BIOMETRIC_DATA_BLOCK_TAG = 0x5F2E;
    public const int BIOMETRIC_DATA_BLOCK_CONSTRUCTED_TAG = 0x7F2E;

    public const int DISCRETIONARY_DATA_FOR_PAYLOAD_TAG = 0x53;
    public const int DISCRETIONARY_DATA_FOR_PAYLOAD_CONSTRUCTED_TAG = 0x73;

    /*
     * FIXME: For 7F2E check ISO7816-11, Table 3: a 7F2E structure appears to include a 5F2E structure?
     * Difference between primitive/constructed.
     */

    /// <summary>From ISO7816-11: Secure Messaging Template tag.</summary>
    public const int SMT_TAG = 0x7D;

    /// <summary>From ISO7816-11: Secure Messaging Template tag.</summary>
    public const int SMT_DO_PV = 0x81;

    /// <summary>From ISO7816-11: Secure Messaging Template tag.</summary>
    public const int SMT_DO_CG = 0x85;

    /// <summary>From ISO7816-11: Secure Messaging Template tag.</summary>
    public const int SMT_DO_CC = 0x8E;

    /// <summary>From ISO7816-11: Secure Messaging Template tag.</summary>
    public const int SMT_DO_DS = 0x9E;

    /// <summary>ISO 7816-11, table C.1., used inside the BHT. Length 2.</summary>
    public const int PATRON_HEADER_VERSION_TAG = 0x80;

    /// <summary>Biometric Type tag, ISO7816-11.</summary>
    public const int BIOMETRIC_TYPE_TAG = 0x81;

    /// <summary>Biometric Subtype tag, ISO7816-11.</summary>
    public const int BIOMETRIC_SUBTYPE_TAG = 0x82;

    /// <summary>
    /// ISO7816-11 table C.1, (7), creation date and time of biometric data (CCYYMMDDhhmmss), used inside
    /// the BHT. Length 2.
    /// </summary>
    public const int CREATION_DATE_AND_TIME_TAG = 0x83;

    /// <summary>
    /// ISO7816-11 table C.1, (8), validity period (from CCYYMMDD, to CCYYMMDD), used inside the BHT.
    /// Length 2.
    /// </summary>
    public const int VALIDITY_PERIOD_TAG = 0x85;

    /// <summary>
    /// ISO7816-11 table C.1, (2), Identifier of product (PID) that created the biometric reference data,
    /// value assigned by IBIA. Length 2.
    /// </summary>
    public const int CREATOR_OF_BIOMETRIC_REFERENCE_DATA = 0x86;

    /// <summary>
    /// ID of the Group or Vendor which defined the BDB, specified in NISTIR-6529A and/or ISO7817-11.
    /// Length 2.
    /// </summary>
    public const int FORMAT_OWNER_TAG = 0x87;

    /// <summary>
    /// BDB Format Type as specified by the Format Owner, specified in NISTIR-6529A and/or ISO7816-11.
    /// Length 2.
    /// </summary>
    public const int FORMAT_TYPE_TAG = 0x88;
}
