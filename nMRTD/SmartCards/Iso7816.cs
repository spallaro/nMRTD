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
/// Port of <c>net.sf.scuba.smartcards.ISO7816</c>: ISO/IEC 7816-4 CLA/INS/SW constants used by JMRTD.
/// Plain constants holder, zero behavior, trivially AOT-safe.
/// </summary>
public static class Iso7816
{
    // CLA
    public const byte ClaIso7816 = 0x00;
    public const byte ClaCommandChaining = 0x10;

    // INS
    public const byte InsExternalAuthenticate = 0x82;
    public const byte InsGetChallenge = 0x84;
    public const byte InsGetResponse = 0xC0;
    public const byte InsInternalAuthenticate = 0x88;
    public const byte InsMse = 0x22;
    public const byte InsPso = 0x2A;
    public const byte InsReadBinary = 0xB0;
    public const byte InsReadBinary2 = 0xB1;
    public const byte InsSelectFile = 0xA4;

    // SW (16-bit status words, widened to int per CommandApdu/ResponseApdu.Sw)
    public const int SwNoError = 0x9000;
    public const int SwFileNotFound = 0x6A82;
    public const int SwEndOfFile = 0x6282;
    public const int SwWrongLength = 0x6700;
    public const int SwSecurityStatusNotSatisfied = 0x6982;
    public const int SwConditionsNotSatisfied = 0x6985;
    public const int SwCommandNotAllowed = 0x6986;
    public const int SwUnknown = 0x6F00;
}
