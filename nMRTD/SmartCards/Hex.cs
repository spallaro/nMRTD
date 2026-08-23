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
/// Port of <c>net.sf.scuba.util.Hex</c>. Uppercase, no separators, matching common ICAO tooling
/// conventions. <see cref="Convert.FromHexString(string)"/> already rejects odd-length input and
/// non-hex-digit characters with a <see cref="FormatException"/>, giving <see cref="DecodeStrict"/>
/// the required strict behavior for free.
/// </summary>
public static class Hex
{
    public static string BytesToHexString(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        return Convert.ToHexString(bytes);
    }

    public static byte[] DecodeStrict(string hex)
    {
        ArgumentNullException.ThrowIfNull(hex);
        return Convert.FromHexString(hex);
    }
}
