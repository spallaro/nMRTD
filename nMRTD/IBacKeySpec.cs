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

namespace nMRTD;

/// <summary>Port of <c>org.jmrtd.BACKeySpec</c>: a BAC key.</summary>
public interface IBacKeySpec : IAccessKeySpec
{
    /// <summary>
    /// Returns the document number. This does not include a check digit. The result may include filler
    /// characters to make sure the resulting length is at least 9.
    /// </summary>
    /// <returns>the document number</returns>
    string GetDocumentNumber();

    /// <summary>Returns the date of birth string.</summary>
    /// <returns>a <c>yymmdd</c> string</returns>
    string GetDateOfBirth();

    /// <summary>Returns the date of expiry string.</summary>
    /// <returns>a <c>yymmdd</c> string</returns>
    string GetDateOfExpiry();
}
