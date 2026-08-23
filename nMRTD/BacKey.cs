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

using System.Globalization;

namespace nMRTD;

/// <summary>Port of <c>org.jmrtd.BACKey</c>: a BAC key.</summary>
public class BacKey : IBacKeySpec
{
    private const string DateFormat = "yyMMdd";

    private string _documentNumber = string.Empty;
    private string _dateOfBirth = string.Empty;
    private string _dateOfExpiry = string.Empty;

    /// <summary>Creates an empty BAC key entry.</summary>
    protected BacKey()
    {
    }

    /// <summary>Creates a BAC key.</summary>
    /// <param name="documentNumber">the document number string, without check digit, cannot be <c>null</c>, and may be shorter than 9</param>
    /// <param name="dateOfBirth">the date of birth, cannot be <c>null</c></param>
    /// <param name="dateOfExpiry">the date of expiry, cannot be <c>null</c></param>
    public BacKey(string documentNumber, DateTime dateOfBirth, DateTime dateOfExpiry)
        : this(documentNumber, ToDateString(dateOfBirth), ToDateString(dateOfExpiry))
    {
    }

    /// <summary>Creates a BAC key.</summary>
    /// <param name="documentNumber">the document number string, cannot be <c>null</c></param>
    /// <param name="dateOfBirth">the date of birth string in <c>yymmdd</c> format, cannot be <c>null</c></param>
    /// <param name="dateOfExpiry">the date of expiry string in <c>yymmdd</c> format, cannot be <c>null</c></param>
    public BacKey(string documentNumber, string dateOfBirth, string dateOfExpiry)
    {
        ArgumentNullException.ThrowIfNull(documentNumber);
        if (dateOfBirth is null || dateOfBirth.Length != 6)
        {
            throw new ArgumentException($"Illegal date: {dateOfBirth}");
        }

        if (dateOfExpiry is null || dateOfExpiry.Length != 6)
        {
            throw new ArgumentException($"Illegal date: {dateOfExpiry}");
        }

        _documentNumber = documentNumber.PadRight(9, '<').Trim();
        _dateOfBirth = dateOfBirth;
        _dateOfExpiry = dateOfExpiry;
    }

    /// <summary>Returns the document number string.</summary>
    /// <returns>the document number string</returns>
    public string GetDocumentNumber() => _documentNumber;

    /// <summary>Returns the date of birth string.</summary>
    /// <returns>a date in <c>yymmdd</c> format</returns>
    public string GetDateOfBirth() => _dateOfBirth;

    /// <summary>Returns the date of expiry string.</summary>
    /// <returns>a date in <c>yymmdd</c> format</returns>
    public string GetDateOfExpiry() => _dateOfExpiry;

    /// <summary>Returns a textual representation of this BAC key.</summary>
    /// <returns>a textual representation of this BAC key</returns>
    public override string ToString() => $"{_documentNumber}, {_dateOfBirth}, {_dateOfExpiry}";

    /// <summary>
    /// Computes the hash code of this BAC key. Document number, date of birth, and date of expiry (with
    /// year in <c>yy</c> precision) are taken into account.
    /// </summary>
    /// <returns>a hash code</returns>
    public override int GetHashCode()
    {
        int result = 5;
        result = (61 * result) + _documentNumber.GetHashCode();
        result = (61 * result) + _dateOfBirth.GetHashCode();
        result = (61 * result) + _dateOfExpiry.GetHashCode();
        return result;
    }

    /// <summary>Tests equality of this BAC key with respect to another object.</summary>
    /// <param name="obj">another object</param>
    /// <returns>whether this BAC key equals another object</returns>
    public override bool Equals(object? obj)
    {
        if (obj is null)
        {
            return false;
        }

        if (obj.GetType() != GetType())
        {
            return false;
        }

        if (ReferenceEquals(obj, this))
        {
            return true;
        }

        BacKey previous = (BacKey)obj;
        return _documentNumber.Equals(previous._documentNumber, StringComparison.Ordinal)
            && _dateOfBirth.Equals(previous._dateOfBirth, StringComparison.Ordinal)
            && _dateOfExpiry.Equals(previous._dateOfExpiry, StringComparison.Ordinal);
    }

    /// <summary>The algorithm of this key specification.</summary>
    /// <returns>constant "BAC"</returns>
    public string GetAlgorithm() => "BAC";

    /// <summary>Returns the encoded key (key seed) for use in key derivation.</summary>
    /// <returns>the encoded key</returns>
    public byte[] GetKey()
    {
        try
        {
            return Util.ComputeKeySeed(_documentNumber, _dateOfBirth, _dateOfExpiry, "SHA-1", true);
        }
        catch (Exception ex)
        {
            throw new ArgumentException("Unexpected exception", ex);
        }
    }

    /// <summary>Sets the document number.</summary>
    /// <param name="documentNumber">the document number to set</param>
    protected void SetDocumentNumber(string documentNumber) => _documentNumber = documentNumber;

    /// <summary>Sets the date of birth.</summary>
    /// <param name="dateOfBirth">the date of birth to set</param>
    protected void SetDateOfBirth(string dateOfBirth) => _dateOfBirth = dateOfBirth;

    /// <summary>Sets the date of expiry.</summary>
    /// <param name="dateOfExpiry">the date of expiry to set</param>
    protected void SetDateOfExpiry(string dateOfExpiry) => _dateOfExpiry = dateOfExpiry;

    /// <summary>Renders a date as a string.</summary>
    /// <param name="date">the date</param>
    /// <returns>a string representing the given date</returns>
    private static string ToDateString(DateTime date) => date.ToString(DateFormat, CultureInfo.InvariantCulture);
}
