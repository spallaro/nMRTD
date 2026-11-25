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

using System.Text;
using nMRTD.Lds;
using nMRTD.SmartCards;

namespace nMRTD.Lds.Icao;

/// <summary>
/// Port of <c>org.jmrtd.lds.icao.MRZInfo</c>: the data structure for storing the MRZ information as
/// found in DG1. Based on ICAO Doc 9303 (Seventh edition) part 4 (TD3), part 5 (TD1), part 6 (TD2), and
/// part 7 (MRV-A, MRV-B).
///
/// Security note: <see cref="CheckDigit(string)"/> implements the ICAO 9303 7-3-1 check-digit algorithm
/// exactly as JMRTD does -- this is also the algorithm used to derive the BAC key seed
/// (<c>org.jmrtd.Util.computeKeySeed</c>), so it must be ported byte-for-byte, including the
/// '&lt;'-over-'0' quirk for the (TD3-only) personal-number check digit.
///
/// NOTE on dates: this class stores <c>dateOfBirth</c>/<c>dateOfExpiry</c> purely as raw 6-character
/// "yyMMdd" strings, exactly as read from the MRZ. The Java source (verified line by line) contains no
/// century-inference logic anywhere in this class -- <c>readDate</c> is a plain fixed-length string
/// read, and there is no conversion to <c>java.util.Date</c>. Any century inference in JMRTD happens
/// elsewhere (if at all), not here.
///
/// NOTE on Country: contrary to what one might expect, this class does not use
/// <c>net.sf.scuba.data.Country</c>/<see cref="nMRTD.SmartCards.Country"/> anywhere -- issuing state and
/// nationality are stored as plain 3-letter MRZ strings. Only <c>net.sf.scuba.data.Gender</c> /
/// <see cref="nMRTD.SmartCards.Gender"/> is used, in the two deprecated legacy constructors.
/// </summary>
public class MRZInfo : AbstractLDSInfo
{
    /// <summary>
    /// The type of document (MRZ), determining the number of lines, number of characters per line, and
    /// positions and lengths of fields, and check-digits.
    /// </summary>
    private enum DocumentType
    {
        /// <summary>Unspecified document type (do not use, choose ID1 or ID3).</summary>
        Unknown,

        /// <summary>MROTD 3 lines of 30 characters, as per part 5.</summary>
        Td1,

        /// <summary>MROTD 2 lines of 36 characters, as per part 6.</summary>
        Td2,

        /// <summary>MRP 2 lines of 44 characters, as per part 4.</summary>
        Td3,

        /// <summary>MRV type A.</summary>
        Mrva,

        /// <summary>MRV type B.</summary>
        Mrvb,
    }

    /// <summary>Unspecified document type (do not use, choose ID1 or ID3).</summary>
    public const int DOC_TYPE_UNSPECIFIED = 0;

    /// <summary>ID1 document type for credit card sized identity cards. Specifies a 3-line MRZ, 30 characters wide.</summary>
    public const int DOC_TYPE_ID1 = 1;

    /// <summary>ID2 document type. Specifies a 2-line MRZ, 36 characters wide.</summary>
    public const int DOC_TYPE_ID2 = 2;

    /// <summary>ID3 document type for passport booklets. Specifies a 2-line MRZ, 44 characters wide.</summary>
    public const int DOC_TYPE_ID3 = 3;

    /// <summary>All valid characters in MRZ.</summary>
    private const string MRZ_CHARS = "<0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    private DocumentType documentType;
    private string documentCode = null!;
    private string issuingState = null!;
    private string primaryIdentifier = null!;
    private string secondaryIdentifier = null!;
    private string nationality = null!;
    private string documentNumber = null!;
    private string dateOfBirth = null!;
    private string gender = null!;
    private string dateOfExpiry = null!;
    private char documentNumberCheckDigit;
    private char dateOfBirthCheckDigit;
    private char dateOfExpiryCheckDigit;

    /// <summary>Over optionalData1, but only for TD3. When empty we prefer '&lt;' over '0'.</summary>
    private char personalNumberCheckDigit;
    private char compositeCheckDigit;

    /// <summary>
    /// For TD1 holds personal number for some issuing states (e.g. NL), but is used to hold (part of)
    /// document number for others.
    /// </summary>
    private string optionalData1 = null!;
    private string? optionalData2;

    /// <summary>Creates a new 3-line, 30 character (TD1) MRZ compliant with ICAO Doc 9303 (seventh edition) part 5.</summary>
    public static MRZInfo CreateTD1MRZInfo(
        string documentCode,
        string issuingState,
        string documentNumber,
        string? optionalData1,
        string dateOfBirth,
        object gender,
        string dateOfExpiry,
        string nationality,
        string? optionalData2,
        string primaryIdentifier,
        string secondaryIdentifier)
    {
        return new MRZInfo(DocumentType.Td1,
            documentCode,
            issuingState,
            documentNumber,
            optionalData1,
            dateOfBirth,
            gender,
            dateOfExpiry,
            nationality,
            optionalData2,
            primaryIdentifier,
            secondaryIdentifier);
    }

    /// <summary>Creates a new 2-line, 36 character (TD2) MRZ compliant with ICAO Doc 9303 (seventh edition) part 6.</summary>
    public static MRZInfo CreateTD2MRZInfo(string documentCode, string issuingState,
        string primaryIdentifier, string secondaryIdentifier,
        string documentNumber, string nationality, string dateOfBirth,
        object gender, string dateOfExpiry, string? optionalData)
    {
        return new MRZInfo(DocumentType.Td2,
            documentCode,
            issuingState,
            documentNumber,
            optionalData,
            dateOfBirth,
            gender,
            dateOfExpiry,
            nationality,
            null,
            primaryIdentifier,
            secondaryIdentifier);
    }

    /// <summary>Creates a new 2-line, 44 character (TD3) MRZ compliant with ICAO Doc 9303 (seventh edition) part 4.</summary>
    public static MRZInfo CreateTD3MRZInfo(string documentCode, string issuingState,
        string primaryIdentifier, string secondaryIdentifier,
        string documentNumber, string nationality, string dateOfBirth,
        object gender, string dateOfExpiry, string? personalNumber)
    {
        return new MRZInfo(DocumentType.Td3,
            documentCode,
            issuingState,
            documentNumber,
            PersonalNumberToOptionalData(personalNumber),
            dateOfBirth,
            gender,
            dateOfExpiry,
            nationality,
            null,
            primaryIdentifier,
            secondaryIdentifier);
    }

    /// <summary>Creates a new 2-line, 44 character (MRV-A) MRZ compliant with ICAO Doc 9303 (seventh edition) part 7.</summary>
    public static MRZInfo CreateMRVAMRZInfo(string documentCode, string issuingState,
        string primaryIdentifier, string secondaryIdentifier,
        string documentNumber, string nationality, string dateOfBirth,
        object gender, string dateOfExpiry, string? optionalData)
    {
        return new MRZInfo(DocumentType.Mrva,
            documentCode,
            issuingState,
            documentNumber,
            optionalData,
            dateOfBirth,
            gender,
            dateOfExpiry,
            nationality,
            null,
            primaryIdentifier,
            secondaryIdentifier);
    }

    /// <summary>Creates a new 2-line, 36 character (MRV-B) MRZ compliant with ICAO Doc 9303 (seventh edition) part 7.</summary>
    public static MRZInfo CreateMRVBMRZInfo(string documentCode, string issuingState,
        string primaryIdentifier, string secondaryIdentifier,
        string documentNumber, string nationality, string dateOfBirth,
        object gender, string dateOfExpiry, string? optionalData)
    {
        return new MRZInfo(DocumentType.Mrvb,
            documentCode,
            issuingState,
            documentNumber,
            optionalData,
            dateOfBirth,
            gender,
            dateOfExpiry,
            nationality,
            null,
            primaryIdentifier,
            secondaryIdentifier);
    }

    /// <summary>Creates a new 2-line MRZ compliant with ICAO Doc 9303 (pre-seventh edition) part 1 vol 1.</summary>
    [Obsolete("Use the corresponding factory method CreateTD3MRZInfo instead.")]
    public MRZInfo(string documentCode, string issuingState,
        string primaryIdentifier, string secondaryIdentifier,
        string documentNumber, string nationality, string dateOfBirth,
        Gender gender, string dateOfExpiry, string? personalNumber)
        : this(GetDocumentTypeFromDocumentCode(documentCode),
            documentCode,
            issuingState,
            documentNumber,
            PersonalNumberToOptionalData(personalNumber),
            dateOfBirth,
            gender,
            dateOfExpiry,
            nationality,
            null,
            primaryIdentifier,
            secondaryIdentifier)
    {
    }

    /// <summary>Creates a new 3-line MRZ compliant with ICAO Doc 9303 (pre-seventh edition) part 3 vol 1.</summary>
    [Obsolete("Use the corresponding factory method CreateTD1MRZInfo instead.")]
    public MRZInfo(string documentCode,
        string issuingState,
        string documentNumber,
        string? optionalData1,
        string dateOfBirth,
        Gender gender,
        string dateOfExpiry,
        string nationality,
        string? optionalData2,
        string primaryIdentifier,
        string secondaryIdentifier)
        : this(GetDocumentTypeFromDocumentCode(documentCode),
            documentCode,
            issuingState,
            documentNumber,
            optionalData1,
            dateOfBirth,
            gender,
            dateOfExpiry,
            nationality,
            optionalData2,
            primaryIdentifier,
            secondaryIdentifier)
    {
    }

    /// <summary>
    /// Creates a new MRZ based on an input stream.
    /// </summary>
    /// <param name="inputStream">contains the contents (value) of DG1 (without the tag and length)</param>
    /// <param name="length">the length of the MRZInfo structure</param>
    public MRZInfo(Stream inputStream, int length)
    {
        try
        {
            ReadObject(inputStream, length);
        }
        catch (IOException ioe)
        {
            throw new ArgumentException("Error reading MRZInfo from stream", ioe);
        }
    }

    /// <summary>
    /// Creates a new MRZ based on the text input. Whitespace in the text input (such as line breaks between the lines
    /// of the MRZ) is ignored. Apart from that, the text must consist of exactly 90 (TD1), 72 (TD2, MRV-B), or 88
    /// (TD3, MRV-A) MRZ characters (<c>A-Z</c>, <c>0-9</c>, and <c>&lt;</c>), as in JMRTD 0.8.10 (5ae69fae).
    /// </summary>
    /// <exception cref="ArgumentException">if the text is not a well-formed MRZ</exception>
    public MRZInfo(string str)
    {
        ArgumentNullException.ThrowIfNull(str);
        var stripped = new StringBuilder(str.Length);
        foreach (char c in str)
        {
            if (!char.IsWhiteSpace(c))
            {
                stripped.Append(c);
            }
        }
        str = stripped.ToString();
        int length = str.Length;
        if (length != 90 && length != 72 && length != 88)
        {
            throw new ArgumentException($"Was expecting 90, 72, or 88 MRZ characters, got {length}", nameof(str));
        }
        for (int i = 0; i < length; i++)
        {
            if (!MRZ_CHARS.Contains(str[i]))
            {
                throw new ArgumentException($"Illegal MRZ character at position {i}: 0x{(int)str[i]:x}", nameof(str));
            }
        }
        try
        {
            ReadObject(new MemoryStream(Encoding.UTF8.GetBytes(str), writable: false), str.Length);
        }
        catch (IOException ioe)
        {
            throw new ArgumentException("Exception", ioe);
        }
    }

    /// <summary>Constructs an MRZInfo object from components.</summary>
    private MRZInfo(DocumentType documentType,
        string documentCode,
        string issuingState,
        string documentNumber,
        string? optionalData1,
        string dateOfBirth,
        object genderObject,
        string dateOfExpiry,
        string nationality,
        string? optionalData2,
        string primaryIdentifier,
        string secondaryIdentifier)
    {
        this.documentType = documentType;

        if (!IsDocumentCodeConsistentWithDocumentType(documentType, documentCode))
        {
            throw new ArgumentException("Wrong document code");
        }

        if (!IsOptionalDataConsistentWithDocumentType(documentType, optionalData1, optionalData2))
        {
            throw new ArgumentException("Wrong optional data length");
        }

        ArgumentNullException.ThrowIfNull(genderObject);

        this.documentCode = TrimTrailingFillerChars(documentCode);
        this.issuingState = issuingState;
        this.primaryIdentifier = TrimTrailingFillerChars(primaryIdentifier).Replace("<", " ");
        this.secondaryIdentifier = TrimTrailingFillerChars(secondaryIdentifier).Replace("<", " ");
        this.documentNumber = TrimTrailingFillerChars(documentNumber);
        this.nationality = nationality;
        this.dateOfBirth = dateOfBirth;
        this.gender = GenderToString(genderObject);
        this.dateOfExpiry = dateOfExpiry;
        this.optionalData1 = optionalData1 == null ? "" : TrimTrailingFillerChars(optionalData1);
        this.optionalData2 = optionalData2 == null ? null : TrimTrailingFillerChars(optionalData2);
        UpdateCheckDigits();
    }

    /// <summary>Returns the date of birth of the passport holder.</summary>
    public string GetDateOfBirth() => dateOfBirth;

    /// <summary>Returns the date of expiry.</summary>
    public string GetDateOfExpiry() => dateOfExpiry;

    /// <summary>Returns the document number.</summary>
    public string GetDocumentNumber() => documentNumber;

    /// <summary>Returns the document type.</summary>
    [Obsolete("Clients should determine type based on GetDocumentCode()")]
    public int GetDocumentType() => documentType switch
    {
        DocumentType.Td1 => DOC_TYPE_ID1,
        DocumentType.Td2 => DOC_TYPE_ID2,
        DocumentType.Td3 => DOC_TYPE_ID3,
        DocumentType.Mrva => 4,
        DocumentType.Mrvb => 5,
        _ => DOC_TYPE_UNSPECIFIED,
    };

    /// <summary>Returns the document code.</summary>
    public string GetDocumentCode() => documentCode;

    /// <summary>Returns the issuing state as a 3 letter code.</summary>
    public string GetIssuingState() => MrzFormat(issuingState, 3);

    /// <summary>
    /// Returns the name of the holder (primary and secondary identifiers). Double filler separates
    /// primary from secondary identifiers. Single fillers separate components within identifiers.
    /// Trailing fillers are removed.
    /// </summary>
    public string GetNameOfHolder()
    {
        return documentType switch
        {
            DocumentType.Td1 => TrimTrailingFillerChars(NameToString(primaryIdentifier, secondaryIdentifier, 30)),
            DocumentType.Td2 or DocumentType.Mrvb => TrimTrailingFillerChars(NameToString(primaryIdentifier, secondaryIdentifier, 31)),
            DocumentType.Td3 or DocumentType.Mrva => TrimTrailingFillerChars(NameToString(primaryIdentifier, secondaryIdentifier, 39)),
            _ => throw new InvalidOperationException("Unsupported document type"),
        };
    }

    /// <summary>
    /// Returns the passport holder's primary identifier (last name). Trailing fillers will have been
    /// removed. Fillers (separating the components within this identifier) will have been replaced by spaces.
    /// </summary>
    public string GetPrimaryIdentifier() => primaryIdentifier;

    /// <summary>
    /// Returns the document holder's secondary identifier (first names). Trailing fillers will have been
    /// removed. Fillers (separating the components within this identifier) will have been replaced by spaces.
    /// </summary>
    public string GetSecondaryIdentifier() => secondaryIdentifier;

    /// <summary>Returns the document holder's first names.</summary>
    public string[] GetSecondaryIdentifierComponents() => secondaryIdentifier.Split([' ', '<']);

    /// <summary>Returns the passport holder's nationality as a 3 digit code.</summary>
    public string GetNationality() => MrzFormat(nationality, 3);

    /// <summary>Returns the personal number (if a personal number is encoded in optional data 1).</summary>
    public string? GetPersonalNumber()
    {
        if (optionalData1 == null)
        {
            return null;
        }
        if (optionalData1.Length > 14)
        {
            return TrimTrailingFillerChars(optionalData1.Substring(0, 14));
        }

        return TrimTrailingFillerChars(optionalData1);
    }

    /// <summary>Returns the passport holder's gender.</summary>
    [Obsolete("Result type will be changed to string in a future version. Use GetGenderCode() instead.")]
    public Gender GetGender() => StringToGender(gender);

    /// <summary>Returns the passport holder's gender.</summary>
    public Gender GetGenderCode() => StringToGender(gender);

    /// <summary>Returns the contents of the first optional data field for ID-1 and ID-3 style MRZs.</summary>
    public string GetOptionalData1() => optionalData1;

    /// <summary>Returns the contents of the second optional data field for ID-1 style MRZs.</summary>
    public string? GetOptionalData2() => optionalData2;

    /// <summary>
    /// Creates a textual representation of this MRZ. This is the 2 or 3 line representation (depending
    /// on the document type) as it appears in the document. All lines end in a newline char.
    /// </summary>
    public override string ToString()
    {
        string str = Encoding.UTF8.GetString(GetEncoded() ?? []);
        return str.Length switch
        {
            90 => str.Substring(0, 30) + "\n" + str.Substring(30, 30) + "\n" + str.Substring(60, 30) + "\n",
            72 => string.Concat(str.AsSpan(0, 36), "\n", str.AsSpan(36, 36), "\n"),
            88 => string.Concat(str.AsSpan(0, 44), "\n", str.AsSpan(44, 44), "\n"),
            _ => str,
        };
    }

    /// <summary>Returns the hash code for this MRZ info.</summary>
    public override int GetHashCode() => 2 * ToString().GetHashCode() + 53;

    /// <summary>Whether this MRZ info is identical to some other object.</summary>
    public override bool Equals(object? obj)
    {
        if (obj == null)
        {
            return false;
        }
        if (obj.GetType() != GetType())
        {
            return false;
        }

        MRZInfo other = (MRZInfo)obj;

        return EqualsModuloFillerChars(documentCode, other.documentCode)
            && EqualsModuloFillerChars(issuingState, other.issuingState)
            && EqualsModuloFillerChars(primaryIdentifier, other.primaryIdentifier)
            && EqualsModuloFillerChars(secondaryIdentifier, other.secondaryIdentifier)
            && EqualsModuloFillerChars(nationality, other.nationality)
            && EqualsModuloFillerChars(documentNumber, other.documentNumber)
            && (EqualsModuloFillerChars(optionalData1, other.optionalData1) || EqualsModuloFillerChars(GetPersonalNumber(), other.GetPersonalNumber()))
            && ((dateOfBirth == null && other.dateOfBirth == null) || (dateOfBirth != null && dateOfBirth.Equals(other.dateOfBirth)))
            && ((gender == null && other.gender == null) || (gender != null && gender.Equals(other.gender)))
            && ((dateOfExpiry == null && other.dateOfExpiry == null) || (dateOfExpiry != null && dateOfExpiry.Equals(other.dateOfExpiry)))
            && EqualsModuloFillerChars(optionalData2, other.optionalData2);
    }

    /// <summary>Computes the 7-3-1 check digit for part of the MRZ.</summary>
    /// <param name="str">a part of the MRZ.</param>
    /// <returns>the resulting check digit (in '0' - '9')</returns>
    public static char CheckDigit(string? str) => CheckDigit(str, false);

    /* ONLY PRIVATE METHODS BELOW */

    private void ReadObject(Stream inputStream, int length)
    {
        if (length != 90 && length != 72 && length != 88)
        {
            // JMRTD 0.8.10 (737881b8): any other length used to be read (as an MRZ of unknown type, reading beyond the
            // declared length) but could not be encoded again.
            throw new IOException($"Unsupported MRZ length {length}, was expecting 90, 72, or 88");
        }

        /* line 1, pos 1 to 2, Document code, all types. */
        documentCode = TrimTrailingFillerChars(ReadString(inputStream, 2));
        documentType = GetDocumentType(documentCode, length);
        switch (documentType)
        {
            case DocumentType.Td1:
                ReadObjectTD1(inputStream);
                break;
            case DocumentType.Td2:
            case DocumentType.Mrvb:
                ReadObjectTD2OrMRVB(inputStream);
                break;
            case DocumentType.Mrva:
            case DocumentType.Td3:
            default:
                /* Assume it's a ID3 document, i.e. 2-line MRZ. */
                ReadObjectTD3OrMRVA(inputStream);
                break;
        }
    }

    private void ReadObjectTD1(Stream inputStream)
    {
        /* line 1, pos 3 to 5 Issuing State or organization */
        issuingState = ReadCountryCode(inputStream);

        /* line 1, pos 6 to 14 Document number */
        documentNumber = ReadString(inputStream, 9);

        /* line 1, pos 15 Check digit */
        documentNumberCheckDigit = (char)ReadUnsignedByte(inputStream);

        /* line 1, pos 16 to 30, Optional data elements */
        string rawOptionalData1 = ReadString(inputStream, 15);
        optionalData1 = TrimTrailingFillerChars(rawOptionalData1);

        ReadDocumentNumberExtension();

        /* line 2, pos 1 to 6, Date of birth */
        dateOfBirth = ReadDate(inputStream);

        /* line 2, pos 7, Check digit */
        dateOfBirthCheckDigit = (char)ReadUnsignedByte(inputStream);

        /* line 2, pos 8, Sex */
        gender = ReadString(inputStream, 1);

        /* line 2, Pos 9 to 14, Date of expiry */
        dateOfExpiry = ReadDate(inputStream);

        /* line 2, pos 15, Check digit */
        dateOfExpiryCheckDigit = (char)ReadUnsignedByte(inputStream);

        /* line 2, pos 16 to 18, Nationality */
        nationality = ReadCountryCode(inputStream);

        /* line 2, pos 19 to 29, Optional data elements */
        optionalData2 = TrimTrailingFillerChars(ReadString(inputStream, 11));

        /* line 2, pos 30, Overall check digit */
        compositeCheckDigit = (char)ReadUnsignedByte(inputStream);

        /* line 3 */
        ReadNameIdentifiers(ReadString(inputStream, 30));
    }

    /// <summary>
    /// Interprets the start of optional data 1 as the remainder of the document number (TD1, TD2), if the document
    /// number check digit is a filler, see Doc 9303 part 5, note j. The extension consists of the remainder of the
    /// document number (at least one character) followed by the check digit, up to the first filler. Any optional
    /// data after that filler remains in optional data 1. If there is no such extension (for instance, if the
    /// optional data starts with a filler), the MRZ is malformed, and document number, check digit and optional data
    /// are left as read. The document number (as read, untrimmed) and optional data 1 (trimmed) should have been set.
    /// Trailing fillers of the resulting document number are removed. As in JMRTD 0.8.10 (5ae69fae).
    /// </summary>
    private void ReadDocumentNumberExtension()
    {
        int extendedDocumentNumberEnd = optionalData1!.IndexOf('<');
        if (extendedDocumentNumberEnd < 0)
        {
            extendedDocumentNumberEnd = optionalData1.Length;
        }
        if (documentNumberCheckDigit == '<' && extendedDocumentNumberEnd >= 2)
        {
            documentNumber += optionalData1.Substring(0, extendedDocumentNumberEnd - 1);
            documentNumberCheckDigit = optionalData1[extendedDocumentNumberEnd - 1];
            optionalData1 = optionalData1.Substring(Math.Min(extendedDocumentNumberEnd + 1, optionalData1.Length));
        }
        documentNumber = TrimTrailingFillerChars(documentNumber);
    }

    /// <summary>
    /// Returns the contents of the optional data field (TD1, TD2) for a document number of more than 9 characters,
    /// see Doc 9303 part 5, note j: the remainder of the document number, its check digit, and (separated by a
    /// filler) optional data 1, if any. Trailing fillers are not included. As in JMRTD 0.8.10 (5ae69fae).
    /// </summary>
    private string GetExtendedDocumentNumberOptionalData()
    {
        string extension = documentNumber.Substring(9) + documentNumberCheckDigit;
        if (optionalData1 == null || EqualsModuloFillerChars(optionalData1, ""))
        {
            return extension;
        }
        return extension + "<" + optionalData1;
    }

    private void ReadObjectTD2OrMRVB(Stream inputStream)
    {
        /* line 1, pos 3 to 5 */
        issuingState = ReadCountryCode(inputStream);

        /* line 1, pos 6 to 36 */
        ReadNameIdentifiers(ReadString(inputStream, 31));

        /* line 2, document number is trimmed below, after a possible extension (keeping the 9 principal characters intact) */
        documentNumber = ReadString(inputStream, 9);
        documentNumberCheckDigit = (char)ReadUnsignedByte(inputStream);
        nationality = ReadCountryCode(inputStream);
        dateOfBirth = ReadDate(inputStream);
        dateOfBirthCheckDigit = (char)ReadUnsignedByte(inputStream);
        gender = ReadString(inputStream, 1);
        dateOfExpiry = ReadDate(inputStream);
        dateOfExpiryCheckDigit = (char)ReadUnsignedByte(inputStream);
        if (documentType == DocumentType.Mrvb)
        {
            optionalData1 = TrimTrailingFillerChars(ReadString(inputStream, 8));
        }
        else if (documentType == DocumentType.Td2)
        {
            optionalData1 = TrimTrailingFillerChars(ReadString(inputStream, 7));
            ReadDocumentNumberExtension();
        }
        documentNumber = TrimTrailingFillerChars(documentNumber);

        if (documentType == DocumentType.Td2)
        {
            compositeCheckDigit = (char)ReadUnsignedByte(inputStream);
        }
    }

    private void ReadObjectTD3OrMRVA(Stream inputStream)
    {
        /* line 1, pos 3 to 5 */
        issuingState = ReadCountryCode(inputStream);

        /* line 1, pos 6 to 44 */
        ReadNameIdentifiers(ReadString(inputStream, 39));

        /* line 2 */
        documentNumber = TrimTrailingFillerChars(ReadString(inputStream, 9));
        documentNumberCheckDigit = (char)ReadUnsignedByte(inputStream);
        nationality = ReadCountryCode(inputStream);
        dateOfBirth = ReadDate(inputStream);
        dateOfBirthCheckDigit = (char)ReadUnsignedByte(inputStream);
        gender = ReadString(inputStream, 1);
        dateOfExpiry = ReadDate(inputStream);
        dateOfExpiryCheckDigit = (char)ReadUnsignedByte(inputStream);
        if (documentType == DocumentType.Mrva)
        {
            optionalData1 = TrimTrailingFillerChars(ReadString(inputStream, 16));
        }
        else
        {
            optionalData1 = TrimTrailingFillerChars(ReadString(inputStream, 14));
            personalNumberCheckDigit = (char)ReadUnsignedByte(inputStream);
            compositeCheckDigit = (char)ReadUnsignedByte(inputStream);
        }
    }

    /// <summary>Writes the MRZ to an output stream. This just outputs the MRZ characters, and does not add newlines.</summary>
    public override void WriteObject(Stream outputStream)
    {
        switch (documentType)
        {
            case DocumentType.Td1:
                WriteObjectTD1(outputStream);
                break;
            case DocumentType.Td2:
            case DocumentType.Mrvb:
                WriteObjectTD2OrMRVB(outputStream);
                break;
            case DocumentType.Td3:
            case DocumentType.Mrva:
                WriteObjectTD3OrMRVA(outputStream);
                break;
            default:
                throw new InvalidOperationException("Unsupported document type");
        }
    }

    /// <summary>Tests equality of two MRZ string while ignoring extra filler characters.</summary>
    public static bool EqualsModuloFillerChars(string? str1, string? str2)
    {
        if (ReferenceEquals(str1, str2))
        {
            return true;
        }
        str1 ??= "";
        str2 ??= "";

        int length = Math.Max(str1.Length, str2.Length);
        return MrzFormat(str1, length).Equals(MrzFormat(str2, length));
    }

    private void WriteObjectTD1(Stream outputStream)
    {
        /* top line */
        WriteDocumentType(outputStream);
        WriteCountryCode(issuingState, outputStream);

        bool isExtendedDocumentNumber = documentNumber.Length > 9;
        if (isExtendedDocumentNumber)
        {
            /*
             * If document number has more than 9 character, the 9 principal
             * character shall be shown in the MRZ in character positions 1 to 9.
             * They shall be followed by a filler character instead of a check
             * digit to indicate a truncated number. The remaining character of
             * the document number shall be shown at the beginning of the field
             * reserved of optional data element (character position 29 to 35 of
             * the lower machine readable line) followed by a check digit and a
             * filler character.
             *
             * Corresponds to Doc 9303 (pre-seventh edition) pt 3 vol 1 page V-10 (note j) (FIXED by Paulo Assumcao)
             *
             * Also see R3-p1_v2_sIV_0041 in Supplement to Doc 9303, release 11.
             */
            WriteString(documentNumber.Substring(0, 9), outputStream, 9);
            outputStream.WriteByte((byte)'<'); /* NOTE: instead of check digit */
            WriteString(GetExtendedDocumentNumberOptionalData(), outputStream, 15);
        }
        else
        {
            WriteString(documentNumber, outputStream, 9); /* FIXME: max size of field */
            outputStream.WriteByte((byte)documentNumberCheckDigit);
            WriteString(optionalData1 ?? "", outputStream, 15); /* FIXME: max size of field */
        }

        /* middle line */
        WriteDateOfBirth(outputStream);
        outputStream.WriteByte((byte)dateOfBirthCheckDigit);
        WriteGender(outputStream);
        WriteDateOfExpiry(outputStream);
        outputStream.WriteByte((byte)dateOfExpiryCheckDigit);
        WriteCountryCode(nationality, outputStream);
        WriteString(optionalData2 ?? "", outputStream, 11);
        outputStream.WriteByte((byte)compositeCheckDigit);

        /* bottom line */
        WriteName(outputStream, 30);
    }

    private void WriteObjectTD2OrMRVB(Stream outputStream)
    {
        /* top line */
        WriteDocumentType(outputStream);
        WriteCountryCode(issuingState, outputStream);
        WriteName(outputStream, 31);

        /* bottom line */

        bool isExtendedDocumentNumber = documentType == DocumentType.Td2 && documentNumber.Length > 9;
        if (isExtendedDocumentNumber)
        {
            WriteString(documentNumber.Substring(0, 9), outputStream, 9);
            outputStream.WriteByte((byte)'<'); /* NOTE: instead of check digit */
        }
        else
        {
            WriteString(documentNumber, outputStream, 9); /* FIXME: max size of field */
            outputStream.WriteByte((byte)documentNumberCheckDigit);
        }

        WriteCountryCode(nationality, outputStream);
        WriteDateOfBirth(outputStream);
        outputStream.WriteByte((byte)dateOfBirthCheckDigit);
        WriteGender(outputStream);
        WriteDateOfExpiry(outputStream);
        outputStream.WriteByte((byte)dateOfExpiryCheckDigit);
        if (documentType == DocumentType.Mrvb)
        {
            WriteString(optionalData1 ?? "", outputStream, 8);
        }
        else if (isExtendedDocumentNumber)
        {
            WriteString(GetExtendedDocumentNumberOptionalData(), outputStream, 7);
            outputStream.WriteByte((byte)compositeCheckDigit);
        }
        else
        {
            WriteString(optionalData1 ?? "", outputStream, 7);
            outputStream.WriteByte((byte)compositeCheckDigit);
        }
    }

    private void WriteObjectTD3OrMRVA(Stream outputStream)
    {
        /* top line */
        WriteDocumentType(outputStream);
        WriteCountryCode(issuingState, outputStream);
        WriteName(outputStream, 39);

        /* bottom line */
        WriteString(documentNumber, outputStream, 9);
        outputStream.WriteByte((byte)documentNumberCheckDigit);
        WriteCountryCode(nationality, outputStream);
        WriteDateOfBirth(outputStream);
        outputStream.WriteByte((byte)dateOfBirthCheckDigit);
        WriteGender(outputStream);
        WriteDateOfExpiry(outputStream);
        outputStream.WriteByte((byte)dateOfExpiryCheckDigit);
        if (documentType == DocumentType.Mrva)
        {
            WriteString(optionalData1 ?? "", outputStream, 16);
        }
        else
        {
            // Must be TD3.
            WriteString(optionalData1 ?? "", outputStream, 14);
            outputStream.WriteByte((byte)personalNumberCheckDigit);
            outputStream.WriteByte((byte)compositeCheckDigit);
        }
    }

    /// <summary>Sets the name identifiers (primary and secondary identifier) based on the name in the MRZ.</summary>
    private void ReadNameIdentifiers(string mrzNameString)
    {
        int delimIndex = mrzNameString.IndexOf("<<", StringComparison.Ordinal);
        if (delimIndex < 0)
        {
            /* Only a primary identifier. */
            primaryIdentifier = TrimTrailingFillerChars(mrzNameString).Replace("<", " ");
            secondaryIdentifier = "";
            return;
        }
        primaryIdentifier = TrimTrailingFillerChars(mrzNameString.Substring(0, delimIndex)).Replace("<", " ");
        string rest = mrzNameString.Substring(delimIndex + 2);
        ReadSecondaryIdentifiers(rest);
    }

    /// <summary>Sets the secondary identifier.</summary>
    private void ReadSecondaryIdentifiers(string secondaryIdentifier)
    {
        this.secondaryIdentifier = TrimTrailingFillerChars(secondaryIdentifier).Replace("<", " ");
    }

    /// <summary>Writes a MRZ string to a stream, optionally formatting the MRZ string.</summary>
    private static void WriteString(string str, Stream outputStream, int width)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(MrzFormat(str, width));
        outputStream.Write(bytes, 0, bytes.Length);
    }

    /// <summary>Writes the issuing state to a stream.</summary>
    private static void WriteCountryCode(string countryCode, Stream outputStream)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(MrzFormat(countryCode, 3));
        outputStream.Write(bytes, 0, bytes.Length);
    }

    /// <summary>Writes the date of expiry to a stream.</summary>
    private void WriteDateOfExpiry(Stream outputStream)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(dateOfExpiry);
        outputStream.Write(bytes, 0, bytes.Length);
    }

    /// <summary>Writes the gender to a stream.</summary>
    private void WriteGender(Stream outputStream)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(gender);
        outputStream.Write(bytes, 0, bytes.Length);
    }

    /// <summary>Writes the data of birth to a stream.</summary>
    private void WriteDateOfBirth(Stream outputStream)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(dateOfBirth);
        outputStream.Write(bytes, 0, bytes.Length);
    }

    /// <summary>Writes the name to a stream.</summary>
    private void WriteName(Stream outputStream, int width)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(NameToString(primaryIdentifier, secondaryIdentifier, width));
        outputStream.Write(bytes, 0, bytes.Length);
    }

    /// <summary>Write the document type to a stream.</summary>
    private void WriteDocumentType(Stream outputStream) => WriteString(documentCode, outputStream, 2);

    /// <summary>Converts a gender to a string to be used in an MRZ.</summary>
    private static string GenderToString(object genderObject)
    {
        if (genderObject is Gender genderValue)
        {
            return genderValue switch
            {
                Gender.Male => "M",
                Gender.Female => "F",
                _ => "<",
            };
        }

        return genderObject.ToString() ?? "null";
    }

    /// <summary>Converts a gender string to a value of the <see cref="Gender"/> enum.</summary>
    private static Gender StringToGender(string? genderStr)
    {
        if (string.Equals("M", genderStr, StringComparison.OrdinalIgnoreCase))
        {
            return Gender.Male;
        }
        if (string.Equals("F", genderStr, StringComparison.OrdinalIgnoreCase))
        {
            return Gender.Female;
        }
        return Gender.Unknown;
    }

    /// <summary>Encodes the personal number as optional data in case of TD3 style MRZ. If the number does
    /// not yet include a check-digit it will be added.</summary>
    private static string PersonalNumberToOptionalData(string? personalNumber)
    {
        if (personalNumber == null || EqualsModuloFillerChars(personalNumber, ""))
        {
            /* optional data field is not used */
            return "";
        }
        if (personalNumber.Length == 15)
        {
            /* it's either a personalNumber with check digit included, or some other optional data. FIXME: Is this case possible? */
            return personalNumber;
        }
        if (personalNumber.Length <= 14)
        {
            /* we'll assume it's a personalNumber without check digit, and we add the check digit ourselves */
            return MrzFormat(personalNumber, 14);
        }

        throw new ArgumentException("Wrong personal number: " + personalNumber);
    }

    /// <summary>Converts the name (primary and secondary identifier) to a single MRZ formatted name field
    /// of the given length.</summary>
    private static string NameToString(string primaryIdentifier, string? secondaryIdentifier, int width)
    {
        string[] primaryComponents = primaryIdentifier.Split([' ', '<']);
        string[] secondaryComponents = string.IsNullOrWhiteSpace(secondaryIdentifier)
            ? []
            : secondaryIdentifier.Split([' ', '<']);

        var name = new StringBuilder();
        bool isFirstPrimaryComponent = true;
        foreach (string primaryComponent in primaryComponents)
        {
            if (isFirstPrimaryComponent)
            {
                isFirstPrimaryComponent = false;
            }
            else
            {
                name.Append('<');
            }
            name.Append(primaryComponent);
        }

        if (!string.IsNullOrWhiteSpace(secondaryIdentifier))
        {
            name.Append("<<");
            bool isFirstSecondaryComponent = true;
            foreach (string secondaryComponent in secondaryComponents)
            {
                if (isFirstSecondaryComponent)
                {
                    isFirstSecondaryComponent = false;
                }
                else
                {
                    name.Append('<');
                }
                name.Append(secondaryComponent);
            }
        }

        return MrzFormat(name.ToString(), width);
    }

    /// <summary>Reads the issuing state as a three letter string.</summary>
    private static string ReadCountryCode(Stream inputStream) => TrimTrailingFillerChars(ReadString(inputStream, 3));

    /// <summary>Reads a date. Result is typically in "yyMMdd" format.</summary>
    private static string ReadDate(Stream inputStream) => ReadString(inputStream, 6);

    /// <summary>Reads a fixed length string from a stream.</summary>
    private static string ReadString(Stream inputStream, int count)
    {
        byte[] data = ReadFully(inputStream, count);
        return Encoding.UTF8.GetString(data).Trim();
    }

    private static int ReadUnsignedByte(Stream inputStream)
    {
        int b = inputStream.ReadByte();
        if (b < 0)
        {
            throw new EndOfStreamException("Unexpected end of stream while reading MRZ.");
        }
        return b;
    }

    private static byte[] ReadFully(Stream inputStream, int count)
    {
        byte[] buffer = new byte[count];
        int totalRead = 0;
        while (totalRead < count)
        {
            int read = inputStream.Read(buffer, totalRead, count - totalRead);
            if (read <= 0)
            {
                throw new EndOfStreamException("Unexpected end of stream while reading MRZ.");
            }
            totalRead += read;
        }
        return buffer;
    }

    /// <summary>Returns the composite part over which the composite check digit is computed.</summary>
    private string? GetComposite(DocumentType documentType)
    {
        var composite = new StringBuilder();
        int documentNumberLength = documentNumber.Length;

        switch (documentType)
        {
            case DocumentType.Td1:
                /*
                 * Upper line:
                 * 6-30, i.e., documentNumber, documentNumberCheckDigit, optionaldata1(15)
                 *
                 * Middle line:
                 * 1-7, i.e., dateOfBirth, dateOfBirthCheckDigit
                 * 9-15, i.e., dateOfExpiry, dateOfExpiryCheckDigit
                 * 19-29, i.e., optionalData2(11)
                 */
                if (documentNumberLength <= 9)
                {
                    composite.Append(MrzFormat(documentNumber, 9));
                    composite.Append(documentNumberCheckDigit);
                    composite.Append(MrzFormat(optionalData1, 15));
                }
                else
                {
                    /* Document number, first 9 characters. */
                    composite.Append(documentNumber.AsSpan(0, 9));
                    composite.Append('<'); /* Filler instead of check digit. */

                    /* Remainder of document number, its check digit, and optional data 1 (as printed). */
                    composite.Append(MrzFormat(GetExtendedDocumentNumberOptionalData(), 15));
                }
                composite.Append(dateOfBirth);
                composite.Append(dateOfBirthCheckDigit);
                composite.Append(dateOfExpiry);
                composite.Append(dateOfExpiryCheckDigit);
                composite.Append(MrzFormat(optionalData2, 11));
                return composite.ToString();
            case DocumentType.Td2:
                /*
                 * Composite check digit lower line: 1-10, 14-20, 22-35,
                 * i.e., computed over the characters as printed (including fillers).
                 */
                if (documentNumberLength <= 9)
                {
                    composite.Append(MrzFormat(documentNumber, 9));
                    composite.Append(documentNumberCheckDigit);
                }
                else
                {
                    /* Document number, first 9 characters. */
                    composite.Append(documentNumber.AsSpan(0, 9));
                    composite.Append('<'); /* Filler instead of check digit. */
                }
                composite.Append(dateOfBirth);
                composite.Append(dateOfBirthCheckDigit);
                composite.Append(dateOfExpiry);
                composite.Append(dateOfExpiryCheckDigit);
                if (documentNumberLength <= 9)
                {
                    composite.Append(MrzFormat(optionalData1, 7));
                }
                else
                {
                    /* Remainder of document number, its check digit, and optional data 1 (as printed). */
                    composite.Append(MrzFormat(GetExtendedDocumentNumberOptionalData(), 7));
                }
                return composite.ToString();
            case DocumentType.Mrvb:
                /* No composite checkdigit for MRV-B. */
                return null;
            case DocumentType.Td3:
                /* Composite check digit lower line: 1-10, 14-20, 22-43. */
                composite.Append(MrzFormat(documentNumber, 9));
                composite.Append(documentNumberCheckDigit);
                composite.Append(dateOfBirth);
                composite.Append(dateOfBirthCheckDigit);
                composite.Append(dateOfExpiry);
                composite.Append(dateOfExpiryCheckDigit);
                composite.Append(MrzFormat(optionalData1, 14));
                composite.Append(personalNumberCheckDigit);
                return composite.ToString();
            case DocumentType.Mrva:
                /* No composite checkdigit for MRV-A. */
                return null;
            default:
                throw new InvalidOperationException("Unsupported document type");
        }
    }

    /// <summary>Updates the check digit fields for document number, date of birth, date of expiry, and composite.</summary>
    private void UpdateCheckDigits()
    {
        documentNumberCheckDigit = CheckDigit(documentNumber);
        dateOfBirthCheckDigit = CheckDigit(dateOfBirth);
        dateOfExpiryCheckDigit = CheckDigit(dateOfExpiry);

        if (documentType == DocumentType.Td3 && optionalData1.Length < 15)
        {
            /*
             * ICAO Doc 9303 Part 4, TD3 personal number check digit: '<' is only used in place of a
             * calculated '0' when the personal number field itself is empty, not whenever it computes to 0.
             */
            bool isPersonalNumberEmpty = EqualsModuloFillerChars(optionalData1, "");
            personalNumberCheckDigit = CheckDigit(MrzFormat(optionalData1, 14), isPersonalNumberEmpty);
        }

        compositeCheckDigit = CheckDigit(GetComposite(documentType));
    }

    /// <summary>
    /// Reformats the input string such that it only contains ['A'-'Z'], ['0'-'9'], '&lt;' characters by
    /// replacing other characters with '&lt;'. Also extends to the given length by adding '&lt;' to the right.
    /// </summary>
    private static string MrzFormat(string? str, int width)
    {
        if (str == null)
        {
            return "";
        }
        if (str.Length > width)
        {
            throw new ArgumentException($"Argument too wide ({str.Length} > {width})");
        }
        str = str.ToUpperInvariant().Trim();
        var result = new StringBuilder();
        foreach (char c in str)
        {
            result.Append(MRZ_CHARS.Contains(c) ? c : '<');
        }
        while (result.Length < width)
        {
            result.Append('<');
        }
        return result.ToString();
    }

    /// <summary>Determines the document-type.</summary>
    /// <param name="documentCode">the document-code</param>
    /// <param name="length">the length of the complete MRZ (excluding whitespace)</param>
    private static DocumentType GetDocumentType(string documentCode, int length)
    {
        if (documentCode == null || documentCode.Length < 1 || documentCode.Length > 2)
        {
            throw new ArgumentException("Was expecting 1 or 2 digit document code, got " + documentCode);
        }

        return length switch
        {
            /* Document-code must start with C, I, or A. */
            90 => DocumentType.Td1,
            72 => documentCode.StartsWith('V') ? DocumentType.Mrvb : DocumentType.Td2,
            88 => documentCode.StartsWith('V') ? DocumentType.Mrva : DocumentType.Td3,
            _ => DocumentType.Unknown,
        };
    }

    /*
     * NOTE: Can be removed once deprecated methods are gone.
     */
    /// <summary>
    /// Determines the document type based on the document code (the first two characters of the MRZ).
    ///
    /// ICAO Doc 9303 part 3 vol 1 defines MRTDs with 3-line MRZs, in this case the document code starts
    /// with "A", "C", or "I" according to note j to Section 6.6 (page V-9).
    ///
    /// ICAO Doc 9303 part 2 defines MRVs with 2-line MRZs, in this case the document code starts with "V".
    ///
    /// ICAO Doc 9303 part 1 vol 1 defines MRPs with 2-line MRZs, in this case the document code starts
    /// with "P" according to Section 9.6 (page IV-15).
    /// </summary>
    private static DocumentType GetDocumentTypeFromDocumentCode(string documentCode)
    {
        if (documentCode.StartsWith('A') || documentCode.StartsWith('C') || documentCode.StartsWith('I'))
        {
            /* MRTD according to ICAO Doc 9303 (seventh edition) part 5 or 6. NOTE: Could also be TD2. */
            return DocumentType.Td1;
        }
        if (documentCode.StartsWith('V'))
        {
            /* MRV according to ICAO Doc 9303 (old) part 2. NOTE: Could also be MRVA. */
            return DocumentType.Mrvb;
        }
        if (documentCode.StartsWith('P'))
        {
            /* MRP according to ICAO Doc 9303 (old) part 1 vol 1 */
            return DocumentType.Td3;
        }
        return DocumentType.Unknown;
    }

    /// <summary>Replaces '&lt;' with ' ' and trims leading and trailing whitespace.</summary>
    private static string TrimTrailingFillerChars(string? str)
    {
        str ??= "";
        char[] chars = str.Trim().ToCharArray();
        for (int i = chars.Length - 1; i >= 0; i--)
        {
            if (chars[i] == '<')
            {
                chars[i] = ' ';
            }
            else
            {
                break;
            }
        }
        return new string(chars).Trim();
    }

    /// <summary>Checks if the document-code is consistent with the given document-type.</summary>
    private static bool IsDocumentCodeConsistentWithDocumentType(DocumentType documentType, string? documentCode)
    {
        if (documentCode == null)
        {
            return false;
        }

        if (documentCode.Length != 1 && documentCode.Length != 2)
        {
            return false;
        }

        return documentType switch
        {
            DocumentType.Td1 or DocumentType.Td2 => documentCode.StartsWith('C') || documentCode.StartsWith('I') || documentCode.StartsWith('A'),
            DocumentType.Td3 => documentCode.StartsWith('P'),
            DocumentType.Mrva or DocumentType.Mrvb => documentCode.StartsWith('V'),
            _ => false,
        };
    }

    /// <summary>Checks if the optional data is consistent with the given document-type.</summary>
    private static bool IsOptionalDataConsistentWithDocumentType(DocumentType documentType, string? optionalData1, string? optionalData2)
    {
        return documentType switch
        {
            DocumentType.Td1 => (optionalData1 == null || optionalData1.Length <= 15) && (optionalData2 == null || optionalData2.Length <= 11),
            DocumentType.Td2 => (optionalData1 == null || optionalData1.Length <= 7) && optionalData2 == null,
            DocumentType.Mrvb => (optionalData1 == null || optionalData1.Length <= 8) && optionalData2 == null,
            DocumentType.Td3 => (optionalData1 == null || optionalData1.Length <= 15) && optionalData2 == null,
            DocumentType.Mrva => (optionalData1 == null || optionalData1.Length <= 16) && optionalData2 == null,
            _ => false,
        };
    }

    /// <summary>
    /// Computes the 7-3-1 check digit for part of the MRZ. If <paramref name="preferFillerOverZero"/> is
    /// <c>true</c> then '&lt;' will be returned on check digit 0.
    /// </summary>
    /// <param name="str">a part of the MRZ</param>
    /// <param name="preferFillerOverZero">a boolean indicating whether fillers should be preferred</param>
    /// <returns>the resulting check digit (in '0' - '9', '&lt;')</returns>
    private static char CheckDigit(string? str, bool preferFillerOverZero)
    {
        byte[] chars = str == null ? [] : Encoding.UTF8.GetBytes(str);
        int[] weights = [7, 3, 1];
        int result = 0;
        for (int i = 0; i < chars.Length; i++)
        {
            result = (result + weights[i % 3] * DecodeMRZDigit(chars[i])) % 10;
        }
        char checkDigit = (char)('0' + result);
        if (preferFillerOverZero && checkDigit == '0')
        {
            checkDigit = '<';
        }
        return checkDigit;
    }

    /// <summary>
    /// Looks up the numerical value for MRZ characters, in order to be able to compute check digits.
    /// </summary>
    /// <param name="ch">a character from the MRZ.</param>
    /// <returns>the numerical value of the character.</returns>
    /// <exception cref="FormatException">if <paramref name="ch"/> is not a valid MRZ character</exception>
    private static int DecodeMRZDigit(byte ch)
    {
        return (char)ch switch
        {
            '<' or '0' => 0,
            '1' => 1,
            '2' => 2,
            '3' => 3,
            '4' => 4,
            '5' => 5,
            '6' => 6,
            '7' => 7,
            '8' => 8,
            '9' => 9,
            'a' or 'A' => 10,
            'b' or 'B' => 11,
            'c' or 'C' => 12,
            'd' or 'D' => 13,
            'e' or 'E' => 14,
            'f' or 'F' => 15,
            'g' or 'G' => 16,
            'h' or 'H' => 17,
            'i' or 'I' => 18,
            'j' or 'J' => 19,
            'k' or 'K' => 20,
            'l' or 'L' => 21,
            'm' or 'M' => 22,
            'n' or 'N' => 23,
            'o' or 'O' => 24,
            'p' or 'P' => 25,
            'q' or 'Q' => 26,
            'r' or 'R' => 27,
            's' or 'S' => 28,
            't' or 'T' => 29,
            'u' or 'U' => 30,
            'v' or 'V' => 31,
            'w' or 'W' => 32,
            'x' or 'X' => 33,
            'y' or 'Y' => 34,
            'z' or 'Z' => 35,
            _ => throw new FormatException($"Could not decode MRZ character {ch} ('{(char)ch}')"),
        };
    }
}
