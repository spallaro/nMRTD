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

using nMRTD.SmartCards;

namespace nMRTD.Lds.Icao;

/// <summary>
/// Port of <c>org.jmrtd.lds.icao.DG11File</c>: file structure for the EF.DG11 file. Data group 11
/// contains additional personal detail(s).
///
/// All fields are optional. See Section 16 of LDS-TR.
/// <list type="number">
/// <item>Name of Holder (Primary and Secondary Identifiers, in full)</item>
/// <item>Other Name(s)</item>
/// <item>Personal Number</item>
/// <item>Place of Birth</item>
/// <item>Date of Birth (in full)</item>
/// <item>Address</item>
/// <item>Telephone Number(s)</item>
/// <item>Profession</item>
/// <item>Title</item>
/// <item>Personal Summary</item>
/// <item>Proof of Citizenship [see 14.5.1]</item>
/// <item>Number of Other Valid Travel Documents</item>
/// <item>Other Travel Document Numbers</item>
/// <item>Custody Information</item>
/// </list>
/// </summary>
public class DG11File : AdditionalDetailDataGroup
{
    public new const int TAG_LIST_TAG = 0x5C;

    public const int FULL_NAME_TAG = 0x5F0E;
    public const int OTHER_NAME_TAG = 0x5F0F;
    public const int PERSONAL_NUMBER_TAG = 0x5F10;

    /// <summary>In 'CCYYMMDD' format.</summary>
    public const int FULL_DATE_OF_BIRTH_TAG = 0x5F2B;

    /// <summary>Fields separated by '&lt;'.</summary>
    public const int PLACE_OF_BIRTH_TAG = 0x5F11;

    /// <summary>Fields separated by '&lt;'.</summary>
    public const int PERMANENT_ADDRESS_TAG = 0x5F42;
    public const int TELEPHONE_TAG = 0x5F12;
    public const int PROFESSION_TAG = 0x5F13;
    public const int TITLE_TAG = 0x5F14;
    public const int PERSONAL_SUMMARY_TAG = 0x5F15;

    /// <summary>Compressed image per ISO/IEC 10918.</summary>
    public const int PROOF_OF_CITIZENSHIP_TAG = 0x5F16;

    /// <summary>Separated by '&lt;'.</summary>
    public const int OTHER_VALID_TD_NUMBERS_TAG = 0x5F17;
    public const int CUSTODY_INFORMATION_TAG = 0x5F18;

    private const string SDF = "yyyyMMdd";

    private string? nameOfHolder;
    private List<string>? otherNames;
    private string? personalNumber;
    private string? fullDateOfBirth;
    private List<string>? placeOfBirth;
    private List<string>? permanentAddress;
    private string? telephone;
    private string? profession;
    private string? title;
    private string? personalSummary;
    private byte[]? proofOfCitizenship;
    private List<string>? otherValidTDNumbers;
    private string? custodyInformation;

    private List<int>? tagPresenceList;

    /// <summary>Constructs a file from binary representation.</summary>
    public DG11File(Stream inputStream)
        : base(LDSFile.EF_DG11_TAG, inputStream)
    {
    }

    /// <summary>Constructs a new file. Use <c>null</c> if data element is not present. Use '&lt;' as separator.</summary>
    public DG11File(string? nameOfHolder,
        List<string>? otherNames, string? personalNumber,
        DateTime? fullDateOfBirth, List<string>? placeOfBirth, List<string>? permanentAddress,
        string? telephone, string? profession, string? title,
        string? personalSummary, byte[]? proofOfCitizenship,
        List<string>? otherValidTDNumbers, string? custodyInformation)
        : this(nameOfHolder,
            otherNames, personalNumber,
            fullDateOfBirth?.ToString(SDF),
            placeOfBirth, permanentAddress,
            telephone, profession, title,
            personalSummary, proofOfCitizenship,
            otherValidTDNumbers, custodyInformation)
    {
    }

    /// <summary>Constructs a new file. Use <c>null</c> if data element is not present. Use '&lt;' as separator.</summary>
    public DG11File(string? nameOfHolder,
        List<string>? otherNames, string? personalNumber,
        string? fullDateOfBirth, List<string>? placeOfBirth, List<string>? permanentAddress,
        string? telephone, string? profession, string? title,
        string? personalSummary, byte[]? proofOfCitizenship,
        List<string>? otherValidTDNumbers, string? custodyInformation)
        : base(LDSFile.EF_DG11_TAG)
    {
        this.nameOfHolder = nameOfHolder;
        this.otherNames = otherNames == null ? null : [.. otherNames];
        this.personalNumber = personalNumber;
        this.fullDateOfBirth = fullDateOfBirth;
        this.placeOfBirth = placeOfBirth == null ? null : (placeOfBirth.Count == 0 ? [""] : [.. placeOfBirth]);
        this.permanentAddress = permanentAddress == null ? null : (permanentAddress.Count == 0 ? [""] : [.. permanentAddress]);
        this.telephone = telephone;
        this.profession = profession;
        this.title = title;
        this.personalSummary = personalSummary;
        this.proofOfCitizenship = proofOfCitizenship;
        this.otherValidTDNumbers = otherValidTDNumbers == null ? null : (otherValidTDNumbers.Count == 0 ? [""] : [.. otherValidTDNumbers]);
        this.custodyInformation = custodyInformation;
    }

    /* Accessors below. */

    /// <summary>Returns the DG11 tag. Overrides the base, as in JMRTD.</summary>
    public override int GetTag() => LDSFile.EF_DG11_TAG;

    /// <summary>Returns the list of tags of fields actually present.</summary>
    public override List<int> GetTagPresenceList()
    {
        if (tagPresenceList != null)
        {
            return tagPresenceList;
        }
        tagPresenceList = new List<int>(12);
        if (nameOfHolder != null)
        {
            tagPresenceList.Add(FULL_NAME_TAG);
        }
        if (otherNames != null)
        {
            tagPresenceList.Add(OTHER_NAME_TAG);
        }
        if (personalNumber != null)
        {
            tagPresenceList.Add(PERSONAL_NUMBER_TAG);
        }
        if (fullDateOfBirth != null)
        {
            tagPresenceList.Add(FULL_DATE_OF_BIRTH_TAG);
        }
        if (placeOfBirth != null)
        {
            tagPresenceList.Add(PLACE_OF_BIRTH_TAG);
        }
        if (permanentAddress != null)
        {
            tagPresenceList.Add(PERMANENT_ADDRESS_TAG);
        }
        if (telephone != null)
        {
            tagPresenceList.Add(TELEPHONE_TAG);
        }
        if (profession != null)
        {
            tagPresenceList.Add(PROFESSION_TAG);
        }
        if (title != null)
        {
            tagPresenceList.Add(TITLE_TAG);
        }
        if (personalSummary != null)
        {
            tagPresenceList.Add(PERSONAL_SUMMARY_TAG);
        }
        if (proofOfCitizenship != null)
        {
            tagPresenceList.Add(PROOF_OF_CITIZENSHIP_TAG);
        }
        if (otherValidTDNumbers != null)
        {
            tagPresenceList.Add(OTHER_VALID_TD_NUMBERS_TAG);
        }
        if (custodyInformation != null)
        {
            tagPresenceList.Add(CUSTODY_INFORMATION_TAG);
        }
        return tagPresenceList;
    }

    /// <summary>Returns the full name of the holder (primary and secondary identifiers).</summary>
    public string? GetNameOfHolder() => nameOfHolder;

    /// <summary>Returns the other names.</summary>
    public List<string>? GetOtherNames() => otherNames == null ? null : [.. otherNames];

    /// <summary>Returns the personal number.</summary>
    public string? GetPersonalNumber() => personalNumber;

    /// <summary>Returns the full date of birth.</summary>
    public string? GetFullDateOfBirth() => fullDateOfBirth;

    /// <summary>Returns the place of birth.</summary>
    public List<string>? GetPlaceOfBirth() => placeOfBirth;

    /// <summary>Returns the permanent address.</summary>
    public List<string>? GetPermanentAddress() => permanentAddress;

    /// <summary>Returns the telephone number.</summary>
    public string? GetTelephone() => telephone;

    /// <summary>Returns the holder's profession.</summary>
    public string? GetProfession() => profession;

    /// <summary>Returns the holder's title.</summary>
    public string? GetTitle() => title;

    /// <summary>Returns the personal summary.</summary>
    public string? GetPersonalSummary() => personalSummary;

    /// <summary>Returns the proof of citizenship.</summary>
    public byte[]? GetProofOfCitizenship() => proofOfCitizenship;

    /// <summary>Returns the other valid travel document numbers.</summary>
    public List<string>? GetOtherValidTDNumbers() => otherValidTDNumbers;

    /// <summary>Returns the custody information.</summary>
    public string? GetCustodyInformation() => custodyInformation;

    public override string ToString()
    {
        return "DG11File ["
            + (nameOfHolder ?? "") + ", "
            + (otherNames == null || otherNames.Count == 0 ? "[]" : $"[{string.Join(", ", otherNames)}]") + ", "
            + (personalNumber ?? "") + ", "
            + (fullDateOfBirth ?? "") + ", "
            + (placeOfBirth == null || placeOfBirth.Count == 0 ? "[]" : $"[{string.Join(", ", placeOfBirth)}]") + ", "
            + (permanentAddress == null || permanentAddress.Count == 0 ? "[]" : $"[{string.Join(", ", permanentAddress)}]") + ", "
            + (telephone ?? "") + ", "
            + (profession ?? "") + ", "
            + (title ?? "") + ", "
            + (personalSummary ?? "") + ", "
            + (proofOfCitizenship == null ? "" : $"image ({proofOfCitizenship.Length})") + ", "
            + (otherValidTDNumbers == null || otherValidTDNumbers.Count == 0 ? "[]" : $"[{string.Join(", ", otherValidTDNumbers)}]") + ", "
            + (custodyInformation ?? "")
            + "]";
    }

    public override int GetHashCode()
    {
        int result = 1;
        const int prime = 31;
        result = prime * result + (proofOfCitizenship == null ? 0 : StructuralHash(proofOfCitizenship));
        var fieldsHash = new HashCode();
        fieldsHash.Add(custodyInformation);
        fieldsHash.Add(fullDateOfBirth);
        fieldsHash.Add(nameOfHolder);
        fieldsHash.Add(ListHash(otherNames));
        fieldsHash.Add(ListHash(otherValidTDNumbers));
        fieldsHash.Add(ListHash(permanentAddress));
        fieldsHash.Add(personalNumber);
        fieldsHash.Add(personalSummary);
        fieldsHash.Add(ListHash(placeOfBirth));
        fieldsHash.Add(profession);
        result = prime * result + fieldsHash.ToHashCode();
        result = prime * result + HashCode.Combine(telephone, title);
        return result;
    }

    private static int StructuralHash(byte[] array)
    {
        var hash = new HashCode();
        foreach (byte b in array)
        {
            hash.Add(b);
        }
        return hash.ToHashCode();
    }

    private static int ListHash(List<string>? list)
    {
        if (list == null)
        {
            return 0;
        }
        var hash = new HashCode();
        foreach (string s in list)
        {
            hash.Add(s);
        }
        return hash.ToHashCode();
    }

    public override bool Equals(object? obj)
    {
        if (ReferenceEquals(this, obj))
        {
            return true;
        }
        if (obj == null)
        {
            return false;
        }
        if (GetType() != obj.GetType())
        {
            return false;
        }

        var other = (DG11File)obj;
        return custodyInformation == other.custodyInformation
            && fullDateOfBirth == other.fullDateOfBirth
            && nameOfHolder == other.nameOfHolder
            && SequenceEqualNullable(otherNames, other.otherNames)
            && SequenceEqualNullable(otherValidTDNumbers, other.otherValidTDNumbers)
            && SequenceEqualNullable(permanentAddress, other.permanentAddress)
            && personalNumber == other.personalNumber
            && personalSummary == other.personalSummary
            && SequenceEqualNullable(placeOfBirth, other.placeOfBirth)
            && profession == other.profession
            && ByteArrayEqualsNullable(proofOfCitizenship, other.proofOfCitizenship)
            && SequenceEqualNullable(GetTagPresenceList(), other.GetTagPresenceList())
            && telephone == other.telephone
            && title == other.title;
    }

    private static bool SequenceEqualNullable<T>(List<T>? a, List<T>? b)
    {
        if (a == null || b == null)
        {
            return a == b;
        }
        return a.SequenceEqual(b);
    }

    private static bool ByteArrayEqualsNullable(byte[]? a, byte[]? b)
    {
        if (a == null || b == null)
        {
            return a == b;
        }
        return a.AsSpan().SequenceEqual(b);
    }

    /// <summary>Reads a field from a stream.</summary>
    protected override void ReadField(int expectedTag, TlvInputStream tlvInputStream)
    {
        int tag = tlvInputStream.ReadTag();
        if (tag != CONTENT_SPECIFIC_CONSTRUCTED_TAG && tag != expectedTag)
        {
            throw new ArgumentException($"Expected {expectedTag:X}, but found {tag:X}");
        }
        tlvInputStream.ReadLength();
        switch (tag)
        {
            case FULL_NAME_TAG:
                nameOfHolder = ReadString(tlvInputStream);
                break;
            case CONTENT_SPECIFIC_CONSTRUCTED_TAG:
                otherNames = ReadContentSpecificFieldsList(tlvInputStream);
                break;
            case OTHER_NAME_TAG:
                /* Work around non-compliant early samples. */
                otherNames = [ReadString(tlvInputStream)];
                break;
            case PERSONAL_NUMBER_TAG:
                personalNumber = ReadString(tlvInputStream);
                break;
            case FULL_DATE_OF_BIRTH_TAG:
                fullDateOfBirth = ReadFullDate(tlvInputStream);
                break;
            case PLACE_OF_BIRTH_TAG:
                placeOfBirth = ReadList(tlvInputStream);
                break;
            case PERMANENT_ADDRESS_TAG:
                permanentAddress = ReadList(tlvInputStream);
                break;
            case TELEPHONE_TAG:
                telephone = ReadString(tlvInputStream);
                break;
            case PROFESSION_TAG:
                profession = ReadString(tlvInputStream);
                break;
            case TITLE_TAG:
                title = ReadString(tlvInputStream);
                break;
            case PERSONAL_SUMMARY_TAG:
                personalSummary = ReadString(tlvInputStream);
                break;
            case PROOF_OF_CITIZENSHIP_TAG:
                proofOfCitizenship = ReadBytes(tlvInputStream);
                break;
            case OTHER_VALID_TD_NUMBERS_TAG:
                otherValidTDNumbers = ReadList(tlvInputStream);
                break;
            case CUSTODY_INFORMATION_TAG:
                custodyInformation = ReadString(tlvInputStream);
                break;
            default:
                throw new ArgumentException($"Unknown field tag in DG11: {tag:X}");
        }
    }

    protected override void WriteField(int tag, TlvOutputStream tlvOut)
    {
        switch (tag)
        {
            case FULL_NAME_TAG:
                WriteString(tag, nameOfHolder, tlvOut);
                break;
            case OTHER_NAME_TAG:
                WriteContentSpecificFieldsList(OTHER_NAME_TAG, otherNames, tlvOut);
                break;
            case PERSONAL_NUMBER_TAG:
                WriteString(tag, personalNumber, tlvOut);
                break;
            case FULL_DATE_OF_BIRTH_TAG:
                WriteString(tag, fullDateOfBirth, tlvOut);
                break;
            case PLACE_OF_BIRTH_TAG:
                WriteList(tag, placeOfBirth, tlvOut);
                break;
            case PERMANENT_ADDRESS_TAG:
                WriteList(tag, permanentAddress, tlvOut);
                break;
            case TELEPHONE_TAG:
                WriteString(tag, telephone, tlvOut);
                break;
            case PROFESSION_TAG:
                WriteString(tag, profession, tlvOut);
                break;
            case TITLE_TAG:
                WriteString(tag, title, tlvOut);
                break;
            case PERSONAL_SUMMARY_TAG:
                WriteString(tag, personalSummary, tlvOut);
                break;
            case PROOF_OF_CITIZENSHIP_TAG:
                tlvOut.WriteTag(tag);
                tlvOut.WriteValue(proofOfCitizenship ?? []);
                break;
            case OTHER_VALID_TD_NUMBERS_TAG:
                WriteList(tag, otherValidTDNumbers, tlvOut);
                break;
            case CUSTODY_INFORMATION_TAG:
                WriteString(tag, custodyInformation, tlvOut);
                break;
            default:
                throw new InvalidOperationException($"Unknown tag in DG11: {tag:X}");
        }
    }
}
