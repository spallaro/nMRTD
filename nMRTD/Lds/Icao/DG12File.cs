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
/// Port of <c>org.jmrtd.lds.icao.DG12File</c>: file structure for the EF.DG12 file. Data group 12 contains
/// additional document detail(s).
/// </summary>
public class DG12File : AdditionalDetailDataGroup
{
    public const int ISSUING_AUTHORITY_TAG = 0x5F19;

    /// <summary>yyyymmdd.</summary>
    public const int DATE_OF_ISSUE_TAG = 0x5F26;

    /// <summary>Formatted per ICAO 9303 rules.</summary>
    public const int NAME_OF_OTHER_PERSON_TAG = 0x5F1A;

    public const int ENDORSEMENTS_AND_OBSERVATIONS_TAG = 0x5F1B;
    public const int TAX_OR_EXIT_REQUIREMENTS_TAG = 0x5F1C;

    /// <summary>Image per ISO/IEC 10918.</summary>
    public const int IMAGE_OF_FRONT_TAG = 0x5F1D;

    /// <summary>Image per ISO/IEC 10918.</summary>
    public const int IMAGE_OF_REAR_TAG = 0x5F1E;

    /// <summary>yyyymmddhhmmss.</summary>
    public const int DATE_AND_TIME_OF_PERSONALIZATION_TAG = 0x5F55;

    public const int PERSONALIZATION_SYSTEM_SERIAL_NUMBER_TAG = 0x5F56;

    private const string SDF = "yyyyMMdd";
    private const string SDTF = "yyyyMMddHHmmss";

    private string? issuingAuthority;
    private string? dateOfIssue;
    private List<string>? namesOfOtherPersons;
    private string? endorsementsAndObservations;
    private string? taxOrExitRequirements;
    private byte[]? imageOfFront;
    private byte[]? imageOfRear;
    private string? dateAndTimeOfPersonalization;
    private string? personalizationSystemSerialNumber;

    private List<int>? tagPresenceList;

    /// <summary>Constructs a new file.</summary>
    /// <param name="issuingAuthority">the issuing authority</param>
    /// <param name="dateOfIssue">the date of issue</param>
    /// <param name="namesOfOtherPersons">names of other persons</param>
    /// <param name="endorsementsAndObservations">endorsements and observations</param>
    /// <param name="taxOrExitRequirements">tax or exit requirements</param>
    /// <param name="imageOfFront">image of front</param>
    /// <param name="imageOfRear">image of rear</param>
    /// <param name="dateAndTimeOfPersonalization">date and time of personalization</param>
    /// <param name="personalizationSystemSerialNumber">personalization system serial number</param>
    public DG12File(string? issuingAuthority, DateTime? dateOfIssue,
        List<string>? namesOfOtherPersons, string? endorsementsAndObservations,
        string? taxOrExitRequirements, byte[]? imageOfFront,
        byte[]? imageOfRear, DateTime? dateAndTimeOfPersonalization,
        string? personalizationSystemSerialNumber)
        : this(issuingAuthority,
            dateOfIssue?.ToString(SDF),
            namesOfOtherPersons, endorsementsAndObservations,
            taxOrExitRequirements, imageOfFront,
            imageOfRear,
            dateAndTimeOfPersonalization?.ToString(SDTF),
            personalizationSystemSerialNumber)
    {
    }

    /// <summary>Constructs a new file.</summary>
    /// <param name="issuingAuthority">the issuing authority</param>
    /// <param name="dateOfIssue">the date of issue</param>
    /// <param name="namesOfOtherPersons">names of other persons</param>
    /// <param name="endorsementsAndObservations">endorsements and observations</param>
    /// <param name="taxOrExitRequirements">tax or exit requirements</param>
    /// <param name="imageOfFront">image of front</param>
    /// <param name="imageOfRear">image of rear</param>
    /// <param name="dateAndTimeOfPersonalization">date and time of personalization</param>
    /// <param name="personalizationSystemSerialNumber">personalization system serial number</param>
    public DG12File(string? issuingAuthority, string? dateOfIssue,
        List<string>? namesOfOtherPersons, string? endorsementsAndObservations,
        string? taxOrExitRequirements, byte[]? imageOfFront,
        byte[]? imageOfRear, string? dateAndTimeOfPersonalization,
        string? personalizationSystemSerialNumber)
        : base(LDSFileTags.EF_DG12_TAG)
    {
        this.issuingAuthority = issuingAuthority;
        this.dateOfIssue = dateOfIssue;
        this.namesOfOtherPersons = namesOfOtherPersons == null ? null : [.. namesOfOtherPersons];
        this.endorsementsAndObservations = endorsementsAndObservations;
        this.taxOrExitRequirements = taxOrExitRequirements;
        this.imageOfFront = imageOfFront;
        this.imageOfRear = imageOfRear;
        this.dateAndTimeOfPersonalization = dateAndTimeOfPersonalization;
        this.personalizationSystemSerialNumber = personalizationSystemSerialNumber;
    }

    /// <summary>Constructs a new file.</summary>
    /// <param name="inputStream">an input stream</param>
    public DG12File(Stream inputStream)
        : base(LDSFileTags.EF_DG12_TAG, inputStream)
    {
    }

    /// <summary>Returns the tags of fields actually present in this file.</summary>
    public override List<int> GetTagPresenceList()
    {
        if (tagPresenceList != null)
        {
            return tagPresenceList;
        }

        tagPresenceList = new List<int>(10);
        if (issuingAuthority != null)
        {
            tagPresenceList.Add(ISSUING_AUTHORITY_TAG);
        }

        if (dateOfIssue != null)
        {
            tagPresenceList.Add(DATE_OF_ISSUE_TAG);
        }

        if (namesOfOtherPersons != null)
        {
            tagPresenceList.Add(NAME_OF_OTHER_PERSON_TAG);
        }

        if (endorsementsAndObservations != null)
        {
            tagPresenceList.Add(ENDORSEMENTS_AND_OBSERVATIONS_TAG);
        }

        if (taxOrExitRequirements != null)
        {
            tagPresenceList.Add(TAX_OR_EXIT_REQUIREMENTS_TAG);
        }

        if (imageOfFront != null)
        {
            tagPresenceList.Add(IMAGE_OF_FRONT_TAG);
        }

        if (imageOfRear != null)
        {
            tagPresenceList.Add(IMAGE_OF_REAR_TAG);
        }

        if (dateAndTimeOfPersonalization != null)
        {
            tagPresenceList.Add(DATE_AND_TIME_OF_PERSONALIZATION_TAG);
        }

        if (personalizationSystemSerialNumber != null)
        {
            tagPresenceList.Add(PERSONALIZATION_SYSTEM_SERIAL_NUMBER_TAG);
        }

        return tagPresenceList;
    }

    /// <summary>Returns the issuing authority.</summary>
    public string? GetIssuingAuthority() => issuingAuthority;

    /// <summary>Returns the date of issuance.</summary>
    public string? GetDateOfIssue() => dateOfIssue;

    /// <summary>Returns names of other persons.</summary>
    public List<string>? GetNamesOfOtherPersons() => namesOfOtherPersons == null ? null : [.. namesOfOtherPersons];

    /// <summary>Returns endorsements and observations.</summary>
    public string? GetEndorsementsAndObservations() => endorsementsAndObservations;

    /// <summary>Returns tax or exit requirements.</summary>
    public string? GetTaxOrExitRequirements() => taxOrExitRequirements;

    /// <summary>Returns image of front.</summary>
    public byte[]? GetImageOfFront() => imageOfFront;

    /// <summary>Returns image of rear.</summary>
    public byte[]? GetImageOfRear() => imageOfRear;

    /// <summary>Returns the date and time of personalization.</summary>
    public string? GetDateAndTimeOfPersonalization() => dateAndTimeOfPersonalization;

    /// <summary>Returns the personalization system serial number.</summary>
    public string? GetPersonalizationSystemSerialNumber() => personalizationSystemSerialNumber;

    /// <summary>Returns the DG12 tag. Overrides the base, as in JMRTD, so that encoding writes 0x6C.</summary>
    public override int GetTag() => LDSFileTags.EF_DG12_TAG;

    /// <summary>Returns a textual representation of this file.</summary>
    public override string ToString() =>
        "DG12File ["
        + (issuingAuthority ?? "") + ", "
        + (dateOfIssue ?? "") + ", "
        + (namesOfOtherPersons == null || namesOfOtherPersons.Count == 0 ? "[]" : $"[{string.Join(", ", namesOfOtherPersons)}]") + ", "
        + (endorsementsAndObservations ?? "") + ", "
        + (taxOrExitRequirements ?? "") + ", "
        + (imageOfFront == null ? "" : $"image ({imageOfFront.Length})") + ", "
        + (imageOfRear == null ? "" : $"image ({imageOfRear.Length})") + ", "
        + (dateAndTimeOfPersonalization ?? "") + ", "
        + (personalizationSystemSerialNumber ?? "")
        + "]";

    public override int GetHashCode()
    {
        const int prime = 31;
        int result = 1;
        result = (prime * result) + (imageOfFront == null ? 0 : StructuralHash(imageOfFront));
        result = (prime * result) + (imageOfRear == null ? 0 : StructuralHash(imageOfRear));
        var fieldsHash = new HashCode();
        fieldsHash.Add(dateAndTimeOfPersonalization);
        fieldsHash.Add(dateOfIssue);
        fieldsHash.Add(endorsementsAndObservations);
        fieldsHash.Add(issuingAuthority);
        fieldsHash.Add(ListHash(namesOfOtherPersons));
        fieldsHash.Add(personalizationSystemSerialNumber);
        fieldsHash.Add(taxOrExitRequirements);
        result = (prime * result) + fieldsHash.ToHashCode();
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

        var other = (DG12File)obj;
        return dateAndTimeOfPersonalization == other.dateAndTimeOfPersonalization
            && dateOfIssue == other.dateOfIssue
            && endorsementsAndObservations == other.endorsementsAndObservations
            && ByteArrayEqualsNullable(imageOfFront, other.imageOfFront)
            && ByteArrayEqualsNullable(imageOfRear, other.imageOfRear)
            && issuingAuthority == other.issuingAuthority
            && SequenceEqualNullable(namesOfOtherPersons, other.namesOfOtherPersons)
            && personalizationSystemSerialNumber == other.personalizationSystemSerialNumber
            && taxOrExitRequirements == other.taxOrExitRequirements;
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
            case ISSUING_AUTHORITY_TAG:
                issuingAuthority = ReadString(tlvInputStream);
                break;
            case DATE_OF_ISSUE_TAG:
                dateOfIssue = ReadFullDate(tlvInputStream);
                break;
            case CONTENT_SPECIFIC_CONSTRUCTED_TAG:
                namesOfOtherPersons = ReadContentSpecificFieldsList(tlvInputStream);
                break;
            case NAME_OF_OTHER_PERSON_TAG:
                /* Work around non-compliant early samples. */
                namesOfOtherPersons = [ReadString(tlvInputStream)];
                break;
            case ENDORSEMENTS_AND_OBSERVATIONS_TAG:
                endorsementsAndObservations = ReadString(tlvInputStream);
                break;
            case TAX_OR_EXIT_REQUIREMENTS_TAG:
                taxOrExitRequirements = ReadString(tlvInputStream);
                break;
            case IMAGE_OF_FRONT_TAG:
                imageOfFront = ReadBytes(tlvInputStream);
                break;
            case IMAGE_OF_REAR_TAG:
                imageOfRear = ReadBytes(tlvInputStream);
                break;
            case DATE_AND_TIME_OF_PERSONALIZATION_TAG:
                dateAndTimeOfPersonalization = ReadFullDateTime(tlvInputStream);
                break;
            case PERSONALIZATION_SYSTEM_SERIAL_NUMBER_TAG:
                personalizationSystemSerialNumber = ReadString(tlvInputStream);
                break;
            default:
                throw new ArgumentException($"Unknown field tag in DG12: {tag:X}");
        }
    }

    protected override void WriteField(int tag, TlvOutputStream tlvOut)
    {
        switch (tag)
        {
            case ISSUING_AUTHORITY_TAG:
                WriteString(tag, issuingAuthority, tlvOut);
                break;
            case DATE_OF_ISSUE_TAG:
                WriteString(tag, dateOfIssue, tlvOut);
                break;
            case NAME_OF_OTHER_PERSON_TAG:
                WriteContentSpecificFieldsList(tag, namesOfOtherPersons, tlvOut);
                break;
            case ENDORSEMENTS_AND_OBSERVATIONS_TAG:
                WriteString(tag, endorsementsAndObservations, tlvOut);
                break;
            case TAX_OR_EXIT_REQUIREMENTS_TAG:
                WriteString(tag, taxOrExitRequirements, tlvOut);
                break;
            case IMAGE_OF_FRONT_TAG:
                WriteBytes(tag, imageOfFront, tlvOut);
                break;
            case IMAGE_OF_REAR_TAG:
                WriteBytes(tag, imageOfRear, tlvOut);
                break;
            case DATE_AND_TIME_OF_PERSONALIZATION_TAG:
                WriteString(tag, dateAndTimeOfPersonalization, tlvOut);
                break;
            case PERSONALIZATION_SYSTEM_SERIAL_NUMBER_TAG:
                WriteString(tag, personalizationSystemSerialNumber, tlvOut);
                break;
            default:
                throw new ArgumentException($"Unknown field tag in DG12: {tag:X}");
        }
    }
}
