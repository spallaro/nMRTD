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

using nMRTD.Lds;
using nMRTD.SmartCards;

namespace nMRTD.Lds.Icao;

/// <summary>
/// Port of <c>org.jmrtd.lds.icao.COMFile</c>: file structure for the EF.COM file. This file contains the
/// common data (version and data group presence table) information.
/// </summary>
public class COMFile : AbstractTaggedLDSFile
{
    private const int TAG_LIST_TAG = 0x5C;
    private const int VERSION_UNICODE_TAG = 0x5F36;
    private const int VERSION_LDS_TAG = 0x5F01;

    private string versionLDS = null!;
    private string updateLevelLDS = null!;
    private string majorVersionUnicode = null!;
    private string minorVersionUnicode = null!;
    private string releaseLevelUnicode = null!;
    private List<int> tagList = null!;

    /// <param name="versionLDS">a numerical string of length 2</param>
    /// <param name="updateLevelLDS">a numerical string of length 2</param>
    /// <param name="majorVersionUnicode">a numerical string of length 2</param>
    /// <param name="minorVersionUnicode">a numerical string of length 2</param>
    /// <param name="releaseLevelUnicode">a numerical string of length 2</param>
    /// <param name="tagList">a list of ICAO data group tags</param>
    /// <exception cref="ArgumentException">if the input is not well-formed</exception>
    public COMFile(string versionLDS, string updateLevelLDS,
        string majorVersionUnicode, string minorVersionUnicode,
        string releaseLevelUnicode, int[] tagList)
        : base(LDSFile.EF_COM_TAG)
    {
        Initialize(versionLDS, updateLevelLDS, majorVersionUnicode, minorVersionUnicode, releaseLevelUnicode, tagList);
    }

    /// <param name="ldsVer">a "x.y" version number</param>
    /// <param name="unicodeVer">a "x.y.z" version number</param>
    /// <param name="tagList">list of tags</param>
    public COMFile(string ldsVer, string unicodeVer, int[] tagList)
        : base(LDSFile.EF_COM_TAG)
    {
        try
        {
            ArgumentNullException.ThrowIfNull(ldsVer);
            ArgumentNullException.ThrowIfNull(unicodeVer);

            string[] ldsTokens = ldsVer.Split('.');
            if (ldsTokens.Length != 2)
            {
                throw new ArgumentException("Could not parse LDS version. Expecting 2 level version number x.y.");
            }
            int versionLDSNumber = int.Parse(ldsTokens[0].Trim());
            int updateLevelLDSNumber = int.Parse(ldsTokens[1].Trim());

            string[] unicodeTokens = unicodeVer.Split('.');
            if (unicodeTokens.Length != 3)
            {
                throw new ArgumentException("Could not parse unicode version. Expecting 3 level version number x.y.z.");
            }
            int majorVersionUnicodeNumber = int.Parse(unicodeTokens[0].Trim());
            int minorVersionUnicodeNumber = int.Parse(unicodeTokens[1].Trim());
            int releaseLevelUnicodeNumber = int.Parse(unicodeTokens[2].Trim());

            Initialize(versionLDSNumber.ToString("D2"),
                updateLevelLDSNumber.ToString("D2"),
                majorVersionUnicodeNumber.ToString("D2"),
                minorVersionUnicodeNumber.ToString("D2"),
                releaseLevelUnicodeNumber.ToString("D2"),
                tagList);
        }
        catch (FormatException fe)
        {
            throw new ArgumentException("Could not parse version number", fe);
        }
    }

    /// <summary>Constructs a new EF.COM file based on the encoded value in <paramref name="inputStream"/>.</summary>
    /// <param name="inputStream">should contain a TLV object with appropriate tag and contents</param>
    /// <exception cref="IOException">if the input could not be decoded</exception>
    public COMFile(Stream inputStream)
        : base(LDSFile.EF_COM_TAG, inputStream)
    {
    }

    protected override void ReadContent(Stream inputStream)
    {
        using var tlvIn = new TlvInputStream(inputStream, leaveOpen: true);
        int versionLDSTag = tlvIn.ReadTag();
        if (versionLDSTag != VERSION_LDS_TAG)
        {
            throw new ArgumentException($"Excepected VERSION_LDS_TAG ({VERSION_LDS_TAG:X}), found {versionLDSTag:X}");
        }
        int versionLDSLength = tlvIn.ReadLength();
        if (versionLDSLength != 4)
        {
            throw new ArgumentException("Wrong length of LDS version object");
        }
        byte[] versionLDSBytes = tlvIn.ReadValue();
        versionLDS = System.Text.Encoding.ASCII.GetString(versionLDSBytes, 0, 2);
        updateLevelLDS = System.Text.Encoding.ASCII.GetString(versionLDSBytes, 2, 2);

        int versionUnicodeTag = tlvIn.ReadTag();
        if (versionUnicodeTag != VERSION_UNICODE_TAG)
        {
            throw new ArgumentException($"Expected VERSION_UNICODE_TAG ({VERSION_UNICODE_TAG:X}), found {versionUnicodeTag:X}");
        }
        int versionUnicodeLength = tlvIn.ReadLength();
        if (versionUnicodeLength != 6)
        {
            throw new ArgumentException("Wrong length of LDS version object");
        }
        byte[] versionUnicodeBytes = tlvIn.ReadValue();
        majorVersionUnicode = System.Text.Encoding.ASCII.GetString(versionUnicodeBytes, 0, 2);
        minorVersionUnicode = System.Text.Encoding.ASCII.GetString(versionUnicodeBytes, 2, 2);
        releaseLevelUnicode = System.Text.Encoding.ASCII.GetString(versionUnicodeBytes, 4, 2);

        int tagListTag = tlvIn.ReadTag();
        if (tagListTag != TAG_LIST_TAG)
        {
            throw new ArgumentException($"Expected TAG_LIST_TAG ({TAG_LIST_TAG:X}), found {tagListTag:X}");
        }
        tlvIn.ReadLength();
        byte[] tagBytes = tlvIn.ReadValue();
        tagList = new List<int>(tagBytes.Length);
        foreach (byte tagByte in tagBytes)
        {
            tagList.Add(tagByte & 0xFF);
        }
    }

    /// <summary>Returns the LDS version as a dot separated string containing version and update level.</summary>
    public string GetLDSVersion()
    {
        if (int.TryParse(versionLDS, out int major) && int.TryParse(updateLevelLDS, out int minor))
        {
            return $"{major}.{minor}";
        }
        return $"{versionLDS}.{updateLevelLDS}";
    }

    /// <summary>Returns the unicode version as a dot separated string containing major version, minor
    /// version, and release level.</summary>
    public string GetUnicodeVersion()
    {
        if (int.TryParse(majorVersionUnicode, out int major)
            && int.TryParse(minorVersionUnicode, out int minor)
            && int.TryParse(releaseLevelUnicode, out int releaseLevel))
        {
            return $"{major}.{minor}.{releaseLevel}";
        }
        return $"{majorVersionUnicode}.{minorVersionUnicode}.{releaseLevelUnicode}";
    }

    /// <summary>Returns the ICAO datagroup tags as a list of bytes.</summary>
    public int[] GetTagList() => [.. tagList];

    /// <summary>Inserts a tag in a proper place if not already present.</summary>
    public void InsertTag(int tag)
    {
        if (tagList.Contains(tag))
        {
            return;
        }
        tagList.Add(tag);
        tagList.Sort();
    }

    protected override void WriteContent(Stream outputStream)
    {
        using var tlvOut = new TlvOutputStream(outputStream, leaveOpen: true);
        tlvOut.WriteTag(VERSION_LDS_TAG);
        tlvOut.WriteValue(System.Text.Encoding.ASCII.GetBytes(versionLDS + updateLevelLDS));
        tlvOut.WriteTag(VERSION_UNICODE_TAG);
        tlvOut.WriteValue(System.Text.Encoding.ASCII.GetBytes(majorVersionUnicode + minorVersionUnicode + releaseLevelUnicode));
        tlvOut.WriteTag(TAG_LIST_TAG);

        byte[] tagBytes = new byte[tagList.Count];
        for (int i = 0; i < tagList.Count; i++)
        {
            tagBytes[i] = (byte)tagList[i];
        }
        /* NOTE: JMRTD calls writeLength(size) then streams one write((byte)tag) per tag; our
         * TlvOutputStream always derives the BER-TLV length from the buffered value on frame close
         * (see its own doc comment), so a single WriteValue call is the equivalent, correct translation --
         * the two-step writeLength/write API this ported from doesn't carry over structurally. */
        tlvOut.WriteValue(tagBytes);
    }

    public override string ToString()
    {
        var result = new System.Text.StringBuilder();
        result.Append("COMFile ");
        result.Append($"LDS {versionLDS}.{updateLevelLDS}");
        result.Append(", ");
        result.Append($"Unicode {majorVersionUnicode}.{minorVersionUnicode}.{releaseLevelUnicode}");
        result.Append(", ");
        result.Append('[');
        int dgCount = tagList.Count;
        for (int i = 0; i < dgCount; i++)
        {
            result.Append("DG" + LDSFileUtil.LookupDataGroupNumberByTag(tagList[i]));
            if (i < dgCount - 1)
            {
                result.Append(", ");
            }
        }
        result.Append(']');
        return result.ToString();
    }

    public override bool Equals(object? other)
    {
        if (other == null)
        {
            return false;
        }
        if (ReferenceEquals(other, this))
        {
            return true;
        }
        if (other.GetType() != GetType())
        {
            return false;
        }

        var otherComFile = (COMFile)other;
        return versionLDS == otherComFile.versionLDS &&
            updateLevelLDS == otherComFile.updateLevelLDS &&
            majorVersionUnicode == otherComFile.majorVersionUnicode &&
            minorVersionUnicode == otherComFile.minorVersionUnicode &&
            releaseLevelUnicode == otherComFile.releaseLevelUnicode &&
            tagList.SequenceEqual(otherComFile.tagList);
    }

    public override int GetHashCode()
    {
        int hash = 17;
        hash = hash * 31 + versionLDS.GetHashCode();
        hash = hash * 31 + updateLevelLDS.GetHashCode();
        hash = hash * 31 + majorVersionUnicode.GetHashCode();
        hash = hash * 31 + minorVersionUnicode.GetHashCode();
        hash = hash * 31 + releaseLevelUnicode.GetHashCode();
        foreach (int tag in tagList)
        {
            hash = hash * 31 + tag;
        }
        return hash;
    }

    /// <summary>Initializes this index file.</summary>
    private void Initialize(string versionLDS, string updateLevelLDS,
        string majorVersionUnicode, string minorVersionUnicode,
        string releaseLevelUnicode, int[] tagList)
    {
        ArgumentNullException.ThrowIfNull(tagList);
        if (versionLDS == null || versionLDS.Length != 2
            || updateLevelLDS == null || updateLevelLDS.Length != 2
            || majorVersionUnicode == null || majorVersionUnicode.Length != 2
            || minorVersionUnicode == null || minorVersionUnicode.Length != 2
            || releaseLevelUnicode == null || releaseLevelUnicode.Length != 2)
        {
            throw new ArgumentException("Malformed COM file component");
        }
        this.versionLDS = versionLDS;
        this.updateLevelLDS = updateLevelLDS;
        this.majorVersionUnicode = majorVersionUnicode;
        this.minorVersionUnicode = minorVersionUnicode;
        this.releaseLevelUnicode = releaseLevelUnicode;
        this.tagList = [.. tagList];
    }
}
