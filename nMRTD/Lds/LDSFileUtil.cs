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

using nMRTD.Lds.Icao;

namespace nMRTD.Lds;

/// <summary>
/// Port of <c>org.jmrtd.lds.LDSFileUtil</c>: static LDS file methods (FID/tag/SFI/data-group-number
/// lookup tables and a factory method for constructing the right LDS file type for a given FID).
/// </summary>
/// <remarks>
/// Java's <c>getLDSFile(short, InputStream)</c> dispatches (by reflection-free switch, matching
/// porting-conventions.md's "no reflection" rule already) across all EF_DG1-EF_DG16 types. Java itself has
/// no dedicated file type for DG8/DG9/DG10/DG13/DG16 (there is no <c>DG8File</c>/etc. in JMRTD at all --
/// those data groups have no ICAO-standardized parseable content), so those branches below throw
/// <see cref="NotSupportedException"/> matching upstream exactly, not as a porting gap.
/// <c>FidToSfi</c> is the one member here with a load-bearing exact name/type: the already-committed
/// <c>DefaultFileSystem.cs</c> references <c>Lds.LDSFileUtil.FidToSfi</c> as an
/// <c>IReadOnlyDictionary&lt;short, byte&gt;</c>. <c>PassportService.EF_*</c>/<c>SFI_*</c> below are
/// forward references to <c>nMRTD.PassportService</c>, a large not-yet-ported file outside this task's
/// scope, mirroring the same forward-reference pattern already used by the committed
/// <c>DefaultFileSystem.cs</c>.
/// </remarks>
public static class LDSFileUtil
{
    public static readonly IReadOnlyDictionary<short, byte> FidToSfi = CreateFidToSfiMap();

    /// <summary>Factory method for creating LDS files for a given input stream.</summary>
    /// <param name="fid">file identifier</param>
    /// <param name="inputStream">a given input stream</param>
    /// <returns>a specific file</returns>
    public static AbstractLDSFile GetLDSFile(short fid, Stream inputStream)
    {
        switch (fid)
        {
            case PassportService.EF_COM:
                return new COMFile(inputStream);
            case PassportService.EF_DG1:
                return new DG1File(inputStream);
            case PassportService.EF_DG2:
                return new DG2File(inputStream);
            case PassportService.EF_DG3:
                return new DG3File(inputStream);
            case PassportService.EF_DG4:
                return new DG4File(inputStream);
            case PassportService.EF_DG5:
                return new DG5File(inputStream);
            case PassportService.EF_DG6:
                return new DG6File(inputStream);
            case PassportService.EF_DG7:
                return new DG7File(inputStream);
            case PassportService.EF_DG8:
                throw new NotSupportedException("DG8 files are not yet supported");
            case PassportService.EF_DG9:
                throw new NotSupportedException("DG9 files are not yet supported");
            case PassportService.EF_DG10:
                throw new NotSupportedException("DG10 files are not yet supported");
            case PassportService.EF_DG11:
                return new DG11File(inputStream);
            case PassportService.EF_DG12:
                return new DG12File(inputStream);
            case PassportService.EF_DG13:
                throw new NotSupportedException("DG13 files are not yet supported");
            case PassportService.EF_DG14:
                return new DG14File(inputStream);
            case PassportService.EF_DG15:
                return new DG15File(inputStream);
            case PassportService.EF_DG16:
                throw new NotSupportedException("DG16 files are not yet supported");
            case PassportService.EF_SOD:
                return new SODFile(inputStream);
            case PassportService.EF_CVCA:
                return new CVCAFile(inputStream);
            default:
                /* NOTE: Java buffers/marks/resets the stream here before attempting a CVCAFile parse as
                 * a fallback, then rethrows regardless of success/failure of the reset -- meaning the
                 * mark/reset dance doesn't actually enable any recovery for the caller, it just throws
                 * either way. Simplified here to a direct attempt without the pointless buffering. */
                try
                {
                    return new CVCAFile(fid, inputStream);
                }
                catch (Exception e)
                {
                    throw new FormatException($"Unknown file {fid:x}", e);
                }
        }
    }

    public static COMFile GetCOMFile(Stream inputStream) => new(inputStream);

    public static CVCAFile GetCVCAFile(Stream inputStream) => new(inputStream);

    public static DG1File GetDG1File(Stream inputStream) => new(inputStream);

    public static DG2File GetDG2File(Stream inputStream) => new(inputStream);

    public static DG3File GetDG3File(Stream inputStream) => new(inputStream);

    public static DG4File GetDG4File(Stream inputStream) => new(inputStream);

    public static DG5File GetDG5File(Stream inputStream) => new(inputStream);

    public static DG6File GetDG6File(Stream inputStream) => new(inputStream);

    public static DG7File GetDG7File(Stream inputStream) => new(inputStream);

    public static DG11File GetDG11File(Stream inputStream) => new(inputStream);

    public static DG12File GetDG12File(Stream inputStream) => new(inputStream);

    public static DG14File GetDG14File(Stream inputStream) => new(inputStream);

    public static DG15File GetDG15File(Stream inputStream) => new(inputStream);

    public static SODFile GetSODFile(Stream inputStream) => new(inputStream);

    /// <summary>Finds a file identifier for an ICAO tag. Corresponds to Table A1 in ICAO-TR-LDS_1.7_2004-05-18.</summary>
    /// <param name="tag">an ICAO tag (the first byte of the EF)</param>
    /// <returns>a file identifier</returns>
    public static short LookupFIDByTag(int tag) => tag switch
    {
        LDSFileTags.EF_COM_TAG => PassportService.EF_COM,
        LDSFileTags.EF_DG1_TAG => PassportService.EF_DG1,
        LDSFileTags.EF_DG2_TAG => PassportService.EF_DG2,
        LDSFileTags.EF_DG3_TAG => PassportService.EF_DG3,
        LDSFileTags.EF_DG4_TAG => PassportService.EF_DG4,
        LDSFileTags.EF_DG5_TAG => PassportService.EF_DG5,
        LDSFileTags.EF_DG6_TAG => PassportService.EF_DG6,
        LDSFileTags.EF_DG7_TAG => PassportService.EF_DG7,
        LDSFileTags.EF_DG8_TAG => PassportService.EF_DG8,
        LDSFileTags.EF_DG9_TAG => PassportService.EF_DG9,
        LDSFileTags.EF_DG10_TAG => PassportService.EF_DG10,
        LDSFileTags.EF_DG11_TAG => PassportService.EF_DG11,
        LDSFileTags.EF_DG12_TAG => PassportService.EF_DG12,
        LDSFileTags.EF_DG13_TAG => PassportService.EF_DG13,
        LDSFileTags.EF_DG14_TAG => PassportService.EF_DG14,
        LDSFileTags.EF_DG15_TAG => PassportService.EF_DG15,
        LDSFileTags.EF_DG16_TAG => PassportService.EF_DG16,
        LDSFileTags.EF_SOD_TAG => PassportService.EF_SOD,
        _ => throw new FormatException($"Unknown tag {tag:x}"),
    };

    /// <summary>Finds a data group number for an ICAO tag.</summary>
    /// <param name="tag">an ICAO tag (the first byte of the EF)</param>
    /// <returns>a data group number (1-16)</returns>
    public static int LookupDataGroupNumberByTag(int tag) => tag switch
    {
        LDSFileTags.EF_DG1_TAG => 1,
        LDSFileTags.EF_DG2_TAG => 2,
        LDSFileTags.EF_DG3_TAG => 3,
        LDSFileTags.EF_DG4_TAG => 4,
        LDSFileTags.EF_DG5_TAG => 5,
        LDSFileTags.EF_DG6_TAG => 6,
        LDSFileTags.EF_DG7_TAG => 7,
        LDSFileTags.EF_DG8_TAG => 8,
        LDSFileTags.EF_DG9_TAG => 9,
        LDSFileTags.EF_DG10_TAG => 10,
        LDSFileTags.EF_DG11_TAG => 11,
        LDSFileTags.EF_DG12_TAG => 12,
        LDSFileTags.EF_DG13_TAG => 13,
        LDSFileTags.EF_DG14_TAG => 14,
        LDSFileTags.EF_DG15_TAG => 15,
        LDSFileTags.EF_DG16_TAG => 16,
        _ => throw new FormatException($"Unknown tag {tag:x}"),
    };

    /// <summary>Finds an ICAO tag for a data group number.</summary>
    /// <param name="number">a data group number (1-16)</param>
    /// <returns>an ICAO tag (the first byte of the EF)</returns>
    public static int LookupTagByDataGroupNumber(int number) => number switch
    {
        1 => LDSFileTags.EF_DG1_TAG,
        2 => LDSFileTags.EF_DG2_TAG,
        3 => LDSFileTags.EF_DG3_TAG,
        4 => LDSFileTags.EF_DG4_TAG,
        5 => LDSFileTags.EF_DG5_TAG,
        6 => LDSFileTags.EF_DG6_TAG,
        7 => LDSFileTags.EF_DG7_TAG,
        8 => LDSFileTags.EF_DG8_TAG,
        9 => LDSFileTags.EF_DG9_TAG,
        10 => LDSFileTags.EF_DG10_TAG,
        11 => LDSFileTags.EF_DG11_TAG,
        12 => LDSFileTags.EF_DG12_TAG,
        13 => LDSFileTags.EF_DG13_TAG,
        14 => LDSFileTags.EF_DG14_TAG,
        15 => LDSFileTags.EF_DG15_TAG,
        16 => LDSFileTags.EF_DG16_TAG,
        _ => throw new FormatException($"Unknown number {number}"),
    };

    /// <summary>Finds a file identifier for a data group number.</summary>
    /// <param name="number">a data group number (1-16)</param>
    /// <returns>a file identifier</returns>
    public static short LookupFIDByDataGroupNumber(int number) => number switch
    {
        1 => PassportService.EF_DG1,
        2 => PassportService.EF_DG2,
        3 => PassportService.EF_DG3,
        4 => PassportService.EF_DG4,
        5 => PassportService.EF_DG5,
        6 => PassportService.EF_DG6,
        7 => PassportService.EF_DG7,
        8 => PassportService.EF_DG8,
        9 => PassportService.EF_DG9,
        10 => PassportService.EF_DG10,
        11 => PassportService.EF_DG11,
        12 => PassportService.EF_DG12,
        13 => PassportService.EF_DG13,
        14 => PassportService.EF_DG14,
        15 => PassportService.EF_DG15,
        16 => PassportService.EF_DG16,
        _ => throw new FormatException($"Unknown number {number}"),
    };

    /// <summary>Finds an ICAO tag for a file identifier. Corresponds to Table A1 in ICAO-TR-LDS_1.7_2004-05-18.</summary>
    /// <param name="fid">a file identifier</param>
    /// <returns>an ICAO tag (first byte of EF)</returns>
    public static short LookupTagByFID(short fid) => fid switch
    {
        PassportService.EF_COM => LDSFileTags.EF_COM_TAG,
        PassportService.EF_DG1 => LDSFileTags.EF_DG1_TAG,
        PassportService.EF_DG2 => LDSFileTags.EF_DG2_TAG,
        PassportService.EF_DG3 => LDSFileTags.EF_DG3_TAG,
        PassportService.EF_DG4 => LDSFileTags.EF_DG4_TAG,
        PassportService.EF_DG5 => LDSFileTags.EF_DG5_TAG,
        PassportService.EF_DG6 => LDSFileTags.EF_DG6_TAG,
        PassportService.EF_DG7 => LDSFileTags.EF_DG7_TAG,
        PassportService.EF_DG8 => LDSFileTags.EF_DG8_TAG,
        PassportService.EF_DG9 => LDSFileTags.EF_DG9_TAG,
        PassportService.EF_DG10 => LDSFileTags.EF_DG10_TAG,
        PassportService.EF_DG11 => LDSFileTags.EF_DG11_TAG,
        PassportService.EF_DG12 => LDSFileTags.EF_DG12_TAG,
        PassportService.EF_DG13 => LDSFileTags.EF_DG13_TAG,
        PassportService.EF_DG14 => LDSFileTags.EF_DG14_TAG,
        PassportService.EF_DG15 => LDSFileTags.EF_DG15_TAG,
        PassportService.EF_DG16 => LDSFileTags.EF_DG16_TAG,
        PassportService.EF_SOD => LDSFileTags.EF_SOD_TAG,
        _ => throw new FormatException($"Unknown fid {fid:x}"),
    };

    /// <summary>Finds a data group number by file identifier.</summary>
    /// <param name="fid">a file id</param>
    /// <returns>a data group number</returns>
    public static int LookupDataGroupNumberByFID(short fid) => fid switch
    {
        PassportService.EF_DG1 => 1,
        PassportService.EF_DG2 => 2,
        PassportService.EF_DG3 => 3,
        PassportService.EF_DG4 => 4,
        PassportService.EF_DG5 => 5,
        PassportService.EF_DG6 => 6,
        PassportService.EF_DG7 => 7,
        PassportService.EF_DG8 => 8,
        PassportService.EF_DG9 => 9,
        PassportService.EF_DG10 => 10,
        PassportService.EF_DG11 => 11,
        PassportService.EF_DG12 => 12,
        PassportService.EF_DG13 => 13,
        PassportService.EF_DG14 => 14,
        PassportService.EF_DG15 => 15,
        PassportService.EF_DG16 => 16,
        _ => throw new FormatException($"Unknown fid {fid:x}"),
    };

    /// <summary>Returns a mnemonic name corresponding to the file represented by the given ICAO tag, such as "EF_COM", "EF_SOD", or "EF_DG1".</summary>
    /// <param name="tag">an ICAO tag (the first byte of the EF)</param>
    public static string LookupFileNameByTag(int tag) => tag switch
    {
        LDSFileTags.EF_COM_TAG => "EF_COM",
        LDSFileTags.EF_DG1_TAG => "EF_DG1",
        LDSFileTags.EF_DG2_TAG => "EF_DG2",
        LDSFileTags.EF_DG3_TAG => "EF_DG3",
        LDSFileTags.EF_DG4_TAG => "EF_DG4",
        LDSFileTags.EF_DG5_TAG => "EF_DG5",
        LDSFileTags.EF_DG6_TAG => "EF_DG6",
        LDSFileTags.EF_DG7_TAG => "EF_DG7",
        LDSFileTags.EF_DG8_TAG => "EF_DG8",
        LDSFileTags.EF_DG9_TAG => "EF_DG9",
        LDSFileTags.EF_DG10_TAG => "EF_DG10",
        LDSFileTags.EF_DG11_TAG => "EF_DG11",
        LDSFileTags.EF_DG12_TAG => "EF_DG12",
        LDSFileTags.EF_DG13_TAG => "EF_DG13",
        LDSFileTags.EF_DG14_TAG => "EF_DG14",
        LDSFileTags.EF_DG15_TAG => "EF_DG15",
        LDSFileTags.EF_DG16_TAG => "EF_DG16",
        LDSFileTags.EF_SOD_TAG => "EF_SOD",
        _ => $"File with tag 0x{tag:x}",
    };

    /// <summary>Returns a mnemonic name corresponding to the file represented by the given file identifier, such as "EF_COM", "EF_SOD", or "EF_DG1".</summary>
    /// <param name="fid">an LDS file identifier</param>
    public static string LookupFileNameByFID(int fid) => fid switch
    {
        PassportService.EF_COM => "EF_COM",
        PassportService.EF_DG1 => "EF_DG1",
        PassportService.EF_DG2 => "EF_DG2",
        PassportService.EF_DG3 => "EF_DG3",
        PassportService.EF_DG4 => "EF_DG4",
        PassportService.EF_DG5 => "EF_DG5",
        PassportService.EF_DG6 => "EF_DG6",
        PassportService.EF_DG7 => "EF_DG7",
        PassportService.EF_DG8 => "EF_DG8",
        PassportService.EF_DG9 => "EF_DG9",
        PassportService.EF_DG10 => "EF_DG10",
        PassportService.EF_DG11 => "EF_DG11",
        PassportService.EF_DG12 => "EF_DG12",
        PassportService.EF_DG13 => "EF_DG13",
        PassportService.EF_DG14 => "EF_DG14",
        PassportService.EF_DG15 => "EF_DG15",
        PassportService.EF_DG16 => "EF_DG16",
        PassportService.EF_SOD => "EF_SOD",
        _ => $"File with FID 0x{fid:x}",
    };

    /// <summary>Returns the short (one byte) file identifier corresponding to the given (two byte) file identifier.</summary>
    /// <param name="fid">a file identifier</param>
    /// <returns>the corresponding short file identifier</returns>
    public static int LookupSFIByFID(short fid)
    {
        if (!FidToSfi.TryGetValue(fid, out byte sfiByte))
        {
            throw new FormatException($"Unknown FID {fid:x}");
        }

        return sfiByte & 0xFF;
    }

    /// <summary>Looks up a file identifier for a given short file identifier.</summary>
    /// <param name="sfi">the short file identifier</param>
    /// <returns>a file identifier</returns>
    public static short LookupFIDBySFI(byte sfi) => sfi switch
    {
        PassportService.SFI_COM => PassportService.EF_COM,
        PassportService.SFI_DG1 => PassportService.EF_DG1,
        PassportService.SFI_DG2 => PassportService.EF_DG2,
        PassportService.SFI_DG3 => PassportService.EF_DG3,
        PassportService.SFI_DG4 => PassportService.EF_DG4,
        PassportService.SFI_DG5 => PassportService.EF_DG5,
        PassportService.SFI_DG6 => PassportService.EF_DG6,
        PassportService.SFI_DG7 => PassportService.EF_DG7,
        PassportService.SFI_DG8 => PassportService.EF_DG8,
        PassportService.SFI_DG9 => PassportService.EF_DG9,
        PassportService.SFI_DG10 => PassportService.EF_DG10,
        PassportService.SFI_DG11 => PassportService.EF_DG11,
        PassportService.SFI_DG12 => PassportService.EF_DG12,
        PassportService.SFI_DG13 => PassportService.EF_DG13,
        PassportService.SFI_DG14 => PassportService.EF_DG14,
        PassportService.SFI_DG15 => PassportService.EF_DG15,
        PassportService.SFI_DG16 => PassportService.EF_DG16,
        PassportService.SFI_SOD => PassportService.EF_SOD,
        PassportService.SFI_CVCA => PassportService.EF_CVCA,
        _ => throw new FormatException($"Unknown SFI {sfi:x}"),
    };

    /// <summary>Returns the data group list from the security object (SOd).</summary>
    /// <param name="sodFile">the security object</param>
    /// <returns>the list of data group numbers</returns>
    public static List<int> GetDataGroupNumbers(SODFile? sodFile)
    {
        /* Get the list of DGs from EF.SOd, we don't trust EF.COM. */
        var dgNumbers = new List<int>();
        if (sodFile == null)
        {
            return dgNumbers;
        }

        dgNumbers.AddRange(sodFile.GetDataGroupHashes().Keys);
        dgNumbers.Sort(); /* NOTE: need to sort it, since we get keys from a set-like source. */
        return dgNumbers;
    }

    /// <summary>Returns the data group list from the document index file (COM).</summary>
    /// <param name="comFile">the document index file</param>
    /// <returns>the list with data group number according to the document index file</returns>
    public static List<int> GetDataGroupNumbers(COMFile? comFile)
    {
        var dgNumbers = new List<int>();
        if (comFile == null)
        {
            return dgNumbers;
        }

        int[] tagList = comFile.GetTagList();
        dgNumbers.AddRange(ToDataGroupList(tagList));
        dgNumbers.Sort(); // NOTE: sort it, just in case.
        return dgNumbers;
    }

    /// <summary>Converts a list with ICAO tags into a list of ICAO data group numbers.</summary>
    /// <param name="tagList">a list of tags specified in ICAO Doc 9303</param>
    /// <returns>the list with data group number according to the security object</returns>
    private static List<int> ToDataGroupList(int[]? tagList)
    {
        if (tagList == null)
        {
            return [];
        }
        var dgNumberList = new List<int>(tagList.Length);
        foreach (int tag in tagList)
        {
            try
            {
                int dgNumber = LookupDataGroupNumberByTag(tag);
                dgNumberList.Add(dgNumber);
            }
            catch (FormatException)
            {
                // NOTE: JMRTD logs a warning here ("Could not find DG number for tag..."); per
                // porting-conventions.md this non-essential warning branch is simply not logged.
            }
        }
        return dgNumberList;
    }

    /// <summary>Creates a map for looking up short file identifiers based on file identifiers.</summary>
    private static Dictionary<short, byte> CreateFidToSfiMap() => new(20)
    {
        [PassportService.EF_COM] = PassportService.SFI_COM,
        [PassportService.EF_DG1] = PassportService.SFI_DG1,
        [PassportService.EF_DG2] = PassportService.SFI_DG2,
        [PassportService.EF_DG3] = PassportService.SFI_DG3,
        [PassportService.EF_DG4] = PassportService.SFI_DG4,
        [PassportService.EF_DG5] = PassportService.SFI_DG5,
        [PassportService.EF_DG6] = PassportService.SFI_DG6,
        [PassportService.EF_DG7] = PassportService.SFI_DG7,
        [PassportService.EF_DG8] = PassportService.SFI_DG8,
        [PassportService.EF_DG9] = PassportService.SFI_DG9,
        [PassportService.EF_DG10] = PassportService.SFI_DG10,
        [PassportService.EF_DG11] = PassportService.SFI_DG11,
        [PassportService.EF_DG12] = PassportService.SFI_DG12,
        [PassportService.EF_DG13] = PassportService.SFI_DG13,
        [PassportService.EF_DG14] = PassportService.SFI_DG14,
        [PassportService.EF_DG15] = PassportService.SFI_DG15,
        [PassportService.EF_DG16] = PassportService.SFI_DG16,
        [PassportService.EF_SOD] = PassportService.SFI_SOD,
        [PassportService.EF_CVCA] = PassportService.SFI_CVCA,
    };
}
