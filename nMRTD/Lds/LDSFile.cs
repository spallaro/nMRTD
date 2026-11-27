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

namespace nMRTD.Lds;

/// <summary>Port of <c>org.jmrtd.lds.LDSFile</c>: LDS element at file level. The ICAO tags of the LDS files
/// (EF.COM, EF.DG1 through EF.DG16, EF.SOD), which JMRTD declares here, are in <see cref="LDSFileTags"/>.</summary>
public interface LDSFile : LDSElement
{
#if !NETFRAMEWORK
    // The constants are in LDSFileTags: .NET Framework does not allow static members in interfaces.
    // These forwarders keep existing code compiling on the other targets.

    /// <summary>ICAO tag for document index (COM).</summary>
    [Obsolete("Use LDSFileTags.EF_COM_TAG.")]
    public const int EF_COM_TAG = LDSFileTags.EF_COM_TAG;

    /// <summary>ICAO data group tag for DG1.</summary>
    [Obsolete("Use LDSFileTags.EF_DG1_TAG.")]
    public const int EF_DG1_TAG = LDSFileTags.EF_DG1_TAG;

    /// <summary>ICAO data group tag for DG2.</summary>
    [Obsolete("Use LDSFileTags.EF_DG2_TAG.")]
    public const int EF_DG2_TAG = LDSFileTags.EF_DG2_TAG;

    /// <summary>ICAO data group tag for DG3.</summary>
    [Obsolete("Use LDSFileTags.EF_DG3_TAG.")]
    public const int EF_DG3_TAG = LDSFileTags.EF_DG3_TAG;

    /// <summary>ICAO data group tag for DG4.</summary>
    [Obsolete("Use LDSFileTags.EF_DG4_TAG.")]
    public const int EF_DG4_TAG = LDSFileTags.EF_DG4_TAG;

    /// <summary>ICAO data group tag for DG5.</summary>
    [Obsolete("Use LDSFileTags.EF_DG5_TAG.")]
    public const int EF_DG5_TAG = LDSFileTags.EF_DG5_TAG;

    /// <summary>ICAO data group tag for DG6.</summary>
    [Obsolete("Use LDSFileTags.EF_DG6_TAG.")]
    public const int EF_DG6_TAG = LDSFileTags.EF_DG6_TAG;

    /// <summary>ICAO data group tag for DG7.</summary>
    [Obsolete("Use LDSFileTags.EF_DG7_TAG.")]
    public const int EF_DG7_TAG = LDSFileTags.EF_DG7_TAG;

    /// <summary>ICAO data group tag for DG8.</summary>
    [Obsolete("Use LDSFileTags.EF_DG8_TAG.")]
    public const int EF_DG8_TAG = LDSFileTags.EF_DG8_TAG;

    /// <summary>ICAO data group tag for DG9.</summary>
    [Obsolete("Use LDSFileTags.EF_DG9_TAG.")]
    public const int EF_DG9_TAG = LDSFileTags.EF_DG9_TAG;

    /// <summary>ICAO data group tag for DG10.</summary>
    [Obsolete("Use LDSFileTags.EF_DG10_TAG.")]
    public const int EF_DG10_TAG = LDSFileTags.EF_DG10_TAG;

    /// <summary>ICAO data group tag for DG11.</summary>
    [Obsolete("Use LDSFileTags.EF_DG11_TAG.")]
    public const int EF_DG11_TAG = LDSFileTags.EF_DG11_TAG;

    /// <summary>ICAO data group tag for DG12.</summary>
    [Obsolete("Use LDSFileTags.EF_DG12_TAG.")]
    public const int EF_DG12_TAG = LDSFileTags.EF_DG12_TAG;

    /// <summary>ICAO data group tag for DG13.</summary>
    [Obsolete("Use LDSFileTags.EF_DG13_TAG.")]
    public const int EF_DG13_TAG = LDSFileTags.EF_DG13_TAG;

    /// <summary>ICAO data group tag for DG14.</summary>
    [Obsolete("Use LDSFileTags.EF_DG14_TAG.")]
    public const int EF_DG14_TAG = LDSFileTags.EF_DG14_TAG;

    /// <summary>ICAO data group tag for DG15.</summary>
    [Obsolete("Use LDSFileTags.EF_DG15_TAG.")]
    public const int EF_DG15_TAG = LDSFileTags.EF_DG15_TAG;

    /// <summary>ICAO data group tag for DG16.</summary>
    [Obsolete("Use LDSFileTags.EF_DG16_TAG.")]
    public const int EF_DG16_TAG = LDSFileTags.EF_DG16_TAG;

    /// <summary>ICAO tag for document security index (SOd).</summary>
    [Obsolete("Use LDSFileTags.EF_SOD_TAG.")]
    public const int EF_SOD_TAG = LDSFileTags.EF_SOD_TAG;
#endif

    /* FIXME: Note that this is not necessarily the total length of the file: for TLV files this
     * gives the length of the value. -- MO (carried over from JMRTD source comment) */

    /// <summary>Returns the length of this file.</summary>
    int GetLength();
}
