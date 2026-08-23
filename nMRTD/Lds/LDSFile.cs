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

/// <summary>Port of <c>org.jmrtd.lds.LDSFile</c>: LDS element at file level. ICAO tags for the LDS files
/// (EF.COM, EF.DG1 through EF.DG16, EF.SOD) live here so both the base classes and the concrete
/// <c>nMRTD.Lds.Icao</c> file classes can reference them as <c>LDSFile.EF_xxx_TAG</c>.</summary>
public interface LDSFile : LDSElement
{
    /* NOTE: In EAC 1.11 documents there is also the CVCA file that has no tag. */

    /// <summary>ICAO tag for document index (COM).</summary>
    public const int EF_COM_TAG = 0x60;

    /// <summary>ICAO data group tag for DG1.</summary>
    public const int EF_DG1_TAG = 0x61;

    /// <summary>ICAO data group tag for DG2.</summary>
    public const int EF_DG2_TAG = 0x75;

    /// <summary>ICAO data group tag for DG3.</summary>
    public const int EF_DG3_TAG = 0x63;

    /// <summary>ICAO data group tag for DG4.</summary>
    public const int EF_DG4_TAG = 0x76;

    /// <summary>ICAO data group tag for DG5.</summary>
    public const int EF_DG5_TAG = 0x65;

    /// <summary>ICAO data group tag for DG6.</summary>
    public const int EF_DG6_TAG = 0x66;

    /// <summary>ICAO data group tag for DG7.</summary>
    public const int EF_DG7_TAG = 0x67;

    /// <summary>ICAO data group tag for DG8.</summary>
    public const int EF_DG8_TAG = 0x68;

    /// <summary>ICAO data group tag for DG9.</summary>
    public const int EF_DG9_TAG = 0x69;

    /// <summary>ICAO data group tag for DG10.</summary>
    public const int EF_DG10_TAG = 0x6A;

    /// <summary>ICAO data group tag for DG11.</summary>
    public const int EF_DG11_TAG = 0x6B;

    /// <summary>ICAO data group tag for DG12.</summary>
    public const int EF_DG12_TAG = 0x6C;

    /// <summary>ICAO data group tag for DG13.</summary>
    public const int EF_DG13_TAG = 0x6D;

    /// <summary>ICAO data group tag for DG14.</summary>
    public const int EF_DG14_TAG = 0x6E;

    /// <summary>ICAO data group tag for DG15.</summary>
    public const int EF_DG15_TAG = 0x6F;

    /// <summary>ICAO data group tag for DG16.</summary>
    public const int EF_DG16_TAG = 0x70;

    /// <summary>ICAO tag for document security index (SOd).</summary>
    public const int EF_SOD_TAG = 0x77;

    /* FIXME: Note that this is not necessarily the total length of the file: for TLV files this
     * gives the length of the value. -- MO (carried over from JMRTD source comment) */

    /// <summary>Returns the length of this file.</summary>
    int GetLength();
}
