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

namespace nMRTD.Lds.Icao;

/// <summary>Port of <c>org.jmrtd.lds.icao.DG6File</c>: file structure for the EF.DG6 file.</summary>
public class DG6File : DisplayedImageDataGroup
{
    /// <summary>Constructs a new file from binary representation.</summary>
    public DG6File(Stream inputStream)
        : base(LDSFileTags.EF_DG6_TAG, inputStream)
    {
    }
}
