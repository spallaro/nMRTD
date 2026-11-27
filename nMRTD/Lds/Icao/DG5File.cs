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

/// <summary>Port of <c>org.jmrtd.lds.icao.DG5File</c>: file structure for the EF.DG5 file (displayed portrait images).</summary>
public class DG5File : DisplayedImageDataGroup
{
    /// <summary>Constructs a new file from a list of displayed images.</summary>
    /// <param name="images">the displayed images, all of which should be of type <i>Portrait</i></param>
    public DG5File(List<DisplayedImageInfo> images)
        : base(LDSFileTags.EF_DG5_TAG, images, DisplayedImageInfo.DISPLAYED_PORTRAIT_TAG)
    {
    }

    /// <summary>Constructs a new file from binary representation.</summary>
    public DG5File(Stream inputStream)
        : base(LDSFileTags.EF_DG5_TAG, inputStream)
    {
    }
}
