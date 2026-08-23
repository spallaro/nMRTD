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

/// <summary>Port of <c>org.jmrtd.lds.LDSElement</c>: top level interface for all data structures in the LDS.</summary>
public interface LDSElement
{
    /// <summary>Returns the encoded contents of this LDS info, or <c>null</c> if encoding failed.</summary>
    byte[]? GetEncoded();
}
