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

namespace nMRTD.SmartCards;

/// <summary>
/// Port of <c>net.sf.scuba.smartcards.FileSystemStructured</c>. Implementations throw
/// <see cref="CardServiceException"/> on I/O failure (Java's checked-exception contract has no direct
/// C# equivalent, so this is a documentation-only constraint, not an enforced one).
/// </summary>
public interface IFileSystemStructured
{
    FileInfo[] GetSelectedPath();

    void SelectFile(short fid);

    byte[] ReadBinary(int offset, int length);
}
