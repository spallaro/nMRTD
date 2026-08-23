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

namespace nMRTD;

/// <summary>Port of <c>org.jmrtd.FileSystemCardService</c>: a card service that acts as a (file identifier indexed) file system.</summary>
public abstract class FileSystemCardService : CardService
{
    /// <summary>Returns a stream to access the file indicated by the file identifier.</summary>
    /// <param name="fid">the file identifier</param>
    /// <returns>a stream to read from</returns>
    /// <exception cref="CardServiceException">on error creating the stream</exception>
    [Obsolete("Use the other overload with explicit max block size.")]
    public abstract CardFileInputStream GetInputStream(short fid);

    /// <summary>Returns a stream to access the file indicated by the file identifier.</summary>
    /// <param name="fid">the file identifier</param>
    /// <param name="maxBlockSize">maximum block size to use for read binaries</param>
    /// <returns>a stream to read from</returns>
    /// <exception cref="CardServiceException">on error creating the stream</exception>
    public abstract CardFileInputStream GetInputStream(short fid, int maxBlockSize);
}
