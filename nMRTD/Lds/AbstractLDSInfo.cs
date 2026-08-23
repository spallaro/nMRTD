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

/// <summary>Port of <c>org.jmrtd.lds.AbstractLDSInfo</c>: base class for data structures that are
/// contained in files in the LDS.</summary>
public abstract class AbstractLDSInfo : LDSElement
{
    /// <summary>Returns an encoding of this LDS info, or <c>null</c> if encoding failed.</summary>
    public byte[]? GetEncoded()
    {
        try
        {
            using var outputStream = new MemoryStream();
            WriteObject(outputStream);
            outputStream.Flush();
            return outputStream.ToArray();
        }
        catch (IOException)
        {
            /* NOTE: Java logs a warning here and returns null on failure; see AbstractLDSFile.cs for the
             * same non-essential-warning-omission precedent applied here. */
            return null;
        }
    }

    /// <summary>Writes this LDS info to a stream.</summary>
    public abstract void WriteObject(Stream outputStream);
}
