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

/// <summary>Port of <c>org.jmrtd.lds.AbstractLDSFile</c>: base class for all files (EF.COM, EF.SOD, and
/// data groups) in the LDS.
///
/// NOTE on visibility: the Java class is package-private (only <c>AbstractTaggedLDSFile</c> in the same
/// package extends it). C# requires a base class to be at least as accessible as its most accessible
/// derived class, and <c>AbstractTaggedLDSFile</c>/<c>DataGroup</c> must be public (concrete file classes
/// in <c>nMRTD.Lds.Icao</c> extend them), so this class is public here too.</summary>
public abstract class AbstractLDSFile : LDSFile
{
    /// <summary>Returns the contents of this file as byte array, includes the ICAO tag and length.</summary>
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
            /* NOTE: Java logs a warning here and returns null on failure. This port follows the
             * non-essential-warning-omission precedent already established elsewhere in this codebase
             * (see DefaultFileSystem.cs) and simply returns null. */
            return null;
        }
    }

    /// <summary>Reads the file from an input stream.</summary>
    protected abstract void ReadObject(Stream inputStream);

    /// <summary>Writes the file to an output stream.</summary>
    protected abstract void WriteObject(Stream outputStream);

    /// <summary>Returns the length of this file.</summary>
    public abstract int GetLength();
}
