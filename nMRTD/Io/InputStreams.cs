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

namespace nMRTD.Io;

/// <summary>
/// Helpers for reading from input streams with untrusted lengths. Port of JMRTD's
/// <c>org.jmrtd.io.InputStreams</c> (0.8.10, commit a4b9e9e2).
/// </summary>
internal static class InputStreams
{
    /// <summary>The size of the chunks in which <see cref="ReadFully"/> reads.</summary>
    private const int ChunkSize = 64 * 1024;

    /// <summary>
    /// Skips exactly <paramref name="n"/> bytes with a Java-style <paramref name="skip"/> function, which returns the
    /// number of bytes it skipped (0 at the end of the stream). Unlike a loop around it, which keeps getting 0 at the
    /// end of the stream, this does not loop forever on a truncated stream.
    /// </summary>
    /// <param name="skip">skips up to the given number of bytes and returns how many were skipped</param>
    /// <param name="n">the number of bytes to skip</param>
    /// <exception cref="EndOfStreamException">if the stream ends before <paramref name="n"/> bytes were skipped</exception>
    public static void SkipFully(Func<long, long> skip, long n)
    {
        long remaining = n;
        while (remaining > 0)
        {
            long skipped = skip(remaining);
            if (skipped <= 0)
            {
                throw new EndOfStreamException($"End of stream after skipping {n - remaining} of {n} bytes");
            }
            remaining -= skipped;
        }
    }

    /// <summary>
    /// Reads exactly <paramref name="length"/> bytes. The length typically comes from the input itself, so memory is
    /// allocated as bytes actually arrive, not up front: a large length on a short stream leads to an
    /// <see cref="EndOfStreamException"/>, not to an <see cref="OutOfMemoryException"/> or an overflow.
    /// </summary>
    /// <param name="inputStream">the stream</param>
    /// <param name="length">the number of bytes to read</param>
    /// <returns>the bytes read</returns>
    /// <exception cref="EndOfStreamException">if the stream ends before <paramref name="length"/> bytes were read</exception>
    /// <exception cref="IOException">if <paramref name="length"/> is negative or too large for an array</exception>
    public static byte[] ReadFully(Stream inputStream, long length)
    {
        if (length < 0 || length > int.MaxValue - 8)
        {
            throw new IOException($"Invalid length {length}");
        }

        using var output = new MemoryStream((int)Math.Min(length, ChunkSize));
        byte[] buffer = new byte[(int)Math.Min(length, ChunkSize)];
        long remaining = length;
        while (remaining > 0)
        {
            int bytesRead = inputStream.Read(buffer, 0, (int)Math.Min(remaining, buffer.Length));
            if (bytesRead <= 0)
            {
                throw new EndOfStreamException($"End of stream after reading {length - remaining} of {length} bytes");
            }
            output.Write(buffer, 0, bytesRead);
            remaining -= bytesRead;
        }
        return output.ToArray();
    }
}
