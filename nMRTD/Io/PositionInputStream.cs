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
/// Port of <c>org.jmrtd.io.PositionInputStream</c>. A stream that decorates an existing stream and
/// keeps track of the current position. Java's <c>InputStream.mark(int)</c>/<c>reset()</c> pair is
/// modeled here via the wrapped stream's own seek support (<see cref="Stream.CanSeek"/>): a genuinely
/// seekable carrier can save/restore an exact position, which is a strict superset of Java's
/// readLimit-bounded mark; a non-seekable carrier silently ignores <see cref="Mark"/> (matching
/// <c>java.io.InputStream</c>'s own default no-op <c>mark()</c>) and <see cref="Reset"/> then throws,
/// matching <c>java.io.InputStream</c>'s default <c>reset()</c> contract.
/// </summary>
/// <remarks>
/// The original Java class logs a warning via <c>java.util.logging.Logger</c> when the carrier's
/// <c>skip()</c> under-delivers. Per porting-conventions.md, pulling in
/// <c>Microsoft.Extensions.Logging.Abstractions</c> for this one warning in a very small decorator class
/// was judged not worth it; the condition is simply not logged here.
/// </remarks>
public class PositionInputStream : Stream
{
    private readonly Stream _carrier;

    private int _position;
    private int _markedPosition = -1;
    private long _markedCarrierPosition;

    /// <summary>Constructs a position input stream by decorating an existing stream.</summary>
    /// <param name="carrier">the existing stream</param>
    public PositionInputStream(Stream carrier)
    {
        _carrier = carrier ?? throw new ArgumentNullException(nameof(carrier));
    }

    /// <summary>Whether this stream supports <see cref="Mark"/>/<see cref="Reset"/> (mirrors the wrapped stream's seek support).</summary>
    public bool MarkSupported => _carrier.CanSeek;

    public override bool CanRead => true;

    public override bool CanWrite => false;

    public override bool CanSeek => false;

    public override long Length => throw new NotSupportedException();

    /// <summary>The position within the stream.</summary>
    public override long Position
    {
        get => _position;
        set => throw new NotSupportedException("PositionInputStream does not support setting Position directly; use Mark()/Reset().");
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        int bytesRead = _carrier.Read(buffer, offset, count);
        if (bytesRead > 0)
        {
            _position += bytesRead;
        }

        return bytesRead;
    }

    public override int ReadByte()
    {
        int b = _carrier.ReadByte();
        if (b >= 0)
        {
            _position++;
        }

        return b;
    }

    /// <summary>Java-style skip: advances the stream, discarding bytes, returning the number actually skipped.</summary>
    /// <param name="n">the number of bytes to skip</param>
    /// <returns>the actual number of bytes skipped</returns>
    public long Skip(long n)
    {
        long skippedBytes = StreamSkip(_carrier, n);
        _position += (int)skippedBytes;
        return skippedBytes;
    }

    /// <summary>Marks the current position, if the carrier supports it (silent no-op otherwise).</summary>
    /// <param name="readLimit">unused; kept for API parity with <c>InputStream.mark(int)</c></param>
    public void Mark(int readLimit)
    {
        if (!_carrier.CanSeek)
        {
            _markedPosition = -1;
            return;
        }

        _markedPosition = _position;
        _markedCarrierPosition = _carrier.Position;
    }

    /// <summary>Resets the stream to the position at the time <see cref="Mark"/> was last called.</summary>
    public void Reset()
    {
        if (_markedPosition < 0)
        {
            throw new IOException("Mark not supported, or mark() was not called.");
        }

        _carrier.Position = _markedCarrierPosition;
        _position = _markedPosition;
    }

    public override void Flush()
    {
        // No-op: this stream only ever reads.
    }

    public override long Seek(long offset, SeekOrigin origin) =>
        throw new NotSupportedException("PositionInputStream does not support Seek; use Mark()/Reset().");

    public override void SetLength(long value) =>
        throw new NotSupportedException("PositionInputStream is read-only.");

    public override void Write(byte[] buffer, int offset, int count) =>
        throw new NotSupportedException("PositionInputStream is read-only.");

    private static long StreamSkip(Stream stream, long n)
    {
        if (n <= 0)
        {
            return 0;
        }

        byte[] discard = new byte[(int)Math.Min(n, 4096)];
        long skipped = 0;
        while (skipped < n)
        {
            int toRead = (int)Math.Min(discard.Length, n - skipped);
            int read = stream.Read(discard, 0, toRead);
            if (read <= 0)
            {
                break;
            }

            skipped += read;
        }

        return skipped;
    }
}
