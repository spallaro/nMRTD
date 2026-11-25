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
/// Port of <c>org.jmrtd.io.SplittableInputStream</c>. Wraps another stream (and yields the same bytes)
/// and can spawn new fresh stream copies (using <see cref="GetInputStream(int)"/>) that also yield the
/// same bytes.
/// </summary>
public class SplittableInputStream : Stream
{
    private readonly InputStreamBuffer _inputStreamBuffer;
    private readonly InputStreamBuffer.SubInputStream _carrier;

    /// <summary>Wraps a stream so that copy streams can be split off.</summary>
    /// <param name="inputStream">the original stream</param>
    /// <param name="length">the precise length of bytes that the original stream provides</param>
    public SplittableInputStream(Stream inputStream, int length)
    {
        _inputStreamBuffer = new InputStreamBuffer(inputStream, length);
        _carrier = _inputStreamBuffer.GetInputStream();
    }

    /// <summary>Updates this stream's buffer based on some other stream's buffer.</summary>
    /// <param name="other">the other stream</param>
    public void UpdateFrom(SplittableInputStream other)
    {
        ArgumentNullException.ThrowIfNull(other);
        _inputStreamBuffer.UpdateFrom(other._inputStreamBuffer);
    }

    /// <summary>Returns a copy of the stream positioned at <paramref name="position"/>.</summary>
    /// <param name="position">a position between 0 and <see cref="GetPosition"/></param>
    /// <returns>a fresh stream</returns>
    public Stream GetInputStream(int position)
    {
        try
        {
            InputStreamBuffer.SubInputStream inputStream = _inputStreamBuffer.GetInputStream();
            InputStreams.SkipFully(inputStream.Skip, position);

            return inputStream;
        }
        catch (IOException ioe)
        {
            throw new InvalidOperationException("Error while skipping to position.", ioe);
        }
    }

    /// <summary>Returns the position within the stream (the number of bytes read since this stream was constructed).</summary>
    /// <returns>the position within this stream</returns>
    public int GetPosition() => (int)_carrier.Position;

    public override bool CanRead => true;

    public override bool CanWrite => false;

    public override bool CanSeek => false;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => _carrier.Position;
        set => throw new NotSupportedException("SplittableInputStream is forward-only; use GetInputStream(int) to split off a repositioned copy.");
    }

    public override int Read(byte[] buffer, int offset, int count) => _carrier.Read(buffer, offset, count);

    public override int ReadByte() => _carrier.ReadByte();

    /// <summary>Java-style skip, returning the number of bytes actually skipped.</summary>
    /// <param name="n">the number of bytes to skip</param>
    /// <returns>the actual number of bytes skipped</returns>
    public long Skip(long n) => _carrier.Skip(n);

    /// <summary>Number of buffered bytes available ahead of the current position without touching the carrier.</summary>
    public int Available() => _carrier.Available();

    /// <summary>Whether this stream supports <see cref="Mark"/>/<see cref="Reset"/> (always true).</summary>
    public bool MarkSupported => true;

    /// <summary>Marks the current position in this stream.</summary>
    /// <param name="readLimit">the maximum number of bytes that can be read before the mark position becomes invalid</param>
    public void Mark(int readLimit) => _carrier.Mark(readLimit);

    /// <summary>Repositions this stream to the position at the time <see cref="Mark"/> was last called.</summary>
    public void Reset() => _carrier.Reset();

    public override void Flush()
    {
        // No-op: this stream only ever reads.
    }

    public override long Seek(long offset, SeekOrigin origin) =>
        throw new NotSupportedException("SplittableInputStream does not support Seek; use GetInputStream(int) or Mark()/Reset().");

    public override void SetLength(long value) =>
        throw new NotSupportedException("SplittableInputStream is read-only.");

    public override void Write(byte[] buffer, int offset, int count) =>
        throw new NotSupportedException("SplittableInputStream is read-only.");
}
