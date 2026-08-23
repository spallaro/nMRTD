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
/// Port of <c>org.jmrtd.io.InputStreamBuffer</c>. Buffers a stream (whose length is known in advance)
/// and can supply clients with fresh "copies" of that stream served from the buffer.
/// </summary>
/// <remarks>
/// NOTE: the original stream should no longer be read from directly; clients should only read bytes
/// from the sub-streams returned by <see cref="GetInputStream"/>.
/// </remarks>
public class InputStreamBuffer
{
    private readonly object _lock = new();

    private readonly PositionInputStream _carrier;

    private readonly FragmentBuffer _buffer;

    /// <summary>Creates an input stream buffer.</summary>
    /// <param name="inputStream">the input stream</param>
    /// <param name="length">the length of the input stream</param>
    public InputStreamBuffer(Stream inputStream, int length)
    {
        ArgumentNullException.ThrowIfNull(inputStream);
        _carrier = new PositionInputStream(inputStream);
        _carrier.Mark(length);
        _buffer = new FragmentBuffer(length);
    }

    /// <summary>Updates this buffer based on some other buffer.</summary>
    /// <param name="other">the other buffer</param>
    public void UpdateFrom(InputStreamBuffer other)
    {
        ArgumentNullException.ThrowIfNull(other);
        _buffer.UpdateFrom(other._buffer);
    }

    /// <summary>Returns a copy of the input stream positioned at 0.</summary>
    /// <returns>a copy of the input stream</returns>
    public SubInputStream GetInputStream()
    {
        lock (_carrier)
        {
            return new SubInputStream(this, _carrier);
        }
    }

    /// <summary>Returns the current position in the buffer.</summary>
    /// <returns>the position in the buffer</returns>
    public int GetPosition()
    {
        lock (_lock)
        {
            return _buffer.GetPosition();
        }
    }

    /// <summary>Returns the number of bytes buffered so far.</summary>
    /// <returns>the number of bytes buffered so far</returns>
    public int GetBytesBuffered()
    {
        lock (_lock)
        {
            return _buffer.GetBytesBuffered();
        }
    }

    /// <summary>Returns the size of the buffer.</summary>
    /// <returns>the size of the buffer</returns>
    public int GetLength() => _buffer.GetLength();

    public override string ToString() => $"InputStreamBuffer [{_buffer}]";

    /// <summary>
    /// The sub-input stream to serve to clients. Unlike Java's non-static inner class, this nested C#
    /// class needs an explicit reference to its owning <see cref="InputStreamBuffer"/> to reach the
    /// shared <see cref="FragmentBuffer"/> and carrier.
    /// </summary>
    public sealed class SubInputStream : Stream
    {
        private readonly InputStreamBuffer _outer;
        private readonly object _syncObject;

        private int _position;
        private int _markedPosition = -1;

        /// <summary>Creates a sub-stream.</summary>
        /// <param name="outer">the owning input stream buffer</param>
        /// <param name="syncObject">an object for locking</param>
        internal SubInputStream(InputStreamBuffer outer, object syncObject)
        {
            _outer = outer;
            _syncObject = syncObject;
        }

        /// <summary>Returns the underlying fragment buffer.</summary>
        public FragmentBuffer Buffer => _outer._buffer;

        public override bool CanRead => true;

        public override bool CanWrite => false;

        public override bool CanSeek => true;

        public override long Length => _outer._buffer.GetLength();

        /// <summary>The position within this stream.</summary>
        public override long Position
        {
            get
            {
                lock (_syncObject)
                {
                    return _position;
                }
            }
            set
            {
                lock (_syncObject)
                {
                    _position = checked((int)value);
                }
            }
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            lock (_syncObject)
            {
                long newPosition = origin switch
                {
                    SeekOrigin.Begin => offset,
                    SeekOrigin.Current => _position + offset,
                    SeekOrigin.End => Length + offset,
                    _ => throw new ArgumentOutOfRangeException(nameof(origin)),
                };
                if (newPosition < 0)
                {
                    throw new IOException("Cannot seek before the beginning of the stream.");
                }

                _position = (int)newPosition;
                return _position;
            }
        }

        public override int ReadByte()
        {
            lock (_syncObject)
            {
                FragmentBuffer buffer = _outer._buffer;
                if (_position >= buffer.GetLength())
                {
                    // FIXME: Is this correct? Isn't buffer capable of growing dynamically? -- MO
                    return -1;
                }

                if (buffer.IsCoveredByFragment(_position))
                {
                    // Serve the byte from the buffer.
                    return buffer.GetBuffer()[_position++];
                }

                // Get it from the carrier.
                if (_outer._carrier.MarkSupported)
                {
                    SyncCarrierPosition(_position);
                }

                int result = _outer._carrier.ReadByte();
                if (result < 0)
                {
                    return -1;
                }

                buffer.AddFragment(_position++, (byte)result);
                return result;
            }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            ArgumentNullException.ThrowIfNull(buffer);
            if (offset < 0 || count < 0 || count > buffer.Length - offset)
            {
                throw new ArgumentOutOfRangeException(nameof(count));
            }

            lock (_syncObject)
            {
                if (count == 0)
                {
                    return 0;
                }

                FragmentBuffer fragmentBuffer = _outer._buffer;
                int len = count;
                if (len > fragmentBuffer.GetLength() - _position)
                {
                    len = fragmentBuffer.GetLength() - _position;
                }

                if (_position >= fragmentBuffer.GetLength())
                {
                    // FIXME: is this correct? See FIXME in ReadByte().
                    return 0;
                }

                if (_outer._carrier.MarkSupported)
                {
                    SyncCarrierPosition(_position);
                }

                FragmentBuffer.Fragment fragment = fragmentBuffer.GetSmallestUnbufferedFragment(_position, len);
                if (fragment.Length > 0)
                {
                    // Copy buffered prefix to buffer.
                    int alreadyBufferedPrefixLength = fragment.Offset - _position;
                    int unbufferedPostfixLength = fragment.Length;
                    Array.Copy(fragmentBuffer.GetBuffer(), _position, buffer, offset, alreadyBufferedPrefixLength);
                    _position += alreadyBufferedPrefixLength;

                    if (_outer._carrier.MarkSupported)
                    {
                        SyncCarrierPosition(_position);
                    }

                    // Read unbuffered postfix from carrier, directly to buffer, and buffer it.
                    int bytesReadFromCarrier = _outer._carrier.Read(buffer, offset + alreadyBufferedPrefixLength, unbufferedPostfixLength);
                    fragmentBuffer.AddFragment(fragment.Offset, buffer, offset + alreadyBufferedPrefixLength, bytesReadFromCarrier);
                    _position += bytesReadFromCarrier;

                    return alreadyBufferedPrefixLength + bytesReadFromCarrier;
                }

                // No unbuffered fragment.
                int length = Math.Min(len, fragmentBuffer.GetLength() - _position);
                Array.Copy(fragmentBuffer.GetBuffer(), _position, buffer, offset, length);
                _position += length;
                return length;
            }
        }

        /// <summary>Java-style skip, returning the number of bytes actually skipped.</summary>
        /// <param name="n">the number of bytes to skip</param>
        /// <returns>the actual number of bytes skipped</returns>
        public long Skip(long n)
        {
            lock (_syncObject)
            {
                int leftInBuffer = _outer._buffer.GetBufferedLength(_position);

                if (n <= leftInBuffer)
                {
                    // If we can skip within the buffer, we do.
                    _position += (int)n;
                    return n;
                }

                // Otherwise, skip what's left in the buffer, then skip within the carrier...
                _position += leftInBuffer;
                long skippedBytes;
                if (_outer._carrier.MarkSupported)
                {
                    SyncCarrierPosition(_position);
                    skippedBytes = _outer._carrier.Skip(n - leftInBuffer);
                    _position += (int)skippedBytes;
                }
                else
                {
                    // As reading via Read() will call ReadByte()/Read(), position is adjusted automatically.
                    skippedBytes = SkipByReading(n - leftInBuffer);
                }

                return leftInBuffer + skippedBytes;
            }
        }

        /// <summary>Number of buffered bytes available ahead of the current position without touching the carrier.</summary>
        public int Available() => _outer._buffer.GetBufferedLength(_position);

        /// <summary>Whether this stream supports <see cref="Mark"/>/<see cref="Reset"/> (always true).</summary>
        public bool MarkSupported => true;

        /// <summary>Marks the current position in this stream.</summary>
        /// <param name="readLimit">unused; kept for API parity with <c>InputStream.mark(int)</c></param>
        public void Mark(int readLimit)
        {
            lock (_syncObject)
            {
                _markedPosition = _position;
            }
        }

        /// <summary>Repositions this stream to the position at the time <see cref="Mark"/> was last called.</summary>
        public void Reset()
        {
            lock (_syncObject)
            {
                if (_markedPosition < 0)
                {
                    throw new IOException("Invalid reset, was Mark() called?");
                }

                _position = _markedPosition;
            }
        }

        public override void Flush()
        {
            // No-op: this stream only ever reads.
        }

        public override void SetLength(long value) =>
            throw new NotSupportedException("SubInputStream is read-only.");

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException("SubInputStream is read-only.");

        /// <summary>
        /// If necessary, resets the carrier (which must support mark) and skips to the current position
        /// in the buffer.
        /// </summary>
        /// <param name="position">the position to skip to</param>
        private void SyncCarrierPosition(int position)
        {
            if (position == _outer._carrier.Position)
            {
                return;
            }

            _outer._carrier.Reset();
            int bytesSkipped = 0;
            while (bytesSkipped < position)
            {
                bytesSkipped += (int)_outer._carrier.Skip(position - bytesSkipped);
            }
        }

        private long SkipByReading(long n)
        {
            long remaining = n;
            long total = 0;
            byte[] discard = new byte[(int)Math.Min(remaining, 2048)];
            while (remaining > 0)
            {
                int toRead = (int)Math.Min(discard.Length, remaining);
                int read = Read(discard, 0, toRead);
                if (read <= 0)
                {
                    break;
                }

                remaining -= read;
                total += read;
            }

            return total;
        }
    }
}
