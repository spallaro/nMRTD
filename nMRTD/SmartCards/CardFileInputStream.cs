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
/// Port of <c>net.sf.scuba.smartcards.CardFileInputStream</c>. A lazily-reading, forward-only stream
/// that reads the currently-selected file (per <see cref="IFileSystemStructured.GetSelectedPath"/>) in
/// <c>maxBlockSize</c>-sized chunks via <see cref="IFileSystemStructured.ReadBinary"/>. Consumed only as
/// a generic <see cref="Stream"/> by LDS file parsers, so only the standard read/position/length surface
/// is implemented (no scuba-specific extra members) -- matches the Java <c>InputStream</c> contract,
/// which does not guarantee mark/reset support either.
/// </summary>
public sealed class CardFileInputStream : Stream
{
    private readonly int _maxBlockSize;
    private readonly IFileSystemStructured _fileSystem;

    private int _position;
    private byte[]? _buffer;
    private int _bufferOffset;
    private int _bufferLength;
    private long? _cachedLength;

    public CardFileInputStream(int maxBlockSize, IFileSystemStructured fileSystem)
    {
        if (maxBlockSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxBlockSize), "maxBlockSize must be positive.");
        }
        _fileSystem = fileSystem ?? throw new ArgumentNullException(nameof(fileSystem));
        _maxBlockSize = maxBlockSize;
    }

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => false;

    public override long Length
    {
        get
        {
            // Cached per-instance: the selected path shouldn't change out from under an open stream.
            if (_cachedLength is { } cached)
            {
                return cached;
            }
            FileInfo[] path = _fileSystem.GetSelectedPath();
            if (path is null || path.Length == 0)
            {
                throw new IOException("No file selected.");
            }
            long length = path[^1].FileLength;
            _cachedLength = length;
            return length;
        }
    }

    public override long Position
    {
        get => _position;
        set => throw new NotSupportedException("CardFileInputStream is forward-only.");
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        if (offset < 0 || count < 0 || offset + count > buffer.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(count));
        }
        if (count == 0)
        {
            return 0;
        }

        long length = Length;
        if (_position >= length)
        {
            return 0;
        }

        int totalRead = 0;
        while (totalRead < count && _position < length)
        {
            if (_buffer is null || _position < _bufferOffset || _position >= _bufferOffset + _bufferLength)
            {
                FillBuffer();
                if (_bufferLength <= 0)
                {
                    break;
                }
            }

            int bufferPos = _position - _bufferOffset;
            int available = _bufferLength - bufferPos;
            int toCopy = Math.Min(available, count - totalRead);
            Array.Copy(_buffer!, bufferPos, buffer, offset + totalRead, toCopy);
            totalRead += toCopy;
            _position += toCopy;
        }

        return totalRead;
    }

    private void FillBuffer()
    {
        long length = Length;
        int blockLength = (int)Math.Min(_maxBlockSize, length - _position);
        if (blockLength <= 0)
        {
            _bufferLength = 0;
            return;
        }

        byte[] data;
        try
        {
            data = _fileSystem.ReadBinary(_position, blockLength);
        }
        catch (CardServiceException ex)
        {
            throw new IOException("Error reading card file.", ex);
        }

        _buffer = data;
        _bufferOffset = _position;
        _bufferLength = data.Length;
    }

    public override void Flush()
    {
        // No-op: this stream only ever reads.
    }

    public override long Seek(long offset, SeekOrigin origin) =>
        throw new NotSupportedException("CardFileInputStream is forward-only.");

    public override void SetLength(long value) =>
        throw new NotSupportedException("CardFileInputStream is read-only.");

    public override void Write(byte[] buffer, int offset, int count) =>
        throw new NotSupportedException("CardFileInputStream is read-only.");
}
