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
/// Port of <c>net.sf.scuba.smartcards.CardFileInputStream</c>. A lazily-reading, forward-only stream over
/// one file of a <see cref="IFileSystemStructured"/>, read in <c>maxBlockSize</c>-sized chunks via
/// <see cref="IFileSystemStructured.ReadBinary"/>. Consumed only as a generic <see cref="Stream"/> by LDS
/// file parsers, so only the standard read/position/length surface is implemented.
///
/// As in SCUBA, the stream is bound to the file that is selected when it is created: it captures that
/// path and length, and re-selects the path before reading if another file has been selected since
/// (for example by a second stream). Every select-and-read sequence runs under a lock on the file system
/// instance (Java: <c>synchronized(fs)</c>). When <see cref="IFileSystemStructured.ReadBinary"/> returns no
/// bytes before the end of the file (<c>DefaultFileSystem</c> does this once, after lowering its READ BINARY
/// length when the card reports a wrong length), the read is retried, as SCUBA does.
/// </summary>
public sealed class CardFileInputStream : Stream
{
    /// <summary>
    /// How many times in a row a read may return no bytes before giving up. SCUBA retries without a limit;
    /// <c>DefaultFileSystem</c> needs one retry, so a small bound keeps a misbehaving file system from
    /// looping forever.
    /// </summary>
    private const int MaxEmptyReads = 3;

    private readonly int _maxBlockSize;
    private readonly IFileSystemStructured _fileSystem;
    private readonly short[] _path;
    private readonly int _fileLength;

    private int _position;
    private byte[]? _buffer;
    private int _bufferOffset;
    private int _bufferLength;

    public CardFileInputStream(int maxBlockSize, IFileSystemStructured fileSystem)
    {
        if (maxBlockSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxBlockSize), "maxBlockSize must be positive.");
        }
        _fileSystem = fileSystem ?? throw new ArgumentNullException(nameof(fileSystem));
        _maxBlockSize = maxBlockSize;

        lock (_fileSystem)
        {
            FileInfo[] path = _fileSystem.GetSelectedPath();
            if (path is null || path.Length == 0)
            {
                throw new CardServiceException("No valid file selected.");
            }
            _path = Array.ConvertAll(path, fileInfo => fileInfo.Fid);
            _fileLength = path[^1].FileLength;
        }
    }

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => false;

    /// <summary>The length of the file this stream was created for.</summary>
    public override long Length => _fileLength;

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
        if (count == 0 || _position >= _fileLength)
        {
            return 0;
        }

        int totalRead = 0;
        while (totalRead < count && _position < _fileLength)
        {
            if (_buffer is null || _position < _bufferOffset || _position >= _bufferOffset + _bufferLength)
            {
                FillBuffer();
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

    /// <summary>Reads the next block at <see cref="_position"/>. Only called before the end of the file.</summary>
    private void FillBuffer()
    {
        int blockLength = Math.Min(_maxBlockSize, _fileLength - _position);
        lock (_fileSystem)
        {
            try
            {
                SelectPathIfNeeded();
                for (int attempt = 0; attempt < MaxEmptyReads; attempt++)
                {
                    byte[] data = _fileSystem.ReadBinary(_position, blockLength);
                    if (data is { Length: > 0 })
                    {
                        _buffer = data;
                        _bufferOffset = _position;
                        _bufferLength = data.Length;
                        return;
                    }
                }
            }
            catch (CardServiceException ex)
            {
                throw new IOException("Error reading card file.", ex);
            }
        }

        throw new IOException($"Error reading card file: no data returned at offset {_position} of {_fileLength}.");
    }

    /// <summary>Re-selects this stream's file if the file system has another one selected. Caller holds the lock.</summary>
    private void SelectPathIfNeeded()
    {
        FileInfo[] selected = _fileSystem.GetSelectedPath();
        if (selected is not null && selected.Length == _path.Length && selected.Select(fileInfo => fileInfo.Fid).SequenceEqual(_path))
        {
            return;
        }

        foreach (short fid in _path)
        {
            _fileSystem.SelectFile(fid);
        }
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
