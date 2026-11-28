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
/// Port of <c>net.sf.scuba.tlv.TLVInputStream</c>: BER-TLV reader over a wrapped <see cref="Stream"/>.
/// Multi-byte tags follow ASN.1 BER tag encoding (tag number in the low 5 bits of the first byte;
/// <c>0x1F</c> there means the tag continues with further bytes, each using bit 8 as a continuation
/// flag). Lengths follow BER-TLV rules: short form &#8804; 0x7F, long form with a <c>0x80 | numLengthBytes</c>
/// prefix. Unlike Java's <c>TLVInputStream</c> (which extends <c>InputStream</c>), this type wraps a
/// <see cref="Stream"/> rather than being one, so the scuba call-site "avoid double-wrap" pattern
/// (checking <c>x instanceof TLVInputStream</c>) doesn't carry over structurally -- call sites that hold
/// a <see cref="TlvInputStream"/> reference already know not to re-wrap it.
/// </summary>
/// <remarks>
/// <para>
/// As SCUBA's <c>TLVInputState</c> (SCUBA 0.1.0), a tag, length bytes or value that would end after the value of
/// the object enclosing it is an <see cref="IOException"/>, raised before the value is read. Where SCUBA counts the
/// bytes that pass through its stream, this reader works with the position of the wrapped stream: callers in nMRTD
/// read values directly from the wrapped stream or with other readers over it, so a count would miss bytes. It
/// remembers where the value of each object it read ends; an object stops enclosing once the position reaches its
/// end, or goes back before its start.
/// </para>
/// <para>
/// The check needs <see cref="Stream.Position"/>; with a stream that does not support it, the reader keeps no
/// state and does not check nesting.
/// </para>
/// </remarks>
public sealed class TlvInputStream : IDisposable
{
    private readonly Stream _stream;
    private readonly bool _leaveOpen;

    private int _pendingLength = -1;

    /// <summary>Whether <see cref="Stream.Position"/> of the wrapped stream can be read; null until first tried.</summary>
    private bool? _hasPosition;

    /// <summary>The tag read last, for the object pushed when its length is read; -1 if not known.</summary>
    private int _pendingTag = -1;

    /// <summary>The objects whose value may still enclose what is read, innermost on top.</summary>
    private readonly Stack<OpenObject> _openObjects = new();

    /// <summary>An object read by this reader: its tag and where its value starts and ends in the wrapped stream.</summary>
    private readonly record struct OpenObject(int Tag, long ValueStart, long ValueEnd);

    public TlvInputStream(Stream stream, bool leaveOpen = false)
    {
        _stream = stream ?? throw new ArgumentNullException(nameof(stream));
        _leaveOpen = leaveOpen;
    }

    /// <summary>Reads the full (possibly multi-byte) BER-TLV tag as an int.</summary>
    /// <exception cref="IOException">if the tag ends after the value of the object enclosing it</exception>
    public int ReadTag()
    {
        long start = GetPosition();
        int firstByte = ReadByteChecked();
        int tag = firstByte;
        if ((firstByte & 0x1F) == 0x1F)
        {
            int tagLength = 1;
            int b;
            do
            {
                b = ReadByteChecked();
                if (++tagLength > 4)
                {
                    // The leading bytes used to be shifted out, giving a wrong tag (SCUBA 0.1.0, 6d2c9f2).
                    throw new IOException("Tags of more than 4 bytes are not supported");
                }
                tag = (tag << 8) | b;
            } while ((b & 0x80) != 0);
        }
        CheckFitsInEnclosing(start, GetPosition(), () => $"Tag {tag:X}");
        _pendingLength = -1;
        _pendingTag = tag;
        return tag;
    }

    /// <summary>Reads the BER-TLV length octets and returns the decoded value length.</summary>
    /// <exception cref="IOException">if the length bytes or the value end after the value of the object enclosing them</exception>
    public int ReadLength()
    {
        long start = GetPosition();
        int firstByte = ReadByteChecked();
        int length;
        if ((firstByte & 0x80) == 0)
        {
            length = firstByte;
        }
        else
        {
            int numLengthBytes = firstByte & 0x7F;
            if (numLengthBytes == 0)
            {
                throw new IOException("Indefinite-length BER-TLV encoding is not supported.");
            }
            // At most 4 significant length bytes, and not more than int.MaxValue: longer or negative lengths used to
            // overflow (SCUBA 0.1.0, 03bc03f). Leading zero bytes are accepted.
            long value = 0;
            for (int i = 0; i < numLengthBytes; i++)
            {
                value = (value << 8) | (uint)ReadByteChecked();
                if (value > int.MaxValue)
                {
                    throw new IOException($"Length of more than {int.MaxValue} bytes is not supported");
                }
            }
            length = (int)value;
        }
        long valueStart = GetPosition();
        if (valueStart >= 0)
        {
            // Checked before anything is read or allocated for the value.
            int tag = _pendingTag;
            CheckFitsInEnclosing(start, valueStart + length, () => $"Length {length} of tag {tag:X}");
            _openObjects.Push(new OpenObject(tag, valueStart, valueStart + length));
        }
        _pendingTag = -1;
        _pendingLength = length;
        return length;
    }

    /// <summary>Reads exactly the bytes indicated by the most recent <see cref="ReadLength"/> call.</summary>
    public byte[] ReadValue()
    {
        if (_pendingLength < 0)
        {
            throw new InvalidOperationException("ReadLength() must be called before ReadValue().");
        }
        // The length comes from the input, so the value is not allocated up front (SCUBA 0.1.0, 03bc03f).
        byte[] value = Io.InputStreams.ReadFully(_stream, _pendingLength);
        _pendingLength = -1;
        return value;
    }

    /// <summary>
    /// Standard <c>InputStream</c>-like skip; used with a known length to skip a value without decoding it. Over a
    /// card file, the skipped bytes are not read from the card.
    /// </summary>
    public long Skip(long n)
    {
        if (n <= 0)
        {
            return 0;
        }
        if (_stream is CardFileInputStream cardFile)
        {
            return cardFile.Skip(n);
        }
        long skipped = 0;
        byte[] discard = new byte[(int)Math.Min(n, 4096)];
        while (skipped < n)
        {
            int toRead = (int)Math.Min(discard.Length, n - skipped);
            int read = _stream.Read(discard, 0, toRead);
            if (read <= 0)
            {
                break;
            }
            skipped += read;
        }
        return skipped;
    }

    /// <summary>
    /// Scans forward until positioned just after the given tag. As in SCUBA, it descends into constructed objects and
    /// skips only the values of primitive ones, so a tag nested in a constructed sibling is found; it used to skip the
    /// value of constructed objects too. The end of the stream before the tag is an <see cref="EndOfStreamException"/>
    /// (SCUBA 0.1.0, a04c2b1).
    /// </summary>
    public void SkipToTag(int tag)
    {
        while (true)
        {
            int t = ReadTag();
            if (t == tag)
            {
                return;
            }
            int len = ReadLength();
            if (IsConstructed(t))
            {
                continue;
            }
            long skipped = Skip(len);
            if (skipped < len)
            {
                throw new EndOfStreamException(
                    $"End of stream while skipping to tag {tag:X} (skipped {skipped} of {len} value bytes of tag {t:X})");
            }
        }
    }

    /// <summary>Whether the tag is constructed: bit 6 of its first byte.</summary>
    private static bool IsConstructed(int tag)
    {
        uint first = (uint)tag;
        while (first > 0xFF)
        {
            first >>= 8;
        }
        return (first & 0x20) != 0;
    }

    /// <summary>
    /// Checks that what starts at <paramref name="start"/> and ends at <paramref name="end"/> fits in the value of
    /// the innermost object enclosing <paramref name="start"/>. Objects that no longer enclose it are dropped first.
    /// Each object was checked against its own enclosing object when it was read, so the innermost one is enough.
    /// </summary>
    private void CheckFitsInEnclosing(long start, long end, Func<string> what)
    {
        if (start < 0)
        {
            return;
        }
        while (_openObjects.Count > 0 && (start >= _openObjects.Peek().ValueEnd || start < _openObjects.Peek().ValueStart))
        {
            _openObjects.Pop();
        }
        if (_openObjects.Count > 0 && end > _openObjects.Peek().ValueEnd)
        {
            OpenObject parent = _openObjects.Peek();
            throw new IOException(
                $"{what()} does not fit in the remaining {parent.ValueEnd - start} value bytes of tag {parent.Tag:X}"
                + $" (length {parent.ValueEnd - parent.ValueStart})");
        }
    }

    /// <summary>The position of the wrapped stream, or -1 if it does not support <see cref="Stream.Position"/>.</summary>
    private long GetPosition()
    {
        if (_hasPosition == false)
        {
            return -1;
        }
        try
        {
            long position = _stream.Position;
            _hasPosition = true;
            return position;
        }
        catch (NotSupportedException)
        {
            _hasPosition = false;
            return -1;
        }
    }

    private int ReadByteChecked()
    {
        int b = _stream.ReadByte();
        if (b < 0)
        {
            throw new EndOfStreamException("Unexpected end of TLV stream.");
        }
        return b;
    }

    public void Dispose()
    {
        if (!_leaveOpen)
        {
            _stream.Dispose();
        }
    }
}
