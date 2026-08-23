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
public sealed class TlvInputStream : IDisposable
{
    private readonly Stream _stream;
    private readonly bool _leaveOpen;

    private int _pendingLength = -1;

    public TlvInputStream(Stream stream, bool leaveOpen = false)
    {
        _stream = stream ?? throw new ArgumentNullException(nameof(stream));
        _leaveOpen = leaveOpen;
    }

    /// <summary>Reads the full (possibly multi-byte) BER-TLV tag as an int.</summary>
    public int ReadTag()
    {
        int firstByte = ReadByteChecked();
        int tag = firstByte;
        if ((firstByte & 0x1F) == 0x1F)
        {
            int b;
            do
            {
                b = ReadByteChecked();
                tag = (tag << 8) | b;
            } while ((b & 0x80) != 0);
        }
        _pendingLength = -1;
        return tag;
    }

    /// <summary>Reads the BER-TLV length octets and returns the decoded value length.</summary>
    public int ReadLength()
    {
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
            length = 0;
            for (int i = 0; i < numLengthBytes; i++)
            {
                length = (length << 8) | ReadByteChecked();
            }
        }
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
        byte[] value = ReadFully(_pendingLength);
        _pendingLength = -1;
        return value;
    }

    /// <summary>Standard <c>InputStream</c>-like skip; used with a known length to skip a value without decoding it.</summary>
    public long Skip(long n)
    {
        if (n <= 0)
        {
            return 0;
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

    /// <summary>Scans forward, skipping values of non-matching tags, until positioned just after the given tag.</summary>
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
            Skip(len);
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

    private byte[] ReadFully(int count)
    {
        byte[] buffer = new byte[count];
        int totalRead = 0;
        while (totalRead < count)
        {
            int read = _stream.Read(buffer, totalRead, count - totalRead);
            if (read <= 0)
            {
                throw new EndOfStreamException("Unexpected end of TLV stream while reading value.");
            }
            totalRead += read;
        }
        return buffer;
    }

    public void Dispose()
    {
        if (!_leaveOpen)
        {
            _stream.Dispose();
        }
    }
}
