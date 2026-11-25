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
/// Port of <c>net.sf.scuba.tlv.TLVUtil</c>: BER-TLV tag/length encoding helpers.
/// </summary>
public static class TlvUtil
{
    /// <summary>How many bytes the given BER-TLV tag value occupies when encoded.</summary>
    public static int GetTagLength(int tag)
    {
        // Unsigned: a 4 byte tag whose first byte has its high bit set (context specific or private class, such
        // as 9F818101 or DFFFFF7F) is a negative int (SCUBA 0.1.0, 6d2c9f2).
        uint unsignedTag = (uint)tag;
        if (unsignedTag <= 0xFF)
        {
            return 1;
        }
        if (unsignedTag <= 0xFFFF)
        {
            return 2;
        }
        if (unsignedTag <= 0xFFFFFF)
        {
            return 3;
        }
        return 4;
    }

    /// <summary>How many bytes <see cref="GetLengthAsBytes"/> would produce for the given length.</summary>
    public static int GetLengthLength(int length)
    {
        if (length < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(length));
        }
        if (length < 0x80)
        {
            return 1;
        }
        if (length < 0x100)
        {
            return 2;
        }
        if (length < 0x10000)
        {
            return 3;
        }
        if (length < 0x1000000)
        {
            return 4;
        }
        return 5;
    }

    /// <summary>BER-TLV length-octet encoding of <paramref name="length"/> (short or long form).</summary>
    public static byte[] GetLengthAsBytes(int length)
    {
        int lengthLength = GetLengthLength(length);
        byte[] result = new byte[lengthLength];
        if (lengthLength == 1)
        {
            result[0] = (byte)length;
            return result;
        }

        result[0] = (byte)(0x80 | (lengthLength - 1));
        for (int i = lengthLength - 1, shift = 0; i >= 1; i--, shift += 8)
        {
            result[i] = (byte)((length >> shift) & 0xFF);
        }
        return result;
    }

    /// <summary>One-shot encode: tag || length || value.</summary>
    public static byte[] TlvEncode(int tag, byte[] value)
    {
        ArgumentNullException.ThrowIfNull(value);
        byte[] tagBytes = TagToBytes(tag);
        byte[] lengthBytes = GetLengthAsBytes(value.Length);
        byte[] result = new byte[tagBytes.Length + lengthBytes.Length + value.Length];
        Buffer.BlockCopy(tagBytes, 0, result, 0, tagBytes.Length);
        Buffer.BlockCopy(lengthBytes, 0, result, tagBytes.Length, lengthBytes.Length);
        Buffer.BlockCopy(value, 0, result, tagBytes.Length + lengthBytes.Length, value.Length);
        return result;
    }

    /// <summary>
    /// Same semantics as <see cref="TlvEncode"/> (spec: "treat as identical semantics to tlvEncode
    /// unless a discrepancy is found during porting" -- none was found; kept as a distinct method only
    /// for call-site parity with JMRTD's EAC/PACE "Data Object" wrapping call sites).
    /// </summary>
    public static byte[] WrapDO(int tag, byte[] value) => TlvEncode(tag, value);

    /// <summary>Strips the outer tag+length, asserting the tag matches <paramref name="expectedTag"/>.</summary>
    public static byte[] UnwrapDO(int expectedTag, byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        using var stream = new MemoryStream(data, writable: false);
        using var tlvIn = new TlvInputStream(stream);
        int tag = tlvIn.ReadTag();
        if (tag != expectedTag)
        {
            throw new ArgumentException($"Expected tag 0x{expectedTag:X}, found 0x{tag:X}.", nameof(data));
        }
        tlvIn.ReadLength();
        return tlvIn.ReadValue();
    }

    private static byte[] TagToBytes(int tag)
    {
        int tagLength = GetTagLength(tag);
        byte[] result = new byte[tagLength];
        for (int i = tagLength - 1, shift = 0; i >= 0; i--, shift += 8)
        {
            result[i] = (byte)((tag >> shift) & 0xFF);
        }
        return result;
    }
}
