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
/// Port of <c>net.sf.scuba.smartcards.CommandAPDU</c>, itself a JSR-268-independent reimplementation of
/// <c>javax.smartcardio.CommandAPDU</c>. Implements the full ISO/IEC 7816-4 case 1-4 command-APDU
/// encoding, in both short form (Nc &#8804; 255, Ne &#8804; 256) and extended form (Nc up to 65535, Ne up
/// to 65536), matching <c>javax.smartcardio.CommandAPDU</c>'s case-detection/encoding rules exactly:
/// extended form is used only when required (Nc &gt; 255 or Ne &gt; 256), and once required, both the Lc
/// and Le fields (when present) switch to the extended encoding together (ISO 7816-4 cases 2E/3E/4E).
/// </summary>
public sealed class CommandApdu
{
    private readonly byte[] _data;

    public int Cla { get; }

    public int Ins { get; }

    public int P1 { get; }

    public int P2 { get; }

    /// <summary>Length of the command data field (Lc), i.e. <c>Data.Length</c>.</summary>
    public int Nc { get; }

    /// <summary>Expected response length (Le). 0 means no Le byte is present at all (case 1/3).</summary>
    public int Ne { get; }

    public byte[] Data => (byte[])_data.Clone();

    /// <summary>Case 1: no data, no Le.</summary>
    public CommandApdu(int cla, int ins, int p1, int p2)
        : this(cla, ins, p1, p2, Array.Empty<byte>(), 0)
    {
    }

    /// <summary>Case 2: no data, explicit Le (e.g. GET CHALLENGE, READ BINARY).</summary>
    public CommandApdu(int cla, int ins, int p1, int p2, int ne)
        : this(cla, ins, p1, p2, Array.Empty<byte>(), ne)
    {
    }

    /// <summary>Case 3: data, no Le.</summary>
    public CommandApdu(int cla, int ins, int p1, int p2, byte[] data)
        : this(cla, ins, p1, p2, data, 0)
    {
    }

    /// <summary>Case 4: data and explicit Le. The most common overload used by JMRTD's APDU senders.</summary>
    public CommandApdu(int cla, int ins, int p1, int p2, byte[] data, int ne)
    {
        ArgumentNullException.ThrowIfNull(data);
        CheckByteRange(cla, nameof(cla));
        CheckByteRange(ins, nameof(ins));
        CheckByteRange(p1, nameof(p1));
        CheckByteRange(p2, nameof(p2));
        if (data.Length > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(data), "Command data (Nc) must be at most 65535 bytes.");
        }
        if (ne < 0 || ne > 65536)
        {
            throw new ArgumentOutOfRangeException(nameof(ne), "Ne must be in range 0..65536.");
        }

        Cla = cla;
        Ins = ins;
        P1 = p1;
        P2 = p2;
        _data = (byte[])data.Clone();
        Nc = _data.Length;
        Ne = ne;
    }

    /// <summary>
    /// Raw-bytes constructor (API parity with <c>javax.smartcardio.CommandAPDU(byte[])</c>; no JMRTD
    /// call site uses it, but it is provided for completeness). Decodes Cla/Ins/P1/P2/Nc/Ne/Data from a
    /// fully-encoded APDU by replaying the same ISO 7816-4 case-detection rules used by
    /// <c>javax.smartcardio.CommandAPDU</c>'s own <c>parse()</c> method.
    /// </summary>
    public CommandApdu(byte[] apdu)
    {
        ArgumentNullException.ThrowIfNull(apdu);
        if (apdu.Length < 4)
        {
            throw new ArgumentException("APDU must be at least 4 bytes long.", nameof(apdu));
        }

        Cla = apdu[0] & 0xFF;
        Ins = apdu[1] & 0xFF;
        P1 = apdu[2] & 0xFF;
        P2 = apdu[3] & 0xFF;

        (int nc, int ne, int dataOffset) = ParseLengths(apdu);
        Nc = nc;
        Ne = ne;
        _data = new byte[nc];
        if (nc > 0)
        {
            Array.Copy(apdu, dataOffset, _data, 0, nc);
        }
    }

    public byte[] GetBytes()
    {
        bool extended = Nc > 255 || Ne > 256;

        int length = 4;
        if (Nc > 0)
        {
            length += extended ? 3 : 1;
            length += Nc;
        }
        if (Ne > 0)
        {
            length += extended ? (Nc > 0 ? 2 : 3) : 1;
        }

        byte[] result = new byte[length];
        int pos = 0;
        result[pos++] = (byte)Cla;
        result[pos++] = (byte)Ins;
        result[pos++] = (byte)P1;
        result[pos++] = (byte)P2;

        if (Nc > 0)
        {
            if (extended)
            {
                result[pos++] = 0x00;
                result[pos++] = (byte)((Nc >> 8) & 0xFF);
                result[pos++] = (byte)(Nc & 0xFF);
            }
            else
            {
                result[pos++] = (byte)Nc;
            }
            Array.Copy(_data, 0, result, pos, Nc);
            pos += Nc;
        }

        if (Ne > 0)
        {
            if (extended)
            {
                if (Nc == 0)
                {
                    result[pos++] = 0x00;
                }
                int encodedNe = Ne == 65536 ? 0 : Ne;
                result[pos++] = (byte)((encodedNe >> 8) & 0xFF);
                result[pos++] = (byte)(encodedNe & 0xFF);
            }
            else
            {
                result[pos++] = (byte)(Ne == 256 ? 0 : Ne);
            }
        }

        return result;
    }

    private static void CheckByteRange(int value, string paramName)
    {
        if (value < 0 || value > 255)
        {
            throw new ArgumentOutOfRangeException(paramName, "Value must be in range 0..255.");
        }
    }

    private static (int Nc, int Ne, int DataOffset) ParseLengths(byte[] apdu)
    {
        int n = apdu.Length;
        if (n == 4)
        {
            // Case 1.
            return (0, 0, 0);
        }

        int b1 = apdu[4] & 0xFF;
        if (n == 5)
        {
            // Case 2s.
            return (0, b1 == 0 ? 256 : b1, 0);
        }

        if (b1 != 0)
        {
            if (n == 5 + b1)
            {
                // Case 3s.
                return (b1, 0, 5);
            }
            if (n == 6 + b1)
            {
                // Case 4s.
                int le = apdu[n - 1] & 0xFF;
                return (b1, le == 0 ? 256 : le, 5);
            }
            throw new ArgumentException($"Invalid APDU: length={n}, b1={b1}.", nameof(apdu));
        }

        if (n < 7)
        {
            throw new ArgumentException("Invalid APDU: too short for extended-length encoding.", nameof(apdu));
        }

        int b2 = ((apdu[5] & 0xFF) << 8) | (apdu[6] & 0xFF);
        if (n == 7)
        {
            // Case 2e.
            return (0, b2 == 0 ? 65536 : b2, 0);
        }
        if (b2 == 0)
        {
            throw new ArgumentException("Invalid APDU: extended Lc cannot be zero when data follows.", nameof(apdu));
        }
        if (n == 7 + b2)
        {
            // Case 3e.
            return (b2, 0, 7);
        }
        if (n == 9 + b2)
        {
            // Case 4e.
            int le = ((apdu[n - 2] & 0xFF) << 8) | (apdu[n - 1] & 0xFF);
            return (b2, le == 0 ? 65536 : le, 7);
        }
        throw new ArgumentException($"Invalid APDU: length={n}, extended b2={b2}.", nameof(apdu));
    }
}
