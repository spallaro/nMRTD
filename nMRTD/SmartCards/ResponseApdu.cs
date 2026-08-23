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
/// Port of <c>net.sf.scuba.smartcards.ResponseAPDU</c>, mirroring <c>javax.smartcardio.ResponseAPDU</c>.
/// Only ever constructed by the transport layer (<see cref="CardService.Transmit"/> implementations).
/// </summary>
public sealed class ResponseApdu
{
    private readonly byte[] _apdu;

    public ResponseApdu(byte[] apdu)
    {
        ArgumentNullException.ThrowIfNull(apdu);
        if (apdu.Length < 2)
        {
            throw new ArgumentException("Response APDU must be at least 2 bytes long (SW1 SW2).", nameof(apdu));
        }
        _apdu = (byte[])apdu.Clone();
    }

    /// <summary>Full raw bytes: data + trailing SW1 SW2.</summary>
    public byte[] GetBytes() => (byte[])_apdu.Clone();

    /// <summary>Response data, i.e. bytes without the trailing SW1 SW2.</summary>
    public byte[] Data
    {
        get
        {
            byte[] data = new byte[_apdu.Length - 2];
            Array.Copy(_apdu, data, data.Length);
            return data;
        }
    }

    public int Sw1 => _apdu[^2] & 0xFF;

    public int Sw2 => _apdu[^1] & 0xFF;

    /// <summary>(SW1 &lt;&lt; 8) | SW2, as a 16-bit unsigned value widened into an int.</summary>
    public int Sw => (Sw1 << 8) | Sw2;
}
