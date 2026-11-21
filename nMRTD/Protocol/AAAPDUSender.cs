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

using nMRTD.Logging;
using nMRTD.SmartCards;

namespace nMRTD.Protocol;

/// <summary>
/// Port of <c>org.jmrtd.protocol.AAAPDUSender</c>: a low-level APDU sender to support the Active
/// Authentication protocol.
/// </summary>
public class AAAPDUSender : IApduLevelAACapable
{
    private readonly object _lock = new();

    private readonly SecureMessagingAPDUSender _secureMessagingSender;

    /// <summary>The log/trace registry shared with every other sender wrapping the same underlying service.</summary>
    public LogSource Log => _secureMessagingSender.Log;

    /// <summary>
    /// Creates an APDU sender for tranceiving Active Authentication protocol APDUs.
    /// </summary>
    /// <param name="service">the card service for tranceiving APDUs</param>
    /// <remarks>
    /// Obsolete: use <see cref="AAAPDUSender(SecureMessagingAPDUSender)"/> instead, sharing a single
    /// <see cref="SecureMessagingAPDUSender"/> between all senders wrapping the same underlying card
    /// service (see <c>PassportService.GetSecureMessagingAPDUSender()</c>).
    /// </remarks>
    [Obsolete("Use AAAPDUSender(SecureMessagingAPDUSender) instead, sharing a single SecureMessagingAPDUSender between all senders wrapping the same underlying card service.")]
    public AAAPDUSender(CardService service)
        : this(new SecureMessagingAPDUSender(service))
    {
    }

    /// <summary>Creates an APDU sender for tranceiving Active Authentication protocol APDUs.</summary>
    /// <param name="secureMessagingSender">the (shared) secure messaging APDU sender for tranceiving APDUs</param>
    public AAAPDUSender(SecureMessagingAPDUSender secureMessagingSender)
    {
        _secureMessagingSender = secureMessagingSender;
    }

    /// <summary>Sends an <c>INTERNAL AUTHENTICATE</c> command to the passport. This is part of AA.</summary>
    /// <param name="wrapper">secure messaging wrapper</param>
    /// <param name="signatureLength">the (expected) length of the signature in bits</param>
    /// <param name="rndIfd">the challenge to send</param>
    /// <returns>the response from the passport (status word removed)</returns>
    /// <exception cref="CardServiceException">on tranceive error</exception>
    public byte[] SendInternalAuthenticate(IApduWrapper? wrapper, int signatureLength, byte[] rndIfd)
    {
        lock (_lock)
        {
            if (rndIfd == null || rndIfd.Length != 8)
            {
                throw new ArgumentException("rndIFD wrong length");
            }

            int le = signatureLength <= GetMaxShortResponseDataLength(wrapper) * 8 ? 256 : 65536;
            var commandApdu = new CommandApdu(Iso7816.ClaIso7816, Iso7816.InsInternalAuthenticate, 0x00, 0x00, rndIfd, le);

            ResponseApdu? responseApdu = null;
            int sw = -1;
            try
            {
                responseApdu = _secureMessagingSender.Transmit(wrapper, commandApdu);
                sw = responseApdu.Sw;
            }
            catch (CardServiceException cse)
            {
                // NOTE: Java logs this at INFO level; omitted per the non-essential-warning-omission
                // precedent used elsewhere in this port (see Util.cs's doc comment).
                sw = cse.Sw;
            }

            if (sw == Iso7816.SwNoError && responseApdu != null)
            {
                return responseApdu.Data;
            }

            if ((sw & 0xFF00) == 0x6100 && le == 256)
            {
                byte[]? normalLengthResponse = responseApdu?.Data;

                // Something is wrong with that length. Try different length.
                commandApdu = new CommandApdu(Iso7816.ClaIso7816, Iso7816.InsInternalAuthenticate, 0x00, 0x00, rndIfd, 65536);
                responseApdu = _secureMessagingSender.Transmit(wrapper, commandApdu);
                byte[]? extendedLengthResponse = responseApdu?.Data;

                if (normalLengthResponse == null && extendedLengthResponse == null)
                {
                    throw new CardServiceException("Internal Authenticate failed", sw);
                }

                if (normalLengthResponse != null && extendedLengthResponse == null)
                {
                    return normalLengthResponse;
                }

                if (normalLengthResponse == null && extendedLengthResponse != null)
                {
                    return extendedLengthResponse;
                }

                // Both are non-null. Send the one with the most data.
                return normalLengthResponse!.Length > extendedLengthResponse!.Length ? normalLengthResponse : extendedLengthResponse;
            }

            if (responseApdu != null)
            {
                // If we got some data, return it, independent of what the status is.
                // NOTE: Java also checks responseAPDU.getData() != null and logs a warning here; the null
                // check is dropped since ResponseApdu.Data never returns null in this port (see
                // ResponseApdu.cs), and the warning is omitted per the non-essential-warning-omission
                // precedent used elsewhere in this port.
                return responseApdu.Data;
            }

            throw new CardServiceException("Internal Authenticate failed", sw);
        }
    }

    /// <summary>
    /// Returns the maximum length of the (unprotected) response data for which the protected response
    /// still fits in a short response APDU (256 bytes). The protected response consists of DO'87
    /// (4 bytes header, padded data), DO'99 (4 bytes), and DO'8E (10 bytes), so the padded data is at
    /// most 238 bytes. Padding always adds at least one byte. This gives 231 bytes for 3DES and 223
    /// bytes for AES secure messaging.
    /// </summary>
    /// <param name="wrapper">the secure messaging wrapper</param>
    /// <returns>the maximum response data length in bytes</returns>
    private static int GetMaxShortResponseDataLength(IApduWrapper? wrapper)
    {
        if (wrapper is not SecureMessagingWrapper secureMessagingWrapper)
        {
            // Consistent with previous behavior.
            return 231;
        }

        int padLength = secureMessagingWrapper.PadLength;
        return (238 / padLength) * padLength - 1;
    }
}
