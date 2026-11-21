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

using BigInteger = Org.BouncyCastle.Math.BigInteger;

using nMRTD.Logging;
using nMRTD.SmartCards;

namespace nMRTD.Protocol;

/// <summary>
/// Port of <c>org.jmrtd.protocol.EACCAAPDUSender</c>: a low-level APDU sender to support the EAC-CA
/// protocol (version 1). This provides functionality for the "DESede" case and for the "AES" case.
/// </summary>
public class EACCAAPDUSender : IApduLevelEacCACapable
{
    /// <summary>The general Authenticate command is used to perform the EAC-CA protocol.</summary>
    private const byte InsBsiGeneralAuthenticate = 0x86;

    private readonly object _lock = new();

    private readonly SecureMessagingAPDUSender _secureMessagingSender;

    /// <summary>The log/trace registry shared with every other sender wrapping the same underlying service.</summary>
    public LogSource Log => _secureMessagingSender.Log;

    /// <summary>Creates an APDU sender for the EAC-CA protocol.</summary>
    /// <param name="service">the card service for tranceiving APDUs</param>
    /// <remarks>
    /// Obsolete: use <see cref="EACCAAPDUSender(SecureMessagingAPDUSender)"/> instead, sharing a single
    /// <see cref="SecureMessagingAPDUSender"/> between all senders wrapping the same underlying card
    /// service (see <c>PassportService.GetSecureMessagingAPDUSender()</c>).
    /// </remarks>
    [Obsolete("Use EACCAAPDUSender(SecureMessagingAPDUSender) instead, sharing a single SecureMessagingAPDUSender between all senders wrapping the same underlying card service.")]
    public EACCAAPDUSender(CardService service)
        : this(new SecureMessagingAPDUSender(service))
    {
    }

    /// <summary>Creates an APDU sender for the EAC-CA protocol.</summary>
    /// <param name="secureMessagingSender">the (shared) secure messaging APDU sender for tranceiving APDUs</param>
    public EACCAAPDUSender(SecureMessagingAPDUSender secureMessagingSender)
    {
        _secureMessagingSender = secureMessagingSender;
    }

    /// <summary>
    /// The MSE KAT APDU, see EAC 1.11 spec, Section B.1. This command is sent in the "DESede" case.
    /// </summary>
    /// <param name="wrapper">secure messaging wrapper</param>
    /// <param name="keyData">key data object (tag 0x91)</param>
    /// <param name="idData">key id data object (tag 0x84), can be <c>null</c></param>
    /// <exception cref="CardServiceException">on error</exception>
    public void SendMseKat(IApduWrapper? wrapper, byte[] keyData, byte[]? idData)
    {
        lock (_lock)
        {
            byte[] data = new byte[keyData.Length + (idData?.Length ?? 0)];
            Array.Copy(keyData, 0, data, 0, keyData.Length);
            if (idData != null)
            {
                Array.Copy(idData, 0, data, keyData.Length, idData.Length);
            }

            var commandApdu = new CommandApdu(Iso7816.ClaIso7816, Iso7816.InsMse, 0x41, 0xA6, data);
            ResponseApdu responseApdu = _secureMessagingSender.Transmit(wrapper, commandApdu);
            int sw = responseApdu.Sw;
            if (sw != Iso7816.SwNoError)
            {
                throw new CardServiceException("Sending MSE KAT failed", sw);
            }
        }
    }

    /* For Chip Authentication. We prefix 0x80 for OID and 0x84 for keyId. */

    /// <summary>
    /// The MSE Set AT for Chip Authentication. This command is the first command that is sent in the
    /// "AES" case.
    /// </summary>
    /// <param name="wrapper">secure messaging wrapper</param>
    /// <param name="oid">the OID</param>
    /// <param name="keyId">the keyId or <c>null</c></param>
    /// <exception cref="CardServiceException">on error</exception>
    public void SendMseSetAtIntAuth(IApduWrapper? wrapper, string oid, BigInteger? keyId)
    {
        lock (_lock)
        {
            const int p1 = 0x41;
            const int p2 = 0xA4;
            ResponseApdu? rapdu;
            if (keyId == null || keyId.SignValue < 0)
            {
                var commandApdu = new CommandApdu(Iso7816.ClaIso7816, Iso7816.InsMse, p1, p2, Util.ToOIDBytes(oid));
                rapdu = _secureMessagingSender.Transmit(wrapper, commandApdu);
            }
            else
            {
                byte[] oidBytes = Util.ToOIDBytes(oid);

                byte[] keyIdBytes = TlvUtil.WrapDO(0x84, Util.I2os(keyId));

                using var stream = new MemoryStream();
                stream.Write(oidBytes, 0, oidBytes.Length);
                stream.Write(keyIdBytes, 0, keyIdBytes.Length);

                var commandApdu = new CommandApdu(Iso7816.ClaIso7816, Iso7816.InsMse, p1, p2, stream.ToArray());
                rapdu = _secureMessagingSender.Transmit(wrapper, commandApdu);
            }

            int sw = rapdu?.Sw ?? -1;
            if (sw != Iso7816.SwNoError)
            {
                throw new CardServiceException("Sending MSE AT failed", sw);
            }
        }
    }

    /// <summary>
    /// Sends a General Authenticate command. This command is the second command that is sent in the
    /// "AES" case. This uses 256 for the expected length.
    /// </summary>
    /// <param name="wrapper">secure messaging wrapper</param>
    /// <param name="data">data to be sent, without the <c>0x7C</c> prefix (this method will add it)</param>
    /// <param name="isLast">indicates whether this is the last command in the chain</param>
    /// <returns>dynamic authentication data without the <c>0x7C</c> prefix (this method will remove it)</returns>
    /// <exception cref="CardServiceException">on error</exception>
    public byte[] SendGeneralAuthenticate(IApduWrapper? wrapper, byte[] data, bool isLast) =>
        SendGeneralAuthenticate(wrapper, data, 256, isLast);

    /// <summary>
    /// Sends a General Authenticate command. This command is the second command that is sent in the
    /// "AES" case.
    /// </summary>
    /// <param name="wrapper">secure messaging wrapper</param>
    /// <param name="data">data to be sent, without the <c>0x7C</c> prefix (this method will add it)</param>
    /// <param name="le">the expected length</param>
    /// <param name="isLast">indicates whether this is the last command in the chain</param>
    /// <returns>dynamic authentication data without the <c>0x7C</c> prefix (this method will remove it)</returns>
    /// <exception cref="CardServiceException">on error</exception>
    public byte[] SendGeneralAuthenticate(IApduWrapper? wrapper, byte[] data, int le, bool isLast)
    {
        lock (_lock)
        {
            byte[] commandData = TlvUtil.WrapDO(0x7C, data); // FIXME: constant for 0x7C (carried over from Java).

            /*
             * NOTE: Support of Protocol Response Data is CONDITIONAL:
             * It MUST be provided for version 2 but MUST NOT be provided for version 1.
             * So, we are expecting 0x7C (= tag), 0x00 (= length) here.
             */
            var commandApdu = new CommandApdu(isLast ? Iso7816.ClaIso7816 : Iso7816.ClaCommandChaining, InsBsiGeneralAuthenticate, 0x00, 0x00, commandData, le);
            ResponseApdu rapdu = _secureMessagingSender.Transmit(wrapper, commandApdu);

            /* Handle error status word. */
            int sw = rapdu.Sw;

            if (sw == Iso7816.SwWrongLength)
            {
                commandApdu = new CommandApdu(isLast ? Iso7816.ClaIso7816 : Iso7816.ClaCommandChaining, InsBsiGeneralAuthenticate, 0x00, 0x00, commandData, 256);
                rapdu = _secureMessagingSender.Transmit(wrapper, commandApdu);
                sw = rapdu.Sw;
            }

            if (sw != Iso7816.SwNoError)
            {
                throw new CardServiceException("Sending general authenticate failed", sw);
            }

            byte[] responseData = rapdu.Data;
            try
            {
                responseData = TlvUtil.UnwrapDO(0x7C, responseData);
            }
            catch (Exception)
            {
                // NOTE: Java logs a warning ("Could not unwrap response to GENERAL AUTHENTICATE") here;
                // omitted per the non-essential-warning-omission precedent used elsewhere in this port.
            }

            return responseData;
        }
    }
}
