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
/// Port of <c>org.jmrtd.protocol.EACTAAPDUSender</c>: a low-level APDU sender to support the (EAC)
/// Terminal Authentication protocol.
/// </summary>
public class EACTAAPDUSender : IApduLevelEacTACapable
{
    private readonly object _lock = new();

    private readonly SecureMessagingAPDUSender _secureMessagingSender;

    /// <summary>The log/trace registry shared with every other sender wrapping the same underlying service.</summary>
    public LogSource Log => _secureMessagingSender.Log;

    /// <summary>Creates an APDU sender.</summary>
    /// <param name="service">the card service for tranceiving APDUs</param>
    /// <remarks>
    /// Obsolete: use <see cref="EACTAAPDUSender(SecureMessagingAPDUSender)"/> instead, sharing a single
    /// <see cref="SecureMessagingAPDUSender"/> between all senders wrapping the same underlying card
    /// service (see <c>PassportService.GetSecureMessagingAPDUSender()</c>).
    /// </remarks>
    [Obsolete("Use EACTAAPDUSender(SecureMessagingAPDUSender) instead, sharing a single SecureMessagingAPDUSender between all senders wrapping the same underlying card service.")]
    public EACTAAPDUSender(CardService service)
        : this(new SecureMessagingAPDUSender(service))
    {
    }

    /// <summary>Creates an APDU sender.</summary>
    /// <param name="secureMessagingSender">the (shared) secure messaging APDU sender for tranceiving APDUs</param>
    public EACTAAPDUSender(SecureMessagingAPDUSender secureMessagingSender)
    {
        _secureMessagingSender = secureMessagingSender;
    }

    /// <summary>
    /// The MSE DST APDU, see EAC 1.11 spec, Section B.2. This means that a case 3 APDU is sent, to which
    /// no response is expected.
    /// </summary>
    /// <param name="wrapper">secure messaging wrapper</param>
    /// <param name="data">public key reference data object (tag 0x83)</param>
    /// <exception cref="CardServiceException">on error</exception>
    public void SendMseSetDst(IApduWrapper? wrapper, byte[] data)
    {
        lock (_lock)
        {
            var commandApdu = new CommandApdu(Iso7816.ClaIso7816, Iso7816.InsMse, 0x81, 0xB6, data);
            ResponseApdu rapdu = _secureMessagingSender.Transmit(wrapper, commandApdu);
            int sw = rapdu.Sw;
            if (sw != Iso7816.SwNoError)
            {
                throw new CardServiceException("Sending MSE Set DST failed", sw);
            }
        }
    }

    /// <summary>Sends a perform security operation command in extended length mode.</summary>
    /// <param name="wrapper">secure messaging wrapper</param>
    /// <param name="certBodyData">the certificate body</param>
    /// <param name="certSignatureData">signature data</param>
    /// <exception cref="CardServiceException">on error communicating over the service</exception>
    public void SendPsoExtendedLengthMode(IApduWrapper? wrapper, byte[] certBodyData, byte[] certSignatureData)
    {
        lock (_lock)
        {
            byte[] certData = new byte[certBodyData.Length + certSignatureData.Length];
            Array.Copy(certBodyData, 0, certData, 0, certBodyData.Length);
            Array.Copy(certSignatureData, 0, certData, certBodyData.Length, certSignatureData.Length);

            var commandApdu = new CommandApdu(Iso7816.ClaIso7816, Iso7816.InsPso, 0, 0xBE, certData);
            ResponseApdu rapdu = _secureMessagingSender.Transmit(wrapper, commandApdu);
            int sw = rapdu.Sw;
            if (sw != Iso7816.SwNoError)
            {
                throw new CardServiceException("Sending PSO failed", sw);
            }
        }
    }

    /// <summary>
    /// The MSE Set AT APDU for TA, see EAC 1.11 spec, Section B.2. MANAGE SECURITY ENVIRONMENT command
    /// with SET Authentication Template function.
    ///
    /// Note that caller is responsible for prefixing the byte array params with specified tags.
    /// </summary>
    /// <param name="wrapper">secure messaging wrapper</param>
    /// <param name="data">public key reference data object (should already be prefixed with tag 0x83)</param>
    /// <exception cref="CardServiceException">on error</exception>
    public void SendMseSetAtExtAuth(IApduWrapper? wrapper, byte[] data)
    {
        lock (_lock)
        {
            var commandApdu = new CommandApdu(Iso7816.ClaIso7816, Iso7816.InsMse, 0x81, 0xA4, data);
            ResponseApdu rapdu = _secureMessagingSender.Transmit(wrapper, commandApdu);
            int sw = rapdu.Sw;
            if (sw != Iso7816.SwNoError)
            {
                throw new CardServiceException("Sending MSE AT failed", sw);
            }
        }
    }

    /// <summary>Sends a <c>GET CHALLENGE</c> command to the passport.</summary>
    /// <param name="wrapper">secure messaging wrapper</param>
    /// <returns>a byte array of length 8 containing the challenge</returns>
    /// <exception cref="CardServiceException">on transceive error</exception>
    public byte[] SendGetChallenge(IApduWrapper? wrapper)
    {
        lock (_lock)
        {
            var commandApdu = new CommandApdu(Iso7816.ClaIso7816, Iso7816.InsGetChallenge, 0x00, 0x00, 8);
            ResponseApdu rapdu = _secureMessagingSender.Transmit(wrapper, commandApdu);
            return rapdu.Data;
        }
    }

    /// <summary>Sends the EXTERNAL AUTHENTICATE command. This is used in EAC-TA.</summary>
    /// <param name="wrapper">secure messaging wrapper</param>
    /// <param name="signature">terminal signature</param>
    /// <exception cref="CardServiceException">if the resulting status word is different from 9000</exception>
    public void SendMutualAuthenticate(IApduWrapper? wrapper, byte[] signature)
    {
        lock (_lock)
        {
            var commandApdu = new CommandApdu(Iso7816.ClaIso7816, Iso7816.InsExternalAuthenticate, 0, 0, signature);
            ResponseApdu rapdu = _secureMessagingSender.Transmit(wrapper, commandApdu);
            int sw = rapdu.Sw;
            if (sw != Iso7816.SwNoError)
            {
                throw new CardServiceException("Sending External Authenticate failed.", sw);
            }
        }
    }
}
