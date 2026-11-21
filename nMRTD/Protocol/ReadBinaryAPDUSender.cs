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
/// Port of <c>org.jmrtd.protocol.ReadBinaryAPDUSender</c>: an APDU sender to support reading binaries,
/// both selection and short file identifier based.
///
/// ADAPTATION: per this port's already-committed <see cref="IApduLevelReadBinaryCapable"/> contract (see
/// docs/scuba-api-surface.md), <see cref="SendReadBinary"/> is declared to return a non-nullable
/// <c>byte[]</c>, mirroring the interface exactly -- but, just like the Java original (which can return
/// <c>null</c>, e.g. when <c>le == 0</c>, "in case the data ended right on the block boundary"), and just
/// like this port's own already-committed <c>DefaultFileSystem.SendReadBinary</c> (which forwards to this
/// method and whose callers explicitly null-check the result despite the same non-nullable-looking
/// signature), this implementation can and does return <c>null</c> in those same edge cases. The
/// non-nullable annotation on the interface member is a pre-existing minor looseness in this codebase,
/// not something to "fix" by inventing a different (e.g. empty-array) sentinel that Java-side callers and
/// the rest of this port do not expect.
/// </summary>
public class ReadBinaryAPDUSender : IApduLevelReadBinaryCapable
{
    private readonly SecureMessagingAPDUSender _secureMessagingSender;
    private readonly object _lock = new();

    /// <summary>The log/trace registry shared with every other sender wrapping the same underlying service.</summary>
    public LogSource Log => _secureMessagingSender.Log;

    /// <summary>
    /// Creates an APDU sender.
    /// </summary>
    /// <param name="service">the card service for tranceiving APDUs</param>
    /// <remarks>
    /// Prefer <see cref="ReadBinaryAPDUSender(SecureMessagingAPDUSender)"/> instead, sharing a single
    /// <see cref="SecureMessagingAPDUSender"/> between all senders wrapping the same underlying card
    /// service.
    /// </remarks>
    [Obsolete("Prefer the constructor accepting a shared SecureMessagingAPDUSender.")]
    public ReadBinaryAPDUSender(CardService service)
        : this(new SecureMessagingAPDUSender(service))
    {
    }

    /// <summary>Creates an APDU sender.</summary>
    /// <param name="secureMessagingSender">the (shared) secure messaging APDU sender for tranceiving APDUs</param>
    public ReadBinaryAPDUSender(SecureMessagingAPDUSender secureMessagingSender)
    {
        _secureMessagingSender = secureMessagingSender ?? throw new ArgumentNullException(nameof(secureMessagingSender));
    }

    /// <summary>
    /// Adds a listener. The listener is notified once per APDU exchange, whether or not secure messaging
    /// is in effect for that exchange.
    /// </summary>
    /// <param name="listener">the listener to add</param>
    public void AddApduListener(IApduListener listener) => _secureMessagingSender.AddApduListener(listener);

    /// <summary>Removes a listener. If the specified listener is not present, this method has no effect.</summary>
    /// <param name="listener">the listener to remove</param>
    public void RemoveApduListener(IApduListener listener) => _secureMessagingSender.RemoveApduListener(listener);

    /// <summary>Returns the currently registered listeners.</summary>
    public IReadOnlyCollection<IApduListener> ApduListeners => _secureMessagingSender.ApduListeners;

    /// <inheritdoc />
    public void SendSelectApplet(IApduWrapper? wrapper, byte[] aid)
    {
        ArgumentNullException.ThrowIfNull(aid);
        lock (_lock)
        {
            var commandApdu = new CommandApdu(Iso7816.ClaIso7816, Iso7816.InsSelectFile, 0x04, 0x0C, aid);
            ResponseApdu responseApdu = _secureMessagingSender.Transmit(wrapper, commandApdu);
            CheckStatusWordAfterFileOperation(commandApdu, responseApdu);
        }
    }

    /// <inheritdoc />
    public void SendSelectMf()
    {
        lock (_lock)
        {
            var commandApdu = new CommandApdu(Iso7816.ClaIso7816, Iso7816.InsSelectFile, 0x00, 0x0C);
            ResponseApdu responseApdu = _secureMessagingSender.Transmit(null, commandApdu);
            CheckStatusWordAfterFileOperation(commandApdu, responseApdu);
        }
    }

    /// <inheritdoc />
    public void SendSelectFile(IApduWrapper? wrapper, short fid)
    {
        lock (_lock)
        {
            byte[] fiddle = [(byte)((fid >> 8) & 0xFF), (byte)(fid & 0xFF)];
            var commandApdu = new CommandApdu(Iso7816.ClaIso7816, Iso7816.InsSelectFile, 0x02, 0x0c, fiddle, 0);
            ResponseApdu responseApdu = _secureMessagingSender.Transmit(wrapper, commandApdu);
            CheckStatusWordAfterFileOperation(commandApdu, responseApdu);
        }
    }

    /// <inheritdoc />
    public byte[] SendReadBinary(IApduWrapper? wrapper, int sfi, int offset, int le, bool isSfiEnabled, bool isTlvEncodedOffsetNeeded)
    {
        lock (_lock)
        {
            // In case the data ended right on the block boundary.
            if (le == 0)
            {
                return null!;
            }

            byte offsetMsb = (byte)((offset & 0xFF00) >> 8);
            byte offsetLsb = (byte)(offset & 0xFF);

            CommandApdu commandApdu;
            if (isTlvEncodedOffsetNeeded)
            {
                // In the case of long read 2 or 3 bytes less of the actual data will be returned, because a
                // tag and length will be sent along, here we need to account for this.
                if (le < 128)
                {
                    le += 2;
                }
                else if (le < 256)
                {
                    le += 3;
                }
                if (le > 256)
                {
                    le = 256;
                }

                byte[] data = [0x54, 0x02, offsetMsb, offsetLsb];
                commandApdu = new CommandApdu(Iso7816.ClaIso7816, Iso7816.InsReadBinary2, 0, 0, data, le);
            }
            else if (isSfiEnabled)
            {
                commandApdu = new CommandApdu(Iso7816.ClaIso7816, Iso7816.InsReadBinary, sfi, offsetLsb, le);
            }
            else
            {
                commandApdu = new CommandApdu(Iso7816.ClaIso7816, Iso7816.InsReadBinary, offsetMsb, offsetLsb, le);
            }

            ResponseApdu? responseApdu = null;
            CardServiceException? transmitException = null;
            try
            {
                responseApdu = _secureMessagingSender.Transmit(wrapper, commandApdu);
            }
            catch (CardServiceException cse)
            {
                transmitException = cse;
                if (_secureMessagingSender.IsConnectionLost(cse))
                {
                    // If fatal, we rethrow the underlying exception. If not, we will probably throw an
                    // exception later on (in CheckStatusWordAfterFileOperation).
                    // FIXME (carried over from Java): consider not catching this cse at all? -- MO
                    throw;
                }

                // NOTE: Java logs the exception here at FINE level; omitted per the non-essential-
                // warning-omission precedent used elsewhere in this port.
            }

            byte[]? responseData = GetResponseData(responseApdu, isTlvEncodedOffsetNeeded);
            // NOTE: Java logs a warning here if responseData is null/empty; omitted per the
            // non-essential-warning-omission precedent used elsewhere in this port.
            CheckStatusWordAfterFileOperation(commandApdu, responseApdu, transmitException);

            return responseData!;
        }
    }

    /* PRIVATE BELOW */

    /// <summary>Returns the response data from a response APDU.</summary>
    /// <param name="responseApdu">the response APDU</param>
    /// <param name="isTlvEncodedOffsetNeeded">whether to expect a <c>0x53</c> tag encoded value</param>
    /// <returns>the response data</returns>
    /// <exception cref="CardServiceException">on error</exception>
    private static byte[]? GetResponseData(ResponseApdu? responseApdu, bool isTlvEncodedOffsetNeeded)
    {
        if (responseApdu == null)
        {
            return null;
        }

        byte[] responseData = responseApdu.Data;
        if (!isTlvEncodedOffsetNeeded)
        {
            return responseData;
        }

        // Strip the response off the tag 0x53 and the length field.
        // FIXME (carried over from Java): use TlvUtil.TlvEncode(...) here. -- MO
        byte[] data = responseData;
        if (data.Length < 2 || data[0] != 0x53) // FIXME: constant for 0x53 (carried over from Java).
        {
            throw new CardServiceException("Malformed read binary long response data");
        }

        int index = 1;
        int valueLength = data[index++] & 0xFF;
        if ((valueLength & 0x80) != 0)
        {
            int lengthByteCount = valueLength & 0x7F;
            if (lengthByteCount == 0 || lengthByteCount > 4 || data.Length - index < lengthByteCount)
            {
                throw new CardServiceException("Malformed read binary long response data");
            }
            if ((data[index] & 0xFF) == 0)
            {
                throw new CardServiceException("Malformed read binary long response data");
            }
            long longValueLength = 0;
            for (int i = 0; i < lengthByteCount; i++)
            {
                longValueLength = (longValueLength << 8) | data[index++];
            }
            if (longValueLength < 128 || longValueLength > int.MaxValue)
            {
                throw new CardServiceException("Malformed read binary long response data");
            }
            valueLength = (int)longValueLength;
        }
        if (valueLength != data.Length - index)
        {
            throw new CardServiceException("Malformed read binary long response data");
        }

        byte[] result = new byte[valueLength];
        Array.Copy(data, index, result, 0, valueLength);
        return result;
    }

    /// <summary>Checks the status word and throws an appropriate <see cref="CardServiceException"/> on error.</summary>
    /// <param name="commandApdu">the command APDU that was sent</param>
    /// <param name="responseApdu">the response APDU that was received</param>
    /// <param name="transmitException">
    /// the exception that left <paramref name="responseApdu"/> <c>null</c>, if any; attached as the cause of
    /// the "No response APDU" exception so that the actual failure (reader error, status word, invalid MAC)
    /// is not lost. JMRTD drops it. The status word stays unset, as in JMRTD, so that callers such as
    /// <c>DefaultFileSystem</c> react to the exception exactly as before.
    /// </param>
    /// <exception cref="CardServiceException">if the response APDU's status word indicates some error</exception>
    private static void CheckStatusWordAfterFileOperation(CommandApdu commandApdu, ResponseApdu? responseApdu, CardServiceException? transmitException = null)
    {
        if (responseApdu == null)
        {
            if (transmitException != null)
            {
                throw new CardServiceException($"No response APDU: {transmitException.Message}", transmitException, CardServiceException.SwNotSet);
            }

            throw new CardServiceException("No response APDU");
        }

        byte[] data = responseApdu.Data;
        int sw = responseApdu.Sw;
        string commandResponseMessage = $"CAPDU = {Hex.BytesToHexString(commandApdu.GetBytes())}, RAPDU = {Hex.BytesToHexString(responseApdu.GetBytes())}";

        // If wrong length (6700) and no data. We abort.
        if ((sw & Iso7816.SwWrongLength) == Iso7816.SwWrongLength && data.Length == 0)
        {
            throw new CardServiceException($"Wrong length, {commandResponseMessage}", sw);
        }

        switch (sw)
        {
            case Iso7816.SwNoError:
                return;
            case Iso7816.SwEndOfFile:
                if (data.Length == 0)
                {
                    throw new CardServiceException($"End of file, {commandResponseMessage}", sw);
                }
                // May have data. Caller should check SW and stop calling on EOF.
                return;
            case Iso7816.SwFileNotFound:
                throw new CardServiceException($"File not found, {commandResponseMessage}", sw);
            case Iso7816.SwSecurityStatusNotSatisfied:
            case Iso7816.SwConditionsNotSatisfied:
            case Iso7816.SwCommandNotAllowed:
                throw new CardServiceException($"Access to file denied, {commandResponseMessage}", sw);
            default:
                throw new CardServiceException($"Error occured, {commandResponseMessage}", sw);
        }
    }
}
