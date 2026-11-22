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
/// Port of <c>org.jmrtd.protocol.SecureMessagingAPDUSender</c>: an APDU sender for tranceiving wrapped
/// APDUs. This is the shared base that the other <c>XxxAPDUSender</c> classes (<c>BACAPDUSender</c>,
/// <c>EACCAAPDUSender</c>, <c>EACTAAPDUSender</c>, <c>PACEAPDUSender</c>, <c>AAAPDUSender</c>,
/// <see cref="ReadBinaryAPDUSender"/>) are constructed from or wrap: each of those has a constructor
/// taking a <see cref="CardService"/> directly (which internally builds its own
/// <see cref="SecureMessagingAPDUSender"/>) and a second constructor taking a shared
/// <see cref="SecureMessagingAPDUSender"/> instance, so that a single instance -- and therefore a single
/// internal listener registered with the underlying <see cref="CardService"/>, and a single sequence
/// number / listener registry for the whole session -- can be shared between all senders wrapping the
/// same service.
///
/// ADAPTATIONs from the Java original:
/// <list type="bullet">
/// <item><c>isExtendedAPDULengthSupported()</c> (which just forwarded to
/// <c>service.isExtendedAPDULengthSupported()</c>) is omitted. That scuba <c>CardService</c> member was
/// deliberately not carried over to this port's <see cref="CardService"/> abstraction (see
/// docs/scuba-api-surface.md) since it has no caller anywhere in JMRTD's own source tree either -- it is
/// genuinely dead code upstream.</item>
/// <item>Java's <c>wrapper.getType()</c> call (used only to label the <see cref="WrappedApduEvent"/>
/// raised per exchange) assumes the concrete wrapper exposes a <c>getType()</c> method; this port's
/// <see cref="IApduWrapper"/> interface (already committed, fixed contract -- see
/// docs/scuba-api-surface.md) intentionally exposes only <c>Wrap</c>/<c>Unwrap</c>, no type tag. This is
/// resolved locally via <see cref="GetWrapperTypeTag"/>, which pattern-matches the two known concrete
/// wrapper types (<see cref="DESedeSecureMessagingWrapper"/>/<see cref="AESSecureMessagingWrapper"/>,
/// each of which still exposes a non-interface <c>Type</c> property mirroring Java's non-<c>@Override</c>
/// <c>getType()</c>) and falls back to the runtime type name for any other <see cref="IApduWrapper"/>
/// implementation.</item>
/// </list>
/// </summary>
public class SecureMessagingAPDUSender
{
    private readonly CardService _service;
    private readonly List<IApduListener> _listeners = [];
    private readonly object _listenersLock = new();
    private readonly object _sequenceNumberLock = new();

    private int _sequenceNumber;

    /// <summary>
    /// The general-purpose (APDU exchanges, protocol steps, execution state, errors) log/trace registry
    /// shared by every protocol sender wrapping the same underlying <see cref="CardService"/> -- see
    /// <see cref="Logging.LogSource"/>'s own doc comment. Distinct from <see cref="AddApduListener"/>:
    /// that mechanism delivers structured, full-byte <see cref="ApduEvent"/>s for every exchange; this one
    /// additionally carries a compact human-readable <see cref="LogLevel.Trace"/> summary of each exchange
    /// (raised from <see cref="Transmit"/>, alongside the free-form protocol-level narration that protocol
    /// classes such as <c>BACProtocol</c>/<c>PaceProtocol</c> raise through it directly) on the same
    /// single subscription, so a caller that just wants readable diagnostic output does not need to also
    /// wire up an <see cref="IApduListener"/> and format the bytes itself.
    /// </summary>
    public LogSource Log { get; } = new();

    /// <summary>
    /// Creates an APDU sender for tranceiving wrapped APDUs.
    ///
    /// Callers should create a single instance per underlying card service and share it (e.g. by
    /// constructor injection) between all senders wrapping that service, rather than creating one
    /// instance per sender. That way there is exactly one internal listener registered with the
    /// underlying service, and one sequence number / listener registry for the whole session.
    /// </summary>
    /// <param name="service">the card service for tranceiving the APDUs</param>
    public SecureMessagingAPDUSender(CardService service)
    {
        _service = service ?? throw new ArgumentNullException(nameof(service));
        _service.AddApduListener(new SequenceNumberListener(this));
    }

    /// <summary>
    /// Keeps our sequence number in sync with the underlying service's. Never forwards to public
    /// listeners -- <see cref="NotifyExchangedApdu"/> is the single place that does that, exactly once
    /// per <see cref="Transmit"/> call, so listeners never see both a raw and a wrapped notification for
    /// one exchange.
    /// </summary>
    private sealed class SequenceNumberListener(SecureMessagingAPDUSender owner) : IApduListener
    {
        public void ExchangedApdu(ApduEvent apduEvent) => owner.UpdateSequenceNumber(apduEvent.SequenceNumber);
    }

    private void UpdateSequenceNumber(int seq)
    {
        lock (_sequenceNumberLock)
        {
            if (seq > _sequenceNumber)
            {
                _sequenceNumber = seq;
            }
        }
    }

    private int GetCurrentSequenceNumber()
    {
        lock (_sequenceNumberLock)
        {
            return _sequenceNumber;
        }
    }

    /// <summary>Transmits an APDU.</summary>
    /// <param name="wrapper">the secure messaging wrapper, or <c>null</c> for none</param>
    /// <param name="commandApdu">the APDU to send</param>
    /// <returns>the APDU received from the PICC</returns>
    /// <exception cref="CardServiceException">if tranceiving failed</exception>
    public ResponseApdu Transmit(IApduWrapper? wrapper, CommandApdu commandApdu)
    {
        CommandApdu plainCapdu = commandApdu;
        if (wrapper != null)
        {
            commandApdu = wrapper.Wrap(commandApdu);
        }

        ResponseApdu responseApdu = _service.Transmit(commandApdu);
        ResponseApdu rawRapdu = responseApdu;
        int sw = responseApdu.Sw;

        int seq = GetCurrentSequenceNumber();

        if (wrapper == null)
        {
            // The underlying card service already notified its own (private, internal-only) listener of
            // this exchange, to keep our sequence number in sync -- see the constructor. Public listeners
            // are only ever registered on this instance, not on the underlying service, so we notify them
            // here, using the same "RAW" type the underlying service itself uses.
            NotifyExchangedApdu(new ApduEvent(this, "RAW", seq, commandApdu, responseApdu));
            LogApduExchange("RAW", commandApdu, responseApdu);
            return responseApdu;
        }

        ResponseApdu? plainTextResponseApdu = null;
        try
        {
            if ((sw & Iso7816.SwWrongLength) == Iso7816.SwWrongLength)
            {
                return responseApdu;
            }

            if (responseApdu.GetBytes().Length <= 2)
            {
                throw new CardServiceException(
                    $"Exception during transmission of wrapped APDU, C={Hex.BytesToHexString(plainCapdu.GetBytes())}", sw);
            }

            responseApdu = wrapper.Unwrap(responseApdu);
            plainTextResponseApdu = responseApdu;
            return responseApdu;
        }
        catch (CardServiceException)
        {
            throw;
        }
        catch (Exception e)
        {
            throw new CardServiceException(
                $"Exception during transmission of wrapped APDU, C={Hex.BytesToHexString(plainCapdu.GetBytes())}", e, sw);
        }
        finally
        {
            // plainTextResponseApdu is null here if wrapper.Unwrap(...) was never reached (SW_WRONG_LENGTH,
            // short response, or an exception), so listeners can tell "not unwrapped" apart from an actual
            // plaintext response.
            string wrapperTypeTag = GetWrapperTypeTag(wrapper);
            NotifyExchangedApdu(new WrappedApduEvent(this, wrapperTypeTag, seq, plainCapdu, plainTextResponseApdu, commandApdu, rawRapdu));
            LogApduExchange(wrapperTypeTag, plainCapdu, rawRapdu);
        }
    }

    /// <summary>Determines whether an exception indicates a tag is lost event.</summary>
    /// <param name="e">an exception</param>
    /// <returns>whether the exception indicates a tag is lost event</returns>
    public bool IsConnectionLost(Exception e) => _service.IsConnectionLost(e);

    /// <summary>Adds a listener.</summary>
    /// <param name="listener">the listener to add</param>
    public void AddApduListener(IApduListener listener)
    {
        ArgumentNullException.ThrowIfNull(listener);
        lock (_listenersLock)
        {
            if (!_listeners.Contains(listener))
            {
                _listeners.Add(listener);
            }
        }
    }

    /// <summary>Removes a listener. If the specified listener is not present, this method has no effect.</summary>
    /// <param name="listener">the listener to remove</param>
    public void RemoveApduListener(IApduListener listener)
    {
        lock (_listenersLock)
        {
            _listeners.Remove(listener);
        }
    }

    /// <summary>Returns the currently registered listeners.</summary>
    public IReadOnlyCollection<IApduListener> ApduListeners
    {
        get
        {
            lock (_listenersLock)
            {
                return _listeners.ToArray();
            }
        }
    }

    /// <summary>
    /// Notifies listeners about an APDU event. Called exactly once per <see cref="Transmit"/> call, so
    /// listeners never see both a raw and a wrapped notification for the same exchange.
    /// </summary>
    /// <param name="apduEvent">the APDU event</param>
    protected void NotifyExchangedApdu(ApduEvent apduEvent)
    {
        IApduListener[] snapshot;
        lock (_listenersLock)
        {
            if (_listeners.Count == 0)
            {
                return;
            }
            snapshot = _listeners.ToArray();
        }

        foreach (IApduListener listener in snapshot)
        {
            listener.ExchangedApdu(apduEvent);
        }
    }

    /// <summary>See this class's doc comment: resolves the type tag Java obtained via <c>wrapper.getType()</c>.</summary>
    private static string GetWrapperTypeTag(IApduWrapper wrapper) => wrapper switch
    {
        DESedeSecureMessagingWrapper desEdeWrapper => desEdeWrapper.Type,
        AESSecureMessagingWrapper aesWrapper => aesWrapper.Type,
        _ => wrapper.GetType().Name,
    };

    /// <summary>
    /// Raises two <see cref="LogLevel.Trace"/> events on <see cref="Log"/> for one APDU exchange -- one for
    /// the outgoing command, one for the incoming response -- rather than a single combined line, so a
    /// listener (e.g. <c>nMRTD.Cli</c>'s console listener) can visually tell requests and responses apart
    /// (arrows, color, etc.) without having to parse a combined string back apart. Each message starts with
    /// a fixed <c>"-->"</c>/<c>"&lt;--"</c> marker for exactly that purpose. Deliberately reports only the
    /// numeric status word, not an interpretation of it (e.g. "OK"/"ERROR") -- that is a presentation
    /// concern for the listener, not something this framework-agnostic library should decide.
    /// </summary>
    private void LogApduExchange(string type, CommandApdu commandApdu, ResponseApdu responseApdu)
    {
        Log.Trace("APDU", $"--> {type} CLA={commandApdu.Cla:X2} INS={commandApdu.Ins:X2} P1={commandApdu.P1:X2} P2={commandApdu.P2:X2} Lc={commandApdu.Data.Length}");
        Log.Trace("APDU", $"<-- {type} SW={responseApdu.Sw:X4} Lr={responseApdu.Data.Length}");
    }

    /* EXPERIMENTAL CODE BELOW (carried over from the Java original: unused within JMRTD itself, kept for
     * 1:1 traceability against Java call sites in case a future port phase wires it up). */

    /// <summary>Sends a (lengthy) command APDU using command chaining as described in ISO 7816-4 5.3.3.</summary>
    /// <param name="commandApdu">the command APDU to send</param>
    /// <param name="chunkSize">the maximum size of data within each APDU</param>
    /// <returns>the resulting response APDUs that were received</returns>
    /// <exception cref="CardServiceException">on error while sending</exception>
    private List<ResponseApdu> SendUsingCommandChaining(CommandApdu commandApdu, int chunkSize)
    {
        byte[] data = commandApdu.Data;
        List<byte[]> segments = Util.Partition(chunkSize, data);
        var responseApdus = new List<ResponseApdu>(segments.Count);
        int index = 0;
        foreach (byte[] segment in segments)
        {
            bool isLast = ++index >= segments.Count;
            int cla = commandApdu.Cla;
            if (!isLast)
            {
                cla |= Iso7816.ClaCommandChaining;
            }
            var partialCommandApdu = new CommandApdu(cla, commandApdu.Ins, commandApdu.P1, commandApdu.P2, segment, commandApdu.Ne);
            ResponseApdu responseApdu = _service.Transmit(partialCommandApdu);
            responseApdus.Add(responseApdu);
        }

        return responseApdus;
    }

    /// <summary>
    /// Response chaining as described in ISO 7816-4 Section 5.3.4. This will send additional
    /// <c>GET RESPONSE</c> APDUs.
    /// </summary>
    /// <param name="wrapper">a secure messaging wrapper</param>
    /// <param name="sw">the status word of the first APDU, of which the first byte is <c>0x61</c></param>
    /// <param name="data">the data of the first response APDU</param>
    /// <returns>the total amount of data</returns>
    /// <exception cref="CardServiceException">on error while sending</exception>
    private byte[] ContinueSendingUsingResponseChaining(IApduWrapper? wrapper, int sw, byte[] data)
    {
        using var stream = new MemoryStream();
        while ((sw & 0xFF00) == 0x6100)
        {
            // More bytes remaining.
            stream.Write(data);

            int remainingLength = sw & 0xFF;
            if (remainingLength <= 0)
            {
                break;
            }

            var capdu = new CommandApdu(Iso7816.ClaIso7816, Iso7816.InsGetResponse, 0x00, 0x00, remainingLength);
            ResponseApdu rapdu = Transmit(wrapper, capdu);
            data = rapdu.Data;
            sw = rapdu.Sw;
        }

        return stream.ToArray();
    }
}
