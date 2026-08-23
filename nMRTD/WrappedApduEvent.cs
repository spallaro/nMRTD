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

using nMRTD.SmartCards;

namespace nMRTD;

/// <summary>
/// Port of <c>org.jmrtd.WrappedAPDUEvent</c>: an event signifying an exchange of wrapped (protected)
/// command and response APDUs. This makes the underlying unprotected APDUs available.
/// </summary>
public class WrappedApduEvent : ApduEvent
{
    /// <summary>The unprotected, plain-text command APDU.</summary>
    public CommandApdu PlainTextCommandApdu { get; }

    /// <summary>
    /// The unprotected, plain-text response APDU, or <c>null</c> if the response was never unwrapped
    /// (e.g. the exchange failed before unwrapping was attempted).
    /// </summary>
    public ResponseApdu? PlainTextResponseApdu { get; }

    /// <summary>Creates an APDU exchange event.</summary>
    /// <param name="source">the source of the event, typically a card service</param>
    /// <param name="type">the type of event, typically this identifies the APDU wrapper somehow</param>
    /// <param name="sequenceNumber">the sequence number of the APDU exchange within a session</param>
    /// <param name="plainTextCommandApdu">the unprotected command APDU</param>
    /// <param name="plainTextResponseApdu">the unprotected response APDU, or <c>null</c> if the response was never unwrapped</param>
    /// <param name="wrappedCommandApdu">the protected command APDU</param>
    /// <param name="wrappedResponseApdu">the protected response APDU</param>
    public WrappedApduEvent(
        object source,
        object type,
        int sequenceNumber,
        CommandApdu plainTextCommandApdu,
        ResponseApdu? plainTextResponseApdu,
        CommandApdu wrappedCommandApdu,
        ResponseApdu wrappedResponseApdu)
        : base(source, type, sequenceNumber, wrappedCommandApdu, wrappedResponseApdu)
    {
        PlainTextCommandApdu = plainTextCommandApdu ?? throw new ArgumentNullException(nameof(plainTextCommandApdu));
        PlainTextResponseApdu = plainTextResponseApdu;
    }
}
