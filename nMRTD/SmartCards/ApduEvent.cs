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
/// Port of <c>net.sf.scuba.smartcards.APDUEvent</c>. The constructor's <c>type</c> parameter is a
/// free-form tag: JMRTD passes the literal string "RAW" for unwrapped exchanges and the wrapper's own
/// algorithm marker for wrapped exchanges, so it is modeled as <see cref="object"/>, not a closed enum.
/// Not sealed: JMRTD's <c>WrappedAPDUEvent</c> (ported in a later phase, alongside secure messaging)
/// extends this type.
/// </summary>
public class ApduEvent
{
    public ApduEvent(object source, object type, int sequenceNumber, CommandApdu commandApdu, ResponseApdu responseApdu)
    {
        Source = source ?? throw new ArgumentNullException(nameof(source));
        Type = type ?? throw new ArgumentNullException(nameof(type));
        SequenceNumber = sequenceNumber;
        CommandApdu = commandApdu ?? throw new ArgumentNullException(nameof(commandApdu));
        ResponseApdu = responseApdu ?? throw new ArgumentNullException(nameof(responseApdu));
    }

    public object Source { get; }

    public object Type { get; }

    public int SequenceNumber { get; }

    public CommandApdu CommandApdu { get; }

    public ResponseApdu ResponseApdu { get; }
}
