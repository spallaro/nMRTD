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
/// Port of <c>net.sf.scuba.smartcards.APDUWrapper</c>. Implemented by JMRTD's secure messaging
/// wrapper (ported in a later phase) to secure/MAC outgoing commands and verify/decrypt incoming
/// responses.
/// </summary>
public interface IApduWrapper
{
    CommandApdu Wrap(CommandApdu commandApdu);

    ResponseApdu Unwrap(ResponseApdu responseApdu);
}
