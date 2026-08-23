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

namespace nMRTD.Logging;

/// <summary>
/// Receives <see cref="LogEvent"/>s raised by the library. Mirrors
/// <see cref="nMRTD.SmartCards.IApduListener"/>'s registration pattern (see <see cref="LogSource"/>), so
/// that consumers already familiar with subscribing to APDU traffic can subscribe to protocol-level
/// logging the same way. For simple cases (a lambda writing to <see cref="Console"/>, for instance), use
/// <see cref="DelegateLogListener"/> instead of implementing this interface directly.
/// </summary>
public interface ILogListener
{
    void Log(LogEvent logEvent);
}
