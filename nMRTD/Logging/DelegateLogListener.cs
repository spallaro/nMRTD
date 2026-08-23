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
/// Adapts a plain delegate (e.g. a lambda writing to <see cref="Console"/>, or a call into an existing
/// logging framework) to <see cref="ILogListener"/>, so callers are not required to declare their own
/// listener class for simple cases.
/// </summary>
public sealed class DelegateLogListener : ILogListener
{
    private readonly Action<LogEvent> _handler;

    /// <summary>Creates a listener that forwards every event to the given delegate.</summary>
    /// <param name="handler">invoked once per raised <see cref="LogEvent"/></param>
    public DelegateLogListener(Action<LogEvent> handler) => _handler = handler ?? throw new ArgumentNullException(nameof(handler));

    public void Log(LogEvent logEvent) => _handler(logEvent);
}
