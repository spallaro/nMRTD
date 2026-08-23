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
/// Registry and dispatch point for <see cref="LogEvent"/>s: owns a list of subscribed
/// <see cref="ILogListener"/>s and raises events to all of them. One instance is shared by every protocol
/// object involved in a single <see cref="PassportService"/> session (mirroring how a single
/// <see cref="nMRTD.Protocol.SecureMessagingAPDUSender"/> is already shared for APDU-level events -- see
/// that class's own doc comment), so a listener registered once (via <c>PassportService.AddLogListener</c>)
/// observes every APDU exchange, protocol step, execution state change, and error raised during that
/// session.
///
/// Deliberately independent of any logging framework: no static/ambient state, no reflection-based
/// provider discovery, nothing unsafe or unsupported under Native AOT. Consumers that want to bridge into
/// Microsoft.Extensions.Logging, Serilog, or plain <see cref="Console"/> output can do so by implementing
/// <see cref="ILogListener"/> or using <see cref="DelegateLogListener"/>.
/// </summary>
public sealed class LogSource
{
    private readonly List<ILogListener> _listeners = [];
    private readonly object _lock = new();

    /// <summary>Adds a listener.</summary>
    /// <param name="listener">the listener to add</param>
    public void AddListener(ILogListener listener)
    {
        ArgumentNullException.ThrowIfNull(listener);
        lock (_lock)
        {
            _listeners.Add(listener);
        }
    }

    /// <summary>Removes a listener. If the specified listener is not present, this method has no effect.</summary>
    /// <param name="listener">the listener to remove</param>
    public void RemoveListener(ILogListener listener)
    {
        lock (_lock)
        {
            _listeners.Remove(listener);
        }
    }

    /// <summary>Returns the currently registered listeners.</summary>
    public IReadOnlyCollection<ILogListener> Listeners
    {
        get
        {
            lock (_lock)
            {
                return _listeners.ToArray();
            }
        }
    }

    /// <summary>
    /// Raises a log event with the given level, category, message, and (optionally) an exception. A no-op
    /// (aside from the listener-count check) if nothing is currently subscribed.
    /// </summary>
    /// <param name="level">the severity of the event</param>
    /// <param name="category">a short free-form source tag, e.g. <c>"PACE"</c>, <c>"BAC"</c>, <c>"APDU"</c></param>
    /// <param name="message">a human-readable description of the event</param>
    /// <param name="exception">the exception associated with the event, if any</param>
    public void Log(LogLevel level, string category, string message, Exception? exception = null)
    {
        ILogListener[] snapshot;
        lock (_lock)
        {
            if (_listeners.Count == 0)
            {
                return;
            }
            snapshot = _listeners.ToArray();
        }

        var logEvent = new LogEvent(DateTimeOffset.Now, level, category, message, exception);
        foreach (ILogListener listener in snapshot)
        {
            listener.Log(logEvent);
        }
    }

    /// <summary>Raises a <see cref="LogLevel.Trace"/> event. See <see cref="Log"/>.</summary>
    public void Trace(string category, string message) => Log(LogLevel.Trace, category, message);

    /// <summary>Raises a <see cref="LogLevel.Debug"/> event. See <see cref="Log"/>.</summary>
    public void Debug(string category, string message) => Log(LogLevel.Debug, category, message);

    /// <summary>Raises a <see cref="LogLevel.Information"/> event. See <see cref="Log"/>.</summary>
    public void Info(string category, string message) => Log(LogLevel.Information, category, message);

    /// <summary>Raises a <see cref="LogLevel.Warning"/> event. See <see cref="Log"/>.</summary>
    public void Warn(string category, string message) => Log(LogLevel.Warning, category, message);

    /// <summary>Raises a <see cref="LogLevel.Error"/> event. See <see cref="Log"/>.</summary>
    public void Error(string category, string message, Exception? exception = null) => Log(LogLevel.Error, category, message, exception);
}
