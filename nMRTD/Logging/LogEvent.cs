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
/// A single log/trace entry raised by the library: an APDU exchange, a protocol step, an execution state
/// change, or an error. Deliberately not tied to any logging framework (e.g.
/// Microsoft.Extensions.Logging) -- consumers that want to feed it into one can do so trivially from an
/// <see cref="ILogListener"/> (or <see cref="DelegateLogListener"/>), but the library itself takes no such
/// dependency, keeping it AOT/trimming-friendly and framework-agnostic. See <see cref="LogSource"/> for how
/// these are raised and dispatched.
/// </summary>
/// <param name="Timestamp">when the event was raised</param>
/// <param name="Level">the severity of the event</param>
/// <param name="Category">a short free-form source tag, e.g. <c>"PACE"</c>, <c>"BAC"</c>, <c>"APDU"</c> -- typically the protocol or component that raised the event</param>
/// <param name="Message">a human-readable description of the event</param>
/// <param name="Exception">the exception associated with the event, if any (typically set only for <see cref="LogLevel.Error"/> events)</param>
public readonly record struct LogEvent(DateTimeOffset Timestamp, LogLevel Level, string Category, string Message, Exception? Exception = null)
{
    public override string ToString() => Exception == null
        ? $"[{Timestamp:HH:mm:ss.fff}] {Level,-11} {Category}: {Message}"
        : $"[{Timestamp:HH:mm:ss.fff}] {Level,-11} {Category}: {Message} -- {Exception.GetType().Name}: {Exception.Message}";
}
