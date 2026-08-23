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

/// <summary>Severity of a <see cref="LogEvent"/>, used by listeners to filter or format log output.</summary>
public enum LogLevel
{
    /// <summary>Fine-grained diagnostic detail, e.g. individual APDU exchanges.</summary>
    Trace,

    /// <summary>Diagnostic detail useful while developing or troubleshooting, but noisy in normal use.</summary>
    Debug,

    /// <summary>A normal protocol step or execution state change (e.g. "Performing PACE (GM/ECDH)...").</summary>
    Information,

    /// <summary>Something unexpected but non-fatal, e.g. a fallback path was taken.</summary>
    Warning,

    /// <summary>An operation failed; <see cref="LogEvent.Exception"/> usually carries the cause.</summary>
    Error,
}
