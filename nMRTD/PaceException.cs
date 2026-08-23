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

namespace nMRTD;

/// <summary>
/// Port of <c>org.jmrtd.PACEException</c>: an exception to signal errors during execution of the PACE
/// protocol.
/// </summary>
[Obsolete("Use CardServiceProtocolException instead.")]
public class PaceException : CardServiceProtocolException
{
    /// <summary>Creates a <see cref="PaceException"/>.</summary>
    /// <param name="message">a message</param>
    /// <param name="step">the protocol step that failed</param>
    public PaceException(string message, int step)
        : base(message, step)
    {
    }

    /// <summary>Creates a <see cref="PaceException"/>.</summary>
    /// <param name="message">a message</param>
    /// <param name="step">the protocol step that failed</param>
    /// <param name="cause">the exception causing this exception</param>
    public PaceException(string message, int step, Exception cause)
        : base(message, step, cause)
    {
    }

    /// <summary>Creates a <see cref="PaceException"/> with a specific status word.</summary>
    /// <param name="message">a message</param>
    /// <param name="step">the protocol step that failed</param>
    /// <param name="sw">the status word that caused this exception</param>
    public PaceException(string message, int step, int sw)
        : base(message, step, sw)
    {
    }

    /// <summary>Creates a <see cref="PaceException"/> with a specific status word.</summary>
    /// <param name="message">a message</param>
    /// <param name="step">the protocol step that failed</param>
    /// <param name="cause">the exception causing this exception</param>
    /// <param name="sw">the status word that caused this exception</param>
    public PaceException(string message, int step, Exception cause, int sw)
        : base(message, step, cause, sw)
    {
    }
}
