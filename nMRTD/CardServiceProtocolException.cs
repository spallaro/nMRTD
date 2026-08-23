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
/// Port of <c>org.jmrtd.CardServiceProtocolException</c>: an exception to signal errors during
/// execution of a protocol.
/// </summary>
public class CardServiceProtocolException : CardServiceException
{
    /// <summary>Identifies the protocol step that failed.</summary>
    public int Step { get; }

    /// <summary>Creates a <see cref="CardServiceProtocolException"/>.</summary>
    /// <param name="message">a message</param>
    /// <param name="step">the protocol step that failed</param>
    public CardServiceProtocolException(string message, int step)
        : base(message)
    {
        Step = step;
    }

    /// <summary>Creates a <see cref="CardServiceProtocolException"/>.</summary>
    /// <param name="message">a message</param>
    /// <param name="step">the protocol step that failed</param>
    /// <param name="cause">the exception causing this exception</param>
    public CardServiceProtocolException(string message, int step, Exception cause)
        : base(message, cause)
    {
        Step = step;
    }

    /// <summary>Creates a <see cref="CardServiceProtocolException"/> with a specific status word.</summary>
    /// <param name="message">a message</param>
    /// <param name="step">the protocol step that failed</param>
    /// <param name="sw">the status word that caused this exception</param>
    public CardServiceProtocolException(string message, int step, int sw)
        : base(message, sw)
    {
        Step = step;
    }

    /// <summary>Creates a <see cref="CardServiceProtocolException"/> with a specific status word.</summary>
    /// <param name="message">a message</param>
    /// <param name="step">the protocol step that failed</param>
    /// <param name="cause">the exception causing this exception</param>
    /// <param name="sw">the status word that caused this exception</param>
    public CardServiceProtocolException(string message, int step, Exception cause, int sw)
        : base(message, cause, sw)
    {
        Step = step;
    }

    public override string Message => $"{base.Message} (step: {Step})";
}
