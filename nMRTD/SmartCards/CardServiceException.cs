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
/// Port of <c>net.sf.scuba.smartcards.CardServiceException</c>. Carries the offending ISO 7816-4
/// status word (SW) when known; <see cref="Sw"/> is <c>-1</c> when no status word applies.
/// </summary>
public class CardServiceException : Exception
{
    public const int SwNotSet = -1;

    public int Sw { get; }

    public CardServiceException(string message)
        : base(message)
    {
        Sw = SwNotSet;
    }

    public CardServiceException(string message, Exception cause)
        : base(message, cause)
    {
        Sw = SwNotSet;
    }

    public CardServiceException(string message, int sw)
        : base(message)
    {
        Sw = sw;
    }

    public CardServiceException(string message, Exception cause, int sw)
        : base(message, cause)
    {
        Sw = sw;
    }
}
