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

/// <summary>Port of <c>org.jmrtd.BACDeniedException</c>: exception for signaling failed BAC.</summary>
[Obsolete("Use CardServiceProtocolException instead.")]
public class BacDeniedException : CardServiceException
{
    /// <summary>The BAC key that was tried before BAC failed.</summary>
    public IBacKeySpec BacKey { get; }

    /// <summary>Creates an exception.</summary>
    /// <param name="msg">the message</param>
    /// <param name="bacKey">the BAC entry that was tried</param>
    /// <param name="sw">status word or -1</param>
    public BacDeniedException(string msg, IBacKeySpec bacKey, int sw)
        : base(msg, sw)
    {
        BacKey = bacKey;
    }
}
