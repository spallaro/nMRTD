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

/// <summary>Port of <c>org.jmrtd.AccessDeniedException</c>: exception for signaling failed BAC.</summary>
[Obsolete("Use CardServiceProtocolException instead.")]
public class AccessDeniedException : CardServiceException
{
    /// <summary>The BAC key that was tried before BAC failed, or <c>null</c>.</summary>
    public IAccessKeySpec? AccessKey { get; }

    /// <summary>Creates an exception.</summary>
    /// <param name="msg">the message</param>
    /// <param name="sw">status word or -1</param>
    public AccessDeniedException(string msg, int sw)
        : this(msg, null, sw)
    {
    }

    /// <summary>Creates an exception.</summary>
    /// <param name="msg">the message</param>
    /// <param name="bacKey">the BAC entry that was tried, or <c>null</c></param>
    /// <param name="sw">status word or -1</param>
    public AccessDeniedException(string msg, IAccessKeySpec? bacKey, int sw)
        : base(msg, sw)
    {
        AccessKey = bacKey;
    }
}
