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

namespace nMRTD.Protocol;

/// <summary>
/// Port of <c>org.jmrtd.protocol.BACResult</c>: result of a Basic Access Control protocol run. Java's
/// <c>Serializable</c> marker is dropped per porting-conventions.md (no reflection-based serialization is
/// needed in this port).
/// </summary>
public sealed class BACResult
{
    /// <summary>The initial access key, or <c>null</c>.</summary>
    public IAccessKeySpec? BacKey { get; }

    /// <summary>The secure messaging wrapper that resulted from the BAC protocol run.</summary>
    public SecureMessagingWrapper Wrapper { get; }

    /// <summary>Creates a BAC result without specifying the initial access key.</summary>
    /// <param name="wrapper">the secure messaging wrapper that resulted from the BAC protocol run</param>
    public BACResult(SecureMessagingWrapper wrapper)
        : this(null, wrapper)
    {
    }

    /// <summary>Creates a BAC result.</summary>
    /// <param name="bacKey">the initial access key</param>
    /// <param name="wrapper">the secure messaging wrapper that resulted from the BAC protocol run</param>
    public BACResult(IAccessKeySpec? bacKey, SecureMessagingWrapper wrapper)
    {
        BacKey = bacKey;
        Wrapper = wrapper;
    }

    /// <summary>Returns a textual representation of this terminal authentication result.</summary>
    /// <returns>a textual representation of this terminal authentication result</returns>
    public override string ToString() =>
        $"BACResult [bacKey: {(BacKey == null ? "-" : BacKey.ToString())}, wrapper: {Wrapper}]";

    public override int GetHashCode()
    {
        const int prime = 1234567891;
        int result = 1991;
        result = (prime * result) + (BacKey?.GetHashCode() ?? 0);
        result = (prime * result) + (Wrapper?.GetHashCode() ?? 0);
        return result;
    }

    public override bool Equals(object? obj)
    {
        if (ReferenceEquals(this, obj))
        {
            return true;
        }

        if (obj is null || GetType() != obj.GetType())
        {
            return false;
        }

        var other = (BACResult)obj;
        return Equals(BacKey, other.BacKey) && Equals(Wrapper, other.Wrapper);
    }
}
