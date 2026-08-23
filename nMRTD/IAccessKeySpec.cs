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
/// Port of <c>org.jmrtd.AccessKeySpec</c>: super interface for <see cref="IBacKeySpec"/> and
/// <c>PaceKeySpec</c>. Java's <c>Serializable</c>/<c>java.security.spec.KeySpec</c> marker interfaces
/// carry no members of their own and are dropped (no reflection-based serialization is needed in this
/// port).
/// </summary>
public interface IAccessKeySpec
{
    /// <summary>Returns the type of access key. Typical values are "BAC" and "PACE".</summary>
    /// <returns>the type of access key</returns>
    string GetAlgorithm();

    /// <summary>Returns the bytes used for deriving the key seed.</summary>
    /// <returns>a byte array with the input for key derivation</returns>
    byte[] GetKey();
}
