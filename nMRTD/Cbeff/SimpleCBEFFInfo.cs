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

namespace nMRTD.Cbeff;

/// <summary>
/// Port of <c>org.jmrtd.cbeff.SimpleCBEFFInfo</c>: simple CBEFF BIR. Specified in ISO 19785-1 (version
/// 2.0) and NISTIR 6529-A (version 1.1).
/// </summary>
/// <typeparam name="B">the embedded BDB</typeparam>
public class SimpleCBEFFInfo<B> : CBEFFInfo<B> where B : BiometricDataBlock
{
    private readonly B _bdb;

    /// <summary>Constructs a simple CBEFF info from the given BDB.</summary>
    /// <param name="bdb">a biometric data block</param>
    public SimpleCBEFFInfo(B bdb)
    {
        _bdb = bdb;
    }

    /// <summary>Returns the biometric data block from this simple CBEFF info.</summary>
    /// <returns>a biometric data block</returns>
    public B GetBiometricDataBlock() => _bdb;

    /* NOTE: Java's SimpleCBEFFInfo does not override equals()/hashCode()/toString() -- it relies on
     * Object's identity-based defaults. Not overriding them here either, for parity. */
}
