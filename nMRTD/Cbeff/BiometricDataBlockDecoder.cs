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
/// Port of <c>org.jmrtd.cbeff.BiometricDataBlockDecoder</c>: interface to be implemented by client code
/// to decode BDB implementations.
/// </summary>
/// <typeparam name="B">the type of BDB implementation that is decoded by this decoder</typeparam>
public interface BiometricDataBlockDecoder<B> where B : BiometricDataBlock
{
    /// <summary>Reads a biometric data block from an input stream.</summary>
    /// <param name="inputStream">the input stream to read from</param>
    /// <param name="sbh">the standard biometric header that preceded this BDB</param>
    /// <param name="index">the index of this BDB</param>
    /// <param name="length">the length of this BDB</param>
    /// <returns>a biometric data block</returns>
    B Decode(Stream inputStream, StandardBiometricHeader sbh, int index, int length);
}
