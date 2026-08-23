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
/// Port of <c>org.jmrtd.cbeff.BiometricDataBlockEncoder</c>: interface to be implemented by client code
/// to encode BDB implementations.
/// </summary>
/// <typeparam name="B">the type of BDB implementation that is encoded by this encoder</typeparam>
public interface BiometricDataBlockEncoder<B> where B : BiometricDataBlock
{
    /// <summary>Writes the biometric data block in <paramref name="bdb"/> to the output stream.</summary>
    /// <param name="bdb">the biometric data block to write</param>
    /// <param name="outputStream">the output stream to write to</param>
    void Encode(B bdb, Stream outputStream);

    /// <summary>Returns the biometric encoding type to be used when encoding BITs.</summary>
    /// <returns>the biometric encoding type, either ISO-19794 or ISO-39794</returns>
    BiometricEncodingType GetEncodingType();
}
