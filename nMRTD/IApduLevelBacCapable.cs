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

using Org.BouncyCastle.Crypto.Parameters;

using nMRTD.SmartCards;

namespace nMRTD;

/// <summary>
/// Port of <c>org.jmrtd.APDULevelBACCapable</c>: the low-level capability of sending APDUs for the BAC
/// protocol. Java's <c>javax.crypto.SecretKey</c> parameters are ported as BouncyCastle
/// <see cref="KeyParameter"/> (raw symmetric key material), per porting-conventions.md's preference for
/// BouncyCastle types when interoperating with the rest of the crypto pipeline.
/// </summary>
public interface IApduLevelBacCapable
{
    /// <summary>Sends a GET CHALLENGE command to the passport.</summary>
    /// <returns>a byte array of length 8 containing the challenge</returns>
    /// <exception cref="CardServiceException">on tranceive error</exception>
    byte[] SendGetChallenge();

    /// <summary>
    /// Sends an EXTERNAL AUTHENTICATE command to the passport. This is part of BAC. The resulting byte
    /// array has length 32 and contains <c>rndIcc</c> (first 8 bytes), <c>rndIfd</c> (next 8 bytes),
    /// their key material <c>kIcc</c> (last 16 bytes).
    /// </summary>
    /// <param name="rndIfd">our challenge</param>
    /// <param name="rndIcc">their challenge</param>
    /// <param name="kIfd">our key material</param>
    /// <param name="kEnc">the static encryption key</param>
    /// <param name="kMac">the static mac key</param>
    /// <returns>
    /// a byte array of length 32 containing the response that was sent by the passport, decrypted
    /// (using <paramref name="kEnc"/>) and verified (using <paramref name="kMac"/>)
    /// </returns>
    /// <exception cref="CardServiceException">on tranceive error</exception>
    byte[] SendMutualAuth(byte[] rndIfd, byte[] rndIcc, byte[] kIfd, KeyParameter kEnc, KeyParameter kMac);
}
