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
/// Port of <c>org.jmrtd.APDULevelAACapable</c>: the low-level capability of sending APDUs for the
/// Active Authentication protocol.
/// </summary>
public interface IApduLevelAACapable
{
    /// <summary>
    /// Sends an INTERNAL AUTHENTICATE command to the ICC. This method will remove the status word from
    /// the response.
    /// </summary>
    /// <param name="wrapper">the secure messaging wrapper to use, or <c>null</c> for none</param>
    /// <param name="signatureLength">the length of the public key in bits</param>
    /// <param name="rndIfd">the challenge to send</param>
    /// <returns>the response from the ICC</returns>
    /// <exception cref="CardServiceException">on transceive error</exception>
    byte[] SendInternalAuthenticate(IApduWrapper? wrapper, int signatureLength, byte[] rndIfd);
}
