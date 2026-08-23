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
/// Port of <c>org.jmrtd.APDULevelEACTACapable</c>: the low-level capability of sending APDUs for the
/// (EAC) Terminal Authentication protocol.
/// </summary>
public interface IApduLevelEacTACapable
{
    /// <summary>The MSE DST APDU, see EAC 1.11 spec, Section B.2.</summary>
    /// <param name="wrapper">secure messaging wrapper</param>
    /// <param name="data">public key reference data object (tag 0x83)</param>
    /// <exception cref="CardServiceException">on error</exception>
    void SendMseSetDst(IApduWrapper? wrapper, byte[] data);

    /// <summary>Sends a perform security operation command in extended length mode.</summary>
    /// <param name="wrapper">secure messaging wrapper</param>
    /// <param name="certBodyData">the certificate body</param>
    /// <param name="certSignatureData">signature data</param>
    /// <exception cref="CardServiceException">on error communicating over the service</exception>
    void SendPsoExtendedLengthMode(IApduWrapper? wrapper, byte[] certBodyData, byte[] certSignatureData);

    /// <summary>
    /// The MSE Set AT APDU for TA, see EAC 1.11 spec, Section B.2. MANAGE SECURITY ENVIRONMENT command
    /// with SET Authentication Template function.
    /// </summary>
    /// <remarks>Caller is responsible for prefixing <paramref name="data"/> with the specified tags.</remarks>
    /// <param name="wrapper">secure messaging wrapper</param>
    /// <param name="data">public key reference data object (should already be prefixed with tag 0x83)</param>
    /// <exception cref="CardServiceException">on error</exception>
    void SendMseSetAtExtAuth(IApduWrapper? wrapper, byte[] data);

    /// <summary>Sends a GET CHALLENGE command to the passport.</summary>
    /// <param name="wrapper">secure messaging wrapper</param>
    /// <returns>a byte array of length 8 containing the challenge</returns>
    /// <exception cref="CardServiceException">on tranceive error</exception>
    byte[] SendGetChallenge(IApduWrapper? wrapper);

    /// <summary>Sends the EXTERNAL AUTHENTICATE command. This is used in EAC-TA.</summary>
    /// <param name="wrapper">secure messaging wrapper</param>
    /// <param name="signature">terminal signature</param>
    /// <exception cref="CardServiceException">if the resulting status word is different from 9000</exception>
    void SendMutualAuthenticate(IApduWrapper? wrapper, byte[] signature);
}
