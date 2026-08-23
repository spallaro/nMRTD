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
/// Port of <c>org.jmrtd.APDULevelPACECapable</c>: the low-level capability of sending APDUs for the
/// PACE protocol.
/// </summary>
public interface IApduLevelPaceCapable
{
    /// <summary>
    /// The MSE AT APDU for PACE, see ICAO TR-SAC-1.01, Section 3.2.1, BSI TR 03110 v2.03 B11.1.
    /// </summary>
    /// <remarks>Caller is (for now) responsible for prefixing the byte[] params with specified tags.</remarks>
    /// <param name="wrapper">secure messaging wrapper</param>
    /// <param name="oid">OID of the protocol to select (this method will prefix 0x80)</param>
    /// <param name="refPublicKeyOrSecretKey">value specifying whether to use MRZ (0x01) or CAN (0x02) (this method will prefix 0x83)</param>
    /// <param name="refPrivateKeyOrForComputingSessionKey">indicates a private key or reference for computing a session key (this method will prefix 0x84)</param>
    /// <exception cref="CardServiceException">on error</exception>
    void SendMseSetAtMutualAuth(IApduWrapper? wrapper, string oid, int refPublicKeyOrSecretKey, byte[] refPrivateKeyOrForComputingSessionKey);

    /// <summary>Sends a General Authenticate command.</summary>
    /// <param name="wrapper">secure messaging wrapper</param>
    /// <param name="data">data to be sent, without the 0x7C prefix (this method will add it)</param>
    /// <param name="le">the length to request</param>
    /// <param name="isLast">indicates whether this is the last command in the chain</param>
    /// <returns>dynamic authentication data without the 0x7C prefix (this method will remove it)</returns>
    /// <exception cref="CardServiceException">on error</exception>
    byte[] SendGeneralAuthenticate(IApduWrapper? wrapper, byte[] data, int le, bool isLast);
}
