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

using System.Numerics;

using nMRTD.SmartCards;

namespace nMRTD;

/// <summary>
/// Port of <c>org.jmrtd.APDULevelEACCACapable</c>: the low-level capability of sending APDUs for the
/// (EAC) Chip Authentication protocol (version 1).
/// </summary>
public interface IApduLevelEacCACapable
{
    /// <summary>The MSE KAT APDU, see EAC 1.11 spec, Section B.1.</summary>
    /// <param name="wrapper">secure messaging wrapper</param>
    /// <param name="keyData">key data object (tag 0x91)</param>
    /// <param name="idData">key id data object (tag 0x84), can be <c>null</c></param>
    /// <exception cref="CardServiceException">on error</exception>
    void SendMseKat(IApduWrapper? wrapper, byte[] keyData, byte[]? idData);

    /// <summary>The MSE Set AT for Chip Authentication.</summary>
    /// <param name="wrapper">secure messaging wrapper</param>
    /// <param name="oid">the OID</param>
    /// <param name="keyId">the keyId or <c>null</c></param>
    /// <exception cref="CardServiceException">on error</exception>
    void SendMseSetAtIntAuth(IApduWrapper? wrapper, string oid, BigInteger? keyId);

    /// <summary>Sends a General Authenticate command.</summary>
    /// <param name="wrapper">secure messaging wrapper</param>
    /// <param name="data">data to be sent, without the 0x7C prefix (this method will add it)</param>
    /// <param name="isLast">indicates whether this is the last command in the chain</param>
    /// <returns>dynamic authentication data without the 0x7C prefix (this method will remove it)</returns>
    /// <exception cref="CardServiceException">on error</exception>
    byte[] SendGeneralAuthenticate(IApduWrapper? wrapper, byte[] data, bool isLast);
}
