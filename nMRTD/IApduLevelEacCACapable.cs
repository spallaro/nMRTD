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

using BigInteger = Org.BouncyCastle.Math.BigInteger;

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
    [Obsolete("Chip Authentication sends GENERAL AUTHENTICATE as a single command (Doc 9303-11, 9.3.1): use SendGeneralAuthenticate(wrapper, data).")]
    byte[] SendGeneralAuthenticate(IApduWrapper? wrapper, byte[] data, bool isLast);

    /// <summary>
    /// Sends the General Authenticate command of Chip Authentication as a single command, with extended length if
    /// the data needs it (Doc 9303-11, 9.3.1), as in JMRTD 0.8.11 (8711eb58). The default implementation sends it
    /// as the last command of a chain.
    /// </summary>
    /// <param name="wrapper">secure messaging wrapper</param>
    /// <param name="data">data to be sent, without the 0x7C prefix (this method will add it)</param>
    /// <returns>dynamic authentication data without the 0x7C prefix (this method will remove it)</returns>
    /// <exception cref="CardServiceException">on error</exception>
#pragma warning disable CS0618
    byte[] SendGeneralAuthenticate(IApduWrapper? wrapper, byte[] data) => SendGeneralAuthenticate(wrapper, data, true);
#pragma warning restore CS0618
}
