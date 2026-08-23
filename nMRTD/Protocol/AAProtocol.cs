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

using Org.BouncyCastle.Crypto;

using nMRTD.Logging;
using nMRTD.SmartCards;

namespace nMRTD.Protocol;

/// <summary>Port of <c>org.jmrtd.protocol.AAProtocol</c>: the Active Authentication protocol.</summary>
public class AAProtocol
{
    private const string LogCategory = "AA";

    private readonly IApduLevelAACapable _service;
    private readonly SecureMessagingWrapper? _wrapper;
    private readonly LogSource _log;

    /// <summary>Creates a protocol instance.</summary>
    /// <param name="service">the service for APDU communication</param>
    /// <param name="wrapper">the secure messaging wrapper, or <c>null</c> for none</param>
    /// <param name="log">the log/trace registry to raise protocol-step and error events on, or <c>null</c> for a private (unobserved) one</param>
    public AAProtocol(IApduLevelAACapable service, SecureMessagingWrapper? wrapper, LogSource? log = null)
    {
        _service = service;
        _wrapper = wrapper;
        _log = log ?? new LogSource();
    }

    /// <summary>Performs the Active Authentication protocol.</summary>
    /// <param name="publicKey">the public key to use (usually read from the card)</param>
    /// <param name="digestAlgorithm">the digest algorithm to use, or <c>null</c></param>
    /// <param name="signatureAlgorithm">signature algorithm</param>
    /// <param name="challenge">challenge</param>
    /// <returns>the AA result</returns>
    /// <exception cref="CardServiceException">on error</exception>
    public AAResult DoAA(AsymmetricKeyParameter publicKey, string? digestAlgorithm, string? signatureAlgorithm, byte[] challenge)
    {
        _log.Info(LogCategory, "Starting Active Authentication.");
        try
        {
            if (challenge == null || challenge.Length != 8)
            {
                throw new ArgumentException("AA failed: bad challenge");
            }

            byte[] response = _service.SendInternalAuthenticate(_wrapper, Util.GetApproximateSignatureSize(publicKey), challenge);
            _log.Info(LogCategory, "Active Authentication completed.");
            return new AAResult(publicKey, digestAlgorithm, signatureAlgorithm, challenge, response);
        }
        catch (Exception e)
        {
            _log.Error(LogCategory, "Active Authentication failed.", e);
            throw new CardServiceProtocolException("Exception", 1, e);
        }
    }
}
