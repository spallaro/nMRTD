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

using System.Security.Cryptography;

using Org.BouncyCastle.Crypto.Parameters;

using nMRTD.Logging;
using nMRTD.SmartCards;

namespace nMRTD.Protocol;

/// <summary>
/// Port of <c>org.jmrtd.protocol.BACProtocol</c>: the Basic Access Control protocol.
///
/// ADAPTATION: Java's <c>java.util.Random random = new SecureRandom()</c> instance field is dropped in
/// favor of calling <see cref="RandomNumberGenerator.Fill(Span{byte})"/> directly at each use site -- a
/// stateless, thread-safe, cryptographically secure source of randomness requiring no instance field.
/// </summary>
public class BACProtocol
{
    private const string LogCategory = "BAC";

    private readonly IApduLevelBacCapable _service;
    private readonly int _maxTranceiveLength;
    private readonly bool _shouldCheckMac;
    private readonly LogSource _log;

    /// <summary>Constructs a BAC protocol instance.</summary>
    /// <param name="service">the service to send APDUs</param>
    /// <param name="maxTranceiveLength">the maximal tranceive length (on responses to <c>READ BINARY</c>) to use in the resulting secure messaging channel</param>
    /// <param name="shouldCheckMac">whether the resulting secure messaging channel should apply strict MAC checking on response APDUs</param>
    /// <param name="log">the log/trace registry to raise protocol-step and error events on, or <c>null</c> for a private (unobserved) one</param>
    public BACProtocol(IApduLevelBacCapable service, int maxTranceiveLength, bool shouldCheckMac, LogSource? log = null)
    {
        _service = service;
        _maxTranceiveLength = maxTranceiveLength;
        _shouldCheckMac = shouldCheckMac;
        _log = log ?? new LogSource();
    }

    /// <summary>Performs the Basic Access Control protocol.</summary>
    /// <param name="bacKey">the key based on the document number, the card holder's birth date, and the document's expiry date</param>
    /// <returns>the BAC result</returns>
    /// <exception cref="CardServiceException">if authentication failed</exception>
    public BACResult DoBAC(IAccessKeySpec bacKey)
    {
        _log.Info(LogCategory, "Starting BAC.");
        try
        {
            byte[] keySeed = bacKey.GetKey();
            var kEnc = new KeyParameter(Util.DeriveKey(keySeed, Util.ENC_MODE));
            var kMac = new KeyParameter(Util.DeriveKey(keySeed, Util.MAC_MODE));

            SecureMessagingWrapper wrapper = DoBACStep(kEnc, kMac);
            _log.Info(LogCategory, "BAC completed; secure messaging established.");
            return new BACResult(bacKey, wrapper);
        }
        catch (Org.BouncyCastle.Crypto.CryptoException ce)
        {
            _log.Error(LogCategory, "BAC failed during key derivation.", ce);
            throw new CardServiceException("Error during BAC", ce);
        }
        catch (CardServiceException e)
        {
            _log.Error(LogCategory, "BAC failed.", e);
            throw;
        }
    }

    /// <summary>
    /// Performs the Basic Access Control protocol. It does BAC using kEnc and kMac keys, usually
    /// calculated from the document number, the card holder's date of birth, and the card's date of
    /// expiry.
    /// </summary>
    /// <param name="kEnc">the static 3DES key required for BAC</param>
    /// <param name="kMac">the static 3DES key required for BAC</param>
    /// <returns>the new secure messaging wrapper</returns>
    /// <exception cref="CardServiceException">if authentication failed</exception>
    public BACResult DoBAC(KeyParameter kEnc, KeyParameter kMac)
    {
        _log.Info(LogCategory, "Starting BAC (explicit keys).");
        BACResult result = new(DoBACStep(kEnc, kMac));
        _log.Info(LogCategory, "BAC completed; secure messaging established.");
        return result;
    }

    /// <summary>Computes the key seed based on the given (MRZ based) BAC key.</summary>
    /// <param name="bacKey">the BAC key</param>
    /// <returns>the key seed</returns>
    public static byte[] ComputeKeySeedForBAC(IBacKeySpec bacKey)
    {
        string documentNumber = bacKey.GetDocumentNumber();
        string dateOfBirth = bacKey.GetDateOfBirth();
        string dateOfExpiry = bacKey.GetDateOfExpiry();

        if (dateOfBirth == null || dateOfBirth.Length != 6)
        {
            throw new ArgumentException($"Wrong date format used for date of birth. Expected yyMMdd, found {dateOfBirth}");
        }

        if (dateOfExpiry == null || dateOfExpiry.Length != 6)
        {
            throw new ArgumentException($"Wrong date format used for date of expiry. Expected yyMMdd, found {dateOfExpiry}");
        }

        if (documentNumber == null)
        {
            throw new ArgumentException($"Wrong document number. Found {documentNumber}");
        }

        documentNumber = FixDocumentNumber(documentNumber);

        return ComputeKeySeedForBAC(documentNumber, dateOfBirth, dateOfExpiry);
    }

    /// <summary>Computes the initial send sequence counter to use, given the randoms generated by PICC and PCD.</summary>
    /// <param name="rndIcc">the PICC's random</param>
    /// <param name="rndIfd">the PCD's random</param>
    /// <returns>the initial send sequence counter to use</returns>
    public static long ComputeSendSequenceCounter(byte[] rndIcc, byte[] rndIfd)
    {
        if (rndIcc == null || rndIcc.Length != 8 || rndIfd == null || rndIfd.Length != 8)
        {
            throw new InvalidOperationException("Wrong length input");
        }

        long ssc = 0;
        for (int i = 4; i < 8; i++)
        {
            ssc <<= 8;
            ssc += rndIcc[i] & 0x000000FF;
        }

        for (int i = 4; i < 8; i++)
        {
            ssc <<= 8;
            ssc += rndIfd[i] & 0x000000FF;
        }

        return ssc;
    }

    /// <summary>Performs the Basic Access Control protocol.</summary>
    /// <param name="kEnc">the static 3DES key required for BAC</param>
    /// <param name="kMac">the static 3DES key required for BAC</param>
    /// <returns>the new secure messaging wrapper</returns>
    /// <exception cref="CardServiceException">if authentication failed</exception>
    private SecureMessagingWrapper DoBACStep(KeyParameter kEnc, KeyParameter kMac)
    {
        byte[] rndIcc;
        try
        {
            _log.Debug(LogCategory, "Step 1: sending GET CHALLENGE.");
            rndIcc = _service.SendGetChallenge();
        }
        catch (Exception e)
        {
            _log.Error(LogCategory, "GET CHALLENGE failed.", e);
            throw new CardServiceProtocolException("BAC failed in GET CHALLENGE", 1, e);
        }

        byte[] rndIfd = new byte[8];
        RandomNumberGenerator.Fill(rndIfd);
        byte[] kIfd = new byte[16];
        RandomNumberGenerator.Fill(kIfd);

        byte[] response;
        try
        {
            _log.Debug(LogCategory, "Step 2: sending MUTUAL AUTHENTICATE.");
            response = _service.SendMutualAuth(rndIfd, rndIcc, kIfd, kEnc, kMac);
        }
        catch (Exception e)
        {
            _log.Error(LogCategory, "MUTUAL AUTHENTICATE failed.", e);
            throw new CardServiceProtocolException("BAC failed in MUTUAL AUTH", 2, e);
        }

        byte[] kIcc = new byte[16];
        Array.Copy(response, 16, kIcc, 0, 16);

        byte[] keySeed = new byte[16];
        for (int i = 0; i < 16; i++)
        {
            keySeed[i] = (byte)((kIfd[i] & 0xFF) ^ (kIcc[i] & 0xFF));
        }

        var ksEnc = new KeyParameter(Util.DeriveKey(keySeed, Util.ENC_MODE));
        var ksMac = new KeyParameter(Util.DeriveKey(keySeed, Util.MAC_MODE));
        long ssc = ComputeSendSequenceCounter(rndIcc, rndIfd);

        return new DESedeSecureMessagingWrapper(ksEnc, ksMac, _maxTranceiveLength, _shouldCheckMac, ssc);
    }

    /// <summary>
    /// Computes the static key seed to be used in BAC KDF, based on information from the MRZ.
    /// </summary>
    /// <param name="documentNumber">a string containing the document number</param>
    /// <param name="dateOfBirth">a string containing the date of birth (YYMMDD)</param>
    /// <param name="dateOfExpiry">a string containing the date of expiry (YYMMDD)</param>
    /// <returns>a byte array of length 16 containing the key seed</returns>
    private static byte[] ComputeKeySeedForBAC(string documentNumber, string dateOfBirth, string dateOfExpiry) =>
        Util.ComputeKeySeed(documentNumber, dateOfBirth, dateOfExpiry, "SHA-1", true);

    /// <summary>Returns the document number, including trailing '&lt;' until length 9.</summary>
    /// <param name="documentNumber">the original document number</param>
    /// <returns>the document number with at least length 9</returns>
    private static string FixDocumentNumber(string? documentNumber)
    {
        string result = documentNumber == null ? string.Empty : documentNumber.Replace('<', ' ').Trim().Replace(' ', '<');
        while (result.Length < 9)
        {
            result += '<';
        }

        return result;
    }
}
