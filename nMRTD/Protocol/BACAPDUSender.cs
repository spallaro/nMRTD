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

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

using nMRTD.Logging;
using nMRTD.SmartCards;

namespace nMRTD.Protocol;

/// <summary>
/// Port of <c>org.jmrtd.protocol.BACAPDUSender</c>: a low-level APDU sender to support the BAC protocol.
///
/// ADAPTATION: Java's <c>Mac.getInstance("ISO9797Alg3Mac", BC_PROVIDER)</c> (plain, no explicit padding --
/// distinct from the <c>"ISO9797ALG3WITHISO7816-4PADDING"</c> mnemonic <c>PaceProtocol.cs</c> uses for its
/// authentication token) and <c>Util.getCipher("DESede/CBC/NoPadding")</c> (JCA provider lookups) are
/// replaced by directly constructed BC primitives -- <see cref="BufferedBlockCipher"/> over
/// <see cref="CbcBlockCipher"/> over <see cref="DesEdeEngine"/> for encryption, and
/// <see cref="ISO9797Alg3Mac"/> over a single-DES <see cref="DesEngine"/> -- matching the same construction
/// already established by <c>DESedeSecureMessagingWrapper.cs</c>. <see cref="ISO9797Alg3Mac"/> implements
/// the retail-MAC triple-DES final step itself from a single-DES engine and a 16-byte key it splits
/// internally; it must not be given an already-<see cref="DesEdeEngine"/> (which only accepts 16-/24-byte
/// keys and rejects the class's internal 8-byte half-key). No explicit <see cref="ISO7816d4Padding"/> is
/// passed to the MAC here: <see cref="SendMutualAuth"/> below already pre-pads its input via
/// <c>Util.Pad</c> before handing it to the MAC (matching Java's own <c>Util.pad(...)</c> call before
/// <c>mac.doFinal(...)</c>) -- passing an explicit padding scheme on top would double-pad an
/// already-block-aligned input, corrupting the MAC (confirmed empirically: this exact double-padding
/// combination produces a MAC that does not match JMRTD's own independently-sourced
/// <c>DESedeSecureMessagingWrapperTest.testStackOverflowTim</c> known-answer vectors). There is no JCA
/// provider-selection concept in this port (BouncyCastle.Cryptography is the sole crypto backend), so the
/// constructor can no longer fail with a checked security exception at construction time.
/// </summary>
public class BACAPDUSender : IApduLevelBacCapable
{
    /// <summary>Initialization vector used by the cipher below. Deliberately duplicated (not shared) with
    /// <c>DESedeSecureMessagingWrapper.ZeroIv</c> -- this mirrors upstream JMRTD, where
    /// <c>BACAPDUSender</c> and <c>DESedeSecureMessagingWrapper</c> likewise each define their own private
    /// copy of the same all-zero IV.</summary>
    private static readonly byte[] ZeroIv = new byte[8];

    private readonly object _lock = new();

    private readonly SecureMessagingAPDUSender _secureMessagingSender;

    /// <summary>The log/trace registry shared with every other sender wrapping the same underlying service.</summary>
    public LogSource Log => _secureMessagingSender.Log;

    /// <summary>DESede encryption/decryption cipher.</summary>
    private readonly BufferedBlockCipher _cipher;

    /// <summary>ISO9797Alg3Mac.</summary>
    private readonly ISO9797Alg3Mac _mac;

    /// <summary>Creates an APDU sender for tranceiving BAC protocol APDUs.</summary>
    /// <param name="service">the card service for tranceiving APDUs</param>
    /// <remarks>
    /// Obsolete: use <see cref="BACAPDUSender(SecureMessagingAPDUSender)"/> instead, sharing a single
    /// <see cref="SecureMessagingAPDUSender"/> between all senders wrapping the same underlying card
    /// service (see <c>PassportService.GetSecureMessagingAPDUSender()</c>).
    /// </remarks>
    [Obsolete("Use BACAPDUSender(SecureMessagingAPDUSender) instead, sharing a single SecureMessagingAPDUSender between all senders wrapping the same underlying card service.")]
    public BACAPDUSender(CardService service)
        : this(new SecureMessagingAPDUSender(service))
    {
    }

    /// <summary>Creates an APDU sender for tranceiving BAC protocol APDUs.</summary>
    /// <param name="secureMessagingSender">the (shared) secure messaging APDU sender for tranceiving APDUs</param>
    public BACAPDUSender(SecureMessagingAPDUSender secureMessagingSender)
    {
        _secureMessagingSender = secureMessagingSender;
        _mac = new ISO9797Alg3Mac(new DesEngine());
        _cipher = new BufferedBlockCipher(new CbcBlockCipher(new DesEdeEngine()));
    }

    /// <summary>Sends a <c>GET CHALLENGE</c> command to the passport.</summary>
    /// <returns>a byte array of length 8 containing the challenge</returns>
    /// <exception cref="CardServiceException">on transceive error</exception>
    public byte[] SendGetChallenge() => SendGetChallenge(null);

    /// <summary>Sends a <c>GET CHALLENGE</c> command to the passport.</summary>
    /// <param name="wrapper">secure messaging wrapper</param>
    /// <returns>a byte array of length 8 containing the challenge</returns>
    /// <exception cref="CardServiceException">on transceive error</exception>
    public byte[] SendGetChallenge(IApduWrapper? wrapper)
    {
        lock (_lock)
        {
            var commandApdu = new CommandApdu(Iso7816.ClaIso7816, Iso7816.InsGetChallenge, 0x00, 0x00, 8);

            // NOTE: preserved Java quirk -- the wrapper parameter is accepted but never actually used;
            // transmit is always invoked with a null wrapper here, exactly as in JMRTD's own BACAPDUSender.
            ResponseApdu responseApdu = _secureMessagingSender.Transmit(null, commandApdu);
            byte[] challenge = responseApdu.Data;
            if (challenge.Length != 8)
            {
                throw new CardServiceException("Get challenge failed", responseApdu.Sw);
            }

            return challenge;
        }
    }

    /// <summary>
    /// Sends an <c>EXTERNAL AUTHENTICATE</c> command to the passport. This is part of BAC. The resulting
    /// byte array has length 32 and contains <c>rndIcc</c> (first 8 bytes), <c>rndIfd</c> (next 8 bytes),
    /// their key material <c>kIcc</c> (last 16 bytes).
    /// </summary>
    /// <param name="rndIfd">our challenge</param>
    /// <param name="rndIcc">their challenge</param>
    /// <param name="kIfd">our key material</param>
    /// <param name="kEnc">the static encryption key</param>
    /// <param name="kMac">the static mac key</param>
    /// <returns>
    /// a byte array of length 32 containing the response that was sent by the passport, decrypted (using
    /// <paramref name="kEnc"/>) and verified (using <paramref name="kMac"/>)
    /// </returns>
    /// <exception cref="CardServiceException">on transceive error</exception>
    public byte[] SendMutualAuth(byte[] rndIfd, byte[] rndIcc, byte[] kIfd, KeyParameter kEnc, KeyParameter kMac)
    {
        lock (_lock)
        {
            try
            {
                if (rndIfd == null || rndIfd.Length != 8)
                {
                    throw new ArgumentException("rndIFD wrong length");
                }

                if (rndIcc == null || rndIcc.Length != 8)
                {
                    rndIcc = new byte[8];
                }

                if (kIfd == null || kIfd.Length != 16)
                {
                    throw new ArgumentException("kIFD wrong length");
                }

                ArgumentNullException.ThrowIfNull(kEnc);
                ArgumentNullException.ThrowIfNull(kMac);

                _cipher.Init(forEncryption: true, new ParametersWithIV(kEnc, ZeroIv));
                byte[] plaintext = new byte[32];
                Array.Copy(rndIfd, 0, plaintext, 0, 8);
                Array.Copy(rndIcc, 0, plaintext, 8, 8);
                Array.Copy(kIfd, 0, plaintext, 16, 16);
                byte[] ciphertext = _cipher.DoFinal(plaintext);
                if (ciphertext.Length != 32)
                {
                    throw new InvalidOperationException($"Cryptogram wrong length {ciphertext.Length}");
                }

                _mac.Init(kMac);
                byte[] paddedCiphertext = Util.Pad(ciphertext, 8);
                _mac.BlockUpdate(paddedCiphertext, 0, paddedCiphertext.Length);
                byte[] mactext = new byte[_mac.GetMacSize()];
                _mac.DoFinal(mactext, 0);
                if (mactext.Length != 8)
                {
                    throw new InvalidOperationException("MAC wrong length");
                }

                byte p1 = 0x00;
                byte p2 = 0x00;

                byte[] data = new byte[32 + 8];
                Array.Copy(ciphertext, 0, data, 0, 32);
                Array.Copy(mactext, 0, data, 32, 8);
                int le = 40; /* 40 means max ne is 40 (0x28). */
                var commandApdu = new CommandApdu(Iso7816.ClaIso7816, Iso7816.InsExternalAuthenticate, p1, p2, data, le);
                ResponseApdu? responseApdu = _secureMessagingSender.Transmit(null, commandApdu);

                if (responseApdu == null)
                {
                    throw new CardServiceException("Mutual authentication failed, received null response APDU");
                }

                // NOTE: preserved Java structure -- Java also null-checks responseAPDU.getBytes() here; the
                // check is dropped since ResponseApdu.GetBytes() never returns null in this port.
                byte[] responseApduBytes = responseApdu.GetBytes();
                int sw = responseApdu.Sw;

                /* Some MRTDs apparently don't support 40 here, try again with 0. See R2-p1_v2_sIII_0035 (and other issues). */
                if (sw != Iso7816.SwNoError)
                {
                    le = 0; /* 0 means ne is max 256 (0xFF). */
                    commandApdu = new CommandApdu(Iso7816.ClaIso7816, Iso7816.InsExternalAuthenticate, p1, p2, data, le);
                    responseApdu = _secureMessagingSender.Transmit(null, commandApdu);
                    if (responseApdu == null)
                    {
                        throw new CardServiceException("Mutual authentication failed, received null response APDU");
                    }
                    responseApduBytes = responseApdu.GetBytes();
                    sw = responseApdu.Sw;
                }

                if (responseApduBytes.Length != 42)
                {
                    throw new CardServiceProtocolException($"Mutual authentication failed: expected length: 40 + 2, actual length: {responseApduBytes.Length}", 0, sw);
                }

                /*
                 * The response is E_IC || M_IC, with E_IC = E(K_Enc, RND.IC || RND.IFD || K.IC).
                 * Check the checksum M_IC of E_IC, decrypt E_IC, and check that RND.IFD was returned
                 * (Doc 9303 - Part 11, 4.3.1, step 4).
                 */
                _mac.Init(kMac);
                byte[] paddedCryptogram = Util.Pad(responseApduBytes, 0, 32, 8);
                _mac.BlockUpdate(paddedCryptogram, 0, paddedCryptogram.Length);
                byte[] expectedChecksum = new byte[_mac.GetMacSize()];
                _mac.DoFinal(expectedChecksum, 0);
                if (!CryptographicOperations.FixedTimeEquals(expectedChecksum, responseApduBytes.AsSpan(32, 8)))
                {
                    throw new CardServiceException("Mutual authentication failed: wrong checksum on the PICC's cryptogram", sw);
                }

                /* Decrypt the response. */
                _cipher.Init(forEncryption: false, new ParametersWithIV(kEnc, ZeroIv));
                byte[] result = _cipher.DoFinal(responseApduBytes, 0, responseApduBytes.Length - 8 - 2);
                if (result.Length != 32)
                {
                    /* The PICC allowed access, but probably the resulting secure channel will be wrong. */
                    throw new CardServiceException($"Cryptogram wrong length, was expecting 32, found {result.Length}", sw);
                }

                if (!CryptographicOperations.FixedTimeEquals(rndIfd, result.AsSpan(8, 8)))
                {
                    throw new CardServiceException("Mutual authentication failed: the PICC did not return RND.IFD", sw);
                }

                return result;
            }
            catch (Org.BouncyCastle.Crypto.CryptoException ce)
            {
                /* Lower level security exception, probably the resulting secure channel will be wrong. */
                throw new CardServiceException("Security exception during mutual auth", ce);
            }
        }
    }
}
