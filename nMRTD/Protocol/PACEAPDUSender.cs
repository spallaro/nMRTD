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

using nMRTD.Logging;
using nMRTD.SmartCards;

namespace nMRTD.Protocol;

/// <summary>
/// Port of <c>org.jmrtd.protocol.PACEAPDUSender</c>: a low-level APDU sender to support the PACE
/// protocol.
/// </summary>
public class PACEAPDUSender : IApduLevelPaceCapable
{
    /// <summary>Shared secret type for non-PACE key.</summary>
    public const byte NoPaceKeyReference = 0x00;

    /// <summary>Shared secret type for PACE according to BSI TR-03110 v2.03 B.11.1.</summary>
    public const byte MrzPaceKeyReference = 0x01;

    /// <summary>Shared secret type for PACE according to BSI TR-03110 v2.03 B.11.1.</summary>
    public const byte CanPaceKeyReference = 0x02;

    /// <summary>Shared secret type for PACE according to BSI TR-03110 v2.03 B.11.1.</summary>
    public const byte PinPaceKeyReference = 0x03;

    /// <summary>Shared secret type for PACE according to BSI TR-03110 v2.03 B.11.1.</summary>
    public const byte PukPaceKeyReference = 0x04;

    /// <summary>The general Authenticate command is used to perform the PACE protocol. See Section 3.2.2 of SAC-TR 1.01.</summary>
    private const byte InsPaceGeneralAuthenticate = 0x86;

    private readonly object _lock = new();

    private readonly SecureMessagingAPDUSender _secureMessagingSender;

    /// <summary>The log/trace registry shared with every other sender wrapping the same underlying service.</summary>
    public LogSource Log => _secureMessagingSender.Log;

    /// <summary>Creates an APDU sender to support the PACE protocol.</summary>
    /// <param name="service">the card service to transceive APDUs</param>
    /// <remarks>
    /// Obsolete: use <see cref="PACEAPDUSender(SecureMessagingAPDUSender)"/> instead, sharing a single
    /// <see cref="SecureMessagingAPDUSender"/> between all senders wrapping the same underlying card
    /// service (see <c>PassportService.GetSecureMessagingAPDUSender()</c>).
    /// </remarks>
    [Obsolete("Use PACEAPDUSender(SecureMessagingAPDUSender) instead, sharing a single SecureMessagingAPDUSender between all senders wrapping the same underlying card service.")]
    public PACEAPDUSender(CardService service)
        : this(new SecureMessagingAPDUSender(service))
    {
    }

    /// <summary>Creates an APDU sender to support the PACE protocol.</summary>
    /// <param name="secureMessagingSender">the (shared) secure messaging APDU sender to transceive APDUs</param>
    public PACEAPDUSender(SecureMessagingAPDUSender secureMessagingSender)
    {
        _secureMessagingSender = secureMessagingSender;
    }

    /// <summary>
    /// The MSE AT APDU for PACE, see ICAO TR-SAC-1.01, Section 3.2.1, BSI TR 03110 v2.03 B11.1. Note
    /// that (for now) caller is responsible for prefixing the byte[] params with specified tags.
    /// </summary>
    /// <param name="wrapper">secure messaging wrapper</param>
    /// <param name="oid">OID of the protocol to select (this method will prefix <c>0x80</c>)</param>
    /// <param name="refPublicKeyOrSecretKey">value specifying whether to use MRZ (<c>0x01</c>) or CAN (<c>0x02</c>) (this method will prefix <c>0x83</c>)</param>
    /// <param name="refPrivateKeyOrForComputingSessionKey">indicates a private key or reference for computing a session key (this method will prefix <c>0x84</c>)</param>
    /// <exception cref="CardServiceException">on error</exception>
    /// <remarks>
    /// ADAPTATION: <see cref="IApduLevelPaceCapable.SendMseSetAtMutualAuth"/>'s
    /// <paramref name="refPrivateKeyOrForComputingSessionKey"/> parameter is declared as a non-nullable
    /// <c>byte[]</c> in the interface (matching Java's parameter type), but -- exactly as in Java's
    /// original implementation below -- this method still accepts and special-cases a <c>null</c> value
    /// at runtime (C#'s nullable-reference-types annotations are compile-time-only, not enforced by the
    /// runtime), since <c>PACEProtocol</c> legitimately has no domain parameter identifier to send in the
    /// common case (a single, unambiguous set of PACE domain parameters).
    /// </remarks>
    public void SendMseSetAtMutualAuth(IApduWrapper? wrapper, string oid, int refPublicKeyOrSecretKey, byte[] refPrivateKeyOrForComputingSessionKey)
    {
        lock (_lock)
        {
            ArgumentNullException.ThrowIfNull(oid);

            byte[] oidBytes = Util.ToOIDBytes(oid);

            /*
             * 0x83 Reference of a public key / secret key.
             * The password to be used is indicated as follows: 0x01: MRZ, 0x02: CAN.
             */
            if (!(refPublicKeyOrSecretKey == MrzPaceKeyReference
                || refPublicKeyOrSecretKey == CanPaceKeyReference
                || refPublicKeyOrSecretKey == PinPaceKeyReference
                || refPublicKeyOrSecretKey == PukPaceKeyReference))
            {
                throw new ArgumentException($"Unsupported key type reference (MRZ, CAN, etc), found {refPublicKeyOrSecretKey}");
            }

            byte[] refPublicKeyOrSecretKeyBytes = TlvUtil.WrapDO(0x83, [(byte)refPublicKeyOrSecretKey]);

            /*
             * 0x84 Reference of a private key / Reference for computing a
             * session key.
             * This data object is REQUIRED to indicate the identifier
             * of the domain parameters to be used if the domain
             * parameters are ambiguous, i.e. more than one set of
             * domain parameters is available for PACE.
             */
            byte[]? refPrivateKeyOrForComputingSessionKeyBytes = refPrivateKeyOrForComputingSessionKey == null
                ? null
                : TlvUtil.WrapDO(0x84, refPrivateKeyOrForComputingSessionKey);

            /* Construct data. */
            using var dataStream = new MemoryStream();
            dataStream.Write(oidBytes);
            dataStream.Write(refPublicKeyOrSecretKeyBytes);
            if (refPrivateKeyOrForComputingSessionKeyBytes != null)
            {
                dataStream.Write(refPrivateKeyOrForComputingSessionKeyBytes);
            }

            byte[] data = dataStream.ToArray();

            /* Transceive APDU. */
            var commandApdu = new CommandApdu(Iso7816.ClaIso7816, Iso7816.InsMse, 0xC1, 0xA4, data);
            ResponseApdu responseApdu = _secureMessagingSender.Transmit(wrapper, commandApdu);

            /* Handle error status word. */
            int sw = responseApdu.Sw;
            if (sw != Iso7816.SwNoError)
            {
                throw new CardServiceException("Sending MSE AT failed", sw);
            }
        }
    }

    /// <summary>Sends a General Authenticate command.</summary>
    /// <param name="wrapper">secure messaging wrapper</param>
    /// <param name="data">data to be sent, without the <c>0x7C</c> prefix (this method will add it)</param>
    /// <param name="le">the expected length to send</param>
    /// <param name="isLast">indicates whether this is the last command in the chain</param>
    /// <returns>dynamic authentication data without the <c>0x7C</c> prefix (this method will remove it)</returns>
    /// <exception cref="CardServiceException">on error</exception>
    public byte[] SendGeneralAuthenticate(IApduWrapper? wrapper, byte[] data, int le, bool isLast)
    {
        lock (_lock)
        {
            /* Transceive APDU. */
            byte[] commandData = TlvUtil.WrapDO(0x7C, data);
            var commandApdu = new CommandApdu(
                isLast ? Iso7816.ClaIso7816 : Iso7816.ClaCommandChaining,
                InsPaceGeneralAuthenticate,
                0x00,
                0x00,
                commandData,
                le);
            ResponseApdu responseApdu = _secureMessagingSender.Transmit(wrapper, commandApdu);

            /* Handle error status word. */
            int sw = responseApdu.Sw;
            if (sw != Iso7816.SwNoError)
            {
                throw new CardServiceException("Sending general authenticate failed", sw);
            }

            byte[] responseData = responseApdu.Data;
            return TlvUtil.UnwrapDO(0x7C, responseData);
        }
    }
}
