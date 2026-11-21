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
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

namespace nMRTD.Protocol;

/// <summary>
/// Port of <c>org.jmrtd.protocol.DESedeSecureMessagingWrapper</c>: secure messaging wrapper for APDUs
/// using DESede (3DES) CBC encryption and the ISO 9797-1 MAC algorithm 3 ("retail MAC"), initially based
/// on Section E.3 of ICAO-TR-PKI.
///
/// ADAPTATION: Java's <c>"DESede/CBC/NoPadding"</c>/<c>"ISO9797Alg3Mac"</c> JCA mnemonics (the latter
/// plain, no explicit padding -- distinct from the <c>"ISO9797ALG3WITHISO7816-4PADDING"</c> mnemonic
/// <c>PaceProtocol.cs</c> uses for its authentication token) are replaced by directly constructed BC
/// primitives: <see cref="BufferedBlockCipher"/> over <see cref="CbcBlockCipher"/> over
/// <see cref="DesEdeEngine"/> for encryption, and <see cref="ISO9797Alg3Mac"/> over a single-DES
/// <see cref="DesEngine"/> for the MAC -- BC's retail-MAC implementation needs its own, separately-Init'd
/// cipher engine instance since it keeps internal block-cipher state independent of the encryption cipher,
/// per <c>SecureMessagingWrapper.cs</c>'s constructor redesign. <see cref="ISO9797Alg3Mac"/> implements the
/// retail-MAC triple-DES final step itself from a single-DES engine and a 16-byte key it splits internally;
/// it must not be given an already-<see cref="DesEdeEngine"/> (which only accepts 16-/24-byte keys and
/// rejects the class's internal 8-byte half-key). No explicit <see cref="ISO7816d4Padding"/> is passed to
/// the MAC here: <c>SecureMessagingWrapper.WrapCommandAPDU</c>/<c>CheckMac</c> already pre-pad their input
/// via <c>Util.Pad</c> before handing it to this MAC (matching Java's own pre-pad-then-<c>mac.doFinal</c>
/// pattern) -- passing an explicit padding scheme on top would double-pad an already-block-aligned input,
/// corrupting the MAC (confirmed empirically against JMRTD's own independently-sourced
/// <c>DESedeSecureMessagingWrapperTest.testStackOverflowTim</c> known-answer vectors).
/// </summary>
public sealed class DESedeSecureMessagingWrapper : SecureMessagingWrapper
{
    /// <summary>Initialization vector consisting of 8 zero bytes.</summary>
    public static readonly byte[] ZeroIv = new byte[8];

    /// <summary>
    /// Constructs a secure messaging wrapper based on the secure messaging session keys. The initial
    /// value of the send sequence counter is set to <c>0L</c>.
    /// </summary>
    /// <param name="ksEnc">the session key for encryption</param>
    /// <param name="ksMac">the session key for macs</param>
    public DESedeSecureMessagingWrapper(KeyParameter ksEnc, KeyParameter ksMac)
        : this(ksEnc, ksMac, shouldCheckMac: true)
    {
    }

    /// <summary>
    /// Constructs a secure messaging wrapper based on the secure messaging session keys. The initial
    /// value of the send sequence counter is set to <c>0L</c>.
    /// </summary>
    /// <param name="ksEnc">the session key for encryption</param>
    /// <param name="ksMac">the session key for macs</param>
    /// <param name="shouldCheckMac">a boolean indicating whether this wrapper will check the MAC in wrapped response APDUs</param>
    public DESedeSecureMessagingWrapper(KeyParameter ksEnc, KeyParameter ksMac, bool shouldCheckMac)
        : this(ksEnc, ksMac, 256, shouldCheckMac, 0L)
    {
    }

    /// <summary>
    /// Constructs a secure messaging wrapper based on the secure messaging session keys and the initial
    /// value of the send sequence counter. Used in BAC and EAC 1.
    /// </summary>
    /// <param name="ksEnc">the session key for encryption</param>
    /// <param name="ksMac">the session key for macs</param>
    /// <param name="ssc">the initial value of the send sequence counter</param>
    public DESedeSecureMessagingWrapper(KeyParameter ksEnc, KeyParameter ksMac, long ssc)
        : this(ksEnc, ksMac, 256, true, ssc)
    {
    }

    /// <summary>Constructs a secure messaging wrapper based on the given existing secure messaging wrapper. This is a convenience copy constructor.</summary>
    /// <param name="wrapper">an existing wrapper</param>
    public DESedeSecureMessagingWrapper(DESedeSecureMessagingWrapper wrapper)
        : this(wrapper.EncryptionKey, wrapper.MacKey, wrapper.MaxTransceiveLength, wrapper.ShouldCheckMac, wrapper.SendSequenceCounter)
    {
    }

    /// <summary>
    /// Constructs a secure messaging wrapper based on the secure messaging session keys and the initial
    /// value of the send sequence counter. Used in BAC and EAC 1.
    /// </summary>
    /// <param name="ksEnc">the session key for encryption</param>
    /// <param name="ksMac">the session key for macs</param>
    /// <param name="maxTransceiveLength">the maximum transceive length, typical values are 256 or 65536</param>
    /// <param name="shouldCheckMac">a boolean indicating whether this wrapper will check the MAC in wrapped response APDUs</param>
    /// <param name="ssc">the initial value of the send sequence counter</param>
    public DESedeSecureMessagingWrapper(KeyParameter ksEnc, KeyParameter ksMac, int maxTransceiveLength, bool shouldCheckMac, long ssc)
        : base(ksEnc, ksMac, new BufferedBlockCipher(new CbcBlockCipher(new DesEdeEngine())), new ISO9797Alg3Mac(new DesEngine()), maxTransceiveLength, shouldCheckMac, ssc)
    {
    }

    /// <summary>Returns the type of secure messaging wrapper. In this case <c>"DESede"</c>.</summary>
    public string Type => "DESede";

    /// <summary>Returns the length (in bytes) to use for padding. For 3DES this is 8.</summary>
    protected override int GetPadLength() => 8;

    protected override byte[] GetEncodedSendSequenceCounter()
    {
        byte[] result = new byte[8];
        // NOTE: matches Java's DataOutputStream.writeLong (big-endian 8-byte encoding).
        ulong ssc = unchecked((ulong)SendSequenceCounter);
        for (int i = 0; i < 8; i++)
        {
            result[i] = (byte)(ssc >> (8 * (7 - i)));
        }
        return result;
    }

    public override string ToString() =>
        $"DESedeSecureMessagingWrapper [ssc: {SendSequenceCounter}, kEnc: {EncryptionKey}, kMac: {MacKey}, shouldCheckMAC: {ShouldCheckMac}, maxTransceiveLength: {MaxTransceiveLength}]";

    public override int GetHashCode() => (31 * base.GetHashCode()) + 13;

    public override bool Equals(object? obj)
    {
        if (ReferenceEquals(this, obj))
        {
            return true;
        }
        if (obj is null || GetType() != obj.GetType())
        {
            return false;
        }
        return base.Equals(obj);
    }

    /// <summary>For DESede secure messaging the IV is always 8 zero bytes.</summary>
    protected override byte[] GetIV() => ZeroIv;
}
