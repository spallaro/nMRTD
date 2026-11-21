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
using Org.BouncyCastle.Crypto.Parameters;

namespace nMRTD.Protocol;

/// <summary>
/// Port of <c>org.jmrtd.protocol.AESSecureMessagingWrapper</c>: an AES secure messaging wrapper for
/// APDUs, based on TR-SAC (AES CBC encryption, AES-CMAC message authentication).
///
/// ADAPTATION: Java's <c>"AES/CBC/NoPadding"</c>/<c>"AESCMAC"</c> JCA mnemonics are replaced by directly
/// constructed BC primitives, per <c>SecureMessagingWrapper.cs</c>'s constructor redesign. Java's
/// <c>sscIVCipher</c> field (a JCE <c>Cipher</c> configured as <c>"AES/ECB/NoPadding"</c>,
/// encrypt-mode, keyed with <c>ksEnc</c>) is ported as a raw <see cref="AesEngine"/>: ECB mode over a
/// single 16-byte (one AES block) input is exactly one <see cref="IBlockCipher.ProcessBlock(byte[], int, byte[], int)"/> call,
/// so no explicit ECB block-cipher-mode wrapper (BC has none anyway -- ECB is simply the bare engine) is
/// needed.
/// </summary>
public sealed class AESSecureMessagingWrapper : SecureMessagingWrapper
{
    private readonly IBlockCipher _sscIvCipher;

    /// <summary>
    /// Constructs a secure messaging wrapper based on the secure messaging session keys and the initial
    /// value of the send sequence counter. Used in BAC and EAC 1.
    /// </summary>
    /// <param name="ksEnc">the session key for encryption</param>
    /// <param name="ksMac">the session key for macs</param>
    /// <param name="ssc">the initial value of the send sequence counter</param>
    public AESSecureMessagingWrapper(KeyParameter ksEnc, KeyParameter ksMac, long ssc)
        : this(ksEnc, ksMac, 256, true, ssc)
    {
    }

    /// <summary>Constructs a secure messaging wrapper based on the given existing secure messaging wrapper. This is a convenience copy constructor.</summary>
    /// <param name="wrapper">an existing wrapper</param>
    public AESSecureMessagingWrapper(AESSecureMessagingWrapper wrapper)
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
    public AESSecureMessagingWrapper(KeyParameter ksEnc, KeyParameter ksMac, int maxTransceiveLength, bool shouldCheckMac, long ssc)
        : base(ksEnc, ksMac, new BufferedBlockCipher(new CbcBlockCipher(new AesEngine())), new CMac(new AesEngine()), maxTransceiveLength, shouldCheckMac, ssc)
    {
        _sscIvCipher = new AesEngine();
        _sscIvCipher.Init(forEncryption: true, ksEnc);
    }

    /// <summary>Returns the type of secure messaging wrapper (in this case <c>"AES"</c>).</summary>
    public string Type => "AES";

    /// <summary>Returns the length (in bytes) to use for padding. For AES this is 16.</summary>
    protected override int GetPadLength() => 16;

    /// <summary>Returns the send sequence counter as bytes, making sure the 128 bit (16 byte) block-size is used.</summary>
    protected override byte[] GetEncodedSendSequenceCounter()
    {
        byte[] result = new byte[16];
        // NOTE: matches Java's DataOutputStream.writeLong (big-endian 8-byte encoding) written into the
        // last 8 bytes, with the leading 8 bytes left as zero.
        ulong ssc = unchecked((ulong)SendSequenceCounter);
        for (int i = 0; i < 8; i++)
        {
            result[8 + i] = (byte)(ssc >> (8 * (7 - i)));
        }
        return result;
    }

    public override string ToString() =>
        $"AESSecureMessagingWrapper [ssc: {SendSequenceCounter}, kEnc: {EncryptionKey}, kMac: {MacKey}, shouldCheckMAC: {ShouldCheckMac}, maxTransceiveLength: {MaxTransceiveLength}]";

    public override int GetHashCode() => (71 * base.GetHashCode()) + 17;

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

    /// <summary>Returns the IV by encrypting the send sequence counter. AES uses IV = E(K_Enc, SSC), see ICAO SAC TR Section 4.6.3.</summary>
    protected override byte[] GetIV()
    {
        byte[] encodedSsc = GetEncodedSendSequenceCounter();
        byte[] encryptedSsc = new byte[encodedSsc.Length];
        _sscIvCipher.ProcessBlock(encodedSsc, 0, encryptedSsc, 0);
        return encryptedSsc;
    }
}
