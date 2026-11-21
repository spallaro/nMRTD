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
using Org.BouncyCastle.Crypto.Parameters;

using nMRTD.SmartCards;

namespace nMRTD.Protocol;

/// <summary>
/// Port of <c>org.jmrtd.protocol.SecureMessagingWrapper</c>: the abstract secure messaging wrapper base
/// class, implementing ICAO Doc 9303 / ICAO-TR-PKI Section E.3 command/response APDU protection.
///
/// ADAPTATIONs from the Java original (see docs/porting-conventions.md and <c>Util.cs</c>'s doc comment
/// for the same general pattern):
/// <list type="bullet">
/// <item>Java's <c>Serializable</c> marker interface is dropped -- this port never relies on
/// reflection-based Java serialization.</item>
/// <item>Java's <c>javax.crypto.SecretKey ksEnc</c>/<c>ksMac</c> fields become BouncyCastle
/// <see cref="KeyParameter"/>, per the convention already established by <c>IApduLevelBacCapable.cs</c>.
/// Unlike Java's <c>SecretKeySpec</c> (which overrides <c>equals</c>/<c>hashCode</c> by key-bytes +
/// algorithm name), BC's <see cref="KeyParameter"/> uses plain reference equality -- so
/// <see cref="Equals(object?)"/>/<see cref="GetHashCode"/> below compare/hash the raw key bytes
/// explicitly (via <see cref="KeyParameter.GetKey"/>) to preserve the original value-equality semantics.</item>
/// <item>The constructor took JCA mnemonic strings (<c>cipherAlg</c>, <c>macAlg</c>) and called the
/// now-removed <c>Util.getCipher</c>/<c>Util.getMac</c> factory methods (there is no JCA
/// provider-selection concept in this port -- BouncyCastle.Cryptography is the sole crypto backend).
/// Instead this constructor takes already-constructed BC primitives directly: an
/// <see cref="IBufferedCipher"/> configured for CBC/NoPadding (built by the concrete DESede/AES
/// subclass, e.g. <c>new BufferedBlockCipher(new CbcBlockCipher(new DesEdeEngine()))</c>) and an
/// <see cref="IMac"/> (e.g. <c>new ISO9797Alg3Mac(new DesEngine())</c> -- no explicit padding, since
/// <see cref="WrapCommandAPDU"/>/<see cref="CheckMac"/> below already pre-pad their input via
/// <c>Util.Pad</c> -- or <c>new CMac(new AesEngine())</c>).</item>
/// <item><c>getIV()</c> returned a JCE <c>IvParameterSpec</c>; <see cref="GetIV"/> here just returns the
/// raw IV bytes.</item>
/// <item>All checked <c>GeneralSecurityException</c>/<c>IOException</c> throws are replaced by ordinary
/// (unchecked) exceptions, matching the Java original's own behavior at the <c>Wrap</c>/<c>Unwrap</c>
/// boundary (which itself catches those checked exceptions and rethrows as unchecked
/// <c>IllegalStateException</c> -- ported here as <see cref="InvalidOperationException"/>).</item>
/// </list>
/// </summary>
public abstract class SecureMessagingWrapper : IApduWrapper
{
    private readonly IBufferedCipher _cipher;
    private readonly IMac _mac;

    private long _ssc;

    /// <summary>The session key for encryption.</summary>
    public KeyParameter EncryptionKey { get; }

    /// <summary>The session key for computing message authentication codes over APDU payloads.</summary>
    public KeyParameter MacKey { get; }

    /// <summary>Whether this wrapper will check the MAC in wrapped response APDUs.</summary>
    public bool ShouldCheckMac { get; }

    /// <summary>The maximum tranceive length of wrapped command and response APDUs, typically 256 or 65536.</summary>
    public int MaxTranceiveLength { get; }

    /// <summary>The current value of the send sequence counter.</summary>
    public long SendSequenceCounter => _ssc;

    /// <summary>
    /// Constructs a secure messaging wrapper based on the secure messaging session keys, already
    /// constructed BC cipher/MAC primitives, and the initial value of the send sequence counter.
    /// </summary>
    /// <param name="ksEnc">the session key for encryption</param>
    /// <param name="ksMac">the session key for message authenticity</param>
    /// <param name="cipher">a CBC/NoPadding buffered block cipher (uninitialized; <see cref="Wrap"/>/<see cref="Unwrap"/> call <c>Init</c> per operation)</param>
    /// <param name="mac">a MAC primitive (uninitialized; <see cref="Wrap"/>/<see cref="Unwrap"/> call <c>Init</c> per operation)</param>
    /// <param name="maxTranceiveLength">the maximum tranceive length, typical values are 256 or 65536</param>
    /// <param name="shouldCheckMac">a boolean indicating whether this wrapper will check the MAC in wrapped response APDUs</param>
    /// <param name="ssc">the initial value of the send sequence counter</param>
    protected SecureMessagingWrapper(KeyParameter ksEnc, KeyParameter ksMac, IBufferedCipher cipher, IMac mac, int maxTranceiveLength, bool shouldCheckMac, long ssc)
    {
        EncryptionKey = ksEnc ?? throw new ArgumentNullException(nameof(ksEnc));
        MacKey = ksMac ?? throw new ArgumentNullException(nameof(ksMac));
        _cipher = cipher ?? throw new ArgumentNullException(nameof(cipher));
        _mac = mac ?? throw new ArgumentNullException(nameof(mac));
        MaxTranceiveLength = maxTranceiveLength;
        ShouldCheckMac = shouldCheckMac;
        _ssc = ssc;
    }

    /// <summary>
    /// Returns a copy of the given wrapper, with an identical (but independent) state, for known secure
    /// messaging wrapper types. If the wrapper type is not recognized the original wrapper is returned.
    /// </summary>
    /// <param name="wrapper">the original wrapper</param>
    /// <returns>a copy of that wrapper</returns>
    public static SecureMessagingWrapper GetInstance(SecureMessagingWrapper wrapper)
    {
        return wrapper switch
        {
            DESedeSecureMessagingWrapper desEdeWrapper => new DESedeSecureMessagingWrapper(desEdeWrapper),
            AESSecureMessagingWrapper aesWrapper => new AESSecureMessagingWrapper(aesWrapper),
            _ => wrapper,
        };
    }

    /// <summary>
    /// Wraps the given command APDU. As a side effect, this method increments the internal send sequence
    /// counter maintained by this wrapper.
    /// </summary>
    /// <param name="commandApdu">the command APDU to wrap</param>
    /// <returns>the wrapped command APDU</returns>
    public CommandApdu Wrap(CommandApdu commandApdu)
    {
        _ssc++;
        try
        {
            return WrapCommandAPDU(commandApdu);
        }
        catch (Exception e) when (e is not InvalidOperationException)
        {
            throw new InvalidOperationException("Unexpected exception", e);
        }
    }

    /// <summary>Unwraps the given response APDU.</summary>
    /// <param name="responseApdu">the response APDU to unwrap</param>
    /// <returns>the unwrapped response APDU</returns>
    public ResponseApdu Unwrap(ResponseApdu responseApdu)
    {
        _ssc++;
        try
        {
            byte[] data = responseApdu.Data;
            if (data.Length <= 0)
            {
                // No sense in unwrapping -- card indicates some kind of error.
                // FIXME (carried over from Java): wouldn't it be cleaner to throw a CardServiceException?
                throw new InvalidOperationException($"Card indicates SM error, SW = {responseApdu.Sw & 0xFFFF:x}");
            }

            return UnwrapResponseAPDU(responseApdu);
        }
        catch (Exception e) when (e is not InvalidOperationException)
        {
            throw new InvalidOperationException("Unexpected exception", e);
        }
    }

    /// <summary>Checks the MAC.</summary>
    /// <param name="rapdu">the bytes of the response APDU, including the <c>0x8E</c> tag, the length of the MAC, the MAC itself, and the status word</param>
    /// <param name="cc">the MAC sent by the other party</param>
    /// <returns>whether the computed MAC is identical</returns>
    protected bool CheckMac(byte[] rapdu, byte[] cc)
    {
        byte[] paddedData = Util.Pad(rapdu, 0, rapdu.Length - 2 - 8 - 2, GetPadLength());

        _mac.Init(MacKey);
        byte[] ssc = GetEncodedSendSequenceCounter();
        _mac.BlockUpdate(ssc, 0, ssc.Length);
        _mac.BlockUpdate(paddedData, 0, paddedData.Length);
        byte[] cc2 = new byte[_mac.GetMacSize()];
        _mac.DoFinal(cc2, 0);

        if (cc2.Length > 8 && cc.Length == 8)
        {
            byte[] newCC2 = new byte[8];
            Array.Copy(cc2, newCC2, newCC2.Length);
            cc2 = newCC2;
        }

        return cc.AsSpan().SequenceEqual(cc2);
    }

    /// <summary>Returns the length (in bytes) to use for padding.</summary>
    protected abstract int GetPadLength();

    /// <summary>
    /// The length (in bytes) to use for padding. Exposes <see cref="GetPadLength"/> to the rest of this
    /// assembly, matching the package-level access Java's <c>protected</c> gives <c>AAAPDUSender</c>.
    /// </summary>
    internal int PadLength => GetPadLength();

    /// <summary>
    /// The length (in bytes) to use for padding. Exposes <see cref="GetPadLength"/> to the rest of this
    /// assembly, matching the package-level access Java's <c>protected</c> gives <c>AAAPDUSender</c>.
    /// </summary>
    internal int PadLength => GetPadLength();

    /// <summary>
    /// The length (in bytes) to use for padding. Exposes <see cref="GetPadLength"/> to the rest of this
    /// assembly, matching the package-level access Java's <c>protected</c> gives <c>AAAPDUSender</c>.
    /// </summary>
    internal int PadLength => GetPadLength();

    /// <summary>
    /// The length (in bytes) to use for padding. Exposes <see cref="GetPadLength"/> to the rest of this
    /// assembly, matching the package-level access Java's <c>protected</c> gives <c>AAAPDUSender</c>.
    /// </summary>
    internal int PadLength => GetPadLength();

    /// <summary>
    /// The length (in bytes) to use for padding. Exposes <see cref="GetPadLength"/> to the rest of this
    /// assembly, matching the package-level access Java's <c>protected</c> gives <c>AAAPDUSender</c>.
    /// </summary>
    internal int PadLength => GetPadLength();

    /// <summary>Returns the raw initialization vector bytes to be used by the encryption cipher.</summary>
    protected abstract byte[] GetIV();

    /// <summary>Returns the send sequence counter encoded as a byte array for inclusion in wrapped APDUs.</summary>
    protected abstract byte[] GetEncodedSendSequenceCounter();

    /* PRIVATE BELOW. */

    /*
     * The SM Data Objects (see [ISO/IEC 7816-4]) MUST be used in the following order:
     *   - Command APDU: [DO'85' or DO'87'] [DO'97'] DO'8E'.
     *   - Response APDU: [DO'85' or DO'87'] [DO'99'] DO'8E'.
     */

    /// <summary>
    /// Performs the actual encoding of a command APDU. Based on Section E.3 of ICAO-TR-PKI, especially
    /// the examples.
    /// </summary>
    private CommandApdu WrapCommandAPDU(CommandApdu commandApdu)
    {
        int cla = commandApdu.Cla;
        int ins = commandApdu.Ins;
        int p1 = commandApdu.P1;
        int p2 = commandApdu.P2;
        int lc = commandApdu.Nc;
        int le = commandApdu.Ne;

        byte[] maskedHeader = [(byte)(cla | 0x0C), (byte)ins, (byte)p1, (byte)p2];
        byte[] paddedMaskedHeader = Util.Pad(maskedHeader, GetPadLength());

        bool hasDO85 = (byte)commandApdu.Ins == Iso7816.InsReadBinary2;

        byte[] do8587 = [];
        byte[] do97 = [];

        // Include the expected length, if present.
        if (le > 0)
        {
            do97 = TlvUtil.WrapDO(0x97, EncodeLe(le));
        }

        // Encrypt command data, if present.
        if (lc > 0)
        {
            byte[] data = Util.Pad(commandApdu.Data, GetPadLength());

            // Re-initialize cipher, this time with IV based on SSC.
            _cipher.Init(forEncryption: true, new ParametersWithIV(EncryptionKey, GetIV()));
            byte[] ciphertext = _cipher.DoFinal(data);

            using var do8587Stream = new MemoryStream();
            do8587Stream.WriteByte(hasDO85 ? (byte)0x85 : (byte)0x87);
            byte[] lengthBytes = TlvUtil.GetLengthAsBytes(ciphertext.Length + (hasDO85 ? 0 : 1));
            do8587Stream.Write(lengthBytes, 0, lengthBytes.Length);
            if (!hasDO85)
            {
                do8587Stream.WriteByte(0x01);
            }
            do8587Stream.Write(ciphertext, 0, ciphertext.Length);
            do8587 = do8587Stream.ToArray();
        }

        using var nStream = new MemoryStream();
        nStream.Write(GetEncodedSendSequenceCounter());
        nStream.Write(paddedMaskedHeader);
        nStream.Write(do8587);
        nStream.Write(do97);
        byte[] n = Util.Pad(nStream.ToArray(), GetPadLength());

        // Compute cryptographic checksum...
        _mac.Init(MacKey);
        _mac.BlockUpdate(n, 0, n.Length);
        byte[] cc = new byte[_mac.GetMacSize()];
        _mac.DoFinal(cc, 0);
        int ccLength = cc.Length;
        if (ccLength != 8)
        {
            ccLength = 8;
        }

        using var do8EStream = new MemoryStream();
        do8EStream.WriteByte(0x8E);
        do8EStream.WriteByte((byte)ccLength);
        do8EStream.Write(cc, 0, ccLength);
        byte[] do8E = do8EStream.ToArray();

        // Construct protected APDU...
        using var resultStream = new MemoryStream();
        resultStream.Write(do8587);
        resultStream.Write(do97);
        resultStream.Write(do8E);
        byte[] data2 = resultStream.ToArray();

        // The requested response is 0x00 or 0x0000, depending on whether extended length is needed.
        if (le <= 256 && data2.Length <= 255)
        {
            return new CommandApdu(maskedHeader[0], maskedHeader[1], maskedHeader[2], maskedHeader[3], data2, 256);
        }

        if (le > 256 || data2.Length > 255)
        {
            return new CommandApdu(maskedHeader[0], maskedHeader[1], maskedHeader[2], maskedHeader[3], data2, 65536);
        }

        // Not sure if this case ever occurs, but this is consistent with previous behavior.
        return new CommandApdu(maskedHeader[0], maskedHeader[1], maskedHeader[2], maskedHeader[3], data2, MaxTranceiveLength);
    }

    /// <summary>Unwraps a response APDU sent by the ICC. Based on Section E.3 of TR-PKI, especially the examples.</summary>
    private ResponseApdu UnwrapResponseAPDU(ResponseApdu responseApdu)
    {
        byte[] rapdu = responseApdu.GetBytes();
        if (rapdu.Length < 2)
        {
            throw new ArgumentException("Invalid response APDU");
        }

        _cipher.Init(forEncryption: false, new ParametersWithIV(EncryptionKey, GetIV()));

        byte[] data = [];
        byte[]? cc = null;
        short sw = 0;

        int pos = 0;
        bool isFinished = false;
        while (!isFinished)
        {
            int tag = ReadByteChecked(rapdu, ref pos);
            switch ((byte)tag)
            {
                case 0x87:
                    data = ReadDO87(rapdu, ref pos, do85: false);
                    break;
                case 0x85:
                    data = ReadDO87(rapdu, ref pos, do85: true);
                    break;
                case 0x99:
                    sw = ReadDO99(rapdu, ref pos);
                    break;
                case 0x8E:
                    cc = ReadDO8E(rapdu, ref pos);
                    isFinished = true;
                    break;
                default:
                    // NOTE: Java logs a warning here; omitted per the non-essential-warning-omission
                    // precedent used elsewhere in this port.
                    break;
            }
        }

        if (ShouldCheckMac && (cc == null || !CheckMac(rapdu, cc)))
        {
            throw new InvalidOperationException("Invalid MAC");
        }

        using var resultStream = new MemoryStream();
        resultStream.Write(data, 0, data.Length);
        resultStream.WriteByte((byte)((sw & 0xFF00) >> 8));
        resultStream.WriteByte((byte)(sw & 0x00FF));
        return new ResponseApdu(resultStream.ToArray());
    }

    /// <summary>Encodes the expected length value to a byte array for inclusion in wrapped APDUs. The result is a byte array of length 1 or 2.</summary>
    private static byte[] EncodeLe(int le)
    {
        if (le is >= 0 and <= 256)
        {
            // NOTE: both 0x00 and 0x100 are mapped to 0x00.
            return [(byte)le];
        }

        return [(byte)((le & 0xFF00) >> 8), (byte)(le & 0xFF)];
    }

    /// <summary>Reads a data object. The <c>0x87</c>/<c>0x85</c> tag has already been read.</summary>
    private byte[] ReadDO87(byte[] rapdu, ref int pos, bool do85)
    {
        // Read length...
        int length;
        int buf = ReadByteChecked(rapdu, ref pos);
        if ((buf & 0x00000080) != 0x00000080)
        {
            // Short form.
            length = buf;
            if (!do85)
            {
                buf = ReadByteChecked(rapdu, ref pos); // Should be 0x01...
                if (buf != 0x01)
                {
                    throw new InvalidOperationException($"DO'87 expected 0x01 marker, found {buf & 0xFF:x}");
                }
            }
        }
        else
        {
            // Long form.
            int lengthBytesCount = buf & 0x0000007F;
            length = 0;
            for (int i = 0; i < lengthBytesCount; i++)
            {
                length = (length << 8) | ReadByteChecked(rapdu, ref pos);
            }
            if (!do85)
            {
                buf = ReadByteChecked(rapdu, ref pos); // Should be 0x01...
                if (buf != 0x01)
                {
                    throw new InvalidOperationException("DO'87 expected 0x01 marker");
                }
            }
        }

        if (!do85)
        {
            length--; // Takes care of the extra 0x01 marker...
        }

        // Read, decrypt, unpad the data...
        byte[] ciphertext = ReadFully(rapdu, ref pos, length);
        byte[] paddedData = _cipher.DoFinal(ciphertext);
        return Util.Unpad(paddedData);
    }

    /// <summary>Reads a data object. The <c>0x99</c> tag has already been read.</summary>
    private static short ReadDO99(byte[] rapdu, ref int pos)
    {
        int length = ReadByteChecked(rapdu, ref pos);
        if (length != 2)
        {
            throw new InvalidOperationException("DO'99 wrong length");
        }
        byte sw1 = (byte)ReadByteChecked(rapdu, ref pos);
        byte sw2 = (byte)ReadByteChecked(rapdu, ref pos);
        return (short)(((sw1 & 0x000000FF) << 8) | (sw2 & 0x000000FF));
    }

    /// <summary>Reads a data object. This assumes that the <c>0x8E</c> tag has already been read.</summary>
    private static byte[] ReadDO8E(byte[] rapdu, ref int pos)
    {
        int length = ReadByteChecked(rapdu, ref pos);
        if (length != 8 && length != 16)
        {
            throw new InvalidOperationException($"DO'8E wrong length for MAC: {length}");
        }
        return ReadFully(rapdu, ref pos, length);
    }

    private static int ReadByteChecked(byte[] data, ref int pos)
    {
        if (pos >= data.Length)
        {
            throw new EndOfStreamException("Unexpected end of response APDU while unwrapping.");
        }
        return data[pos++] & 0xFF;
    }

    private static byte[] ReadFully(byte[] data, ref int pos, int count)
    {
        if (count < 0 || pos + count > data.Length)
        {
            throw new EndOfStreamException("Unexpected end of response APDU while unwrapping.");
        }
        byte[] result = new byte[count];
        Array.Copy(data, pos, result, 0, count);
        pos += count;
        return result;
    }

    public override string ToString() =>
        $"SecureMessagingWrapper [ssc: {_ssc}, ksEnc: {EncryptionKey}, ksMac: {MacKey}, maxTranceiveLength: {MaxTranceiveLength}, shouldCheckMAC: {ShouldCheckMac}]";

    public override int GetHashCode()
    {
        const int prime = 31;
        int result = 1;
        result = (prime * result) + KeyHash(EncryptionKey);
        result = (prime * result) + KeyHash(MacKey);
        result = (prime * result) + MaxTranceiveLength;
        result = (prime * result) + (ShouldCheckMac ? 1231 : 1237);
        result = (prime * result) + (int)(_ssc ^ (_ssc >>> 32));
        return result;
    }

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

        var other = (SecureMessagingWrapper)obj;
        return KeyEquals(EncryptionKey, other.EncryptionKey)
            && KeyEquals(MacKey, other.MacKey)
            && MaxTranceiveLength == other.MaxTranceiveLength
            && ShouldCheckMac == other.ShouldCheckMac
            && _ssc == other._ssc;
    }

    /// <summary>
    /// Value-based key comparison, substituting for Java <c>SecretKeySpec.equals</c> (which BC's
    /// <see cref="KeyParameter"/> does not provide -- see this class's doc comment).
    /// </summary>
    private static bool KeyEquals(KeyParameter? a, KeyParameter? b)
    {
        if (ReferenceEquals(a, b))
        {
            return true;
        }
        if (a is null || b is null)
        {
            return false;
        }
        return a.GetKey().AsSpan().SequenceEqual(b.GetKey());
    }

    /// <summary>Value-based key hash, substituting for Java <c>SecretKeySpec.hashCode</c> (see <see cref="KeyEquals"/>).</summary>
    private static int KeyHash(KeyParameter? key)
    {
        if (key is null)
        {
            return 0;
        }
        var hash = new HashCode();
        hash.AddBytes(key.GetKey());
        return hash.ToHashCode();
    }
}
