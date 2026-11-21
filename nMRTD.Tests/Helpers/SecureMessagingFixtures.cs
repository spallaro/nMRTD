using nMRTD.Protocol;
using nMRTD.SmartCards;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using static nMRTD.Tests.Helpers.TestData;

namespace nMRTD.Tests.Helpers;

/// <summary>Builds protected response APDUs as a chip would, for 3DES and AES secure messaging.</summary>
internal static class SecureMessagingFixtures
{
    public static readonly KeyParameter DesEnc = new(Hex("00112233445566778899AABBCCDDEEFF0011223344556677"));
    public static readonly KeyParameter DesMac = new(Hex("1032547698BADCFE0123456789ABCDEF"));
    public static readonly KeyParameter AesEnc = new(Hex("00112233445566778899AABBCCDDEEFF"));
    public static readonly KeyParameter AesMac = new(Hex("FFEEDDCCBBAA99887766554433221100"));

    public static SecureMessagingWrapper NewWrapper(bool aes) => aes
        ? new AESSecureMessagingWrapper(AesEnc, AesMac, 256, true, 0L)
        : new DESedeSecureMessagingWrapper(DesEnc, DesMac, 256, true, 0L);

    /// <summary>
    /// A protected response: DO'87 with the encrypted <paramref name="data"/> (if any), then
    /// <paramref name="extra"/>, DO'99 (9000) and DO'8E with a MAC of <paramref name="macLength"/> bytes.
    /// </summary>
    public static ResponseApdu Protected(bool aes, long ssc, byte[] data, byte[]? extra = null, int macLength = 8)
    {
        int bs = aes ? 16 : 8;
        byte[] encSsc = EncodeSsc(ssc, bs);
        byte[] iv;
        if (aes)
        {
            var ecb = new AesEngine();
            ecb.Init(true, AesEnc);
            iv = new byte[16];
            ecb.ProcessBlock(encSsc, 0, iv, 0);
        }
        else
        {
            iv = new byte[8];
        }

        var ms = new MemoryStream();
        if (data.Length > 0)
        {
            var cipher = new BufferedBlockCipher(new CbcBlockCipher(aes ? new AesEngine() : new DesEdeEngine()));
            cipher.Init(true, new ParametersWithIV(aes ? AesEnc : DesEnc, iv));
            byte[] enc = cipher.DoFinal(Util.Pad(data, bs));
            ms.WriteByte(0x87);
            int l = enc.Length + 1;
            if (l < 0x80)
            {
                ms.WriteByte((byte)l);
            }
            else if (l < 0x100)
            {
                ms.WriteByte(0x81);
                ms.WriteByte((byte)l);
            }
            else
            {
                ms.WriteByte(0x82);
                ms.WriteByte((byte)(l >> 8));
                ms.WriteByte((byte)l);
            }
            ms.WriteByte(1);
            ms.Write(enc);
        }
        if (extra != null) ms.Write(extra);
        ms.Write([0x99, 0x02, 0x90, 0x00]);

        byte[] dos = ms.ToArray();
        IMac mac = aes ? new CMac(new AesEngine(), 128) : new ISO9797Alg3Mac(new DesEngine());
        mac.Init(aes ? AesMac : DesMac);
        byte[] macIn = encSsc.Concat(Util.Pad(dos, bs)).ToArray();
        mac.BlockUpdate(macIn, 0, macIn.Length);
        byte[] cc = new byte[mac.GetMacSize()];
        mac.DoFinal(cc, 0);

        ms.WriteByte(0x8E);
        ms.WriteByte((byte)macLength);
        ms.Write(cc, 0, macLength);
        ms.Write([0x90, 0x00]);
        return new ResponseApdu(ms.ToArray());
    }

    private static byte[] EncodeSsc(long ssc, int len)
    {
        var b = new byte[len];
        for (int i = 0; i < 8; i++) b[len - 1 - i] = (byte)(ssc >> (8 * i));
        return b;
    }
}
