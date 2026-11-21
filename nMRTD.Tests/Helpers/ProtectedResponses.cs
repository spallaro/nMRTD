using nMRTD.SmartCards;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace nMRTD.Tests.Helpers;

/// <summary>
/// The <c>createProtectedResponse</c> helpers of JMRTD's AES and 3DES secure messaging wrapper tests,
/// with Bouncy Castle in place of JCA: DO'87 (data encrypted under K_Enc), the extra data objects, DO'99
/// and DO'8E with the first <c>macLength</c> bytes of the MAC over SSC || pad(data objects).
/// </summary>
internal static class ProtectedResponses
{
    public static ResponseApdu Create(bool aes, KeyParameter encKey, KeyParameter macKey, long ssc, byte[] data, byte[] extraDataObjects, int macLength, int sw)
    {
        int blockSize = aes ? 16 : 8;
        byte[] encodedSsc = new byte[blockSize];
        for (int i = 0; i < 8; i++)
        {
            encodedSsc[blockSize - 1 - i] = (byte)(ssc >> (8 * i));
        }

        byte[] iv = new byte[blockSize];
        if (aes)
        {
            /* The IV is E(K_Enc, SSC), see ICAO SAC TR Section 4.6.3. */
            var ecb = new AesEngine();
            ecb.Init(true, encKey);
            ecb.ProcessBlock(encodedSsc, 0, iv, 0);
        }

        var cipher = new BufferedBlockCipher(new CbcBlockCipher(aes ? new AesEngine() : new DesEdeEngine()));
        cipher.Init(true, new ParametersWithIV(encKey, iv));
        byte[] encryptedData = cipher.DoFinal(Util.Pad(data, blockSize));

        var responseData = new MemoryStream();
        responseData.WriteByte(0x87);
        responseData.WriteByte((byte)(encryptedData.Length + 1));
        responseData.WriteByte(0x01);
        responseData.Write(encryptedData, 0, encryptedData.Length);
        responseData.Write(extraDataObjects, 0, extraDataObjects.Length);
        responseData.WriteByte(0x99);
        responseData.WriteByte(0x02);
        responseData.WriteByte((byte)(sw >> 8));
        responseData.WriteByte((byte)sw);
        byte[] dataObjects = responseData.ToArray();

        byte[] macInput = [.. encodedSsc, .. Util.Pad(dataObjects, blockSize)];
        IMac mac = aes ? new CMac(new AesEngine(), 128) : new ISO9797Alg3Mac(new DesEngine());
        mac.Init(macKey);
        mac.BlockUpdate(macInput, 0, macInput.Length);
        byte[] checksum = new byte[mac.GetMacSize()];
        mac.DoFinal(checksum, 0);

        responseData.WriteByte(0x8E);
        responseData.WriteByte((byte)macLength);
        responseData.Write(checksum, 0, macLength);
        responseData.WriteByte(0x90);
        responseData.WriteByte(0x00);
        return new ResponseApdu(responseData.ToArray());
    }
}
