using nMRTD.Protocol;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace nMRTD.Tests.Jmrtd.Protocol;

/// <summary>Port of JMRTD's <c>org.jmrtd.protocol.BACProtocolTest</c>.</summary>
/// <remarks>
/// End-to-end test of <c>BACProtocol.doBAC</c> against a scripted (fake) card, exercising the full
/// GET CHALLENGE / EXTERNAL AUTHENTICATE exchange through <c>BACAPDUSender</c> and
/// <c>SecureMessagingAPDUSender</c>, not just the static KDF helpers.
/// ADAPTATION: JCA ciphers and MACs are Bouncy Castle engines; <c>Util.DeriveKey</c> returns raw key bytes.
/// </remarks>
public class BACProtocolTest
{
    /* ICAO Doc 9303 Part 11, Appendix D.2 worked example. */
    private const string DOCUMENT_NUMBER = "L898902C3";
    private const string DATE_OF_BIRTH = "690806";
    private const string DATE_OF_EXPIRY = "940623";

    private static readonly byte[] RND_ICC = TestData.Hex("4608F91988702212");

    /* The (fake) chip's contribution to the session key seed. */
    private static readonly byte[] K_ICC = TestData.Hex("30F49CB0B5D0A97CB0B5D0A9BABABABA");

    [Fact]
    public void testDoBACEndToEndViaScriptedCardService()
    {
        IAccessKeySpec bacKey = new BacKey(DOCUMENT_NUMBER, DATE_OF_BIRTH, DATE_OF_EXPIRY);
        var kEnc = new KeyParameter(Util.DeriveKey(bacKey.GetKey(), Util.ENC_MODE));
        var kMac = new KeyParameter(Util.DeriveKey(bacKey.GetKey(), Util.MAC_MODE));

        var service = new FakeBACChip(kEnc, kMac, false, false);

        var protocol = new BACProtocol(new BACAPDUSender(new SecureMessagingAPDUSender(service)), 256, true);

        BACResult result = protocol.DoBAC(bacKey);

        /* Exactly the two APDUs BAC needs, nothing more. */
        List<CommandApdu> commands = service.GetCommands();
        Assert.Equal(2, commands.Count);

        CommandApdu getChallenge = commands[0];
        Assert.Equal(Iso7816.ClaIso7816, (byte)getChallenge.Cla);
        Assert.Equal(Iso7816.InsGetChallenge, (byte)getChallenge.Ins);
        Assert.Equal(8, getChallenge.Ne);

        CommandApdu mutualAuth = commands[1];
        Assert.Equal(Iso7816.ClaIso7816, (byte)mutualAuth.Cla);
        Assert.Equal(Iso7816.InsExternalAuthenticate, (byte)mutualAuth.Ins);
        Assert.Equal(40, mutualAuth.Data.Length); /* 32 bytes ciphertext + 8 bytes MAC. */

        /*
         * rndIFD and kIFD are generated with an internal SecureRandom inside BACProtocol, so we cannot know
         * them up front. Recover them from the actual EXTERNAL AUTHENTICATE request we just captured, the
         * same way the (fake) chip would have to, and independently re-derive what the resulting session
         * keys and send sequence counter should be.
         */
        byte[] plaintext = TripleDesCbc(false, kEnc, mutualAuth.Data[..32]);
        byte[] rndIFD = plaintext[..8];
        byte[] kIFD = plaintext[16..32];

        var expectedKeySeed = new byte[16];
        for (int i = 0; i < 16; i++)
        {
            expectedKeySeed[i] = (byte)((kIFD[i] & 0xFF) ^ (K_ICC[i] & 0xFF));
        }
        byte[] expectedKsEnc = Util.DeriveKey(expectedKeySeed, Util.ENC_MODE);
        byte[] expectedKsMac = Util.DeriveKey(expectedKeySeed, Util.MAC_MODE);
        long expectedSsc = BACProtocol.ComputeSendSequenceCounter(RND_ICC, rndIFD);

        Assert.NotNull(result.Wrapper);
        Assert.IsType<DESedeSecureMessagingWrapper>(result.Wrapper);
        Assert.Equal(expectedKsEnc, result.Wrapper.EncryptionKey.GetKey());
        Assert.Equal(expectedKsMac, result.Wrapper.MacKey.GetKey());
        Assert.Equal(expectedSsc, result.Wrapper.SendSequenceCounter);
        Assert.Equal(bacKey, result.BacKey);
    }

    [Fact]
    public void testDoBACFailsWhenGetChallengeFails()
    {
        var service = new ScriptedCardService(Response([], Iso7816.SwConditionsNotSatisfied));
        var protocol = new BACProtocol(new BACAPDUSender(new SecureMessagingAPDUSender(service)), 256, true);
        IAccessKeySpec bacKey = new BacKey(DOCUMENT_NUMBER, DATE_OF_BIRTH, DATE_OF_EXPIRY);

        Assert.ThrowsAny<CardServiceProtocolException>(() => protocol.DoBAC(bacKey));
        Assert.Single(service.GetCommands());
    }

    [Fact]
    public void testDoBACFailsWhenMutualAuthFails()
    {
        var service = new ScriptedCardService(
            Response(RND_ICC, Iso7816.SwNoError),
            Response([], Iso7816.SwConditionsNotSatisfied));
        var protocol = new BACProtocol(new BACAPDUSender(new SecureMessagingAPDUSender(service)), 256, true);
        IAccessKeySpec bacKey = new BacKey(DOCUMENT_NUMBER, DATE_OF_BIRTH, DATE_OF_EXPIRY);

        Assert.ThrowsAny<CardServiceProtocolException>(() => protocol.DoBAC(bacKey));
    }

    /*
     * The terminal checks that the PICC returned RND.IFD (Doc 9303 - Part 11, 4.3.1, step 4c).
     */
    [Fact]
    public void testDoBACFailsWhenPICCDoesNotReturnRNDIFD()
    {
        IAccessKeySpec bacKey = new BacKey(DOCUMENT_NUMBER, DATE_OF_BIRTH, DATE_OF_EXPIRY);
        var service = new FakeBACChip(
            new KeyParameter(Util.DeriveKey(bacKey.GetKey(), Util.ENC_MODE)), new KeyParameter(Util.DeriveKey(bacKey.GetKey(), Util.MAC_MODE)), true, false);
        var protocol = new BACProtocol(new BACAPDUSender(new SecureMessagingAPDUSender(service)), 256, true);

        CardServiceProtocolException e = Assert.ThrowsAny<CardServiceProtocolException>(() => protocol.DoBAC(bacKey));
        Assert.Contains("RND.IFD", e.InnerException!.Message);
    }

    /*
     * The terminal checks the checksum M_IC of the PICC's cryptogram (Doc 9303 - Part 11, 4.3.1, step 4a).
     */
    [Fact]
    public void testDoBACFailsOnWrongChecksum()
    {
        IAccessKeySpec bacKey = new BacKey(DOCUMENT_NUMBER, DATE_OF_BIRTH, DATE_OF_EXPIRY);
        var service = new FakeBACChip(
            new KeyParameter(Util.DeriveKey(bacKey.GetKey(), Util.ENC_MODE)), new KeyParameter(Util.DeriveKey(bacKey.GetKey(), Util.MAC_MODE)), false, true);
        var protocol = new BACProtocol(new BACAPDUSender(new SecureMessagingAPDUSender(service)), 256, true);

        CardServiceProtocolException e = Assert.ThrowsAny<CardServiceProtocolException>(() => protocol.DoBAC(bacKey));
        Assert.Contains("checksum", e.InnerException!.Message);
    }

    private static byte[] TripleDesCbc(bool encrypt, KeyParameter key, byte[] input)
    {
        var cipher = new BufferedBlockCipher(new CbcBlockCipher(new DesEdeEngine()));
        cipher.Init(encrypt, new ParametersWithIV(key, new byte[8]));
        return cipher.DoFinal(input);
    }

    /// <summary>
    /// A (fake) chip for BAC. GET CHALLENGE returns RND_ICC. EXTERNAL AUTHENTICATE is answered as a real chip
    /// would: it decrypts the terminal's cryptogram to learn RND.IFD, and returns
    /// E(K_Enc, RND.IC || RND.IFD || K.IC) || MAC(K_MAC, padded ciphertext), optionally corrupted.
    /// </summary>
    private sealed class FakeBACChip(KeyParameter kEnc, KeyParameter kMac, bool isRNDIFDCorrupted, bool isChecksumCorrupted)
        /* The second (placeholder) response is replaced in Transmit. */
        : ScriptedCardService(Response(RND_ICC, Iso7816.SwNoError), Response([], Iso7816.SwNoError))
    {
        public override ResponseApdu Transmit(CommandApdu commandApdu)
        {
            ResponseApdu scriptedResponse = base.Transmit(commandApdu);
            if ((byte)commandApdu.Ins != Iso7816.InsExternalAuthenticate)
            {
                return scriptedResponse;
            }

            byte[] terminalPlaintext = TripleDesCbc(false, kEnc, commandApdu.Data[..32]);

            var plaintext = new byte[32];
            Array.Copy(RND_ICC, 0, plaintext, 0, 8);
            Array.Copy(terminalPlaintext, 0, plaintext, 8, 8); /* RND.IFD */
            Array.Copy(K_ICC, 0, plaintext, 16, 16);
            if (isRNDIFDCorrupted)
            {
                plaintext[8] ^= 0x01;
            }

            byte[] ciphertext = TripleDesCbc(true, kEnc, plaintext);

            IMac mac = new ISO9797Alg3Mac(new DesEngine());
            mac.Init(kMac);
            byte[] padded = Util.Pad(ciphertext, 8);
            mac.BlockUpdate(padded, 0, padded.Length);
            var checksum = new byte[mac.GetMacSize()];
            mac.DoFinal(checksum, 0);
            if (isChecksumCorrupted)
            {
                checksum[7] ^= 0x01;
            }

            var data = new byte[32 + 8];
            Array.Copy(ciphertext, 0, data, 0, 32);
            Array.Copy(checksum, 0, data, 32, 8);
            return Response(data, Iso7816.SwNoError);
        }
    }

    private static ResponseApdu Response(byte[] data, int sw)
    {
        var bytes = new byte[data.Length + 2];
        Array.Copy(data, 0, bytes, 0, data.Length);
        bytes[^2] = (byte)(sw >> 8);
        bytes[^1] = (byte)sw;
        return new ResponseApdu(bytes);
    }
}
