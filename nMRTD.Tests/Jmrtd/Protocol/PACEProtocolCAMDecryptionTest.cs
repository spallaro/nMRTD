using nMRTD.Protocol;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace nMRTD.Tests.Jmrtd.Protocol;

/// <summary>Port of JMRTD's <c>org.jmrtd.protocol.PACEProtocolCAMDecryptionTest</c>.</summary>
/// <remarks>
/// Tests for <c>PACEProtocol.decryptChipAuthenticationData</c>, the last step of PACE-CAM (Doc 9303-11,
/// 4.4.5.5). The Encrypted Chip Authentication Data (A_PICC) is AES/CBC encrypted with IV = E(K_enc, -1),
/// where -1 is the all-ones 128 bit block. ADAPTATION: JCA ciphers are Bouncy Castle engines.
/// </remarks>
public class PACEProtocolCAMDecryptionTest
{
    private static readonly byte[] MINUS_ONE_BLOCK =
    [
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
    ];

    [Fact]
    public void testDecryptChipAuthenticationDataRoundTrip()
    {
        foreach (int keyLength in new[] { 128, 192, 256 })
        {
            KeyParameter encKey = GenerateAESKey(keyLength);

            /* A realistic CA_PICC: e.g. a 32 byte EC private key scalar for a 256 bit curve. */
            var chipAuthenticationData = new byte[32];
            new SecureRandom().NextBytes(chipAuthenticationData);

            byte[] encryptedChipAuthenticationData = EncryptReference(encKey, chipAuthenticationData);

            byte[] decrypted = PaceProtocol.DecryptChipAuthenticationData(encKey, encryptedChipAuthenticationData);

            Assert.Equal(chipAuthenticationData, decrypted);
        }
    }

    [Fact]
    public void testDecryptChipAuthenticationDataShorterThanOneBlock()
    {
        KeyParameter encKey = GenerateAESKey(128);

        /* Shorter than one block, so the (input)correctness of the IV affects the entire result. */
        byte[] chipAuthenticationData = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        byte[] encryptedChipAuthenticationData = EncryptReference(encKey, chipAuthenticationData);

        byte[] decrypted = PaceProtocol.DecryptChipAuthenticationData(encKey, encryptedChipAuthenticationData);

        Assert.Equal(chipAuthenticationData, decrypted);
    }

    /// <summary>
    /// Regression guard for the actual bug: using the all-ones block directly as IV (instead of
    /// E(K_enc, -1)) must NOT recover the correct plaintext.
    /// </summary>
    [Fact]
    public void testAllOnesBlockUsedDirectlyAsIvIsWrong()
    {
        KeyParameter encKey = GenerateAESKey(128);

        var chipAuthenticationData = new byte[32];
        new SecureRandom().NextBytes(chipAuthenticationData);

        byte[] encryptedChipAuthenticationData = EncryptReference(encKey, chipAuthenticationData);

        var wrongIvCipher = new BufferedBlockCipher(new CbcBlockCipher(new AesEngine()));
        wrongIvCipher.Init(false, new ParametersWithIV(encKey, MINUS_ONE_BLOCK));
        byte[] wronglyDecryptedPadded = wrongIvCipher.DoFinal(encryptedChipAuthenticationData);

        byte[] wronglyDecryptedFirstBlock = wronglyDecryptedPadded[..16];
        byte[] correctFirstBlock = chipAuthenticationData[..16];

        Assert.NotEqual(correctFirstBlock, wronglyDecryptedFirstBlock);
    }

    private static KeyParameter GenerateAESKey(int keyLength) =>
        new(SecureRandom.GetNextBytes(new SecureRandom(), keyLength / 8));

    /// <summary>
    /// Independent reference implementation of the PACE-CAM encryption side (Doc 9303-11, 4.4.5.5), used
    /// to build test vectors without relying on the decryption code under test.
    /// </summary>
    private static byte[] EncryptReference(KeyParameter encKey, byte[] chipAuthenticationData)
    {
        var ivCipher = new AesEngine();
        ivCipher.Init(true, encKey);
        var iv = new byte[16];
        ivCipher.ProcessBlock(MINUS_ONE_BLOCK, 0, iv, 0);

        byte[] padded = Util.Pad(chipAuthenticationData, 16);

        var cipher = new BufferedBlockCipher(new CbcBlockCipher(new AesEngine()));
        cipher.Init(true, new ParametersWithIV(encKey, iv));
        return cipher.DoFinal(padded);
    }
}
