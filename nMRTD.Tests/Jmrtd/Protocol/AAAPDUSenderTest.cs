using nMRTD.Cert;
using nMRTD.Lds;
using nMRTD.Protocol;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace nMRTD.Tests.Jmrtd.Protocol;

/// <summary>Port of JMRTD's <c>org.jmrtd.protocol.AAAPDUSenderTest</c>.</summary>
/**
  * Tests the choice between a short and an extended Le in {@code INTERNAL AUTHENTICATE}.
  * The protected response fits in 256 bytes for at most 231 (3DES) or 223 (AES) bytes of signature.
  */
public class AAAPDUSenderTest
{

    private static readonly byte[] RND_IFD = { 1, 2, 3, 4, 5, 6, 7, 8 };

    [Fact]
    public void usesShortLeUpTo231BytesWithDESede()
    {
        assertLe(CreateDESedeWrapper(), 231 * 8, false);
        assertLe(CreateDESedeWrapper(), 232 * 8, true);
    }

    [Fact]
    public void usesShortLeUpTo223BytesWithAES()
    {
        assertLe(CreateAESWrapper(), 223 * 8, false);
        assertLe(CreateAESWrapper(), 224 * 8, true);
    }

    [Fact]
    public void usesExtendedLeForLargeRSAKeys()
    {
        assertLe(CreateDESedeWrapper(), 2048, true);
        assertLe(CreateAESWrapper(), 2048, true);
    }

    [Fact]
    public void usesShortLeForSmallKeys()
    {
        assertLe(CreateDESedeWrapper(), 1024, false);
        assertLe(CreateAESWrapper(), 1536, false);
    }

    [Fact]
    public void keepsThresholdWithoutSecureMessaging()
    {
        assertLe(null!, 231 * 8, false);
        assertLe(null!, 232 * 8, true);
    }

    /**
      * Sends INTERNAL AUTHENTICATE (the card refuses), and checks the Le of the sent command:
      * the outer Le, and (under secure messaging) the value of DO'97.
      */
    private static void assertLe(IApduWrapper wrapper, int signatureLength, bool isExtendedLengthExpected)
    {
        ScriptedCardService service = new ScriptedCardService(response(Iso7816.SwSecurityStatusNotSatisfied));
        AAAPDUSender sender = new AAAPDUSender(new SecureMessagingAPDUSender(service));
        try
        {
            sender.SendInternalAuthenticate(wrapper, signatureLength, RND_IFD);
        }
        catch (CardServiceException)
        {
            /* Expected. */
        }

        CommandApdu command = service.GetCommands()[0];
        string message = "signatureLength = " + signatureLength + ", command = " + Hex.BytesToHexString(command.GetBytes());
        Assert.Equal( isExtendedLengthExpected ? 65536 : 256, command.Ne);
        if (wrapper != null)
        {
            Assert.Equal( isExtendedLengthExpected ? new byte[] { 0x00, 0x00 } : new byte[] { 0x00 },
                    GetDO97Value(command.Data));
        }
    }

    /* The command data is DO'87, DO'97, DO'8E, all with single byte lengths here. */
    private static byte[] GetDO97Value(byte[] data)
    {
        int offset = 0;
        while (offset < data.Length)
        {
            int tag = data[offset++] & 0xFF;
            int length = data[offset++] & 0xFF;
            if (tag == 0x97)
            {
                byte[] value = new byte[length];
                Array.Copy(data, offset, value, 0, length);
                return value;
            }
            offset += length;
        }
        return null!;
    }

    private static SecureMessagingWrapper CreateDESedeWrapper()
    {
        return new DESedeSecureMessagingWrapper(
                new KeyParameter(TestData.Hex("00112233445566778899AABBCCDDEEFF0011223344556677")),
                new KeyParameter(TestData.Hex("1032547698BADCFE0123456789ABCDEF1032547698BADCFE")), 0L);
    }

    private static SecureMessagingWrapper CreateAESWrapper()
    {
        return new AESSecureMessagingWrapper(
                new KeyParameter(TestData.Hex("00112233445566778899AABBCCDDEEFF")),
                new KeyParameter(TestData.Hex("FFEEDDCCBBAA99887766554433221100")), 0L);
    }

    private static ResponseApdu response(int sw)
    {
        return new ResponseApdu(new byte[] { (byte)(sw >> 8), (byte)sw });
    }

    /// <summary>The error status words from JMRTD bug #90.</summary>
    private static readonly int[] ErrorSws =
    [
        0x6300, 0x6700, 0x6800, 0x6900, 0x6982, 0x6A00, 0x6A80, 0x6A88, 0x6B00, 0x6C00, 0x6E00, 0x6F00, 0x6FFF,
    ];

    /// <summary>A protected error response without data is an error, not an (empty) signature (JMRTD 0.8.10, bug
    /// #90, ddbbc826).</summary>
    [Fact]
    public void throwsOnProtectedErrorResponse()
    {
        var macKey = new KeyParameter(TestData.Hex("1032547698BADCFE0123456789ABCDEF1032547698BADCFE"));
        var encKey = new KeyParameter(TestData.Hex("00112233445566778899AABBCCDDEEFF0011223344556677"));
        foreach (int sw in ErrorSws)
        {
            var service = new ScriptedCardService(nMRTD.Tests.Helpers.ProtectedResponses.Create(false, encKey, macKey, 2L, [], [], 8, sw));
            AssertThrowsCardServiceException(new AAAPDUSender(new SecureMessagingAPDUSender(service)), CreateDESedeWrapper(), sw);
        }
    }

    /// <summary>A plain error response without data is an error, with and without secure messaging (JMRTD 0.8.10,
    /// bug #90).</summary>
    [Fact]
    public void throwsOnPlainErrorResponse()
    {
        foreach (int sw in ErrorSws)
        {
            AssertThrowsCardServiceException(new AAAPDUSender(new SecureMessagingAPDUSender(new ScriptedCardService(response(sw)))), CreateDESedeWrapper(), sw);
            AssertThrowsCardServiceException(new AAAPDUSender(new SecureMessagingAPDUSender(new ScriptedCardService(response(sw)))), null, sw);
        }
    }

    /// <summary>A signature with a warning status word is still returned.</summary>
    [Fact]
    public void returnsDataWithWarningStatusWord()
    {
        byte[] signature = [1, 2, 3, 4];
        var answer = new ResponseApdu([1, 2, 3, 4, 0x62, 0x82]);
        var sender = new AAAPDUSender(new SecureMessagingAPDUSender(new ScriptedCardService(answer)));
        Assert.Equal(signature, sender.SendInternalAuthenticate(null, 1024, RND_IFD));
    }

    private static void AssertThrowsCardServiceException(AAAPDUSender sender, IApduWrapper? wrapper, int sw)
    {
        string message = $"SW = {sw:x4}{(wrapper == null ? ", plain" : ", secure messaging")}";
        try
        {
            byte[] answer = sender.SendInternalAuthenticate(wrapper, 1024, RND_IFD);
            Assert.Fail($"{message}, response = {Hex.BytesToHexString(answer)}");
        }
        catch (CardServiceException)
        {
            // Expected.
        }
    }
}
