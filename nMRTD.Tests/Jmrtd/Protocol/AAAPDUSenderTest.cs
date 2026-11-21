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
            /* Expected under secure messaging. Without, the (empty) response data is returned. */
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
}
