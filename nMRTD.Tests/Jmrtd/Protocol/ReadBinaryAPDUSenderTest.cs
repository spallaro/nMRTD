using nMRTD.Cert;
using nMRTD.Lds;
using nMRTD.Protocol;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace nMRTD.Tests.Jmrtd.Protocol;

/// <summary>Port of JMRTD's <c>org.jmrtd.protocol.ReadBinaryAPDUSenderTest</c>.</summary>
public class ReadBinaryAPDUSenderTest
{

    [Fact]
    public void encodesStandardAndSFIReads()
    {
        ScriptedCardService standardService = new ScriptedCardService(response(new byte[] { 1, 2 }, Iso7816.SwNoError));
        ReadBinaryAPDUSender standardSender = new ReadBinaryAPDUSender(new SecureMessagingAPDUSender(standardService));
        Assert.Equal(new byte[] { 1, 2 },
                standardSender.SendReadBinary(null, 0, 0x1234, 2, false, false));
        CommandApdu standard = standardService.GetCommands()[0];
        Assert.Equal(Iso7816.InsReadBinary & 0xFF, standard.Ins);
        Assert.Equal(0x12, standard.P1);
        Assert.Equal(0x34, standard.P2);

        ScriptedCardService sfiService = new ScriptedCardService(response(new byte[] { 3 }, Iso7816.SwNoError));
        ReadBinaryAPDUSender sfiSender = new ReadBinaryAPDUSender(new SecureMessagingAPDUSender(sfiService));
        Assert.Equal(new byte[] { 3 },
                sfiSender.SendReadBinary(null, 0x81, 0x44, 1, true, false));
        CommandApdu sfi = sfiService.GetCommands()[0];
        Assert.Equal(0x81, sfi.P1);
        Assert.Equal(0x44, sfi.P2);
    }

    [Fact]
    public void encodesAndDecodesLongRead()
    {
        ScriptedCardService service = new ScriptedCardService(
                response(new byte[] { 0x53, 0x03, 0x21, 0x22, 0x23 }, Iso7816.SwNoError));
        ReadBinaryAPDUSender sender = new ReadBinaryAPDUSender(new SecureMessagingAPDUSender(service));

        Assert.Equal(new byte[] { 0x21, 0x22, 0x23 },
                sender.SendReadBinary(null, 0, 0x8123, 3, false, true));

        CommandApdu command = service.GetCommands()[0];
        Assert.Equal(Iso7816.InsReadBinary2 & 0xFF, command.Ins);
        Assert.Equal(new byte[] { 0x54, 0x02, 0x81, 0x23 }, command.Data);
        Assert.Equal(5, command.Ne);
    }

    [Fact]
    public void decodesLongFormResponseLengths()
    {
        byte[] value128 = new byte[128];
        byte[] value256 = new byte[256];
        for (int i = 0; i < value128.Length; i++)
        {
            value128[i] = (byte)i;
        }
        for (int i = 0; i < value256.Length; i++)
        {
            value256[i] = (byte)i;
        }

        ScriptedCardService length81Service = new ScriptedCardService(
                response(tlvResponse(new byte[] { 0x81, 0x80 }, value128),
                        Iso7816.SwNoError));
        Assert.Equal(value128, new ReadBinaryAPDUSender(new SecureMessagingAPDUSender(length81Service))
                .SendReadBinary(null, 0, 0, value128.Length, false, true));

        ScriptedCardService length82Service = new ScriptedCardService(
                response(tlvResponse(new byte[] { 0x82, 0x01, 0x00 }, value256),
                        Iso7816.SwNoError));
        Assert.Equal(value256, new ReadBinaryAPDUSender(new SecureMessagingAPDUSender(length82Service))
                .SendReadBinary(null, 0, 0, value256.Length, false, true));
    }

    [Fact]
    public void acceptsEndOfFileOnlyWhenItCarriesData()
    {
        ScriptedCardService withData = new ScriptedCardService(
                response(new byte[] { 0x55 }, Iso7816.SwEndOfFile));
        Assert.Equal(new byte[] { 0x55 },
                new ReadBinaryAPDUSender(new SecureMessagingAPDUSender(withData)).SendReadBinary(null, 0, 0, 1, false, false));

        ScriptedCardService withoutData = new ScriptedCardService(response(Iso7816.SwEndOfFile));
        Assert.ThrowsAny<CardServiceException>(() => new ReadBinaryAPDUSender(new SecureMessagingAPDUSender(withoutData)).SendReadBinary(null, 0, 0, 1, false, false));
    }

    [Fact]
    public void rejectsMalformedLongReadResponses()
    {
        assertMalformed(new byte[0]);
        assertMalformed(new byte[] { 0x53 });
        assertMalformed(new byte[] { 0x53, 0x81 });
        assertMalformed(new byte[] { 0x53, 0x02, 0x01 });
        assertMalformed(new byte[] { 0x52, 0x00 });
        assertMalformed(new byte[] { 0x53, 0x81, 0x01, 0x01 });
        assertMalformed(new byte[] { 0x53, 0x82, 0x00, 0x80 });
        assertMalformed(new byte[] {
                0x53, 0x84, 0x80, 0x00, 0x00, 0x00 });
        assertMalformed(new byte[] { 0x53, 0x01, 0x01, 0x02 });
    }

    private static byte[] tlvResponse(byte[] encodedLength, byte[] value)
    {
        byte[] result = new byte[1 + encodedLength.Length + value.Length];
        result[0] = 0x53;
        Array.Copy(encodedLength, 0, result, 1, encodedLength.Length);
        Array.Copy(value, 0, result, 1 + encodedLength.Length, value.Length);
        return result;
    }

    private static void assertMalformed(byte[] data)
    {
        ScriptedCardService service = new ScriptedCardService(response(data, Iso7816.SwNoError));
        Assert.ThrowsAny<CardServiceException>(() => new ReadBinaryAPDUSender(new SecureMessagingAPDUSender(service)).SendReadBinary(null, 0, 0, 1, false, true));
    }

    private static ResponseApdu response(int sw)
    {
        return response(new byte[0], sw);
    }

    private static ResponseApdu response(byte[] data, int sw)
    {
        byte[] bytes = new byte[data.Length + 2];
        Array.Copy(data, 0, bytes, 0, data.Length);
        bytes[bytes.Length - 2] = (byte)(sw >> 8);
        bytes[bytes.Length - 1] = (byte)sw;
        return new ResponseApdu(bytes);
    }
}
