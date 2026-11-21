using nMRTD.Cert;
using nMRTD.Lds;
using nMRTD.Protocol;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace nMRTD.Tests.Jmrtd.Protocol;

/// <summary>Port of JMRTD's <c>org.jmrtd.protocol.EACCAAPDUSenderTest</c>.</summary>
public class EACCAAPDUSenderTest
{

    [Fact]
    public void retriesGeneralAuthenticateWithShortLength()
    {
        ScriptedCardService service = new ScriptedCardService(
                response(Iso7816.SwWrongLength),
                response(new byte[] { 0x7C, 0x03, 0x01, 0x02, 0x03 }, Iso7816.SwNoError));
        EACCAAPDUSender sender = new EACCAAPDUSender(new SecureMessagingAPDUSender(service));

        byte[] result = sender.SendGeneralAuthenticate(null, new byte[] { 0x11, 0x22 }, 65536, true);

        Assert.Equal(new byte[] { 0x01, 0x02, 0x03 }, result);
        List<CommandApdu> commands = service.GetCommands();
        Assert.Equal(2, commands.Count);
        Assert.Equal(65536, commands[0].Ne);
        Assert.Equal(256, commands[1].Ne);
        Assert.Equal(commands[0].Data, commands[1].Data);
    }

    [Fact]
    public void usesCommandChainingClassForNonFinalSegment()
    {
        ScriptedCardService service = new ScriptedCardService(
                response(new byte[] { 0x7C, 0x00 }, Iso7816.SwNoError));
        EACCAAPDUSender sender = new EACCAAPDUSender(new SecureMessagingAPDUSender(service));

        Assert.Equal(new byte[0],
                sender.SendGeneralAuthenticate(null, new byte[] { 0x01 }, 256, false));

        CommandApdu command = service.GetCommands()[0];
        Assert.Equal(Iso7816.ClaCommandChaining & 0xFF, command.Cla);
        Assert.Equal(new byte[] { 0x7C, 0x01, 0x01 }, command.Data);
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
