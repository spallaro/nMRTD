using nMRTD.Protocol;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Crypto.Parameters;

namespace nMRTD.Tests.Jmrtd.Protocol;

/// <summary>Port of JMRTD's <c>org.jmrtd.protocol.EACCAAPDUSenderTest</c> (0.8.11, 8711eb58 and ab463f56):
/// GENERAL AUTHENTICATE for EAC-CA is a single command, with extended length if needed (Doc 9303-11, 9.3.1), without
/// retry or command chaining.</summary>
public class EACCAAPDUSenderTest
{
    [Fact]
    public void sendsGeneralAuthenticateAsSingleCommand()
    {
        var service = new ScriptedCardService(response(new byte[] { 0x7C, 0x00 }, Iso7816.SwNoError));
        var sender = new EACCAAPDUSender(new SecureMessagingAPDUSender(service));

        Assert.Equal(new byte[0], sender.SendGeneralAuthenticate(null, new byte[] { 0x80, 0x02, 0x01, 0x02 }));

        List<CommandApdu> commands = service.GetCommands();
        Assert.Single(commands);
        CommandApdu command = commands[0];
        Assert.Equal(Iso7816.ClaIso7816 & 0xFF, command.Cla);
        Assert.Equal(0x86, command.Ins);
        Assert.Equal(new byte[] { 0x7C, 0x04, 0x80, 0x02, 0x01, 0x02 }, command.Data);
        Assert.Equal(256, command.Ne);
    }

    /// <summary>A DH 2048 key: '80 82 01 00' and 256 bytes, so '7C 82 01 04' and 260 bytes, in one extended length
    /// command.</summary>
    [Fact]
    public void sendsLongGeneralAuthenticateWithExtendedLength()
    {
        var service = new ScriptedCardService(response(new byte[] { 0x7C, 0x00 }, Iso7816.SwNoError));
        var sender = new EACCAAPDUSender(new SecureMessagingAPDUSender(service));
        byte[] keyData = Enumerable.Repeat((byte)0x5A, 256).ToArray();
        byte[] data = TlvUtil.WrapDO(0x80, keyData);

        sender.SendGeneralAuthenticate(null, data);

        List<CommandApdu> commands = service.GetCommands();
        Assert.Single(commands);
        CommandApdu command = commands[0];
        Assert.Equal(Iso7816.ClaIso7816 & 0xFF, command.Cla);
        Assert.Equal(TlvUtil.WrapDO(0x7C, data), command.Data);
        Assert.Equal(0x00, command.GetBytes()[4]); // extended length
    }

    [Fact]
    public void doesNotRetryGeneralAuthenticate()
    {
        var service = new ScriptedCardService(
            response(Iso7816.SwWrongLength),
            response(new byte[] { 0x7C, 0x00 }, Iso7816.SwNoError));
        var sender = new EACCAAPDUSender(new SecureMessagingAPDUSender(service));

        var e = Assert.Throws<CardServiceException>(() => sender.SendGeneralAuthenticate(null, new byte[] { 0x80, 0x01, 0x01 }));

        Assert.Equal(Iso7816.SwWrongLength & 0xFFFF, e.Sw & 0xFFFF);
        Assert.Single(service.GetCommands());
    }

    /// <summary>No retry under secure messaging either (Doc 9303-11, 9.3.1); the sender takes back the command
    /// answered with a plain 6700.</summary>
    [Fact]
    public void doesNotRetryGeneralAuthenticateUnderSecureMessaging()
    {
        var service = new ScriptedCardService(
            response(Iso7816.SwWrongLength),
            response(new byte[] { 0x7C, 0x00 }, Iso7816.SwNoError));
        var sender = new EACCAAPDUSender(new SecureMessagingAPDUSender(service));
        var key = new KeyParameter(new byte[16]);
        var wrapper = new AESSecureMessagingWrapper(key, key, 0L);

        Assert.Throws<CardServiceException>(() => sender.SendGeneralAuthenticate(wrapper, new byte[] { 0x80, 0x01, 0x01 }));

        Assert.Single(service.GetCommands());
        Assert.Equal(0L, wrapper.SendSequenceCounter);
    }

#pragma warning disable CS0618 // The obsolete variants keep their behaviour.
    [Fact]
    public void retriesGeneralAuthenticateWithShortLength()
    {
        var service = new ScriptedCardService(
            response(Iso7816.SwWrongLength),
            response(new byte[] { 0x7C, 0x03, 0x01, 0x02, 0x03 }, Iso7816.SwNoError));
        var sender = new EACCAAPDUSender(new SecureMessagingAPDUSender(service));

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
        var service = new ScriptedCardService(response(new byte[] { 0x7C, 0x00 }, Iso7816.SwNoError));
        var sender = new EACCAAPDUSender(new SecureMessagingAPDUSender(service));

        Assert.Equal(new byte[0], sender.SendGeneralAuthenticate(null, new byte[] { 0x01 }, 256, false));

        CommandApdu command = service.GetCommands()[0];
        Assert.Equal(Iso7816.ClaCommandChaining & 0xFF, command.Cla);
        Assert.Equal(new byte[] { 0x7C, 0x01, 0x01 }, command.Data);
    }
#pragma warning restore CS0618

    private static ResponseApdu response(int sw) => response([], sw);

    private static ResponseApdu response(byte[] data, int sw)
    {
        byte[] bytes = new byte[data.Length + 2];
        Array.Copy(data, 0, bytes, 0, data.Length);
        bytes[^2] = (byte)(sw >> 8);
        bytes[^1] = (byte)sw;
        return new ResponseApdu(bytes);
    }
}
