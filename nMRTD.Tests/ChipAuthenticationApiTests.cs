using nMRTD.Lds;
using nMRTD.Protocol;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Math;
using static nMRTD.Tests.Helpers.TestData;

namespace nMRTD.Tests;

/// <summary>The key ID of DG14's Chip Authentication infos flows into the CA commands unchanged.</summary>
public class ChipAuthenticationApiTests
{
    private static byte[] SendMseSetAtIntAuth(BigInteger? keyId)
    {
        byte[]? data = null;
        var card = new FakeCard(cmd => { data = cmd.Data; return [0x90, 0x00]; });
        new EACCAAPDUSender(new SecureMessagingAPDUSender(card)).SendMseSetAtIntAuth(null, SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128, keyId);
        return data!;
    }

    [Fact]
    public void KeyIdFromDg14IsSentAsDataObject84()
    {
        var info = new ChipAuthenticationInfo(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128, 1, BigInteger.ValueOf(5));

        byte[] data = SendMseSetAtIntAuth(info.GetKeyId());

        AssertContains(Hex("84 01 05"), data, "key ID data object");
    }

    [Fact]
    public void MissingKeyIdIsOmitted()
    {
        byte[] data = SendMseSetAtIntAuth(null);

        Assert.True(data.AsSpan().IndexOf((byte)0x84) < 0, Convert.ToHexString(data));
    }
}
