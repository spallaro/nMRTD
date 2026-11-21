using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.Tests.Helpers;
using static nMRTD.Tests.Helpers.TestData;

namespace nMRTD.Tests;

/// <summary>Encode / decode round trips of LDS files and image infos.</summary>
public class LdsEncodingTests
{
    [Fact]
    public void SignedCardSecurityFileRoundTrips()
    {
        var paceInfo = new PACEInfo(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, 2, PACEInfo.PARAM_ID_ECP_BRAINPOOL_P256_R1);
        var chipAuthenticationInfo = new ChipAuthenticationInfo(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128, 1);
        var file = new CardSecurityFile("SHA-256", "SHA256withRSA", new SecurityInfo[] { paceInfo, chipAuthenticationInfo },
            SigningFixtures.KeyPair.Private, SigningFixtures.Certificate);
        byte[] encoded = file.GetEncoded()!;

        var parsed = new CardSecurityFile(new MemoryStream(encoded));

        Assert.Equal(2, parsed.GetSecurityInfos().Count);
        Assert.Contains(paceInfo, parsed.GetSecurityInfos());
        Assert.Contains(chipAuthenticationInfo, parsed.GetSecurityInfos());
        Assert.Equal(encoded, parsed.GetEncoded());
    }

    [Fact]
    public void Dg11RoundTripsWithTag6B()
    {
        var dg11 = new DG11File("ERIKSSON<<ANNA<MARIA", ["ANNA<MARIA<NILSSON"], "123456789",
            new DateTime(1974, 8, 12), ["ZENITH", "UTOPIA"], null, "+31 555 0123", "Engineer", null, null, null, null, null);
        byte[] encoded = dg11.GetEncoded()!;
        Assert.Equal(0x6B, encoded[0]);

        var parsed = new DG11File(new MemoryStream(encoded));

        Assert.Equal("ERIKSSON<<ANNA<MARIA", parsed.GetNameOfHolder());
        Assert.Equal("123456789", parsed.GetPersonalNumber());
        Assert.Equal(dg11, parsed);
        Assert.Equal(encoded, parsed.GetEncoded());
    }

    [Fact]
    public void DisplayedImageExposesItsBytesAndLength()
    {
        byte[] jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46];
        var image = new DisplayedImageInfo(ImageInfo.TYPE_PORTRAIT, jpeg);

        Assert.Equal(jpeg.Length, image.GetImageLength());
        Assert.Equal(jpeg, ReadAll(image.GetImageInputStream()));

        var parsed = new DisplayedImageInfo(new MemoryStream(image.GetEncoded()!));
        Assert.Equal(jpeg, ReadAll(parsed.GetImageInputStream()));
    }
}
