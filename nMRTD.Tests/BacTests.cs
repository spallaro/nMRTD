using nMRTD.Protocol;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using static nMRTD.Tests.Helpers.TestData;

namespace nMRTD.Tests;

/// <summary>BAC mutual authentication, with the ICAO 9303-11 Appendix D.3 vectors.</summary>
public class BacTests
{
    private static readonly KeyParameter BacEnc = new(Hex("AB94FDECF2674FDFB9B391F85D7F76F2"));
    private static readonly KeyParameter BacMac = new(Hex("7962D9ECE03D1ACD4C76089DCE131543"));
    private static readonly byte[] RndIfd = Hex("781723860C06C226");
    private static readonly byte[] RndIcc = Hex("4608F91988702212");
    private static readonly byte[] KIfd = Hex("0B795240CB7049B01C19B33E32804F0B");
    private static readonly byte[] KIcc = Hex("0B4F80323EB3191CB04970CB4052790B");

    /// <summary>The PICC's EXTERNAL AUTHENTICATE response: E(RND.ICC || RND.IFD || K.ICC) || MAC || 9000.</summary>
    private static byte[] BacResponse(byte[] returnedRndIfd, bool tamperMac)
    {
        var c = new BufferedBlockCipher(new CbcBlockCipher(new DesEdeEngine()));
        c.Init(true, new ParametersWithIV(BacEnc, new byte[8]));
        byte[] e = c.DoFinal(RndIcc.Concat(returnedRndIfd).Concat(KIcc).ToArray());
        var m = new ISO9797Alg3Mac(new DesEngine());
        m.Init(BacMac);
        byte[] p = Util.Pad(e, 8);
        m.BlockUpdate(p, 0, p.Length);
        byte[] mm = new byte[8];
        m.DoFinal(mm, 0);
        if (tamperMac) mm[0] ^= 1;
        return e.Concat(mm).Concat(new byte[] { 0x90, 0x00 }).ToArray();
    }

    private static byte[] DoBac(byte[] response) =>
        new BACAPDUSender(new SecureMessagingAPDUSender(new FakeCard(_ => response)))
            .SendMutualAuth(RndIfd, RndIcc, KIfd, BacEnc, BacMac);

    [Fact]
    public void ResponseCryptogramMatchesIcaoVector() =>
        Assert.Equal(
            Hex("46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F2F2D235D074D7449"),
            BacResponse(RndIfd, false)[..40]);

    [Fact]
    public void ValidExternalAuthenticateResponseAccepted() =>
        Assert.Equal(RndIcc.Concat(RndIfd).Concat(KIcc).ToArray(), DoBac(BacResponse(RndIfd, false)));

    [Fact]
    public void WrongChecksumOnPiccCryptogramRejected() =>
        Assert.ThrowsAny<CardServiceException>(() => DoBac(BacResponse(RndIfd, true)));

    [Fact]
    public void PiccNotReturningRndIfdRejected() =>
        Assert.ThrowsAny<CardServiceException>(() => DoBac(BacResponse(Hex("0000000000000000"), false)));
}
