using nMRTD.Protocol;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using static nMRTD.Tests.Helpers.TestData;

namespace nMRTD.Tests;

public class PaceTests
{
    private static readonly ECDomainParameters Ec = BrainpoolP256r1;
    private static readonly BigInteger DhY = DhG.ModPow(BigInteger.ValueOf(12345), DhP);

    [Fact]
    public void GmDhMappedGeneratorOneRejected() =>
        Assert.ThrowsAny<ArgumentException>(() => PaceProtocol.MapNonceGMWithDH(new byte[] { 0 }, BigInteger.One, DhWithQ));

    [Fact]
    public void GmDhMappedGeneratorZeroRejected() =>
        Assert.ThrowsAny<ArgumentException>(() => PaceProtocol.MapNonceGMWithDH(new byte[] { 1 }, BigInteger.Zero, DhWithQ));

    [Fact]
    public void GmDhKeepsQInMappedParameters() =>
        Assert.Equal(DhQ, PaceProtocol.MapNonceGMWithDH(new byte[] { 5 }, DhG, DhWithQ).Q);

    [Fact]
    public void ImDhRequiresQ() =>
        Assert.ThrowsAny<ArgumentException>(() => PaceProtocol.MapNonceImWithDH(new byte[16], new byte[16], "AES", DhNoQ));

    [Fact]
    public void ImDhKeepsQAndMapsIntoSubgroup()
    {
        var m = PaceProtocol.MapNonceImWithDH(Hex("2923BE84E16CD6AE529049F1F1BBE9EB"), Hex("5DD4CBFC96F5453B130D890A1CDBAE32"), "AES", DhWithQ);
        Assert.Equal(DhQ, m.Q);
        Assert.Equal(BigInteger.One, m.G.ModPow(DhQ, DhP));
    }

    [Fact]
    public void DhPublicValueOutsideSubgroupRejected()
    {
        Assert.ThrowsAny<Org.BouncyCastle.Security.InvalidKeyException>(() => PaceProtocol.CheckDHPublicValue(BigInteger.One, DhWithQ));
        Assert.ThrowsAny<Org.BouncyCastle.Security.InvalidKeyException>(() => PaceProtocol.CheckDHPublicValue(DhP, DhWithQ));
        Assert.ThrowsAny<Org.BouncyCastle.Security.InvalidKeyException>(() => PaceProtocol.CheckDHPublicValue(DhP.Subtract(BigInteger.One), DhWithQ));
    }

    [Fact]
    public void DhValidPublicValueAcceptedWithAndWithoutQ()
    {
        PaceProtocol.CheckDHPublicValue(DhY, DhWithQ);
        PaceProtocol.CheckDHPublicValue(DhY, DhNoQ);
    }

    [Fact]
    public void GmEcdhMappedGeneratorAtInfinityRejected()
    {
        var h = Ec.G.Multiply(BigInteger.ValueOf(5)).Negate();
        Assert.ThrowsAny<ArgumentException>(() => PaceProtocol.MapNonceGMWithECDH(new byte[] { 5 }, h, Ec));
    }

    [Fact]
    public void GmEcdhValidMappingWorks()
    {
        var mapped = PaceProtocol.MapNonceGMWithECDH(new byte[] { 5 }, Ec.G.Multiply(BigInteger.ValueOf(7)), Ec);
        Assert.NotNull(mapped);
    }

    [Fact]
    public void PublicKeyDataObjectEncodesEcBasePointUncompressedInTag84()
    {
        var pub = new ECPublicKeyParameters(Ec.G.Multiply(BigInteger.ValueOf(3)).Normalize(), Ec);
        byte[] enc = PaceProtocol.EncodePublicKeyDataObject(PaceEcOid, pub, false);
        byte[] g = Util.EcPoint2OS(Ec.G, Ec.Curve.FieldSize);
        Assert.Equal(65, g.Length);
        Assert.Equal(0x04, g[0]);
        AssertContains(new byte[] { 0x84, 0x41 }.Concat(g).ToArray(), enc, "tag 84 with uncompressed G not found");
    }

    [Fact]
    public void PublicKeyDataObjectEncodesDhQInTag82()
    {
        byte[] enc = PaceProtocol.EncodePublicKeyDataObject(PaceDhOid, new DHPublicKeyParameters(DhY, DhWithQ), false);
        byte[] q = Util.I2os(DhQ);
        AssertContains(new byte[] { 0x82, (byte)q.Length }.Concat(q).ToArray(), enc, "tag 82 with q not found");
    }

    [Fact]
    public void PublicKeyDataObjectForDhWithoutQRejected() =>
        Assert.ThrowsAny<ArgumentException>(() =>
            PaceProtocol.EncodePublicKeyDataObject(PaceDhOid, new DHPublicKeyParameters(DhY, DhNoQ), false));

    [Fact]
    public void PublicKeyDataObjectWithKnownContextEncodes()
    {
        Assert.NotEmpty(PaceProtocol.EncodePublicKeyDataObject(PaceEcOid, new ECPublicKeyParameters(Ec.G.Multiply(BigInteger.ValueOf(3)).Normalize(), Ec)));
        Assert.NotEmpty(PaceProtocol.EncodePublicKeyDataObject(PaceDhOid, new DHPublicKeyParameters(DhY, DhNoQ)));
    }

    /// <summary>Regression (review fix 8): a plain BacKey must use key reference 01 (MRZ), as JMRTD does.</summary>
    [Fact]
    public void DoPaceWithBacKeySendsMrzKeyReference()
    {
        byte[]? mseData = null;
        var card = new FakeCard(cmd =>
        {
            if (cmd.Ins == 0x22)
            {
                mseData = cmd.Data;
                return [0x90, 0x00];
            }
            return [0x6A, 0x80]; // stop at GENERAL AUTHENTICATE
        });
        var pace = new PaceProtocol(new PACEAPDUSender(new SecureMessagingAPDUSender(card)), null, 256, true);
        try
        {
            pace.DoPace(new BacKey("L898902C<", "690806", "940623"), PaceEcOid, Ec, null);
        }
        catch (CardServiceException)
        {
            // expected: the fake card refuses GENERAL AUTHENTICATE
        }
        Assert.NotNull(mseData);
        AssertContains([0x83, 0x01, 0x01], mseData!, "no 83 01 01 in MSE:Set AT");
    }

    /// <summary>Regression (review fix 9): a failure on the card keeps the card's status word.</summary>
    [Fact]
    public void PaceFailureKeepsCardStatusWord()
    {
        var card = new FakeCard(cmd => cmd.Ins == 0x22 ? [0x90, 0x00] : [0x69, 0x82]);
        var pace = new PaceProtocol(new PACEAPDUSender(new SecureMessagingAPDUSender(card)), null, 256, true);
        var e = Assert.ThrowsAny<CardServiceException>(() =>
            pace.DoPace(new BacKey("L898902C<", "690806", "940623"), PaceEcOid, Ec, null));
        Assert.Equal(0x6982, e.Sw & 0xFFFF);
        Assert.Equal(0x6982, new CardServiceException("wrapped", new CardServiceException("inner", 0x6982)).Sw);
        Assert.Equal(CardServiceException.SwNotSet, new CardServiceException("wrapped", new IOException()).Sw);
    }
}
