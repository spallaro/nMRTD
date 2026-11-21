using System.Security.Cryptography;
using Org.BouncyCastle.Math;

namespace nMRTD.Tests;

public class UtilTests
{
    [Fact]
    public void UnpadAllZeroBytesRejected() =>
        Assert.ThrowsAny<CryptographicException>(() => Util.Unpad(new byte[8]));

    [Fact]
    public void UnpadNormalPadding() =>
        Assert.Equal(new byte[] { 1, 2 }, Util.Unpad([1, 2, 0x80, 0, 0, 0, 0, 0]));

    [Fact]
    public void Os2ECPointEvenLengthRejected() =>
        Assert.ThrowsAny<ArgumentException>(() => Util.Os2ECPoint([4, 1, 2, 3]));

    [Fact]
    public void Os2ECPointValidPoint()
    {
        var (x, y) = Util.Os2ECPoint([4, 1, 2]);
        Assert.Equal(BigInteger.One, x);
        Assert.Equal(BigInteger.Two, y);
    }
}
