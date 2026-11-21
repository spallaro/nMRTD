using nMRTD.SmartCards;
using static nMRTD.Tests.Helpers.SecureMessagingFixtures;
using static nMRTD.Tests.Helpers.TestData;

namespace nMRTD.Tests;

/// <summary>Unwrapping of protected responses, for 3DES (<c>aes = false</c>) and AES (<c>aes = true</c>).</summary>
public class SecureMessagingTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ValidProtectedResponseUnwraps(bool aes)
    {
        var r = NewWrapper(aes).Unwrap(Protected(aes, 1, [1, 2, 3]));
        Assert.Equal([1, 2, 3], r.Data);
        Assert.Equal(0x9000, r.Sw & 0xFFFF);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void TamperedCiphertextFailsOnMacBeforeDecrypting(bool aes)
    {
        byte[] b = Protected(aes, 1, [1, 2, 3]).GetBytes();
        b[3 + (aes ? 15 : 7)] ^= 1;
        var e = Assert.ThrowsAny<InvalidOperationException>(() => NewWrapper(aes).Unwrap(new ResponseApdu(b)));
        Assert.Equal("Invalid MAC", e.Message);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void TamperedMacRejected(bool aes)
    {
        byte[] b = Protected(aes, 1, [1, 2, 3]).GetBytes();
        b[^3] ^= 1;
        var e = Assert.ThrowsAny<InvalidOperationException>(() => NewWrapper(aes).Unwrap(new ResponseApdu(b)));
        Assert.Equal("Invalid MAC", e.Message);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void UnknownDataObjectSkippedAsAWhole(bool aes)
    {
        var r = NewWrapper(aes).Unwrap(Protected(aes, 1, [1, 2, 3], Hex("AA 0A 8E 08 00 00 00 00 00 00 00 00")));
        Assert.Equal([1, 2, 3], r.Data);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void DataAfterDo8ERejected(bool aes)
    {
        byte[] b = Protected(aes, 1, [1, 2, 3]).GetBytes();
        byte[] x = new byte[b.Length + 2];
        Array.Copy(b, x, b.Length - 2);
        x[b.Length - 2] = 0x99;
        x[b.Length - 1] = 0;
        x[^2] = 0x90;
        x[^1] = 0;
        Assert.ThrowsAny<InvalidOperationException>(() => NewWrapper(aes).Unwrap(new ResponseApdu(x)));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void BadDo87LengthRejected(bool aes)
    {
        byte[] b = Protected(aes, 1, [1, 2, 3]).GetBytes();
        b[1] = 0x7F;
        Assert.ThrowsAny<InvalidOperationException>(() => NewWrapper(aes).Unwrap(new ResponseApdu(b)));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ReplayedResponseRejected(bool aes)
    {
        var w = NewWrapper(aes);
        var resp = Protected(aes, 1, [1, 2, 3]);
        w.Unwrap(resp);
        Assert.ThrowsAny<InvalidOperationException>(() => w.Unwrap(resp));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ResponseForWrongSscRejected(bool aes) =>
        Assert.ThrowsAny<InvalidOperationException>(() => NewWrapper(aes).Unwrap(Protected(aes, 2, [1, 2, 3])));

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void MissingDo8ERejected(bool aes)
    {
        byte[] b = Protected(aes, 1, [1, 2, 3]).GetBytes();
        byte[] x = new byte[b.Length - 10];
        Array.Copy(b, x, b.Length - 12);
        x[^2] = 0x90;
        x[^1] = 0;
        var e = Assert.ThrowsAny<InvalidOperationException>(() => NewWrapper(aes).Unwrap(new ResponseApdu(x)));
        Assert.Equal("Invalid MAC", e.Message);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void NoDo87StatusWordOnly(bool aes) =>
        Assert.Empty(NewWrapper(aes).Unwrap(Protected(aes, 1, [])).Data);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void LongResponseUsesLongFormLength(bool aes)
    {
        byte[] d = Enumerable.Range(0, 300).Select(i => (byte)i).ToArray();
        Assert.Equal(d, NewWrapper(aes).Unwrap(Protected(aes, 1, d)).Data);
    }

    [Fact]
    public void AesFullLengthCmacAccepted() =>
        Assert.Equal([1, 2, 3], NewWrapper(true).Unwrap(Protected(true, 1, [1, 2, 3], null, 16)).Data);

    [Fact]
    public void AesTamperedFullLengthCmacRejected()
    {
        byte[] b = Protected(true, 1, [1, 2, 3], null, 16).GetBytes();
        b[^3] ^= 1;
        Assert.ThrowsAny<InvalidOperationException>(() => NewWrapper(true).Unwrap(new ResponseApdu(b)));
    }

    [Fact]
    public void DesWrapThenUnwrapWithSsc2()
    {
        var w = NewWrapper(false);
        w.Wrap(new CommandApdu(0x00, 0xB0, 0x00, 0x00, 256));
        Assert.Equal(Hex("0102030405060708090A"), w.Unwrap(Protected(false, 2, Hex("0102030405060708090A"))).Data);
    }
}
