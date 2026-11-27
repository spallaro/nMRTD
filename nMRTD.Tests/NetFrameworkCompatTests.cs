#if NETFRAMEWORK

using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace nMRTD.Tests;

/// <summary>
/// The stand-ins in <c>nMRTD.Compat</c> for the .NET 6+ base library members that .NET Framework lacks: they must
/// behave as the originals do, including their errors. Only compiled for .NET Framework.
/// </summary>
public class NetFrameworkCompatTests
{
    [Fact]
    public void ThrowIfNullNamesTheArgument()
    {
        object? value = null;
        ArgumentNullException e = Assert.Throws<ArgumentNullException>(() => ArgumentNullException.ThrowIfNull(value));
        Assert.Equal(nameof(value), e.ParamName);
        ArgumentNullException.ThrowIfNull(new object());
    }

    [Fact]
    public void HexStringsRoundTrip()
    {
        byte[] bytes = [0x00, 0x0A, 0x7F, 0x80, 0xFF];
        Assert.Equal("000A7F80FF", Convert.ToHexString(bytes));
        Assert.Equal(bytes, Convert.FromHexString("000a7F80fF"));
        Assert.Empty(Convert.FromHexString(""));
    }

    [Theory]
    [InlineData("ABC")]
    [InlineData("0G")]
    [InlineData("-1")]
    public void InvalidHexStringsAreRejected(string s)
    {
        Assert.Throws<FormatException>(() => Convert.FromHexString(s));
    }

    [Fact]
    public void Latin1MapsEveryByteToTheSameCodePoint()
    {
        byte[] bytes = [0x41, 0xC9, 0xFF];
        Assert.Equal("AÉÿ", Encoding.Latin1.GetString(bytes));
        Assert.Equal(bytes, Encoding.Latin1.GetBytes("AÉÿ"));
    }

    [Fact]
    public void FillWritesTheWholeSpan()
    {
        byte[] buffer = new byte[64];
        RandomNumberGenerator.Fill(buffer.AsSpan(8, 48));
        Assert.All(buffer.Take(8), b => Assert.Equal(0, b));
        Assert.All(buffer.Skip(56), b => Assert.Equal(0, b));
        Assert.Contains(buffer.Skip(8).Take(48), b => b != 0);
    }

    [Fact]
    public void StreamWriteWritesTheSpan()
    {
        using var stream = new MemoryStream();
        stream.Write(new ReadOnlySpan<byte>([1, 2, 3]));
        Assert.Equal([1, 2, 3], stream.ToArray());
    }

    [Fact]
    public void AddBytesDependsOnTheBytes()
    {
        var a = new HashCode();
        a.AddBytes([1, 2, 3]);
        var b = new HashCode();
        b.AddBytes([1, 2, 3]);
        Assert.Equal(a.ToHashCode(), b.ToHashCode());
    }

    [Theory]
    [InlineData(StringComparison.Ordinal, false)]
    [InlineData(StringComparison.OrdinalIgnoreCase, true)]
    [InlineData(StringComparison.InvariantCulture, false)]
    [InlineData(StringComparison.InvariantCultureIgnoreCase, true)]
    [InlineData(StringComparison.CurrentCulture, false)]
    [InlineData(StringComparison.CurrentCultureIgnoreCase, true)]
    public void GetHashCodeFollowsTheComparison(StringComparison comparison, bool ignoresCase)
    {
        Assert.Equal("abc".GetHashCode(comparison), "abc".GetHashCode(comparison));
        Assert.Equal(ignoresCase, "abc".GetHashCode(comparison) == "ABC".GetHashCode(comparison));
    }

    [Fact]
    public void StartsWithAChar()
    {
        Assert.True("<<A".StartsWith('<'));
        Assert.False("A<<".StartsWith('<'));
        Assert.False("".StartsWith('<'));
    }

    [Fact]
    public void SplitOnAString()
    {
        Assert.Equal(["A", "B", "", "C"], "A<<B<<<<C".Split("<<"));
        Assert.Equal(["A", "B", "C"], "A<<B<<<<C".Split("<<", StringSplitOptions.RemoveEmptyEntries));
    }

    [Fact]
    public void BigIntegerToByteArrayMatchesTheModernOverload()
    {
        var value = new BigInteger(0x80FF); // two's complement little endian: FF 80 00
        Assert.Equal([0xFF, 0x80, 0x00], value.ToByteArray(isUnsigned: false, isBigEndian: false));
        Assert.Equal([0x00, 0x80, 0xFF], value.ToByteArray(isUnsigned: false, isBigEndian: true));
        Assert.Equal([0xFF, 0x80], value.ToByteArray(isUnsigned: true, isBigEndian: false));
        Assert.Equal([0x80, 0xFF], value.ToByteArray(isUnsigned: true, isBigEndian: true));
        Assert.Equal([0x00], BigInteger.Zero.ToByteArray(isUnsigned: true, isBigEndian: true));
        Assert.Throws<OverflowException>(() => BigInteger.MinusOne.ToByteArray(isUnsigned: true, isBigEndian: true));
    }

    [Fact]
    public void FixedTimeEqualsComparesContentAndLength()
    {
        Assert.True(CryptographicOperations.FixedTimeEquals([1, 2, 3], [1, 2, 3]));
        Assert.False(CryptographicOperations.FixedTimeEquals([1, 2, 3], [1, 2, 4]));
        Assert.False(CryptographicOperations.FixedTimeEquals([1, 2, 3], [1, 2]));
        Assert.True(CryptographicOperations.FixedTimeEquals([], []));
    }
}

#endif
