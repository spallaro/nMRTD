using nMRTD.Tests.Helpers;
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

    /// <summary>UndoWrap restores the state from before Wrap: wrapping the same command again gives the same bytes
    /// (JMRTD 0.8.11, DESedeSecureMessagingWrapperTest.testUndoWrapRestoresState).</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void UndoWrapRestoresTheState(bool aes)
    {
        var command = new CommandApdu(0x00, 0xB0, 0x00, 0x00, 256);
        var wrapper = NewWrapper(aes);
        byte[] first = wrapper.Wrap(command).GetBytes();

        wrapper.UndoWrap();

        Assert.Equal(0L, wrapper.SendSequenceCounter);
        Assert.Equal(first, wrapper.Wrap(command).GetBytes());
        Assert.Equal(1L, wrapper.SendSequenceCounter);
    }

    /// <summary>UndoWrap only right after Wrap: not on a fresh wrapper, not twice, not after Unwrap
    /// (JMRTD 0.8.11, DESedeSecureMessagingWrapperTest.testUndoWrapOnlyRightAfterWrap).</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void UndoWrapOnlyRightAfterWrap(bool aes)
    {
        var command = new CommandApdu(0x00, 0xB0, 0x00, 0x00, 256);

        var fresh = NewWrapper(aes);
        Assert.Throws<InvalidOperationException>(fresh.UndoWrap);
        Assert.Equal(0L, fresh.SendSequenceCounter);

        var twice = NewWrapper(aes);
        twice.Wrap(command);
        twice.UndoWrap();
        Assert.Throws<InvalidOperationException>(twice.UndoWrap);
        Assert.Equal(0L, twice.SendSequenceCounter);

        var unwrapped = NewWrapper(aes);
        unwrapped.Wrap(command);
        unwrapped.Unwrap(Protected(aes, 2, [1]));
        Assert.Throws<InvalidOperationException>(unwrapped.UndoWrap);
        Assert.Equal(2L, unwrapped.SendSequenceCounter);
    }

    /// <summary>A plain 67xx under secure messaging is returned and the wrapped command taken back, so the next
    /// command has the send sequence counter the chip expects (JMRTD 0.8.11,
    /// SecureMessagingAPDUSenderTest.takesBackCommandAnsweredWithPlainWrongLength).</summary>
    [Theory]
    [InlineData(false, 0x6700)]
    [InlineData(false, 0x6701)]
    [InlineData(true, 0x6700)]
    public void PlainWrongLengthTakesTheCommandBack(bool aes, int sw)
    {
        var wrapper = NewWrapper(aes);
        var sender = new nMRTD.Protocol.SecureMessagingAPDUSender(
            new ScriptedCardService(new ResponseApdu([(byte)(sw >> 8), (byte)sw])));

        ResponseApdu response = sender.Transmit(wrapper, new CommandApdu(0x00, 0xB0, 0x00, 0x00, 65536));

        Assert.Equal(sw, response.Sw & 0xFFFF);
        Assert.Equal(0L, wrapper.SendSequenceCounter);
    }

    /// <summary>A plain status word that only matched the old 67xx mask (6Fxx) is an error, not a wrong length.</summary>
    [Fact]
    public void PlainUnknownErrorIsNotAWrongLength()
    {
        var wrapper = NewWrapper(false);
        var sender = new nMRTD.Protocol.SecureMessagingAPDUSender(new ScriptedCardService(new ResponseApdu([0x6F, 0x00])));

        var e = Assert.Throws<CardServiceException>(() => sender.Transmit(wrapper, new CommandApdu(0x00, 0xB0, 0x00, 0x00, 256)));

        Assert.Equal(0x6F00, e.Sw & 0xFFFF);
    }
}
