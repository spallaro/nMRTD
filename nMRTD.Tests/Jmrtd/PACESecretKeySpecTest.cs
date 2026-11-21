using static nMRTD.Tests.Helpers.TestData;

namespace nMRTD.Tests.Jmrtd;

/// <summary>Port of JMRTD's <c>org.jmrtd.PACESecretKeySpecTest</c>.</summary>
/// <remarks>
/// ADAPTATION: nMRTD's <c>PaceSecretKeySpec</c> is not a JCA <c>SecretKeySpec</c>, so Java's
/// <c>getEncoded()</c> is <c>GetKey()</c>. Not ported:
/// <c>testUtilDeriveKeyProducesPACESecretKeySpecWithKeyReference</c>, as nMRTD's <c>Util.DeriveKey</c>
/// returns raw key bytes and has no overload taking a PACE key reference.
/// </remarks>
public class PACESecretKeySpecTest
{
    private static readonly byte[] KEY_BYTES = Hex("000102030405060708090A0B0C0D0E0F");

    [Fact]
    public void testConstructorAndAccessors()
    {
        var keySpec = new PaceSecretKeySpec(KEY_BYTES, "AES", PassportService.MrzPaceKeyReference);
        Assert.Equal(PassportService.MrzPaceKeyReference, keySpec.KeyReference);
        Assert.Equal("AES", keySpec.GetAlgorithm());
        Assert.Equal(KEY_BYTES, keySpec.GetKey());
    }

    [Fact]
    public void testOffsetLengthConstructorSlicesCorrectly()
    {
        byte[] buffer = Hex("FFFFFF000102030405060708090A0B0C0D0E0FFFFFFF");
        var keySpec = new PaceSecretKeySpec(buffer, 3, 16, "AES", PassportService.CanPaceKeyReference);
        Assert.Equal(KEY_BYTES, keySpec.GetKey());
        Assert.Equal(PassportService.CanPaceKeyReference, keySpec.KeyReference);
    }

    [Fact]
    public void testEqualsAndHashCodeReflexiveAndTypeChecks()
    {
        var keySpec = new PaceSecretKeySpec(KEY_BYTES, "AES", PassportService.MrzPaceKeyReference);
        Assert.True(keySpec.Equals(keySpec));
        Assert.False(keySpec.Equals(null));
        Assert.False(keySpec.Equals("not a key spec"));
    }

    [Fact]
    public void testEqualsAndHashCodeSameFields()
    {
        var keySpec1 = new PaceSecretKeySpec(KEY_BYTES, "AES", PassportService.MrzPaceKeyReference);
        var keySpec2 = new PaceSecretKeySpec((byte[])KEY_BYTES.Clone(), "AES", PassportService.MrzPaceKeyReference);
        Assert.Equal(keySpec1, keySpec2);
        Assert.Equal(keySpec1.GetHashCode(), keySpec2.GetHashCode());
    }

    /*
     * The whole point of this subclass is to distinguish PACE keys of different origin
     * (MRZ vs CAN vs PIN vs PUK) that could otherwise carry identical key bytes -- so a
     * differing keyReference alone must make two otherwise-identical specs unequal.
     */
    [Fact]
    public void testEqualsDistinguishesKeyReference()
    {
        var mrzKeySpec = new PaceSecretKeySpec(KEY_BYTES, "AES", PassportService.MrzPaceKeyReference);
        var canKeySpec = new PaceSecretKeySpec((byte[])KEY_BYTES.Clone(), "AES", PassportService.CanPaceKeyReference);
        Assert.NotEqual(mrzKeySpec, canKeySpec);
    }

    [Fact]
    public void testEqualsDistinguishesKeyBytes()
    {
        var keySpec1 = new PaceSecretKeySpec(KEY_BYTES, "AES", PassportService.MrzPaceKeyReference);
        var otherKeyBytes = (byte[])KEY_BYTES.Clone();
        otherKeyBytes[0] ^= 0x01;
        var keySpec2 = new PaceSecretKeySpec(otherKeyBytes, "AES", PassportService.MrzPaceKeyReference);
        Assert.NotEqual(keySpec1, keySpec2);
    }
}
