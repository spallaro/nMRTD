using System.Text;

namespace nMRTD.Tests.Jmrtd;

/// <summary>Port of JMRTD's <c>org.jmrtd.PACEKeySpecTest</c>.</summary>
public class PACEKeySpecTest
{
    [Fact]
    public void testPACEKeySpec()
    {
        string can = "12345";
        PaceKeySpec paceCANKey = PaceKeySpec.CreateCanKey(can);
        Assert.Equal("PACE", paceCANKey.GetAlgorithm());
        Assert.NotNull(paceCANKey.GetKey());
        Assert.Equal(Encoding.UTF8.GetBytes(can), paceCANKey.GetKey());
        Assert.Equal(PassportService.CanPaceKeyReference, paceCANKey.KeyReference);

        PaceKeySpec paceMRZKey = PaceKeySpec.CreateMrzKey(new BacKey("123456789", "710121", "331231"));
        Assert.Equal("PACE", paceMRZKey.GetAlgorithm());
        Assert.NotNull(paceMRZKey.GetKey());
        Assert.Equal(PassportService.MrzPaceKeyReference, paceMRZKey.KeyReference);

        PaceKeySpec pacePINKey = PaceKeySpec.CreatePinKey("0000");
        Assert.Equal("PACE", pacePINKey.GetAlgorithm());
        Assert.NotNull(pacePINKey.GetKey());
        Assert.Equal(PassportService.PinPaceKeyReference, pacePINKey.KeyReference);

        PaceKeySpec pacePUKKey = PaceKeySpec.CreatePukKey("12345678");
        Assert.Equal("PACE", pacePUKKey.GetAlgorithm());
        Assert.NotNull(pacePUKKey.GetKey());
        Assert.Equal(PassportService.PukPaceKeyReference, pacePUKKey.KeyReference);
    }

    [Fact]
    public void testPACESecretKeySpec()
    {
        string algorithm = "AES"; // ???
        byte keyRef = PassportService.CanPaceKeyReference;
        var paceSecretKeySpec = new PaceSecretKeySpec(Encoding.UTF8.GetBytes("12345"), algorithm, keyRef);
        Assert.Equal(algorithm, paceSecretKeySpec.GetAlgorithm());
        Assert.Equal(keyRef, paceSecretKeySpec.KeyReference);
    }
}
