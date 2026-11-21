using nMRTD.Tests.Helpers;
using static nMRTD.Tests.Helpers.ChipCrypto;
using static nMRTD.Tests.Helpers.TestData;

namespace nMRTD.Tests.EndToEnd;

/// <summary>
/// Known-answer tests of the simulated chip's own primitives, against the worked examples of ICAO Doc 9303-11,
/// so that the end-to-end tests compare the library with a chip that is right by the specification.
/// </summary>
public class SimulatedChipTests
{
    private static byte[] WithoutParity(byte[] key) => key.Select(b => (byte)(b & 0xFE)).ToArray();

    /// <summary>Doc 9303-11 Appendix D.2: BAC key derivation from the MRZ.</summary>
    [Fact]
    public void BacKeysMatchTheIcaoWorkedExample()
    {
        byte[] mrz = MrzInformation("L898902C", "690806", "940623");
        Assert.Equal("L898902C<369080619406236", System.Text.Encoding.ASCII.GetString(mrz));

        byte[] seed = Sha1(mrz)[..16];
        Assert.Equal(Hex("239AB9CB282DAF66231DC5A4DF6BFBAE"), seed);
        Assert.Equal(WithoutParity(Hex("AB94FDECF2674FDFB9B391F85D7F76F2")), WithoutParity(Kdf(seed, KdfEnc, false, 128)));
        Assert.Equal(WithoutParity(Hex("7962D9ECE03D1ACD4C76089DCE131543")), WithoutParity(Kdf(seed, KdfMac, false, 128)));
    }

    /// <summary>Doc 9303-11 Appendix G.1: the PACE password key and the encrypted nonce (ECDH-GM, AES-128).</summary>
    [Fact]
    public void PacePasswordKeyAndNonceMatchTheIcaoWorkedExample()
    {
        byte[] passwordKey = Kdf(Sha1(MrzInformation("T22000129", "640812", "101031")), KdfPace, true, 128);
        Assert.Equal(Hex("89DED1B26624EC1E634C1989302849DD"), passwordKey);
        Assert.Equal(Hex("3F00C4D39D153F2B2A214A078D899B22"),
            Cbc(false, true, passwordKey, new byte[16], Hex("95A3A016522EE98D01E76CB6B98B42C3")));
    }

    [Fact]
    public void PaddingRoundTrips()
    {
        Assert.Equal(Hex("0102800000000000"), Pad([1, 2], 8));
        Assert.Equal(Hex("01020304050607088000000000000000"), Pad([1, 2, 3, 4, 5, 6, 7, 8], 8));
        Assert.Equal(new byte[] { 1, 2 }, Unpad(Pad([1, 2], 16)));
    }
}
