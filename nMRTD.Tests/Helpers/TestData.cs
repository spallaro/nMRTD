using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace nMRTD.Tests.Helpers;

/// <summary>Shared, immutable test values and small helpers.</summary>
internal static class TestData
{
    public const string PaceEcOid = "0.4.0.127.0.7.2.2.4.2.2";
    public const string PaceDhOid = "0.4.0.127.0.7.2.2.4.1.2";

    public static readonly ECDomainParameters BrainpoolP256r1 = EcParameters("brainpoolP256r1");

    // RFC 5114 1024-bit MODP group with 160-bit prime order subgroup.
    public static readonly BigInteger DhP = new("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", 16);
    public static readonly BigInteger DhG = new("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5", 16);
    public static readonly BigInteger DhQ = new("F518AA8781A8DF278ABA4E7D64B7CB9D49462353", 16);
    public static readonly DHParameters DhWithQ = new(DhP, DhG, DhQ);
    public static readonly DHParameters DhNoQ = new(DhP, DhG);

    public static ECDomainParameters EcParameters(string curveName)
    {
        var x9 = TeleTrusTNamedCurves.GetByName(curveName);
        return new ECDomainParameters(x9.Curve, x9.G, x9.N, x9.H);
    }

    public static byte[] Hex(string s) => Convert.FromHexString(s.Replace(" ", ""));

    public static byte[] ReadAll(Stream s)
    {
        var ms = new MemoryStream();
        s.CopyTo(ms);
        return ms.ToArray();
    }

    public static void AssertContains(byte[] expected, byte[] actual, string message) =>
        Assert.True(actual.AsSpan().IndexOf(expected) >= 0, $"{message}: {Convert.ToHexString(actual)}");
}
