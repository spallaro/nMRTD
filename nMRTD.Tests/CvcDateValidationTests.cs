using nMRTD.Cert;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using static nMRTD.Tests.Helpers.TestData;

namespace nMRTD.Tests;

/// <summary>Validation of the unpacked-BCD dates (tags 5F25, 5F24) of card verifiable certificates.</summary>
public class CvcDateValidationTests
{
    private static byte[] RealCvca() =>
        File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "certs", "orig", "certCVCA_orig.cvcert"));

    /// <summary>Offset of the 6 date digits after <c>5F25 06</c> in an encoded certificate.</summary>
    private static int EffectiveDateOffset(byte[] certificate)
    {
        int index = certificate.AsSpan().IndexOf(Hex("5F25 06"));
        Assert.True(index >= 0);
        return index + 3;
    }

    [Fact]
    public void NonDigitByteInADateIsRejected()
    {
        byte[] certificate = RealCvca();
        certificate[EffectiveDateOffset(certificate) + 1] = 0x0A;

        var e = Assert.Throws<IOException>(() => CardVerifiableCertificate.Parse(certificate));
        Assert.Contains("BCD digit", e.Message);
    }

    [Fact]
    public void ImpossibleDateIsRejected()
    {
        byte[] certificate = RealCvca();
        int offset = EffectiveDateOffset(certificate);
        certificate[offset + 2] = 1; // month 13
        certificate[offset + 3] = 3;

        var e = Assert.Throws<IOException>(() => CardVerifiableCertificate.Parse(certificate));
        Assert.Contains("Invalid date", e.Message);
    }

    [Fact]
    public void ThreeBytePackedDateIsRejected()
    {
        // 7F21 { 7F4E { ..., 5F25 06 <6 digits>, ... }, 5F37 ... } with the effective date replaced by a
        // 3-byte packed BCD value (the format earlier versions of this port wrote).
        byte[] certificate = RealCvca();
        int offset = EffectiveDateOffset(certificate);
        byte[] packed = [0x08, 0x05, 0x19];
        byte[] shrunk = certificate[..(offset - 1)]
            .Concat(new byte[] { 0x03 }).Concat(packed)
            .Concat(certificate[(offset + 6)..]).ToArray();
        FixLength(shrunk, Hex("7F21"), -3);
        FixLength(shrunk, Hex("7F4E"), -3);

        var e = Assert.Throws<IOException>(() => CardVerifiableCertificate.Parse(shrunk));
        Assert.Contains("6-byte", e.Message);
    }

    [Fact]
    public void DatesOutsideTwoDigitYearRangeCannotBeEncoded()
    {
        var generator = new ECKeyPairGenerator();
        generator.Init(new ECKeyGenerationParameters(BrainpoolP256r1, new SecureRandom()));
        var keyPair = generator.GenerateKeyPair();
        var who = new CVCPrincipal("UT", "CVCA", "00001");
        var chat = new CVCAuthorizationTemplate(CVCAuthorizationTemplate.Role.Cvca, CVCAuthorizationTemplate.Permission.ReadAccessDg3);

        Assert.Throws<ArgumentOutOfRangeException>(() => CVCertificateBuilder.CreateCertificate(
            keyPair.Public, keyPair.Private, "SHA256withECDSA", who, who, chat, new DateOnly(1999, 12, 31), new DateOnly(2029, 1, 1)));
    }

    /// <summary>Adds <paramref name="delta"/> to the BER length that follows the first <paramref name="tag"/>.</summary>
    private static void FixLength(byte[] data, byte[] tag, int delta)
    {
        int at = data.AsSpan().IndexOf(tag) + tag.Length;
        switch (data[at])
        {
            case 0x81:
                data[at + 1] = (byte)(data[at + 1] + delta);
                break;
            case 0x82:
                int length = ((data[at + 1] << 8) | data[at + 2]) + delta;
                data[at + 1] = (byte)(length >> 8);
                data[at + 2] = (byte)length;
                break;
            default:
                data[at] = (byte)(data[at] + delta);
                break;
        }
    }
}
