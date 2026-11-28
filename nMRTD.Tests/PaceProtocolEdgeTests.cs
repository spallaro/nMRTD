using nMRTD.Lds;
using nMRTD.Protocol;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using static nMRTD.Tests.Helpers.TestData;

namespace nMRTD.Tests;

/// <summary>
/// The checks and error paths of <see cref="PaceProtocol"/>: invalid arguments of its static helpers, and each step
/// with a chip that answers wrongly, with the side (PICC or PCD) and the step the error is reported with.
/// </summary>
public class PaceProtocolEdgeTests
{
    private static readonly ECDomainParameters Ec = BrainpoolP256r1;
    private const string EcAesOid = SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128;
    private const string EcCamOid = SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_128;

    // ---- Static helpers ----

    [Theory]
    [InlineData("L898902C<", "6908", "940623", "date of birth")]
    [InlineData("L898902C<", "690806", "9406230", "date of expiry")]
    [InlineData(null, "690806", "940623", "document number")]
    public void MrzKeyWithMalformedFieldsIsRejected(string? documentNumber, string dateOfBirth, string dateOfExpiry, string field)
    {
        var e = Assert.Throws<ArgumentException>(() => PaceProtocol.ComputeKeySeedForPace(new StubBacKey(documentNumber!, dateOfBirth, dateOfExpiry)));

        Assert.Contains(field, e.Message);
    }

    [Fact]
    public void OtherAccessKeysAreUsedAsTheyAre() =>
        Assert.Equal([1, 2, 3], PaceProtocol.ComputeKeySeedForPace(new StubAccessKey([1, 2, 3])));

    [Fact]
    public void CanKeySeedDependsOnTheCan()
    {
        Assert.Equal(PaceProtocol.ComputeKeySeedForPace("123456"), PaceProtocol.ComputeKeySeedForPace("123456"));
        Assert.NotEqual(PaceProtocol.ComputeKeySeedForPace("123456"), PaceProtocol.ComputeKeySeedForPace("654321"));
    }

    [Fact]
    public void ImDhWithGeneratorOneIsRejected() =>
        Assert.Throws<ArgumentException>(() => PaceProtocol.MapNonceImWithDH(new byte[16], new byte[16], "AES", new DHParameters(DhP, BigInteger.One, DhQ)));

    [Fact]
    public void PseudoRandomFunctionRejectsMissingOrWrongSizedNoncesAndUnknownCiphers()
    {
        Assert.Throws<ArgumentException>(() => PaceProtocol.PseudoRandomFunction(null!, new byte[16], DhP, "AES"));
        Assert.Contains("Unknown length 64", Assert.Throws<ArgumentException>(() => PaceProtocol.PseudoRandomFunction(new byte[8], new byte[16], DhP, "AES")).Message);
        Assert.Contains("Unsupported cipher", Assert.Throws<ArgumentException>(() => PaceProtocol.PseudoRandomFunction(new byte[16], new byte[16], DhP, "Twofish")).Message);
    }

    /// <summary>The point encoding of the integrated mapping needs p = 3 (mod 4); NIST P-224 has p = 1 (mod 4).</summary>
    [Fact]
    public void IcartPointEncodingNeedsPrimeThreeModFour() =>
        Assert.Throws<ArgumentException>(() => PaceProtocol.IcartPointEncode(BigInteger.Two, P224()));

    private static ECDomainParameters P224()
    {
        var x9 = Org.BouncyCastle.Asn1.X9.ECNamedCurveTable.GetByName("P-224");
        return new ECDomainParameters(x9.Curve, x9.G, x9.N, x9.H);
    }

    [Fact]
    public void PublicKeysOtherThanDhAndEcAreRejected()
    {
        var rsa = (RsaKeyParameters)KeyPairs.Rsa(1024).Public;

        Assert.Throws<ArgumentException>(() => PaceProtocol.EncodePublicKeyDataObject(EcAesOid, rsa));
        Assert.Throws<ArgumentException>(() => PaceProtocol.EncodePublicKeyForSmartCard(rsa));
        Assert.Throws<ArgumentException>(() => PaceProtocol.DecodePublicKeyFromSmartCard([0x04], "not domain parameters"));
    }

    // ---- Key derivation and consistency (PCD side, before anything is sent) ----

    [Fact]
    public void NoWrapperBeforePace() => Assert.Null(Pace(new FakeCard(_ => [0x90, 0x00])).Wrapper);

    [Fact]
    public void ObjectIdentifierThatIsNotPaceIsAPcdSideError()
    {
        var card = new FakeCard(_ => [0x90, 0x00]);

        var e = Assert.Throws<CardServiceProtocolException>(() => Pace(card).DoPace(PaceKeySpec.CreateCanKey("123456"), SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128, Ec, null));

        Assert.StartsWith("PCD side error in key derivation step", e.Message);
    }

    [Theory]
    [InlineData(EcAesOid, false)]
    [InlineData(SecurityInfo.ID_PACE_DH_GM_3DES_CBC_CBC, true)]
    public void DomainParametersOfTheOtherAgreementAreRejectedBeforeSending(string oid, bool ec)
    {
        int commands = 0;
        var card = new FakeCard(_ => { commands++; return [0x90, 0x00]; });

        var e = Assert.Throws<CardServiceProtocolException>(() => Pace(card).DoPace(PaceKeySpec.CreateCanKey("123456"), oid, ec ? Ec : DhWithQ, null));

        Assert.IsType<ArgumentException>(e.InnerException);
        Assert.Equal(0, commands);
    }

    // ---- Step 1 ----

    [Fact]
    public void Step1ResponseWithoutEncryptedNonceIsAPiccSideError()
    {
        var card = new FakeCard(_ => Hex("7C03810100 9000"));

        var e = Assert.Throws<CardServiceProtocolException>(() => Pace(card).DoPaceStep1(StaticKey(EcAesOid), "AES"));

        Assert.StartsWith("PICC side exception in tranceiving nonce step", e.Message);
        Assert.Equal(1, e.Step);
    }

    [Fact]
    public void Step1NonceThatIsNotWholeBlocksIsAnError()
    {
        var card = new FakeCard(_ => [0x7C, 0x11, 0x80, 0x0F, .. new byte[15], 0x90, 0x00]);

        var e = Assert.Throws<CardServiceProtocolException>(() => Pace(card).DoPaceStep1(StaticKey(EcAesOid), "AES"));

        Assert.Equal(1, e.Step);
        Assert.IsAssignableFrom<CryptoException>(e.InnerException);
    }

    // ---- Step 2 ----

    [Fact]
    public void Step2RefusedByTheChipIsAPiccSideError()
    {
        var card = new FakeCard(_ => [0x69, 0x82]);
#pragma warning disable CS0618 // The overload without the key length is tested too.
        var e = Assert.Throws<CardServiceProtocolException>(() =>
            Pace(card).DoPaceStep2(PACEInfo.MappingType.GM, "ECDH", Ec, new byte[16], "AES"));
#pragma warning restore CS0618

        Assert.StartsWith("PICC side exception in mapping nonce step", e.Message);
        Assert.Equal(2, e.Step);
    }

    [Fact]
    public void UnknownMappingTypeIsRejected() =>
        Assert.Equal(2, Assert.Throws<CardServiceProtocolException>(() =>
            Pace(new FakeCard(_ => [0x90, 0x00])).DoPaceStep2((PACEInfo.MappingType)99, "ECDH", Ec, new byte[16], "AES", 128)).Step);

    [Fact]
    public void ImWithAWrongNonceOrKeyLengthIsRejected()
    {
        PaceProtocol pace = Pace(new FakeCard(_ => [0x90, 0x00]));

        Assert.Contains("unexpected nonce length 80", Assert.Throws<CardServiceProtocolException>(() => pace.DoPaceStep2Im("DH", DhWithQ, new byte[10], "AES", 128)).Message);
        Assert.Contains("unsupported key length 100", Assert.Throws<CardServiceProtocolException>(() => pace.DoPaceStep2Im("DH", DhWithQ, new byte[16], "AES", 100)).Message);
    }

    /// <summary>Without a key length, it is 128 bits for 3DES and the nonce length for AES.</summary>
    [Theory]
    [InlineData("AES")]
    [InlineData("DESede")]
    public void ImWithDhMapsTheNonce(string cipher)
    {
#pragma warning disable CS0618 // The overload without the key length is tested too.
        PACEIMMappingResult result = Pace(new FakeCard(_ => Hex("7C00 9000"))).DoPaceStep2Im("DH", DhWithQ, new byte[16], cipher);
#pragma warning restore CS0618

        var mapped = Assert.IsType<DHParameters>(result.EphemeralParameters);
        Assert.Equal(DhQ, mapped.Q);
        Assert.Equal(16, result.GetPcdNonce()!.Length);
    }

    [Fact]
    public void ImRefusedByTheChipIsAPiccSideError() =>
        Assert.StartsWith("PICC side exception in mapping nonce step",
            Assert.Throws<CardServiceProtocolException>(() => Pace(new FakeCard(_ => [0x69, 0x82])).DoPaceStep2Im("DH", DhWithQ, new byte[16], "AES", 128)).Message);

    [Fact]
    public void ImDhWithoutSubgroupOrderIsAPcdSideError() =>
        Assert.StartsWith("PCD side error in mapping nonce step",
            Assert.Throws<CardServiceProtocolException>(() => Pace(new FakeCard(_ => Hex("7C00 9000"))).DoPaceStep2Im("DH", DhNoQ, new byte[16], "AES", 128)).Message);

    // ---- Step 3 ----

    [Fact]
    public void Step3WithParametersOfTheOtherAgreementIsAPcdSideError()
    {
        PaceProtocol pace = Pace(new FakeCard(_ => [0x90, 0x00]));
        AsymmetricCipherKeyPair dh = GenerateDh();

        Assert.Equal(3, Assert.Throws<CardServiceProtocolException>(() => pace.DoPaceStep3GenerateKeyPair("ECDH", DhWithQ)).Step);
        Assert.Equal(3, Assert.Throws<CardServiceProtocolException>(() => pace.DoPaceStep3GenerateKeyPair("DH", Ec)).Step);
        Assert.Equal(3, Assert.Throws<CardServiceProtocolException>(() => pace.DoPaceStep3KeyAgreement("ECDH", dh.Private, dh.Public)).Step);
    }

    // ---- Step 4 ----

    [Fact]
    public void Step4TokenUnderAnotherTagIsStillChecked()
    {
        (AsymmetricCipherKeyPair pcd, AsymmetricCipherKeyPair picc, KeyParameter macKey) = Step4Keys();
        byte[] token = PaceProtocol.GenerateAuthenticationToken(EcAesOid, macKey, pcd.Public);
        var card = new FakeCard(_ => [.. TlvUtil.WrapDO(0x7C, TlvUtil.WrapDO(0x87, token)), 0x90, 0x00]);

        Assert.Null(Pace(card).DoPaceStep4(EcAesOid, PACEInfo.MappingType.GM, pcd, picc.Public, macKey));
    }

    [Fact]
    public void Step4CamDataUnderAnotherTagIsReturned()
    {
        (AsymmetricCipherKeyPair pcd, AsymmetricCipherKeyPair picc, KeyParameter macKey) = Step4Keys();
        byte[] token = PaceProtocol.GenerateAuthenticationToken(EcCamOid, macKey, pcd.Public);
        var card = new FakeCard(_ => [.. TlvUtil.WrapDO(0x7C, [.. TlvUtil.WrapDO(0x86, token), .. TlvUtil.WrapDO(0x8B, [1, 2, 3])]), 0x90, 0x00]);

        Assert.Equal([1, 2, 3], Pace(card).DoPaceStep4(EcCamOid, PACEInfo.MappingType.CAM, pcd, picc.Public, macKey));
    }

    [Fact]
    public void Step4CamWithoutChipAuthenticationDataReturnsNull()
    {
        (AsymmetricCipherKeyPair pcd, AsymmetricCipherKeyPair picc, KeyParameter macKey) = Step4Keys();
        byte[] token = PaceProtocol.GenerateAuthenticationToken(EcCamOid, macKey, pcd.Public);
        var card = new FakeCard(_ => [.. TlvUtil.WrapDO(0x7C, TlvUtil.WrapDO(0x86, token)), 0x90, 0x00]);

        Assert.Null(Pace(card).DoPaceStep4(EcCamOid, PACEInfo.MappingType.CAM, pcd, picc.Public, macKey));
    }

    [Fact]
    public void Step4TokenThatCannotBeComputedIsAPcdSideError()
    {
        (AsymmetricCipherKeyPair pcd, AsymmetricCipherKeyPair picc, KeyParameter macKey) = Step4Keys();

        var e = Assert.Throws<CardServiceProtocolException>(() =>
            Pace(new FakeCard(_ => [0x90, 0x00])).DoPaceStep4("1.2.3.4", PACEInfo.MappingType.GM, pcd, picc.Public, macKey));

        Assert.StartsWith("PCD side exception in authentication token generation step", e.Message);
        Assert.Equal(4, e.Step);
    }

    // ---- Helpers ----

    private static PaceProtocol Pace(CardService card) => new(new PACEAPDUSender(new SecureMessagingAPDUSender(card)), null, 256, true);

    private static PaceSecretKeySpec StaticKey(string oid) => PaceProtocol.DeriveStaticPaceKey(PaceKeySpec.CreateCanKey("123456"), oid);

    private static (AsymmetricCipherKeyPair Pcd, AsymmetricCipherKeyPair Picc, KeyParameter MacKey) Step4Keys() =>
        (GenerateEc(), GenerateEc(), new KeyParameter(new byte[16]));

    private static AsymmetricCipherKeyPair GenerateEc()
    {
        var generator = new ECKeyPairGenerator();
        generator.Init(new ECKeyGenerationParameters(Ec, new SecureRandom()));
        return generator.GenerateKeyPair();
    }

    private static AsymmetricCipherKeyPair GenerateDh()
    {
        var generator = new DHKeyPairGenerator();
        generator.Init(new DHKeyGenerationParameters(new SecureRandom(), DhWithQ));
        return generator.GenerateKeyPair();
    }

    private sealed class StubBacKey(string documentNumber, string dateOfBirth, string dateOfExpiry) : IBacKeySpec
    {
        public string GetAlgorithm() => "BAC";

        public byte[] GetKey() => [];

        public string GetDocumentNumber() => documentNumber;

        public string GetDateOfBirth() => dateOfBirth;

        public string GetDateOfExpiry() => dateOfExpiry;
    }

    private sealed class StubAccessKey(byte[] key) : IAccessKeySpec
    {
        public string GetAlgorithm() => "test";

        public byte[] GetKey() => key;
    }
}
