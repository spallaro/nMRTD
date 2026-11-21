using nMRTD.Lds;
using nMRTD.Protocol;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using static nMRTD.Tests.Helpers.TestData;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace nMRTD.Tests.Jmrtd.Protocol;

public partial class PACEProtocolTest
{
    [Fact]
    public void testDutch2014PassportWithGMAndECDH()
    {
        string oid = "0.4.0.127.0.7.2.2.4.2.4"; // id-PACE-ECDH-GM-AES-CBC-CMAC-256
        Assert.Equal(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256, oid);
        int version = 2;
        int paramId = 14;
        var paceInfo = new PACEInfo(oid, version, paramId);

        string cipherAlg = PACEInfo.ToCipherAlgorithm(oid);
        Assert.Equal("AES", cipherAlg);
        string digestAlg = PACEInfo.ToDigestAlgorithm(oid);
        Assert.Equal("SHA-256", digestAlg);
        int keyLength = PACEInfo.ToKeyLength(oid);
        Assert.Equal(256, keyLength);
        string agreementAlg = PACEInfo.ToKeyAgreementAlgorithm(oid);
        Assert.Equal("ECDH", agreementAlg);

        object parameters = PACEInfo.ToParameterSpec(paceInfo.GetParameterId()!);
        ECDomainParameters ecParams = Assert.IsAssignableFrom<ECDomainParameters>(parameters);
        BigInteger p = Util.GetPrime(ecParams);
        Assert.NotNull(p);

        byte[] nonceS = Hex("1BBF56756A0C1E74AE3524685D970724");
        ECPrivateKeyParameters pcdMappingPrivateKey = EcPrivateKey("CFE032E195BC18D1B6C7F5C137CF9FDA52ECACF04A066839022AC1AF686AB3AA2102E9C918624262", ecParams);
        byte[] piccMappingEncodedPublicKey = Hex("04"
            + "AED562971B07877839B064B39132394E79CEF2BED81D8907B539030FB85D1D45EEA9788F28280629"
            + "53C25E414F44CA391C633FFA9983C0EC05C895636A4B2B44B446848FE57E9F8587B0202CFF4BE70E");

        AsymmetricKeyParameter piccMappingPublicKey = PaceProtocol.DecodePublicKeyFromSmartCard(piccMappingEncodedPublicKey, parameters);

        var mappingAgreement = new PACEGMWithECDHAgreement();
        mappingAgreement.Init(pcdMappingPrivateKey);
        ECPoint mappingSharedSecret = mappingAgreement.DoPhase((ECPublicKeyParameters)piccMappingPublicKey);
        ECDomainParameters ephemeralParams = PaceProtocol.MapNonceGMWithECDH(nonceS, mappingSharedSecret, ecParams);

        AsymmetricCipherKeyPair kp = Helpers.KeyPairs.EC(ephemeralParams);
        AsymmetricKeyParameter pcdPrivateKey = kp.Private;
        var keyAgreement = new ECDHBasicAgreement();
        keyAgreement.Init(pcdPrivateKey);
    }

    [Fact]
    public void testPseudoRandomFunctionWorkedExampleH1()
    {
        var parameters = (ECDomainParameters)PACEInfo.ToParameterSpec(PACEInfo.PARAM_ID_ECP_BRAINPOOL_P256_R1);
        BigInteger p = Util.GetPrime(parameters);
        byte[] s = Hex("2923BE84 E16CD6AE 529049F1 F1BBE9EB");
        byte[] t = Hex("5DD4CBFC 96F5453B 130D890A 1CDBAE32");
        byte[] expectedX = Hex("A2F8FF2D F50E52C6 599F386A DCB595D2" + "29F6A167 ADE2BE5F 2C3296AD D5B7430E");
        byte[] x = PaceProtocol.PseudoRandomFunction(s, t, p, "AES");
        Assert.Equal(expectedX, x);
    }

    [Fact]
    public void testSpecSamplePACEIMWithECDHPointEncodingExampleH1()
    {
        byte[] expectedMappedGeneratorX = Hex("8E82D315 59ED0FDE 92A4D049 8ADD3C23"
            + "BABA94FB 77691E31 E90AEA77 FB17D427");
        byte[] expectedMappedGeneratorY = Hex("4C1AE14B D0C3DBAC 0C871B7F 36081693"
            + "64437CA3 0AC243A0 89D3F266 C1E60FAD");
        var staticParameters = (ECDomainParameters)PACEInfo.ToParameterSpec(PACEInfo.PARAM_ID_ECP_BRAINPOOL_P256_R1);
        byte[] pseudRandomFunctionResult = Hex("A2F8FF2D F50E52C6 599F386A DCB595D2"
            + "29F6A167 ADE2BE5F 2C3296AD D5B7430E");

        ECPoint mappedGenerator = PaceProtocol.IcartPointEncode(Util.Os2i(pseudRandomFunctionResult), staticParameters).Normalize();
        Assert.Equal(Util.Os2i(expectedMappedGeneratorX), mappedGenerator.AffineXCoord.ToBigInteger());
        Assert.Equal(Util.Os2i(expectedMappedGeneratorY), mappedGenerator.AffineYCoord.ToBigInteger());
    }

    [Fact]
    public void testPACEIMWithDHWorkedExampleH2()
    {
        var p = new BigInteger(("B10B8F96 A080E01D DE92DE5E AE5D54EC"
            + "52C99FBC FB06A3C6 9A6A9DCA 52D23B61"
            + "6073E286 75A23D18 9838EF1E 2EE652C0"
            + "13ECB4AE A9061123 24975C3C D49B83BF"
            + "ACCBDD7D 90C4BD70 98488E9C 219A7372"
            + "4EFFD6FA E5644738 FAA31A4F F55BCCC0"
            + "A151AF5F 0DC8B4BD 45BF37DF 365C1A65"
            + "E68CFDA7 6D4DA708 DF1FB2BC 2E4A4371").Replace(" ", ""), 16);
        byte[] s = Hex("FA5B7E3E 49753A0D B9178B7B 9BD898C8");
        byte[] t = Hex("B3A6DB3C 870C3E99 245E0D1C 06B747DE");
        byte[] expectedX = Hex("A0C7C50C 002061A5 1CC87D25 4EF38068"
            + "607417B6 EE1B3647 3CFB800D 2D2E5FA2"
            + " B6980F01 105D24FA B22ACD1B FA5C8A4C"
            + "093ECDFA FE6D7125 D42A843E 33860383"
            + "5CF19AFA FF75EFE2 1DC5F6AA 1F9AE46C"
            + "25087E73 68166FB0 8C1E4627 AFED7D93"
            + "570417B7 90FF7F74 7E57F432 B04E1236"
            + "819E0DFE F5B6E77C A4999925 328182D2");
        byte[] x = PaceProtocol.PseudoRandomFunction(s, t, p, "AES");
        Assert.Equal(expectedX, x);

        BigInteger expectedMappedGenerator = Util.Os2i(Hex("1D7D767F 11E333BC D6DBAEF4 0E799E7A"
            + "926B9697 3550656F F3C83072 6D118D61"
            + "C276CDCC 61D475CF 03A98E0C 0E79CAEB"
            + "A5BE2557 8BD4551D 0B109032 36F0B0F9"
            + "76852FA7 8EEA14EA 0ACA87D1 E91F688F"
            + "E0DFF897 BBE35A47 2621D343 564B262F"
            + "34223AE8 FC59B664 BFEDFA2B FE7516CA"
            + "5510A6BB B633D517 EC25D4E0 BBAA16C2"));
        BigInteger g = Util.Os2i(Hex("A4D1CBD5 C3FD3412 6765A442 EFB99905"
            + "F8104DD2 58AC507F D6406CFF 14266D31"
            + "266FEA1E 5C41564B 777E690F 5504F213"
            + "160217B4 B01B886A 5E91547F 9E2749F4"
            + "D7FBD7D3 B9A92EE1 909D0D22 63F80A76"
            + "A6A24C08 7A091F53 1DBF0A01 69B6A28A"
            + "D662A4D1 8E73AFA3 2D779D59 18D08BC8"
            + "858F4DCE F97C2A24 855E6EEB 22B3B2E5"));
        BigInteger q = Util.Os2i(Hex("F518AA87 81A8DF27 8ABA4E7D 64B7CB9D"
            + "49462353"));

        var parameters = new DHParameters(p, g, q); // Java: DHCParameterSpec(p, g, q)
        DHParameters mappedParams = PaceProtocol.MapNonceImWithDH(s, t, "AES", parameters);
        BigInteger mappedGenerator = mappedParams.G;
        Assert.Equal(expectedMappedGenerator, mappedGenerator);
        Assert.Equal(q, mappedParams.Q); // Java: mappedParams instanceof DHCParameterSpec, with q
        Assert.Equal(BigInteger.One, mappedGenerator.ModPow(q, p));
    }
}
