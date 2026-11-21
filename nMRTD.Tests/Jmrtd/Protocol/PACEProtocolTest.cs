using nMRTD.Lds;
using nMRTD.Protocol;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using static nMRTD.Tests.Helpers.TestData;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace nMRTD.Tests.Jmrtd.Protocol;

/// <summary>Port of JMRTD's <c>org.jmrtd.protocol.PACEProtocolTest</c>.</summary>
/// <remarks>
/// ADAPTATION: JCA key factories, key agreements and MACs are Bouncy Castle key parameters, agreements
/// and MACs; JCA's <c>ECParameterSpec</c>/<c>DHParameterSpec</c> are <c>ECDomainParameters</c>/
/// <c>DHParameters</c>. JMRTD's <c>PACEProtocol.updateParameterSpec</c> re-attaches the private key's
/// domain parameters to a public key; here the test keys are built on those parameters already.
/// <c>Util.DeriveKey</c> returns raw key bytes.
/// </remarks>
public partial class PACEProtocolTest
{
    [Fact]
    public void testMacs()
    {
        IMac macDESede = MacUtilities.GetMac("DESedeMac");
        IMac macAES = MacUtilities.GetMac("AESCMAC");
        Assert.NotNull(macDESede);
        Assert.NotNull(macAES);
    }

    [Fact]
    public void testPoint()
    {
        byte[] paceInfoBytes = Hex("3012060A 04007F00 07020204 02020201 0202010D");
        PACEInfo paceInfo = PACEInfo.CreatePACEInfo(paceInfoBytes);
        BigInteger? paramId = paceInfo.GetParameterId();
        Assert.NotNull(paramId);
        string oid = paceInfo.GetObjectIdentifier();
        object parameters = PACEInfo.ToParameterSpec(paramId);
        paceInfo.GetObjectIdentifier();

        AsymmetricKeyParameter publicKey = EcPublicKey(
            "2DB7A64C 0355044E C9DF1905 14C625CB A2CEA487 54887122 F3A5EF0D 5EDD301C",
            "3556F3B3 B186DF10 B857B58F 6A7EB80F 20BA5DC7 BE1D43D9 BF850149 FBB36462",
            (ECDomainParameters)parameters);
        byte[] encodedPublicKeyForSmartCard = PaceProtocol.EncodePublicKeyForSmartCard(publicKey);
        byte[] encodedPublicKeyForMac = PaceProtocol.EncodePublicKeyDataObject(oid, publicKey);
        Assert.NotNull(encodedPublicKeyForSmartCard);
        Assert.NotNull(encodedPublicKeyForMac);
    }

    /// <summary>
    /// G.1.1. ECDH based example. This example is based on ECDH applying the standardized BrainpoolP256r1
    /// domain parameters (see RFC 5639).
    /// </summary>
    [Fact]
    public void testSupplementSampleECDHGM()
    {
        string serialNumber = "T22000129"; /* Check digit 3 */
        string dateOfBirth = "640812"; /* Check digit 5 */
        string dateOfExpiry = "101031"; /* Check digit 8 */

        byte[] paceInfoBytes = Hex("3012060A 04007F00 07020204 02020201 0202010D");
        PACEInfo paceInfo = PACEInfo.CreatePACEInfo(paceInfoBytes);
        Assert.NotNull(paceInfo);
        BigInteger paramId = paceInfo.GetParameterId()!;
        string oid = paceInfo.GetObjectIdentifier();

        Assert.Equal("0.4.0.127.0.7.2.2.4.2.2", oid);
        Assert.Equal(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, oid);
        Assert.Equal(BigInteger.ValueOf(13), paramId);
        Assert.Equal(PACEInfo.PARAM_ID_ECP_BRAINPOOL_P256_R1, paramId.IntValue);

        object parameters = PACEInfo.ToParameterSpec(paramId);
        ECDomainParameters ecParams = Assert.IsAssignableFrom<ECDomainParameters>(parameters);

        string cipherAlg = PACEInfo.ToCipherAlgorithm(oid);
        Assert.Equal("AES", cipherAlg);
        string digestAlg = PACEInfo.ToDigestAlgorithm(oid);
        Assert.Equal("SHA-1", digestAlg);
        int keyLength = PACEInfo.ToKeyLength(oid);
        Assert.Equal(128, keyLength);

        /* Given */
        byte[] expectedKeySeed = Hex("7E2D2A41 C74EA0B3 8CD36F86 3939BFA8 E9032AAD");
        byte[] expectedEncodedSecretKey = Hex("89DED1B2 6624EC1E 634C1989 302849DD");

        byte[] keySeed = Util.ComputeKeySeed(serialNumber, dateOfBirth, dateOfExpiry, "SHA-1", false);
        Assert.Equal(expectedKeySeed, keySeed);
        byte[] secretKey = Util.DeriveKey(keySeed, cipherAlg, keyLength, Util.PACE_MODE);
        Assert.Equal(expectedEncodedSecretKey, secretKey);

        /* Encrypted Nonce. Next, the chip randomly generates the nonce s and encrypts it by means of K_pi. */
        byte[] nonceS = Hex("3F00C4D3 9D153F2B 2A214A07 8D899B22");

        /*
         * Map nonce. The nonce is mapped to an ephemeral group generator via generic mapping. The required
         * randomly chosen ephemeral keys are also collected in the next table.
         */
        ECPrivateKeyParameters pcdMappingPrivateKey = EcPrivateKey("7F4EF07B 9EA82FD7 8AD689B3 8D0BC78C F21F249D 953BC46F 4C6E1925 9C010F99", ecParams);
        ECPublicKeyParameters pcdMappingPublicKey = EcPublicKey(
            "7ACF3EFC 982EC455 65A4B155 129EFBC7 4650DCBF A6362D89 6FC70262 E0C2CC5E",
            "544552DC B6725218 799115B5 5C9BAA6D 9F6BC3A9 618E70C2 5AF71777 A9C4922D", ecParams);
        Assert.NotNull(pcdMappingPublicKey);

        ECPrivateKeyParameters piccMappingPrivateKey = EcPrivateKey("498FF497 56F2DC15 87840041 839A8598 2BE7761D 14715FB0 91EFA7BC E9058560", ecParams);
        Assert.NotNull(piccMappingPrivateKey);
        ECPublicKeyParameters piccMappingPublicKey = EcPublicKey(
            "824FBA91 C9CBE26B EF53A0EB E7342A3B F178CEA9 F45DE0B7 0AA60165 1FBA3F57",
            "30D8C879 AAA9C9F7 3991E61B 58F4D52E B87A0A0C 709A49DC 63719363 CCD13C54", ecParams);

        var mappingAgreement = new PACEGMWithECDHAgreement();
        mappingAgreement.Init(pcdMappingPrivateKey);
        ECPoint sharedSecretH = mappingAgreement.DoPhase(piccMappingPublicKey);

        ECDomainParameters ephemeralParams = PaceProtocol.MapNonceGMWithECDH(nonceS, sharedSecretH, ecParams);

        AsymmetricCipherKeyPair kp = Helpers.KeyPairs.EC(ephemeralParams);
        var keyAgreement = new ECDHBasicAgreement();
        keyAgreement.Init(kp.Private);
        Assert.NotNull(keyAgreement.CalculateAgreement(new ECPublicKeyParameters(piccMappingPublicKey.Q, ephemeralParams)));

        byte[] expectedEphemeralGeneratorX = Hex("8CED63C9 1426D4F0 EB1435E7 CB1D74A4 6723A0AF 21C89634 F65A9AE8 7A9265E2");
        byte[] expectedEphemeralGeneratorY = Hex("8C879506 743F8611 AC33645C 5B985C80 B5F09A0B 83407C1B 6A4D857A E76FE522");

        ECDomainParameters ephemeralECParams = PaceProtocol.MapNonceGMWithECDH(nonceS, sharedSecretH, ecParams);
        ECPoint ephemeralGenerator = ephemeralECParams.G.Normalize();
        byte[] ephemeralGeneratorX = Util.I2os(ephemeralGenerator.AffineXCoord.ToBigInteger());
        byte[] ephemeralGeneratorY = Util.I2os(ephemeralGenerator.AffineYCoord.ToBigInteger());
        Assert.Equal(expectedEphemeralGeneratorX, ephemeralGeneratorX);
        Assert.Equal(expectedEphemeralGeneratorY, ephemeralGeneratorY);

        /*
         * Perform Key Agreement. In the third step, chip and terminal perform an anonymous ECDH key agreement
         * using the new domain parameters determined by the ephemeral group generator G~ of the previous step.
         */
        BigInteger p = Util.GetPrime(ephemeralParams);
        Assert.NotNull(p);
        ECPrivateKeyParameters pcdPrivateKey = EcPrivateKey("A73FB703 AC1436A1 8E0CFA5A BB3F7BEC 7A070E7A 6788486B EE230C4A 22762595", ephemeralECParams);
        ECPublicKeyParameters pcdPublicKey = EcPublicKey(
            "2DB7A64C 0355044E C9DF1905 14C625CB A2CEA487 54887122 F3A5EF0D 5EDD301C",
            "3556F3B3 B186DF10 B857B58F 6A7EB80F 20BA5DC7 BE1D43D9 BF850149 FBB36462", ephemeralECParams);
        ECPublicKeyParameters piccPublicKey = EcPublicKey(
            "9E880F84 2905B8B3 181F7AF7 CAA9F0EF B743847F 44A306D2 D28C1D9E C65DF6DB",
            "7764B222 77A2EDDC 3C265A9F 018F9CB8 52E111B7 68B32690 4B59A019 3776F094", ephemeralECParams);
        byte[] expectedSharedSecret = Hex("28768D20 701247DA E81804C9 E780EDE5 82A9996D B4A31502 0B273319 7DB84925");

        Assert.NotEqual(pcdPublicKey, piccPublicKey);
        byte[] sharedSecretBytes = EcdhSecret(pcdPrivateKey, piccPublicKey);
        Assert.NotNull(sharedSecretBytes);
        Assert.Equal(expectedSharedSecret, sharedSecretBytes);

        /* Derive secure messaging keys. */
        byte[] expectedEncKeyBytes = Hex("F5F0E35C 0D7161EE 6724EE51 3A0D9A7F");
        byte[] expectedMacKeyBytes = Hex("FE251C78 58B356B2 4514B3BD 5F4297D1");
        byte[] encKeyBytes = Util.DeriveKey(sharedSecretBytes, cipherAlg, keyLength, Util.ENC_MODE);
        Assert.Equal(expectedEncKeyBytes, encKeyBytes);
        byte[] macKeyBytes = Util.DeriveKey(sharedSecretBytes, cipherAlg, keyLength, Util.MAC_MODE);
        Assert.Equal(expectedMacKeyBytes, macKeyBytes);
        var macKey = new KeyParameter(macKeyBytes);

        /* Mutual authentication. */
        byte[] expectedInputDataForPCDToken = Hex("7F494F06 0A04007F 00070202 04020286"
            + "41049E88 0F842905 B8B3181F 7AF7CAA9"
            + "F0EFB743 847F44A3 06D2D28C 1D9EC65D"
            + "F6DB7764 B22277A2 EDDC3C26 5A9F018F"
            + "9CB852E1 11B768B3 26904B59 A0193776"
            + "F094");
        byte[] expectedInputDataForPICCToken = Hex("7F494F06 0A04007F 00070202 04020286"
            + "41042DB7 A64C0355 044EC9DF 190514C6"
            + "25CBA2CE A4875488 7122F3A5 EF0D5EDD"
            + "301C3556 F3B3B186 DF10B857 B58F6A7E"
            + "B80F20BA 5DC7BE1D 43D9BF85 0149FBB3"
            + "6462");

        byte[] encodedPCDPublicKeyDataObject = PaceProtocol.EncodePublicKeyDataObject(oid, pcdPublicKey);
        Assert.Equal(expectedInputDataForPICCToken, encodedPCDPublicKeyDataObject);

        byte[] encodedPICCPublicKeyDataObject = PaceProtocol.EncodePublicKeyDataObject(oid, piccPublicKey);
        Assert.Equal(expectedInputDataForPCDToken, encodedPICCPublicKeyDataObject);

        byte[] expectedPCDAuthenticationToken = Hex("C2B0BD78 D94BA866");
        byte[] expectedPICCAuthenticationToken = Hex("3ABB9674 BCE93C08");

        byte[] pcdToken = PaceProtocol.GenerateAuthenticationToken(oid, macKey, piccPublicKey);
        byte[] piccToken = PaceProtocol.GenerateAuthenticationToken(oid, macKey, pcdPublicKey);
        Assert.Equal(expectedPCDAuthenticationToken, pcdToken);
        Assert.Equal(expectedPICCAuthenticationToken, piccToken);
    }

    private static ECPublicKeyParameters EcPublicKey(string x, string y, ECDomainParameters parameters) =>
        new(parameters.Curve.CreatePoint(Util.Os2i(Hex(x)), Util.Os2i(Hex(y))), parameters);

    private static ECPrivateKeyParameters EcPrivateKey(string d, ECDomainParameters parameters) =>
        new(Util.Os2i(Hex(d)), parameters);

    /// <summary>JCA's ECDH <c>KeyAgreement.generateSecret()</c>: the x-coordinate, field-size octets.</summary>
    private static byte[] EcdhSecret(ECPrivateKeyParameters privateKey, ECPublicKeyParameters publicKey)
    {
        var agreement = new ECDHBasicAgreement();
        agreement.Init(privateKey);
        return BigIntegers.AsUnsignedByteArray(agreement.GetFieldSize(), agreement.CalculateAgreement(publicKey));
    }
}
