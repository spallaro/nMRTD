using nMRTD.Lds;
using nMRTD.Protocol;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace nMRTD.Tests.Jmrtd.Protocol;

/// <summary>
/// Port of JMRTD's <c>org.jmrtd.protocol.PACECAMWorkedExampleTest</c> (0.8.10, d2b9471c): Doc 9303-11 (8th edition),
/// Appendix I, Worked Example: PACE - PACE CA Mapping (informative), ECDH with BrainpoolP256r1 and AES-128, MRZ as
/// password. Its <c>ChipAuthenticationPublicKeyInfo</c> references standardized domain parameters (9.5.1), which
/// used to be decoded as no key.
/// </summary>
public class PACECAMWorkedExampleTest
{
    private static readonly byte[] PaceInfoBytes = Bytes("3012060A 04007F00 07020204 06020201 0202010D");

    private static readonly byte[] ChipAuthenticationPublicKeyInfoBytes = Bytes(
        "30620609 04007F00 07020201 02305230 0C060704 007F0007 01020201 0D034200"
        + "04187270 9494399E 7470A643 1BE25E83 EEE24FEA 568C2ED2 8DB48E05 DB3A610D"
        + "C884D256 A40E35EF CB59BF67 53D3A489 D28C7A4D 973C2DA1 38A6E7A4 A08F68E1"
        + "6F02010D");

    [Fact]
    public void testWorkedExample()
    {
        PACEInfo paceInfo = PACEInfo.CreatePACEInfo(PaceInfoBytes);
        string oid = paceInfo.GetObjectIdentifier();
        Assert.Equal(SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_128, oid);
        Assert.Equal(PACEInfo.PARAM_ID_ECP_BRAINPOOL_P256_R1, paceInfo.GetParameterId()!.IntValue);
        var staticParams = (ECDomainParameters)PACEInfo.ToParameterSpec(paceInfo.GetParameterId()!);
        string cipherAlg = PACEInfo.ToCipherAlgorithm(oid);
        int keyLength = PACEInfo.ToKeyLength(oid);

        // K and K_pi from the MRZ (document number C11T002JM, check digit 4; 960812, 2; 231031, 4).
        var accessKey = new BacKey("C11T002JM", "960812", "231031");
        Assert.Equal(Bytes("894D03F1 48C6265E 89845B21 8856EA34 D00EF8E8"), PaceProtocol.ComputeKeySeedForPace(accessKey));
        byte[] staticPaceKey = PaceProtocol.DeriveStaticPaceKey(accessKey, oid).GetKey();
        Assert.Equal(Bytes("4E6F6FBF 7BE748B9 32C7B741 61BBA9DF"), staticPaceKey);

        // Encrypted nonce.
        var staticPaceCipher = new CbcBlockCipher(new AesEngine());
        staticPaceCipher.Init(false, new ParametersWithIV(new KeyParameter(staticPaceKey), new byte[16]));
        byte[] nonceS = new byte[16];
        staticPaceCipher.ProcessBlock(Bytes("CB60E8E0 D85B76A9 BD304747 C2AD42E2"), 0, nonceS, 0);
        Assert.Equal(Bytes("658B860B C94DF6F0 44FCE6D5 C82CF8E5"), nonceS);

        // Map nonce (generic mapping).
        var pcdMappingPrivateKey = PrivateKey("5D8BB87B D74D985A 4B7D4325 B9F7B976 FE835122 77340079 8914AA22 738135CC", staticParams);
        var piccMappingPublicKey = PublicKey(
            "A234236A A9B9621E 8EFB73B5 245C0E09 D2576E52 77183C12 08BDD552 80CAE8B3",
            "04F36571 3A356E65 A451E165 ECC9AC0A C46E3771 342C8FE5 AEDD0926 85338E23", staticParams);
        var mappingAgreement = new PACEGMWithECDHAgreement();
        mappingAgreement.Init(pcdMappingPrivateKey);
        ECPoint sharedSecretH = mappingAgreement.DoPhase(piccMappingPublicKey).Normalize();
        AssertPoint("2C1DCC17 73346492 C6636A36 EE4B965E 292E9AAE 7EE37736 EF58B9D0 A043F348",
            "403A8CF3 3CA7DC0D 9DF61D08 89CE2442 4FF97C1A AD48A5CA 2A554B07 1EF7638D", sharedSecretH);
        ECDomainParameters ephemeralParams = PaceProtocol.MapNonceGMWithECDH(nonceS, sharedSecretH, staticParams);
        AssertPoint("89F0B5EA BF3BE293 C75903A3 98613192 5C9F5B51 5CA95AF4 85DC7E88 6F03245D",
            "44BEFB2D D3A0DBD7 1CB5E618 971CF474 7F12B79E 548379A4 0E45963B AAF3E829", ephemeralParams.G.Normalize());

        // Key agreement with the mapped generator.
        var pcdPrivateKey = PrivateKey("76ECFDAA 9841C323 A3F5FC5E 88B88DB3 EFF7E35E BF57A7E6 946CB630 006C2120", ephemeralParams);
        var pcdPublicKey = PublicKey(
            "446C9340 84D9DAB8 63944F21 9520076C 29EE3F7A E6722B11 FF319EC1 C7728F95",
            "5483400B FF60BF0C 59292700 09277DC2 A515E125 75010AD9 BA916CF1 BF86FEFC", ephemeralParams);
        var piccPublicKey = PublicKey(
            "02AD566F 3C6EC7F9 324509AD 50A51FA5 2030782A 4968FCFE DF737DAE A9933331",
            "11C3B9B4 C2287789 BD137E7F 8AA882E2 A3C633CC D6ECC2C6 3C57AD40 1A09C2E1", ephemeralParams);
        var keyAgreement = new ECDHBasicAgreement();
        keyAgreement.Init(pcdPrivateKey);
        byte[] sharedSecret = Org.BouncyCastle.Utilities.BigIntegers.AsUnsignedByteArray(32, keyAgreement.CalculateAgreement(piccPublicKey));
        Assert.Equal(Bytes("67950559 D0C06B4D 4B86972D 14460837 461087F8 419FDBC3 6AAF6CEA AC462832"), sharedSecret);

        var encKey = new KeyParameter(Util.DeriveKey(sharedSecret, cipherAlg, keyLength, Util.ENC_MODE));
        var macKey = new KeyParameter(Util.DeriveKey(sharedSecret, cipherAlg, keyLength, Util.MAC_MODE));
        Assert.Equal(Bytes("0A9DA4DB 03BDDE39 FC5202BC 44B2E89E"), encKey.GetKey());
        Assert.Equal(Bytes("4B1C0649 1ED5140C A2B537D3 44C6C0B1"), macKey.GetKey());

        // Mutual authentication.
        Assert.Equal(Bytes("E86BD060 18A1CD3B"), PaceProtocol.GenerateAuthenticationToken(oid, macKey, piccPublicKey));
        Assert.Equal(Bytes("8596CF05 5C67C1A3"), PaceProtocol.GenerateAuthenticationToken(oid, macKey, pcdPublicKey));

        // Chip Authentication data, IV = E(KS_Enc, -1).
        var ivCipher = new AesEngine();
        ivCipher.Init(true, encKey);
        byte[] iv = new byte[16];
        ivCipher.ProcessBlock(Bytes("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF"), 0, iv, 0);
        Assert.Equal(Bytes("F6A3B75A 1E933941 DD7A13E2 520779DF"), iv);
        byte[] chipAuthenticationData = PaceProtocol.DecryptChipAuthenticationData(encKey, Bytes(
            "1EEA964D AAE372AC 990E3EFD E6333353 BFC89A67 04D93DA8 798CF77F 5B7A54BD"
            + "10CBA372 B42BE0B9 B5F28AA8 DE2F4F92"));
        Assert.Equal(Bytes("85DC3FA9 3D0952BF A82F5FD1 89EE75BD 82F11D1F 0B8ED4BF 5319AC9B 53C426B3"), chipAuthenticationData);

        // The terminal verifies PK_MAP,IC = KA(CA_IC, PK_IC, D_IC), with PK_IC from EF.CardSecurity.
        var caPublicKeyInfo = (ChipAuthenticationPublicKeyInfo)SecurityInfo.GetInstance(Asn1Object.FromByteArray(ChipAuthenticationPublicKeyInfoBytes))!;
        Assert.Equal(BigInteger.ValueOf(13), caPublicKeyInfo.GetKeyId());
        ECPoint caPublicPoint = ((ECPublicKeyParameters)caPublicKeyInfo.GetSubjectPublicKey()).Q.Normalize();
        AssertPoint("18727094 94399E74 70A6431B E25E83EE E24FEA56 8C2ED28D B48E05DB 3A610DC8",
            "84D256A4 0E35EFCB 59BF6753 D3A489D2 8C7A4D97 3C2DA138 A6E7A4A0 8F68E16F", caPublicPoint);
        // Encoded again (with explicit domain parameters), it is the same key.
        var reencoded = (ChipAuthenticationPublicKeyInfo)SecurityInfo.GetInstance(Asn1Object.FromByteArray(caPublicKeyInfo.GetEncoded()!))!;
        Assert.Equal(caPublicPoint, ((ECPublicKeyParameters)reencoded.GetSubjectPublicKey()).Q.Normalize());
        Assert.Equal(BigInteger.ValueOf(13), reencoded.GetKeyId());

        ECPoint product = staticParams.Curve.ImportPoint(caPublicPoint).Multiply(Util.Os2i(chipAuthenticationData)).Normalize();
        Assert.Equal(piccMappingPublicKey.Q.Normalize(), product); // PK_MAP,IC = CA_IC * PK_IC
    }

    private static byte[] Bytes(string hex) => Convert.FromHexString(hex.Replace(" ", ""));

    private static void AssertPoint(string x, string y, ECPoint point)
    {
        Assert.Equal(Util.Os2i(Bytes(x)), point.AffineXCoord.ToBigInteger());
        Assert.Equal(Util.Os2i(Bytes(y)), point.AffineYCoord.ToBigInteger());
    }

    private static ECPrivateKeyParameters PrivateKey(string s, ECDomainParameters parameters) =>
        new(Util.Os2i(Bytes(s)), parameters);

    private static ECPublicKeyParameters PublicKey(string x, string y, ECDomainParameters parameters) =>
        new(parameters.Curve.CreatePoint(Util.Os2i(Bytes(x)), Util.Os2i(Bytes(y))), parameters);
}
