using nMRTD.Lds;
using nMRTD.Protocol;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;
using static nMRTD.Tests.Helpers.TestData;

namespace nMRTD.Tests.Jmrtd.Protocol;

public partial class PACEProtocolTest
{
    [Fact]
    public void testSupplementDHGMSample()
    {
        byte[] paceInfoBytes = Hex("3012060A 04007F00 07020204 01020201 02020100");
        byte[] nonceSBytes = Hex("FA5B7E3E 49753A0D B9178B7B 9BD898C8");
        byte[] sharedSecretHBytes = Hex(
            "5BABEBEF 5B74E5BA 94B5C063 FDA15F1F"
            + "1CDE9487 3EE0A5D3 A2FCAB49 F258D07F"
            + "544F13CB 66658C3A FEE9E727 389BE3F6"
            + "CBBBD321 28A8C21D D6EEA3CF 7091CDDF"
            + "B08B8D00 7D40318D CCA4FFBF 51208790"
            + "FB4BD111 E5A968ED 6B6F08B2 6CA87C41"
            + "0B3CE0C3 10CE104E ABD16629 AA48620C"
            + "1279270C B0750C0D 37C57FFF E302AE7F");
        byte[] expectedEphemeralGeneratorBytes = Hex(
            "7C9CBFE9 8F9FBDDA 8D143506 FA7D9306"
            + "F4CB17E3 C71707AF F5E1C1A1 23702496"
            + "84D64EE3 7AF44B8D BD9D45BF 6023919C"
            + "BAA027AB 97ACC771 666C8E98 FF483301"
            + "BFA4872D EDE9034E DFACB708 14166B7F"
            + "36067682 9B826BEA 57291B5A D69FBC84"
            + "EF1E7790 32A30580 3F743417 93E86974"
            + "2D401325 B37EE856 5FFCDEE6 18342DC5");

        PACEInfo paceInfo = PACEInfo.CreatePACEInfo(paceInfoBytes);
        Assert.NotNull(paceInfo);
        string oid = paceInfo.GetObjectIdentifier();
        Assert.Equal(SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_128, oid); // id-PACE-DH-GM-AES-CBC-CMAC-128

        string cipherAlg = PACEInfo.ToCipherAlgorithm(oid);
        Assert.Equal("AES", cipherAlg);
        string digestAlg = PACEInfo.ToDigestAlgorithm(oid);
        Assert.Equal("SHA-1", digestAlg);
        int keyLength = PACEInfo.ToKeyLength(oid);
        Assert.Equal(128, keyLength);
        string agreementAlg = PACEInfo.ToKeyAgreementAlgorithm(oid);
        Assert.Equal("DH", agreementAlg);

        object parameters = PACEInfo.ToParameterSpec(paceInfo.GetParameterId()!);
        DHParameters dhParams = Assert.IsAssignableFrom<DHParameters>(parameters);

        DHParameters ephemeralDHParams = PaceProtocol.MapNonceGMWithDH(nonceSBytes, Util.Os2i(sharedSecretHBytes), dhParams);
        BigInteger ephemeralGenerator = ephemeralDHParams.G;
        byte[] ephemeralGeneratorBytes = Util.I2os(ephemeralGenerator);
        Assert.Equal(expectedEphemeralGeneratorBytes, ephemeralGeneratorBytes);

        // Java: ephemeralParams instanceof DHCParameterSpec, with the static parameters' q.
        Assert.NotNull(ephemeralDHParams.Q);
        Assert.Equal(dhParams.Q, ephemeralDHParams.Q);

        BigInteger p = Util.GetPrime(ephemeralDHParams);

        BigInteger pcdPrivateKeyFieldElement = Util.Os2i(Hex("4BD0E547 40F9A028 E6A515BF DAF96784"
            + "8C4F5F5F FF65AA09 15947FFD 1A0DF2FA"
            + "6981271B C905F355 1457B7E0 3AC3B806"
            + "6DE4AA40 6C1171FB 43DD939C 4BA16175"
            + "103BA3DE E16419AA 248118F9 0CC36A3D"
            + "6F4C3736 52E0C3CC E7F0F1D0 C5425B36"
            + "00F0F0D6 A67F004C 8BBA33F2 B4733C72"
            + "52445C1D FC4F1107 203F71D2 EFB28161"));
        BigInteger pcdPublicKeyFieldElement = Util.Os2i(Hex("00907D89 E2D425A1 78AA81AF 4A7774EC"
            + "8E388C11 5CAE6703 1E85EECE 520BD911"
            + "551B9AE4 D04369F2 9A02626C 86FBC674"
            + "7CC7BC35 2645B616 1A2A42D4 4EDA80A0"
            + "8FA8D61B 76D3A154 AD8A5A51 786B0BC0"
            + "71470578 71A92221 2C5F67F4 31731722"
            + "36B7747D 1671E6D6 92A3C7D4 0A0C3C5C"
            + "E397545D 015C175E B5130551 EDBC2EE5 D4"));
        BigInteger piccPublicKeyFieldElement = Util.Os2i(Hex("075693D9 AE941877 573E634B 6E644F8E"
            + "60AF17A0 076B8B12 3D920107 4D36152B"
            + "D8B3A213 F53820C4 2ADC79AB 5D0AEEC3"
            + "AEFB9139 4DA476BD 97B9B14D 0A65C1FC"
            + "71A0E019 CB08AF55 E1F72900 5FBA7E3F"
            + "A5DC4189 9238A250 767A6D46 DB974064"
            + "386CD456 743585F8 E5D90CC8 B4004B1F"
            + "6D866C79 CE0584E4 9687FF61 BC29AEA1"));
        byte[] expectedSharedSecret = Hex("6BABC7B3 A72BCD7E A385E4C6 2DB2625B"
            + "D8613B24 149E146A 629311C4 CA6698E3"
            + "8B834B6A 9E9CD718 4BA8834A FF5043D4"
            + "36950C4C 1E783236 7C10CB8C 314D40E5"
            + "990B0DF7 013E64B4 549E2270 923D06F0"
            + "8CFF6BD3 E977DDE6 ABE4C31D 55C0FA2E"
            + "465E553E 77BDF75E 3193D383 4FC26E8E"
            + "B1EE2FA1 E4FC97C1 8C3F6CFF FE2607FD");

        PaceProtocol.CheckDHPublicValue(pcdPublicKeyFieldElement, ephemeralDHParams);
        PaceProtocol.CheckDHPublicValue(piccPublicKeyFieldElement, ephemeralDHParams);

        /* Java: keys from DHPrivateKeySpec/DHPublicKeySpec (p, g), so without q. */
        var keyParameters = new DHParameters(p, ephemeralGenerator);
        var pcdPrivateKey = new DHPrivateKeyParameters(pcdPrivateKeyFieldElement, keyParameters);
        var pcdPublicKey = new DHPublicKeyParameters(pcdPublicKeyFieldElement, keyParameters);
        var piccPublicKey = new DHPublicKeyParameters(piccPublicKeyFieldElement, keyParameters);

        Assert.NotEqual(pcdPublicKey, piccPublicKey);
        var keyAgreement = new DHBasicAgreement();
        keyAgreement.Init(pcdPrivateKey);
        byte[] sharedSecretBytes = BigIntegers.AsUnsignedByteArray(keyAgreement.GetFieldSize(), keyAgreement.CalculateAgreement(piccPublicKey));
        Assert.NotNull(sharedSecretBytes);
        Assert.Equal(expectedSharedSecret, sharedSecretBytes);

        byte[] expectedEncKeyBytes = Hex("2F7F46AD CC9E7E52 1B45D192 FAFA9126");
        byte[] expectedMacKeyBytes = Hex("805A1D27 D45A5116 F73C5446 9462B7D8");

        byte[] encKeyBytes = Util.DeriveKey(sharedSecretBytes, cipherAlg, keyLength, Util.ENC_MODE);
        Assert.Equal(expectedEncKeyBytes, encKeyBytes);
        byte[] macKeyBytes = Util.DeriveKey(sharedSecretBytes, cipherAlg, keyLength, Util.MAC_MODE);
        Assert.Equal(expectedMacKeyBytes, macKeyBytes);
        var macKey = new KeyParameter(macKeyBytes);

        byte[] expectedInputDataForPCDToken = Hex("7F49818F 060A0400 7F000702 02040102"
            + "84818007 5693D9AE 94187757 3E634B6E"
            + "644F8E60 AF17A007 6B8B123D 9201074D"
            + "36152BD8 B3A213F5 3820C42A DC79AB5D"
            + "0AEEC3AE FB91394D A476BD97 B9B14D0A"
            + "65C1FC71 A0E019CB 08AF55E1 F729005F"
            + "BA7E3FA5 DC418992 38A25076 7A6D46DB"
            + "97406438 6CD45674 3585F8E5 D90CC8B4"
            + "004B1F6D 866C79CE 0584E496 87FF61BC"
            + "29AEA1");
        byte[] expectedInputDataForPICCToken = Hex("7F49818F 060A0400 7F000702 02040102"
            + "84818090 7D89E2D4 25A178AA 81AF4A77"
            + "74EC8E38 8C115CAE 67031E85 EECE520B"
            + "D911551B 9AE4D043 69F29A02 626C86FB"
            + "C6747CC7 BC352645 B6161A2A 42D44EDA"
            + "80A08FA8 D61B76D3 A154AD8A 5A51786B"
            + "0BC07147 057871A9 22212C5F 67F43173"
            + "172236B7 747D1671 E6D692A3 C7D40A0C"
            + "3C5CE397 545D015C 175EB513 0551EDBC"
            + "2EE5D4");

        byte[] encodedPCDPublicKeyDataObject = PaceProtocol.EncodePublicKeyDataObject(oid, pcdPublicKey);
        Assert.Equal(expectedInputDataForPICCToken, encodedPCDPublicKeyDataObject);

        byte[] encodedPICCPublicKeyDataObject = PaceProtocol.EncodePublicKeyDataObject(oid, piccPublicKey);
        Assert.Equal(expectedInputDataForPCDToken, encodedPICCPublicKeyDataObject);

        byte[] expectedPCDAuthenticationToken = Hex("B46DD9BD 4D98381F");
        byte[] expectedPICCAuthenticationToken = Hex("917F37B5 C0E6D8D1");

        byte[] pcdAuthenticationToken = PaceProtocol.GenerateAuthenticationToken(oid, macKey, piccPublicKey);
        byte[] piccAuthenticationToken = PaceProtocol.GenerateAuthenticationToken(oid, macKey, pcdPublicKey);
        Assert.Equal(expectedPCDAuthenticationToken, pcdAuthenticationToken);
        Assert.Equal(expectedPICCAuthenticationToken, piccAuthenticationToken);
    }
}
