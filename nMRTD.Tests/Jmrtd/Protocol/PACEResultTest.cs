using nMRTD.Cert;
using nMRTD.Lds;
using nMRTD.Protocol;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace nMRTD.Tests.Jmrtd.Protocol;

/// <summary>Port of JMRTD's <c>org.jmrtd.protocol.PACEResultTest</c>.</summary>
public class PACEResultTest
{

    [Fact]
    public void testPACEResult()
    {
        string oid = PACEInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256;

        IAccessKeySpec paceKey = PaceKeySpec.CreateCanKey("12345");

        AsymmetricCipherKeyPair piccKeyPair = KeyPairs.EC("P-256");
        AsymmetricKeyParameter piccPublicKey = piccKeyPair.Public;

        AsymmetricCipherKeyPair pcdKeyPair = KeyPairs.EC("P-256");

        SecureMessagingWrapper wrapper = new AESSecureMessagingWrapper(GetRandomAESKey(), GetRandomAESKey(), PassportService.NormalMaxTransceiveLength, true, 0L);

        PACEInfo.MappingType mappingType = PACEInfo.ToMappingType(oid);
        string agreementType = PACEInfo.ToKeyAgreementAlgorithm(oid);
        string cipherAlg = PACEInfo.ToCipherAlgorithm(oid);
        string digestAlg = PACEInfo.ToDigestAlgorithm(oid);
        int keyLength = PACEInfo.ToKeyLength(oid);

        PACEMappingResult? mappingResult = null;

        PACEResult paceResult = new PACEResult(paceKey, mappingType, agreementType, cipherAlg, digestAlg, keyLength, mappingResult, pcdKeyPair, piccPublicKey, wrapper);

        Assert.Equal(paceKey, paceResult.PaceKey);
        Assert.Equal(mappingType, paceResult.MappingType);
        Assert.Equal(agreementType, paceResult.AgreementAlg);
        Assert.Equal(cipherAlg, paceResult.CipherAlg);
        Assert.Equal(digestAlg, paceResult.DigestAlg);
        Assert.Equal(keyLength, paceResult.KeyLength);
        Assert.Equal(mappingResult, paceResult.MappingResult);
    }

    [Fact]
    public void testPACEResultEquals()
    {
            string oid = PACEInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256;

            IAccessKeySpec paceKey = PaceKeySpec.CreateCanKey("12345");

            AsymmetricCipherKeyPair piccKeyPair = KeyPairs.EC("P-256");
            AsymmetricKeyParameter piccPublicKey = piccKeyPair.Public;

            AsymmetricCipherKeyPair pcdKeyPair = KeyPairs.EC("P-256");

            SecureMessagingWrapper wrapper = new AESSecureMessagingWrapper(GetRandomAESKey(), GetRandomAESKey(), PassportService.NormalMaxTransceiveLength, true, 0L);

            PACEInfo.MappingType mappingType = PACEInfo.ToMappingType(oid);
            string agreementType = PACEInfo.ToKeyAgreementAlgorithm(oid);
            string cipherAlg = PACEInfo.ToCipherAlgorithm(oid);
            string digestAlg = PACEInfo.ToDigestAlgorithm(oid);
            int keyLength = PACEInfo.ToKeyLength(oid);

            PACEMappingResult? mappingResult = null;

            PACEResult paceResult = new PACEResult(paceKey, mappingType, agreementType, cipherAlg, digestAlg, keyLength, mappingResult, pcdKeyPair, piccPublicKey, wrapper);
            PACEResult anotherPACEResult = new PACEResult(paceKey, mappingType, agreementType, cipherAlg, digestAlg, keyLength, mappingResult, pcdKeyPair, piccPublicKey, wrapper);

            Assert.Equal(paceResult.GetHashCode(), anotherPACEResult.GetHashCode());
            Assert.Equal(paceResult, anotherPACEResult);
            Assert.Equal(paceResult.ToString(), anotherPACEResult.ToString());
    }

    [Fact]
    public void testMappingResultDefensivelyCopiesPICCNonce()
    {
        byte[] piccNonce = new byte[] { 1, 2, 3, 4 };
        byte[] expectedPICCNonce = (byte[])piccNonce.Clone();
        PACEMappingResult mappingResult = new TestMappingResult(null, piccNonce, null); // Java: an anonymous subclass

        piccNonce[0] ^= 0x7F;
        Assert.Equal(expectedPICCNonce, mappingResult.GetPiccNonce());

        byte[] returnedPICCNonce = mappingResult.GetPiccNonce()!;
        returnedPICCNonce[0] ^= 0x7F;
        Assert.Equal(expectedPICCNonce, mappingResult.GetPiccNonce());
    }

    private static KeyParameter GetRandomAESKey()
    {
        return new KeyParameter(Org.BouncyCastle.Security.SecureRandom.GetNextBytes(new Org.BouncyCastle.Security.SecureRandom(), 16)); // Java: KeyGenerator "AES"
    }

    private sealed class TestMappingResult(object? staticParameters, byte[]? piccNonce, object? ephemeralParameters)
        : PACEMappingResult(staticParameters, piccNonce, ephemeralParameters);
}
