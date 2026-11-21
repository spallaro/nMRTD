using nMRTD.Cert;
using nMRTD.Lds;
using nMRTD.Protocol;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace nMRTD.Tests.Jmrtd.Protocol;

/// <summary>Port of JMRTD's <c>org.jmrtd.protocol.PACECAMResultTest</c>.</summary>
public class PACECAMResultTest
{

    [Fact]
    public void testPACECAMResult()
    {
        string documentNumner = "123456789";
        string dateOfBirth = "710121";
        string dateOfExpiry = "331231";
        IAccessKeySpec paceKey = PaceKeySpec.CreateMrzKey(new BacKey(documentNumner, dateOfBirth, dateOfExpiry));
        string agreementAlg = "ECDH";
        string cipherAlg = "AES";
        string digestAlg = "SHA-256";
        int keyLength = 128;
        PACEMappingResult? mappingResult = null;

        AsymmetricCipherKeyPair piccKeyPair = KeyPairs.EC("P-256");
        AsymmetricKeyParameter piccPublicKey = piccKeyPair.Public;

        AsymmetricCipherKeyPair pcdKeyPair = KeyPairs.EC("P-256");

        SecureMessagingWrapper wrapper = new AESSecureMessagingWrapper(GetRandomAESKey(), GetRandomAESKey(), PassportService.NormalMaxTransceiveLength, true, 0L);

        byte[] chipAuthenticationData = new byte[8]; // FIXME: Generate randomly.

        byte[] encryptedChipAuthenticationData = new byte[128]; // FIXME: Encrypt chipAuthenticationData ourselves.

        PACECAMResult paceCAMResult = new PACECAMResult(paceKey, agreementAlg, cipherAlg, digestAlg, keyLength, mappingResult, pcdKeyPair, piccPublicKey, encryptedChipAuthenticationData, chipAuthenticationData, wrapper);

        Assert.Equal(agreementAlg, paceCAMResult.AgreementAlg);
        Assert.Equal(paceKey, paceCAMResult.PaceKey);

        Assert.Equal(cipherAlg, paceCAMResult.CipherAlg);
        Assert.Equal(digestAlg, paceCAMResult.DigestAlg);
        Assert.Equal(keyLength, paceCAMResult.KeyLength);
        Assert.Equal(mappingResult, paceCAMResult.MappingResult);
        Assert.Equal(PACEInfo.MappingType.CAM, paceCAMResult.MappingType);

        Assert.Equal(pcdKeyPair, paceCAMResult.PcdKeyPair);

        Assert.Equal(piccPublicKey, paceCAMResult.PiccPublicKey);

        Assert.True(Enumerable.SequenceEqual(encryptedChipAuthenticationData, paceCAMResult.GetEncryptedChipAuthenticationData()!));
        Assert.True(Enumerable.SequenceEqual(chipAuthenticationData, paceCAMResult.GetChipAuthenticationData()!));

        encryptedChipAuthenticationData[0] = 1;
        chipAuthenticationData[0] = 1;
        Assert.Equal(new byte[128], paceCAMResult.GetEncryptedChipAuthenticationData());
        Assert.Equal(new byte[8], paceCAMResult.GetChipAuthenticationData());

        byte[] returnedEncryptedData = paceCAMResult.GetEncryptedChipAuthenticationData()!;
        byte[] returnedData = paceCAMResult.GetChipAuthenticationData()!;
        returnedEncryptedData[0] = 1;
        returnedData[0] = 1;
        Assert.Equal(new byte[128], paceCAMResult.GetEncryptedChipAuthenticationData());
        Assert.Equal(new byte[8], paceCAMResult.GetChipAuthenticationData());
    }

    [Fact]
    public void testPACECAMResultEquals()
    {
        string documentNumner = "123456789";
        string dateOfBirth = "710121";
        string dateOfExpiry = "331231";
        IAccessKeySpec paceKey = PaceKeySpec.CreateMrzKey(new BacKey(documentNumner, dateOfBirth, dateOfExpiry));
        string agreementAlg = "ECDH";
        string cipherAlg = "AES";
        string digestAlg = "SHA-256";
        int keyLength = 128;
        PACEMappingResult? mappingResult = null;

        AsymmetricCipherKeyPair piccKeyPair = KeyPairs.EC("P-256");
        AsymmetricKeyParameter piccPublicKey = piccKeyPair.Public;

        AsymmetricCipherKeyPair pcdKeyPair = KeyPairs.EC("P-256");

        KeyParameter encKey = GetRandomAESKey();
        KeyParameter macKey = GetRandomAESKey();

        SecureMessagingWrapper wrapper = new AESSecureMessagingWrapper(encKey, macKey, PassportService.NormalMaxTransceiveLength, true, 0L);
        SecureMessagingWrapper anotherWrapper = new AESSecureMessagingWrapper(encKey, macKey, 0L);

        byte[] chipAuthenticationData = new byte[8]; // FIXME: Generate randomly.

        byte[] encryptedChipAuthenticationData = new byte[128]; // FIXME: Encrypt chipAuthenticationData ourselves.

        PACECAMResult paceCAMResult = new PACECAMResult(paceKey, agreementAlg, cipherAlg, digestAlg, keyLength, mappingResult, pcdKeyPair, piccPublicKey, encryptedChipAuthenticationData, chipAuthenticationData, wrapper);
        PACECAMResult anotherPACECAMResult = new PACECAMResult(paceKey, agreementAlg, cipherAlg, digestAlg, keyLength, mappingResult, pcdKeyPair, piccPublicKey, encryptedChipAuthenticationData, chipAuthenticationData, anotherWrapper);

        Assert.Equal(paceCAMResult.GetHashCode(), anotherPACECAMResult.GetHashCode());
        Assert.Equal(paceCAMResult, anotherPACECAMResult);
        Assert.Equal(paceCAMResult.ToString(), anotherPACECAMResult.ToString());
    }

    private static KeyParameter GetRandomAESKey()
    {
        return new KeyParameter(Org.BouncyCastle.Security.SecureRandom.GetNextBytes(new Org.BouncyCastle.Security.SecureRandom(), 16)); // Java: KeyGenerator "AES"
    }
}
