using nMRTD.Cert;
using nMRTD.Lds;
using nMRTD.Protocol;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace nMRTD.Tests.Jmrtd.Protocol;

/// <summary>Port of JMRTD's <c>org.jmrtd.protocol.CAResultTest</c>.</summary>
/**
  * Tests for CAResult class.
  *
  * @author The JMRTD team (info@jmrtd.org)
  *
  * @version $Revision$
  *
  * @since 0.6.2
  */
public class CAResultTest
{

    [Fact]
    public void testCAResult()
    {
        BigInteger keyId = BigInteger.ValueOf(-1L);

        AsymmetricCipherKeyPair piccKeyPair = KeyPairs.EC("P-256");
        AsymmetricKeyParameter piccPublicKey = piccKeyPair.Public;

        AsymmetricCipherKeyPair pcdKeyPair = KeyPairs.EC("P-256");
        AsymmetricKeyParameter pcdPublicKey = pcdKeyPair.Public;
        AsymmetricKeyParameter pcdPrivateKey = pcdKeyPair.Private;

        SecureMessagingWrapper wrapper = new AESSecureMessagingWrapper(GetRandomAESKey(), GetRandomAESKey(), PassportService.NormalMaxTransceiveLength, true, 0L);

        byte[] keyHash = EACCAProtocol.GetKeyHash("ECDH", pcdPublicKey);
        byte[] expectedKeyHash = (byte[])keyHash.Clone();
        EACCAResult caResult = new EACCAResult(keyId, piccPublicKey, keyHash, pcdPublicKey, pcdPrivateKey, wrapper);

        Assert.Equal(piccPublicKey, caResult.PublicKey);

        Assert.Equal(pcdPublicKey, caResult.PCDPublicKey);
        Assert.Equal(pcdPrivateKey, caResult.PCDPrivateKey);

        Assert.Equal(wrapper, caResult.Wrapper);

        keyHash[0] ^= 0x7F;
        Assert.Equal(expectedKeyHash, caResult.GetKeyHash());
        byte[] returnedKeyHash = caResult.GetKeyHash()!;
        returnedKeyHash[0] ^= 0x7F;
        Assert.Equal(expectedKeyHash, caResult.GetKeyHash());
    }

    [Fact]
    public void testCAResultEquals()
    {
        BigInteger keyId = BigInteger.ValueOf(-1L);

        AsymmetricCipherKeyPair piccKeyPair = KeyPairs.EC("P-256");
        AsymmetricKeyParameter piccPublicKey = piccKeyPair.Public;

        AsymmetricCipherKeyPair pcdKeyPair = KeyPairs.EC("P-256");
        AsymmetricKeyParameter pcdPublicKey = pcdKeyPair.Public;
        AsymmetricKeyParameter pcdPrivateKey = pcdKeyPair.Private;

        KeyParameter encKey = GetRandomAESKey();
        KeyParameter macKey = GetRandomAESKey();
        SecureMessagingWrapper wrapper = new AESSecureMessagingWrapper(encKey, macKey, PassportService.NormalMaxTransceiveLength, true, 0L);
        SecureMessagingWrapper anotherWrapper = new AESSecureMessagingWrapper(encKey, macKey, 256, true, 0L);

        EACCAResult caResult = new EACCAResult(keyId, piccPublicKey, EACCAProtocol.GetKeyHash("ECDH", pcdPublicKey), pcdPublicKey, pcdPrivateKey, wrapper);
        EACCAResult anotherCAResult = new EACCAResult(keyId, piccPublicKey, EACCAProtocol.GetKeyHash("ECDH", pcdPublicKey), pcdPublicKey, pcdPrivateKey, anotherWrapper);

        Assert.Equal(caResult.GetHashCode(), anotherCAResult.GetHashCode());
        Assert.Equal(caResult, anotherCAResult);
        Assert.Equal(caResult.ToString(), anotherCAResult.ToString());
    }

    private static KeyParameter GetRandomAESKey()
    {
        return new KeyParameter(Org.BouncyCastle.Security.SecureRandom.GetNextBytes(new Org.BouncyCastle.Security.SecureRandom(), 16)); // Java: KeyGenerator "AES"
    }

}
