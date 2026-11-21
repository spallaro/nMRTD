using nMRTD.Cert;
using nMRTD.Lds;
using nMRTD.Protocol;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace nMRTD.Tests.Jmrtd.Protocol;

/// <summary>Port of JMRTD's <c>org.jmrtd.protocol.TAResultTest</c>.</summary>
/**
  * Tests for TAResult class.
  *
  * @author The JMRTD team (info@jmrtd.org)
  *
  * @version $Revision$
  *
  * @since 0.6.2
  */
public class TAResultTest
{

    [Fact]
    public void testTAResult()
    {
        BigInteger keyId = BigInteger.ValueOf(-1L);

        AsymmetricCipherKeyPair piccKeyPair = KeyPairs.EC("P-256");
        AsymmetricKeyParameter piccPublicKey = piccKeyPair.Public;

        AsymmetricCipherKeyPair pcdKeyPair = KeyPairs.EC("P-256");
        AsymmetricKeyParameter pcdPublicKey = pcdKeyPair.Public;
        AsymmetricKeyParameter pcdPrivateKey = pcdKeyPair.Private;

        SecureMessagingWrapper wrapper = new AESSecureMessagingWrapper(GetRandomAESKey(), GetRandomAESKey(), PassportService.NormalMaxTransceiveLength, true, 0L);

        EACCAResult caResult = new EACCAResult(keyId, piccPublicKey, EACCAProtocol.GetKeyHash("ECDH", pcdPublicKey), pcdPublicKey, pcdPrivateKey, wrapper);

        CVCPrincipal cvcPrincipal = new CVCPrincipal("CAReference00001");
        List<CardVerifiableCertificate> terminalCertificates = new List<CardVerifiableCertificate>();
        AsymmetricKeyParameter? terminalKey = null;
        string documentNumber = "123456789";
        byte[] cardChallenge = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        byte[] expectedCardChallenge = (byte[])cardChallenge.Clone();
        EACTAResult taResult = new EACTAResult(caResult, cvcPrincipal, terminalCertificates, terminalKey, documentNumber, cardChallenge);

        Assert.Equal(caResult, taResult.ChipAuthenticationResult);
        Assert.Equal(cvcPrincipal, taResult.CAReference);
        Assert.Equal(terminalCertificates, taResult.CVCertificates);
        Assert.Equal(terminalKey, taResult.TerminalKey);
        Assert.Equal(documentNumber, taResult.DocumentNumber);
        Assert.Equal(expectedCardChallenge, taResult.GetCardChallenge());

        cardChallenge[0] ^= 0x7F;
        Assert.Equal(expectedCardChallenge, taResult.GetCardChallenge());
        byte[] returnedCardChallenge = taResult.GetCardChallenge()!;
        returnedCardChallenge[0] ^= 0x7F;
        Assert.Equal(expectedCardChallenge, taResult.GetCardChallenge());
    }

    [Fact]
    public void testTAResultEquals()
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
        SecureMessagingWrapper anotherWrapper = new AESSecureMessagingWrapper(encKey, macKey, PassportService.NormalMaxTransceiveLength, true, 0L);

        EACCAResult caResult = new EACCAResult(keyId, piccPublicKey, EACCAProtocol.GetKeyHash("ECDH", pcdPublicKey), pcdPublicKey, pcdPrivateKey, wrapper);
        EACCAResult anotherCAResult = new EACCAResult(keyId, piccPublicKey, EACCAProtocol.GetKeyHash("ECDH", pcdPublicKey), pcdPublicKey, pcdPrivateKey, anotherWrapper);

        CVCPrincipal cvcPrincipal = new CVCPrincipal("CAReference00001");
        List<CardVerifiableCertificate> terminalCertificates = new List<CardVerifiableCertificate>();
        AsymmetricKeyParameter? terminalKey = null;
        string documentNumber = "123456789";
        byte[]? cardChallenge = null;
        EACTAResult taResult = new EACTAResult(caResult, cvcPrincipal, terminalCertificates, terminalKey, documentNumber, cardChallenge);
        EACTAResult anotherTAResult = new EACTAResult(anotherCAResult, cvcPrincipal, terminalCertificates, terminalKey, documentNumber, cardChallenge);

        Assert.Equal(taResult.GetHashCode(), anotherTAResult.GetHashCode());
        Assert.Equal(taResult, anotherTAResult);
        Assert.Equal(taResult.ToString(), anotherTAResult.ToString());
    }

    private static KeyParameter GetRandomAESKey()
    {
        return new KeyParameter(Org.BouncyCastle.Security.SecureRandom.GetNextBytes(new Org.BouncyCastle.Security.SecureRandom(), 16)); // Java: KeyGenerator "AES"
    }
}
