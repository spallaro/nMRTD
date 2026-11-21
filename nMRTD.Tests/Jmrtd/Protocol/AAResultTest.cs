using nMRTD.Cert;
using nMRTD.Lds;
using nMRTD.Protocol;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace nMRTD.Tests.Jmrtd.Protocol;

/// <summary>Port of JMRTD's <c>org.jmrtd.protocol.AAResultTest</c>.</summary>
public class AAResultTest
{

    [Fact]
    public void testAAResult()
    {
        string digAlg = "SHA-256";
        string sigAlg = "SHA256WithECDSA";


        AsymmetricCipherKeyPair aaKeyPair = KeyPairs.EC("P-256");
        AsymmetricKeyParameter publicKey = aaKeyPair.Public;
        AsymmetricKeyParameter privateKey = aaKeyPair.Private;

        ISigner signature = Org.BouncyCastle.Security.SignerUtilities.GetSigner(sigAlg);
        signature.Init(true, privateKey);
        byte[] challenge = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        signature.BlockUpdate(challenge, 0, challenge.Length);
        byte[] response = signature.GenerateSignature();
        Assert.NotNull(response);

        AAResult aaResult = new AAResult(publicKey, digAlg, sigAlg, challenge, response);
        Assert.Equal(digAlg, aaResult.DigestAlgorithm);
        Assert.Equal(sigAlg, aaResult.SignatureAlgorithm);
        Assert.Equal(publicKey, aaResult.PublicKey);
        Assert.True(Enumerable.SequenceEqual(challenge, aaResult.GetChallenge()!));
        Assert.True(Enumerable.SequenceEqual(response, aaResult.GetResponse()!));

        AAResult anotherAAResult = new AAResult(publicKey, digAlg, sigAlg, (byte[])challenge.Clone(), (byte[])response.Clone());
        Assert.Equal(aaResult.GetHashCode(), anotherAAResult.GetHashCode());
        Assert.Equal(aaResult, anotherAAResult);
        Assert.Equal(aaResult.ToString(), anotherAAResult.ToString());

        int originalHashCode = aaResult.GetHashCode();
        challenge[0] ^= 0x7F;
        response[0] ^= 0x7F;
        Assert.Equal(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 },
                aaResult.GetChallenge());
        byte[] returnedChallenge = aaResult.GetChallenge()!;
        byte[] returnedResponse = aaResult.GetResponse()!;
        returnedChallenge[0] ^= 0x7F;
        returnedResponse[0] ^= 0x7F;
        Assert.Equal(originalHashCode, aaResult.GetHashCode());
        Assert.Equal(anotherAAResult, aaResult);
    }
}
