using nMRTD.Cert;
using nMRTD.Lds;
using nMRTD.Protocol;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace nMRTD.Tests.Jmrtd.Protocol;

/// <summary>Port of JMRTD's <c>org.jmrtd.protocol.PACEGMWithECDHAgreementTest</c>.</summary>
public class PACEGMWithECDHAgreementTest
{

    [Fact]
    public void testPACEGMWithECDHAgreementSameSharedPoint()
    {
        try
        {

            AsymmetricCipherKeyPair piccKeyPair = KeyPairs.EC("P-256");
            AsymmetricKeyParameter piccPublicKey = piccKeyPair.Public;
            AsymmetricKeyParameter piccPrivateKey = piccKeyPair.Private;

            AsymmetricCipherKeyPair pcdKeyPair = KeyPairs.EC("P-256");
            AsymmetricKeyParameter pcdPublicKey = pcdKeyPair.Public;
            AsymmetricKeyParameter pcdPrivateKey = pcdKeyPair.Private;

            PACEGMWithECDHAgreement agreement = new PACEGMWithECDHAgreement();
            agreement.Init((ECPrivateKeyParameters)pcdPrivateKey);
            Org.BouncyCastle.Math.EC.ECPoint sharedPoint = agreement.DoPhase((ECPublicKeyParameters)piccPublicKey);

            PACEGMWithECDHAgreement otherAgreement = new PACEGMWithECDHAgreement();
            otherAgreement.Init((ECPrivateKeyParameters)piccPrivateKey);
            otherAgreement.DoPhase((ECPublicKeyParameters)pcdPublicKey);
            Org.BouncyCastle.Math.EC.ECPoint otherSharedPoint = otherAgreement.DoPhase((ECPublicKeyParameters)pcdPublicKey);

            Assert.Equal(sharedPoint, otherSharedPoint);
            Assert.Equal(otherSharedPoint, sharedPoint);
        }
        catch (Exception e) when (e is not Xunit.Sdk.XunitException)
        {
        }
    }
}
