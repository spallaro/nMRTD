using nMRTD.Cert;
using nMRTD.Lds;
using nMRTD.Protocol;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace nMRTD.Tests.Jmrtd.Protocol;

/// <summary>Port of JMRTD's <c>org.jmrtd.protocol.PACEGMTest</c>.</summary>




public class PACEGMTest
{

    private static readonly byte[] ZERO_04_64 = [
            0x04,
            0,0,0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,0,0,
            0,0,0,0
    ];

    private static readonly byte[] ZERO_32 =
        [
                0,0,0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,0,0,
                0,0
        ];

    [Fact(Skip = "Not portable: Bouncy Castle .NET's ECPublicKeyParameters rejects the off-curve point (0, 0) that JCA's KeyFactory accepts, so the nMRTD calls under test are never reached.")]
    public void testP()
    {
        string oid = "0.4.0.127.0.7.2.2.4.2.1";

        ECDomainParameters secp256r1 = Util.GetECDomainParameters("secp256r1");
        var p = new ECPublicKeyParameters(secp256r1.Curve.CreatePoint(BigInteger.Zero, BigInteger.Zero), secp256r1);
        byte[] encodedPublicKey = PaceProtocol.EncodePublicKeyForSmartCard(p);
        int keyLength = PACEInfo.ToKeyLength(oid);

        var macKey = new KeyParameter(Util.DeriveKey(ZERO_32, "DESede", keyLength, Util.MAC_MODE));
        byte[] token = PaceProtocol.GenerateAuthenticationToken("0.4.0.127.0.7.2.2.4.2.1", macKey, p);
    }
}
