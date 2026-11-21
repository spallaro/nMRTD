using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.Protocol;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using static nMRTD.Tests.EndToEnd.EndToEnd;

namespace nMRTD.Tests.EndToEnd;

/// <summary>
/// Active Authentication end to end. The library only transports the challenge and the signature (it has no
/// verifier), so the test verifies the response against the DG15 key read from the chip, as a terminal would.
/// </summary>
public class ActiveAuthenticationEndToEndTests
{
    private static bool VerifyRsa(RsaKeyParameters key, byte[] challenge, byte[] signature)
    {
        var verifier = new Iso9796d2Signer(new RsaEngine(), new Sha1Digest(), true);
        verifier.Init(false, key);
        verifier.UpdateWithRecoveredMessage(signature);
        verifier.BlockUpdate(challenge, 0, challenge.Length);
        return verifier.VerifySignature(signature);
    }

    private static bool VerifyEcdsa(ECPublicKeyParameters key, byte[] challenge, byte[] signature)
    {
        var verifier = new ECDsaSigner();
        verifier.Init(false, key);
        var digest = new Sha256Digest();
        digest.BlockUpdate(challenge, 0, challenge.Length);
        byte[] hash = new byte[digest.GetDigestSize()];
        digest.DoFinal(hash, 0);
        int half = signature.Length / 2;
        return verifier.VerifySignature(hash, new BigInteger(1, signature[..half]), new BigInteger(1, signature[half..]));
    }

    [Theory]
    [InlineData("RSA-1024", false)]
    [InlineData("RSA-2048", true)]
    [InlineData("RSA-2048", false)]
    [InlineData("ECDSA-P256", true)]
    public void ActiveAuthenticationResponseVerifiesWithTheDg15Key(string keyKind, bool usePace)
    {
        var document = new SimulatedDocument
        {
            ActiveAuthenticationKey = keyKind switch
            {
                "RSA-1024" => SimulatedDocument.RsaKey1024,
                "RSA-2048" => SimulatedDocument.RsaKey2048,
                _ => SimulatedDocument.GenerateEc(12),
            },
        };
        document.Pace.Add(new SimulatedChip.PaceSupport(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, 13));
        SimulatedChip chip = document.Build();
        PassportService service = Open(chip);
        if (usePace)
        {
            DoPace(service, PaceKeySpec.CreateCanKey(SimulatedDocument.Can));
        }
        else
        {
            DoBac(service);
        }

        AsymmetricKeyParameter publicKey = new DG15File(new MemoryStream(Read(service, PassportService.EF_DG15))).GetPublicKey()!;
        byte[] challenge = ChipCrypto.RandomBytes(8);
        bool isEc = publicKey is ECPublicKeyParameters;
        if (isEc)
        {
            IReadOnlyCollection<SecurityInfo> infos = new DG14File(new MemoryStream(Read(service, PassportService.EF_DG14))).GetSecurityInfos();
            Assert.Equal(ActiveAuthenticationInfo.ECDSA_PLAIN_SHA256_OID, infos.OfType<ActiveAuthenticationInfo>().Single().GetSignatureAlgorithmOID());
        }

        AAResult result = service.DoAA(publicKey, isEc ? "SHA-256" : "SHA-1", isEc ? "SHA256withECDSA" : "SHA1withRSA/ISO9796-2", challenge);

        byte[] response = result.GetResponse()!;
        Assert.Equal(challenge, result.GetChallenge());
        Assert.True(isEc
            ? VerifyEcdsa((ECPublicKeyParameters)publicKey, challenge, response)
            : VerifyRsa((RsaKeyParameters)publicKey, challenge, response));
        byte[] otherChallenge = challenge.Select(b => (byte)~b).ToArray();
        Assert.False(isEc
            ? VerifyEcdsa((ECPublicKeyParameters)publicKey, otherChallenge, response)
            : VerifyRsa((RsaKeyParameters)publicKey, otherChallenge, response));
    }
}
