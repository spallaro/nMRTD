using nMRTD.Cert;
using nMRTD.Lds;
using nMRTD.Protocol;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace nMRTD.Tests.Jmrtd.Protocol;

/// <summary>Port of JMRTD's <c>org.jmrtd.protocol.EACCAProtocolTest</c>.</summary>
/// <remarks>
/// Java-only, not ported: <c>testGetKeyHashNonBouncyCastleKey</c> (a JCA <c>ECPublicKey</c> from another
/// provider; nMRTD only has Bouncy Castle keys).
/// </remarks>
/**
  * Tests for the pure (non-APDU) helper logic in {@link EACCAProtocol}:
  * the OID-driven secure messaging key derivation in
  * {@link EACCAProtocol#restartSecureMessaging} and the best-effort OID
  * inference in {@code inferChipAuthenticationOIDfromPublicKeyOID}.
  */
public class EACCAProtocolTest
{

    /*
      * ICAO Doc 9303 Part 11, Appendix D.2 BAC worked example key seed, reused
      * here as a stand-in Chip Authentication shared secret since restartSecureMessaging
      * applies the same TR-SAC 4.2.1 KDF (DESede, 128-bit key length, ENC/MAC mode)
      * as BAC does; see UtilTest.testBACKeyDerivationICAOWorkedExample for the
      * independent verification of this vector.
      */
    private static readonly byte[] DESEDE_SHARED_SECRET = TestData.Hex("7FF74C962710A2404373FC9CE8A1C6E2");
    private static readonly byte[] EXPECTED_DESEDE_ENC_KEY = TestData.Hex("906CFE5E080051EFA05FC5B044E535CA906CFE5E080051EF");
    private static readonly byte[] EXPECTED_DESEDE_MAC_KEY = TestData.Hex("E4F1F75506EC63594CA27D0EF91C01D7E4F1F75506EC6359");

    /*
      * BSI TR-03110 / ICAO 9303 Part 11 Appendix G.1.1 ECDH-GM worked example
      * shared secret and resulting AES-128 session keys, reused here since
      * restartSecureMessaging applies the same TR-SAC 4.2.2 KDF (AES, 128-bit
      * key length, ENC/MAC mode) as PACE post-key-agreement does; see
      * PACEProtocolTest.testSupplementSampleECDHGM for the full worked example.
      */
    private static readonly byte[] AES_SHARED_SECRET = TestData.Hex(
            "28768D20701247DAE81804C9E780EDE582A9996DB4A315020B2733197DB84925");
    private static readonly byte[] EXPECTED_AES_ENC_KEY = TestData.Hex("F5F0E35C0D7161EE6724EE513A0D9A7F");
    private static readonly byte[] EXPECTED_AES_MAC_KEY = TestData.Hex("FE251C7858B356B24514B3BD5F4297D1");

    [Fact]
    public void testRestartSecureMessagingDESede()
    {
        SecureMessagingWrapper wrapper = EACCAProtocol.RestartSecureMessaging(
                SecurityInfo.ID_CA_ECDH_3DES_CBC_CBC, DESEDE_SHARED_SECRET, 256, true);

        Assert.IsType<DESedeSecureMessagingWrapper>(wrapper);
        Assert.Equal(EXPECTED_DESEDE_ENC_KEY, wrapper.EncryptionKey.GetKey());
        Assert.Equal(EXPECTED_DESEDE_MAC_KEY, wrapper.MacKey.GetKey());
        Assert.Equal(0L, wrapper.SendSequenceCounter);
        Assert.Equal(256, wrapper.MaxTransceiveLength);
        Assert.True(wrapper.ShouldCheckMac);
    }

    [Fact]
    public void testRestartSecureMessagingAES()
    {
        SecureMessagingWrapper wrapper = EACCAProtocol.RestartSecureMessaging(
                SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128, AES_SHARED_SECRET, 65536, false);

        Assert.IsType<AESSecureMessagingWrapper>(wrapper);
        Assert.Equal(EXPECTED_AES_ENC_KEY, wrapper.EncryptionKey.GetKey());
        Assert.Equal(EXPECTED_AES_MAC_KEY, wrapper.MacKey.GetKey());
        Assert.Equal(0L, wrapper.SendSequenceCounter);
        Assert.Equal(65536, wrapper.MaxTransceiveLength);
        Assert.False(wrapper.ShouldCheckMac);
    }

    [Fact]
    public void testInferChipAuthenticationOIDfromPublicKeyOID()
    {
        Assert.Equal(SecurityInfo.ID_CA_ECDH_3DES_CBC_CBC,
                inferChipAuthenticationOIDfromPublicKeyOID(SecurityInfo.ID_PK_ECDH));
        Assert.Equal(SecurityInfo.ID_CA_DH_3DES_CBC_CBC,
                inferChipAuthenticationOIDfromPublicKeyOID(SecurityInfo.ID_PK_DH));
        Assert.Null(inferChipAuthenticationOIDfromPublicKeyOID("1.2.3.4.5"));
        Assert.Null(inferChipAuthenticationOIDfromPublicKeyOID(null));
    }

    private static string? inferChipAuthenticationOIDfromPublicKeyOID(string? publicKeyOID)
    {
        System.Reflection.MethodInfo method = typeof(EACCAProtocol).GetMethod("InferChipAuthenticationOidFromPublicKeyOid",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;
        return (string?)method.Invoke(null, [publicKeyOID]);
    }

    /*
      * The key hash (Comp) of a non-BouncyCastle EC key is the same as of the BouncyCastle key
      * (was a ClassCastException), and is the x-coordinate of fixed length.
      */
    /*
      * An EC public key that is not a BouncyCastle key (as from another provider, for example on Android).
      */
}
