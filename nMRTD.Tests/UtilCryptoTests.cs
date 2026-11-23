using nMRTD.Lds;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using static nMRTD.Tests.Helpers.TestData;

namespace nMRTD.Tests;

/// <summary>
/// The key-related helpers of <see cref="Util"/>: public key encoding, key derivation (BSI TR-03110 KDF),
/// algorithm name inference and EC helpers.
/// </summary>
public class UtilCryptoTests
{
    [Fact]
    public void DhKeyWithQEncodesAsX942AndKeepsQ()
    {
        var key = (DHPublicKeyParameters)KeyPairs.DH(DhWithQ).Public;

        var spki = Util.ToSubjectPublicKeyInfo(key)!;
        var decoded = Assert.IsType<DHPublicKeyParameters>(Util.ToPublicKey(spki));

        Assert.Equal(X9ObjectIdentifiers.DHPublicNumber, spki.Algorithm.Algorithm);
        Assert.Equal(DhQ, decoded.Parameters.Q);
        Assert.Equal(key, decoded);
    }

    [Fact]
    public void DhKeyWithoutQEncodesAsPkcs3()
    {
        var key = (DHPublicKeyParameters)KeyPairs.DH(DhNoQ).Public;

        var spki = Util.ToSubjectPublicKeyInfo(key)!;

        Assert.Equal(PkcsObjectIdentifiers.DhKeyAgreement, spki.Algorithm.Algorithm);
        Assert.Equal(key, Util.ToPublicKey(spki));
    }

    [Fact]
    public void EcKeyEncodesWithExplicitParameters()
    {
        var key = (ECPublicKeyParameters)KeyPairs.EC("brainpoolP256r1").Public;

        var spki = Util.ToSubjectPublicKeyInfo(key)!;

        Assert.False(X962Parameters.GetInstance(spki.Algorithm.Parameters).IsNamedCurve);
        Assert.Equal(key, Util.ToPublicKey(spki));
    }

    [Fact]
    public void OtherKeysAreNotEncoded()
    {
        Assert.Null(Util.ToSubjectPublicKeyInfo(SigningFixtures.KeyPair.Public));
        Assert.Null(Util.ToPublicKey(new Org.BouncyCastle.Asn1.X509.SubjectPublicKeyInfo(
            new Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier(new Org.BouncyCastle.Asn1.DerObjectIdentifier("1.2.3.4")), new byte[] { 1 })));
    }

    /// <summary>BSI TR-03110 KDF: K = H(seed || nonce || counter), truncated; SHA-1 for 3DES and AES-128,
    /// SHA-256 for AES-192 and AES-256.</summary>
    [Theory]
    [InlineData("AES", 128, "SHA-1", 16)]
    [InlineData("AES", 192, "SHA-256", 24)]
    [InlineData("AES", 256, "SHA-256", 32)]
    public void AesKeyDerivationTruncatesTheRightHash(string cipher, int keyLength, string digest, int keyBytes)
    {
        byte[] seed = Hex("0102030405060708090A0B0C0D0E0F10");
        byte[] nonce = Hex("A1A2A3A4");

        byte[] key = Util.DeriveKey(seed, cipher, keyLength, nonce, Util.ENC_MODE);

        byte[] hash = DigestUtilities.CalculateDigest(digest, [.. seed, .. nonce, 0, 0, 0, (byte)Util.ENC_MODE]);
        Assert.Equal(hash[..keyBytes], key);
        Assert.Equal(digest, Util.InferDigestAlgorithmFromCipherAlgorithmForKeyDerivation(cipher, keyLength));
    }

    [Fact]
    public void TripleDesKeyDerivationRepeatsTheFirstKey()
    {
        byte[] seed = Hex("0102030405060708090A0B0C0D0E0F10");

        byte[] key = Util.DeriveKey(seed, "DESede", 128, null, Util.MAC_MODE);

        byte[] hash = DigestUtilities.CalculateDigest("SHA-1", [.. seed, 0, 0, 0, (byte)Util.MAC_MODE]);
        Assert.Equal([.. hash[..16], .. hash[..8]], key);
    }

    [Theory]
    [InlineData("DESede", 192)]
    [InlineData("AES", 100)]
    [InlineData("Blowfish", 128)]
    public void UnsupportedKeyDerivationIsRejected(string cipher, int keyLength) =>
        Assert.ThrowsAny<ArgumentException>(() => Util.DeriveKey(Hex("00"), cipher, keyLength, null, Util.ENC_MODE));

    [Theory]
    [InlineData("SHA1withRSA", "SHA-1")]
    [InlineData("SHA224withECDSA", "SHA-224")]
    [InlineData("sha256withRSA", "SHA-256")]
    [InlineData("SHA384withECDSA", "SHA-384")]
    [InlineData("SHA512withRSA", "SHA-512")]
    [InlineData("SHA256withRSAandMGF1", "SHA-256")]
    [InlineData("RSA", null)]
    public void DigestIsInferredFromTheSignatureAlgorithm(string signatureAlgorithm, string? digest) =>
        Assert.Equal(digest, Util.InferDigestAlgorithmFromSignatureAlgorithm(signatureAlgorithm));

    [Fact]
    public void KeyTypeHelpers()
    {
        var dh = (DHPublicKeyParameters)KeyPairs.DH(DhWithQ).Public;
        var ec = KeyPairs.EC("brainpoolP256r1");

        Assert.Equal("DH", Util.InferKeyAgreementAlgorithm(dh));
        Assert.Equal("ECDH", Util.InferKeyAgreementAlgorithm(ec.Public));
        Assert.Equal(SecurityInfo.ID_PK_DH, Util.InferProtocolIdentifier(dh));
        Assert.Equal(SecurityInfo.ID_PK_ECDH, Util.InferProtocolIdentifier(ec.Public));
        Assert.Throws<ArgumentException>(() => Util.InferProtocolIdentifier(SigningFixtures.KeyPair.Public));

        Assert.Same(dh.Parameters, Util.GetAlgorithmParams(dh));
        Assert.Same(((ECPublicKeyParameters)ec.Public).Parameters, Util.GetAlgorithmParams(ec.Public));
        Assert.Same(((ECPrivateKeyParameters)ec.Private).Parameters, Util.GetAlgorithmParams(ec.Private));
        Assert.Throws<ArgumentException>(() => Util.GetAlgorithmParams(null));
        Assert.Throws<NotSupportedException>(() => Util.GetAlgorithmParams(SigningFixtures.KeyPair.Public));

        Assert.Equal("EC [brainpoolP256r1]", Util.GetDetailedPublicKeyAlgorithm(ec.Public));
        Assert.StartsWith("DH [p.length = 1024", Util.GetDetailedPublicKeyAlgorithm(dh));
        Assert.Equal("RSA [2048 bit]", Util.GetDetailedPublicKeyAlgorithm(SigningFixtures.KeyPair.Public));
        Assert.Equal("null", Util.GetDetailedPublicKeyAlgorithm(null));
    }

    [Fact]
    public void MissingDomainParametersAreAddedToAnEcKey()
    {
        var ec = (ECPublicKeyParameters)KeyPairs.EC("brainpoolP256r1").Public;
        var dh = (DHPublicKeyParameters)KeyPairs.DH(DhWithQ).Public;

        var withParameters = Assert.IsType<ECPublicKeyParameters>(Util.AddMissingParametersToPublicKey(BrainpoolP256r1, ec));

        Assert.Equal(ec.Q, withParameters.Q);
        Assert.Same(BrainpoolP256r1, withParameters.Parameters);
        Assert.Same(dh, Util.AddMissingParametersToPublicKey(BrainpoolP256r1, dh));
        Assert.Null(Util.AddMissingParametersToPublicKey(BrainpoolP256r1, null));
    }

    [Fact]
    public void AffineYIsOneOfTheTwoSquareRoots()
    {
        var q = ((ECPublicKeyParameters)KeyPairs.EC("brainpoolP256r1").Public).Q.Normalize();
        BigInteger p = BrainpoolP256r1.Curve.Field.Characteristic;
        BigInteger y = q.AffineYCoord.ToBigInteger();

        BigInteger computed = Util.ComputeAffineY(q.AffineXCoord.ToBigInteger(), BrainpoolP256r1);

        Assert.True(computed.Equals(y) || computed.Equals(p.Subtract(y)));
    }
}
