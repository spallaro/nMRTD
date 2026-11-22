using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using static nMRTD.Tests.Helpers.TestData;

namespace nMRTD.Tests;

/// <summary>
/// DH Chip Authentication public keys in DG14 keep their domain parameters through a decode and encode
/// round trip: X9.42 keys (<c>dhpublicnumber</c>, with q, as RFC 3279 and TR-03110 describe) and PKCS #3
/// keys (<c>dhKeyAgreement</c>, without q).
/// </summary>
public class ChipAuthenticationDhKeyTests
{
    [Fact]
    public void KeyWithQSurvivesRoundTrip()
    {
        var publicKey = (DHPublicKeyParameters)KeyPairs.DH(DhWithQ).Public;
        var info = new ChipAuthenticationPublicKeyInfo(publicKey, BigInteger.One);

        var decoded = Assert.IsType<ChipAuthenticationPublicKeyInfo>(SecurityInfo.GetInstance(Asn1Object.FromByteArray(info.GetEncoded()!)));

        var decodedKey = Assert.IsType<DHPublicKeyParameters>(decoded.GetSubjectPublicKey());
        Assert.Equal(DhQ, decodedKey.Parameters.Q);
        Assert.Equal(publicKey, decodedKey);
        Assert.Equal(info, decoded);
    }

    [Fact]
    public void KeyWithQIsEncodedAsX942()
    {
        var publicKey = (DHPublicKeyParameters)KeyPairs.DH(DhWithQ).Public;
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfoOf(new ChipAuthenticationPublicKeyInfo(publicKey));

        Assert.Equal(X9ObjectIdentifiers.DHPublicNumber, spki.Algorithm.Algorithm);
        var domainParameters = DHDomainParameters.GetInstance(spki.Algorithm.Parameters);
        Assert.Equal(DhP, domainParameters.P.Value);
        Assert.Equal(DhG, domainParameters.G.Value);
        Assert.Equal(DhQ, domainParameters.Q.Value);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void X942EncodedKeyIsReencodedUnchanged(bool withOptionalFields)
    {
        var publicKey = (DHPublicKeyParameters)KeyPairs.DH(DhWithQ).Public;
        DerInteger? j = withOptionalFields ? new DerInteger(DhP.Subtract(BigInteger.One).Divide(DhQ)) : null;
        DHValidationParms? validation = withOptionalFields ? new DHValidationParms(new DerBitString(Hex("0102030405060708090A0B0C0D0E0F1011121314")), new DerInteger(42)) : null;
        var x942 = new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(X9ObjectIdentifiers.DHPublicNumber, new DHDomainParameters(new DerInteger(DhP), new DerInteger(DhG), new DerInteger(DhQ), j, validation)),
            new DerInteger(publicKey.Y));
        byte[] encoded = new DerSequence(new DerObjectIdentifier(SecurityInfo.ID_PK_DH), x942, new DerInteger(7)).GetEncoded(Asn1Encodable.Der);

        SecurityInfo? decoded = SecurityInfo.GetInstance(Asn1Object.FromByteArray(encoded));

        Assert.Equal(encoded, Assert.IsType<ChipAuthenticationPublicKeyInfo>(decoded).GetEncoded());
    }

    [Fact]
    public void Pkcs3KeyStaysPkcs3()
    {
        var publicKey = (DHPublicKeyParameters)KeyPairs.DH(DhNoQ).Public;
        var info = new ChipAuthenticationPublicKeyInfo(publicKey);
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfoOf(info);

        Assert.Equal(PkcsObjectIdentifiers.DhKeyAgreement, spki.Algorithm.Algorithm);
        Assert.Equal(info, SecurityInfo.GetInstance(Asn1Object.FromByteArray(info.GetEncoded()!)));
    }

    [Fact]
    public void DG14WithX942KeySurvivesRoundTrip()
    {
        var publicKey = (DHPublicKeyParameters)KeyPairs.DH(DhWithQ).Public;
        var dg14 = new DG14File(new List<SecurityInfo>
        {
            new ChipAuthenticationInfo(SecurityInfo.ID_CA_DH_AES_CBC_CMAC_128, ChipAuthenticationInfo.VERSION_1, BigInteger.One),
            new ChipAuthenticationPublicKeyInfo(publicKey, BigInteger.One),
        });

        var copy = new DG14File(new MemoryStream(dg14.GetEncoded()!));

        Assert.Equal(dg14.GetEncoded(), copy.GetEncoded());
        Assert.Equal(dg14.GetSecurityInfos().ToHashSet(), copy.GetSecurityInfos().ToHashSet());
    }

    private static SubjectPublicKeyInfo SubjectPublicKeyInfoOf(ChipAuthenticationPublicKeyInfo info) =>
        SubjectPublicKeyInfo.GetInstance(Asn1Sequence.GetInstance(Asn1Object.FromByteArray(info.GetEncoded()!))[1]);
}
