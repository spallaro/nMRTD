using nMRTD.Lds;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using static nMRTD.Tests.Helpers.TestData;

namespace nMRTD.Tests.Jmrtd.Lds;

/// <summary>Port of JMRTD's <c>org.jmrtd.lds.ActiveAuthenticationInfoTest</c>.</summary>
/// <remarks>Java-only, not ported: <c>testActiveAuthenticationInfoSerializable</c> (Java serialization).</remarks>
public class ActiveAuthenticationInfoTest
{
    [Fact]
    public void testActiveAuthenticationInfo()
    {
        var aaInfo = new ActiveAuthenticationInfo(ActiveAuthenticationInfo.ECDSA_PLAIN_SHA256_OID); //  0.4.0.127.0.7.1.1.4.1.3
        Assert.Equal(ActiveAuthenticationInfo.ID_AA, aaInfo.GetObjectIdentifier());
        Assert.Equal("id-AA", aaInfo.GetProtocolOIDString());
        Assert.Equal(ActiveAuthenticationInfo.ECDSA_PLAIN_SHA256_OID, aaInfo.GetSignatureAlgorithmOID());
    }

    [Fact]
    public void testActiveAuthenticationInfoEquals()
    {
        var aaInfo = new ActiveAuthenticationInfo(ActiveAuthenticationInfo.ECDSA_PLAIN_SHA256_OID); //  0.4.0.127.0.7.1.1.4.1.3
        var anotherAAInfo = new ActiveAuthenticationInfo(ActiveAuthenticationInfo.ECDSA_PLAIN_SHA256_OID); //  0.4.0.127.0.7.1.1.4.1.3
        Assert.Equal(aaInfo.GetHashCode(), anotherAAInfo.GetHashCode());
        Assert.Equal(aaInfo, anotherAAInfo);
        Assert.Equal(aaInfo.ToString(), anotherAAInfo.ToString());
    }
}

/// <summary>Port of JMRTD's <c>org.jmrtd.lds.ChipAuthenticationInfoTest</c>.</summary>
/// <remarks>Java-only, not ported: <c>testSerializable</c> (Java serialization).</remarks>
public class ChipAuthenticationInfoTest
{
    [Fact]
    public void testConstruct()
    {
        Assert.NotNull(GetSampleObject());
    }

    [Fact]
    public void testChipAuthenticationInfoEquals()
    {
        ChipAuthenticationInfo chipAuthenticationInfo = GetSampleObject();
        var anotherChipAuthenticationInfo = new ChipAuthenticationInfo(chipAuthenticationInfo.GetObjectIdentifier(), chipAuthenticationInfo.GetVersion(), chipAuthenticationInfo.GetKeyId());
        Assert.Equal(chipAuthenticationInfo.GetHashCode(), anotherChipAuthenticationInfo.GetHashCode());
        Assert.Equal(chipAuthenticationInfo, anotherChipAuthenticationInfo);
        Assert.Equal(chipAuthenticationInfo.ToString(), anotherChipAuthenticationInfo.ToString());
    }

    [Fact]
    public void testChipAuthenticationInfoEqualsWithoutKeyId()
    {
        var chipAuthenticationInfo = new ChipAuthenticationInfo(SecurityInfo.ID_CA_DH_3DES_CBC_CBC, ChipAuthenticationInfo.VERSION_1);
        var anotherChipAuthenticationInfo = new ChipAuthenticationInfo(SecurityInfo.ID_CA_DH_3DES_CBC_CBC, ChipAuthenticationInfo.VERSION_1);
        Assert.Equal(chipAuthenticationInfo.GetHashCode(), anotherChipAuthenticationInfo.GetHashCode());
        Assert.Equal(chipAuthenticationInfo, anotherChipAuthenticationInfo);

        var withKeyId = new ChipAuthenticationInfo(SecurityInfo.ID_CA_DH_3DES_CBC_CBC, ChipAuthenticationInfo.VERSION_1, BigInteger.ValueOf(1));
        Assert.NotEqual(chipAuthenticationInfo, withKeyId);
    }

    /// <summary>Elaborate sample.</summary>
    private static ChipAuthenticationInfo GetSampleObject() =>
        new(SecurityInfo.ID_CA_DH_3DES_CBC_CBC, ChipAuthenticationInfo.VERSION_1, BigInteger.ValueOf(1));
}

/// <summary>Port of JMRTD's <c>org.jmrtd.lds.ChipAuthenticationPublicKeyInfoTest</c>.</summary>
/// <remarks>Java-only, not ported: <c>testSerializable</c> (Java serialization).</remarks>
public class ChipAuthenticationPublicKeyInfoTest
{
    [Fact]
    public void testConstruct()
    {
        Assert.NotNull(GetSampleObject());
    }

    [Fact]
    public void testChipAuthenticationPublicKeyInfoEquals()
    {
        ChipAuthenticationPublicKeyInfo chipAuthenticationPublicKeyInfo = GetSampleObject();
        var anotherChipAuthenticationPublicKeyInfo = new ChipAuthenticationPublicKeyInfo(chipAuthenticationPublicKeyInfo.GetSubjectPublicKey(), chipAuthenticationPublicKeyInfo.GetKeyId());
        Assert.Equal(chipAuthenticationPublicKeyInfo.GetHashCode(), anotherChipAuthenticationPublicKeyInfo.GetHashCode());
        Assert.Equal(chipAuthenticationPublicKeyInfo, anotherChipAuthenticationPublicKeyInfo);
        Assert.Equal(chipAuthenticationPublicKeyInfo.ToString(), anotherChipAuthenticationPublicKeyInfo.ToString());
    }

    /// <summary>Elaborate sample (Java: a 192-bit EC key from Bouncy Castle, which is P-192).</summary>
    private static ChipAuthenticationPublicKeyInfo GetSampleObject() =>
        new(KeyPairs.EC("P-192").Public, BigInteger.ValueOf(1));
}

/// <summary>Port of JMRTD's <c>org.jmrtd.lds.TerminalAuthenticationInfoTest</c>.</summary>
/// <remarks>Java-only, not ported: <c>testSerializable</c> (Java serialization).</remarks>
public class TerminalAuthenticationInfoTest
{
    [Fact]
    public void testTerminalAuthenticationInfo()
    {
        var taInfo = new TerminalAuthenticationInfo();
        Assert.Equal(SecurityInfo.ID_TA, taInfo.GetObjectIdentifier()); // 0.4.0.127.0.7.2.2.2
        Assert.Equal("id-TA", taInfo.GetProtocolOIDString());
        Assert.Equal(1, taInfo.GetVersion());
        Assert.Equal(-1, taInfo.GetFileId());
        Assert.Equal(-1, taInfo.GetShortFileId());
    }
}

/// <summary>Port of JMRTD's <c>org.jmrtd.lds.CardAccessFileTest</c>.</summary>
public class CardAccessFileTest
{
    [Fact]
    public void testCardAccessFile()
    {
        var aaInfo = new ActiveAuthenticationInfo(ActiveAuthenticationInfo.ECDSA_PLAIN_SHA256_OID);
        var paceInfo = new PACEInfo(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256, 2, PACEInfo.PARAM_ID_ECP_NIST_P256_R1);
        List<SecurityInfo> securityInfos = [aaInfo, paceInfo];
        var cardAccessFile = new CardAccessFile(securityInfos);
        IReadOnlyCollection<SecurityInfo> actualSecurityInfos = cardAccessFile.GetSecurityInfos();
        Assert.Equal(new HashSet<SecurityInfo>(securityInfos), new HashSet<SecurityInfo>(actualSecurityInfos));
    }

    [Fact]
    public void testCardAccessFileEquals()
    {
        var aaInfo = new ActiveAuthenticationInfo(ActiveAuthenticationInfo.ECDSA_PLAIN_SHA256_OID);
        var paceInfo = new PACEInfo(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256, 2, PACEInfo.PARAM_ID_ECP_NIST_P256_R1);
        List<SecurityInfo> securityInfos = [aaInfo, paceInfo];
        var cardAccessFile = new CardAccessFile(securityInfos);

        var anotherAAInfo = new ActiveAuthenticationInfo(ActiveAuthenticationInfo.ECDSA_PLAIN_SHA256_OID);
        var anotherPACEInfo = new PACEInfo(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256, 2, PACEInfo.PARAM_ID_ECP_NIST_P256_R1);
        List<SecurityInfo> anotherSecurityInfos = [anotherAAInfo, anotherPACEInfo];
        var anotherCardAccessFile = new CardAccessFile(anotherSecurityInfos);

        Assert.Equal(cardAccessFile, anotherCardAccessFile);
    }
}

/// <summary>Port of JMRTD's <c>org.jmrtd.lds.CardSecurityFileTest</c>.</summary>
/// <remarks>
/// JMRTD's helpers <c>testSimilar</c> and <c>testAttributesSHA256withECDSASample</c> are not annotated
/// as tests and never run there, so they are not ported.
/// </remarks>
public class CardSecurityFileTest
{
    [Fact]
    public void testParseSampleCardSecurityFileFromResource()
    {
        using Stream inputStream = Fixtures.GetInputStream("/efcardsecurity/efcardsecurity.dump");
        Assert.NotNull(inputStream);
        var cardSecurityFile = new CardSecurityFile(inputStream);
        Assert.NotNull(cardSecurityFile);
    }
}

/// <summary>Port of JMRTD's <c>org.jmrtd.lds.CVCAFileTest</c>.</summary>
public class CVCAFileTest
{
    [Fact]
    public void test1()
    {
        string name1 = "CAReference00001";
        var f = new CVCAFile(name1, null);
        Assert.Equal(name1, f.GetCAReference()!.Name);
        Assert.Null(f.GetAltCAReference());
    }

    [Fact]
    public void test2()
    {
        string name1 = "CAReference00001";
        string name2 = "CAReference00002";
        var f = new CVCAFile(name1, name2);
        Assert.Equal(name1, f.GetCAReference()!.Name);
        Assert.Equal(name2, f.GetAltCAReference()!.Name);
    }

    [Fact]
    public void testReflexive1()
    {
        string name1 = "CAReference00001";
        string name2 = "CAReference00002";
        var f = new CVCAFile(name1, name2);
        var input = new MemoryStream(f.GetEncoded()!);
        var f2 = new CVCAFile(input);
        Assert.Equal(f.GetEncoded(), f2.GetEncoded());
    }

    [Fact]
    public void testReflexive2()
    {
        string name1 = "CAReference00001";
        var f = new CVCAFile(name1, null);
        var input = new MemoryStream(f.GetEncoded()!);
        var f2 = new CVCAFile(input);
        Assert.Equal(f.GetEncoded(), f2.GetEncoded());
    }
}

/// <summary>Port of JMRTD's <c>org.jmrtd.lds.SecurityInfoTest</c>.</summary>
public class SecurityInfoTest
{
    [Fact]
    public void testActiveAuthenticationInfoRoundTrip()
    {
        var original = new ActiveAuthenticationInfo(ActiveAuthenticationInfo.ECDSA_PLAIN_SHA256_OID);
        Asn1Object der = original.GetDERObject();
        Assert.NotNull(der);

        SecurityInfo? parsed = SecurityInfo.GetInstance(der);
        ActiveAuthenticationInfo actual = Assert.IsType<ActiveAuthenticationInfo>(parsed);
        Assert.Equal(original.GetObjectIdentifier(), actual.GetObjectIdentifier());
        Assert.Equal(original.GetVersion(), actual.GetVersion());
        Assert.Equal(original.GetSignatureAlgorithmOID(), actual.GetSignatureAlgorithmOID());
        Assert.Equal(original, actual);
    }

    [Fact]
    public void testChipAuthenticationInfoRoundTrip()
    {
        var original = new ChipAuthenticationInfo(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128, 2, BigInteger.ValueOf(42));
        Asn1Object der = original.GetDERObject();
        Assert.NotNull(der);

        SecurityInfo? parsed = SecurityInfo.GetInstance(der);
        ChipAuthenticationInfo actual = Assert.IsType<ChipAuthenticationInfo>(parsed);
        Assert.Equal(original.GetObjectIdentifier(), actual.GetObjectIdentifier());
        Assert.Equal(original.GetVersion(), actual.GetVersion());
        Assert.Equal(original.GetKeyId(), actual.GetKeyId());
        Assert.Equal(original, actual);
    }

    [Fact]
    public void testChipAuthenticationPublicKeyInfoRoundTrip()
    {
        var kp = KeyPairs.EC("P-256"); // Java: KeyPairGenerator "EC", 256 bits
        var original = new ChipAuthenticationPublicKeyInfo(SecurityInfo.ID_PK_ECDH, kp.Public, BigInteger.ValueOf(99));
        Asn1Object der = original.GetDERObject();
        Assert.NotNull(der);

        SecurityInfo? parsed = SecurityInfo.GetInstance(der);
        ChipAuthenticationPublicKeyInfo actual = Assert.IsType<ChipAuthenticationPublicKeyInfo>(parsed);
        Assert.Equal(original.GetObjectIdentifier(), actual.GetObjectIdentifier());
        Assert.Equal(original.GetKeyId(), actual.GetKeyId());
        Assert.Equal(original.GetSubjectPublicKey(), actual.GetSubjectPublicKey());
        Assert.Equal(original, actual);
    }

    [Fact]
    public void testTerminalAuthenticationInfoRoundTrip()
    {
        var original = new TerminalAuthenticationInfo(0x011C, 2);
        Asn1Object der = original.GetDERObject();
        Assert.NotNull(der);

        SecurityInfo? parsed = SecurityInfo.GetInstance(der);
        TerminalAuthenticationInfo actual = Assert.IsType<TerminalAuthenticationInfo>(parsed);
        Assert.Equal(original.GetObjectIdentifier(), actual.GetObjectIdentifier());
        Assert.Equal(original.GetVersion(), actual.GetVersion());
        Assert.Equal(original.GetFileId(), actual.GetFileId());
        Assert.Equal(original.GetShortFileId(), actual.GetShortFileId());
        Assert.Equal(original, actual);
    }

    [Fact]
    public void testPACEInfoRoundTrip()
    {
        var original = new PACEInfo(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, 2, BigInteger.ValueOf(3));
        Asn1Object der = original.GetDERObject();
        Assert.NotNull(der);

        SecurityInfo? parsed = SecurityInfo.GetInstance(der);
        PACEInfo actual = Assert.IsType<PACEInfo>(parsed);
        Assert.Equal(original.GetObjectIdentifier(), actual.GetObjectIdentifier());
        Assert.Equal(original.GetVersion(), actual.GetVersion());
        Assert.Equal(original.GetParameterId(), actual.GetParameterId());
        Assert.Equal(original, actual);
    }

    [Fact]
    public void testPACEDomainParameterInfoRoundTrip()
    {
        var curve = new FpCurve(
            new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839"),
            new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16),
            new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16),
            new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307"),
            BigInteger.One);
        var ecSpec = new ECDomainParameters(
            curve,
            curve.DecodePoint(Hex("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")),
            new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307"),
            BigInteger.One);
        AlgorithmIdentifier ai = PACEDomainParameterInfo.ToAlgorithmIdentifier(ecSpec);

        var original = new PACEDomainParameterInfo(SecurityInfo.ID_PACE_ECDH_GM, ai, BigInteger.ValueOf(11));
        Asn1Object der = original.GetDERObject();
        Assert.NotNull(der);

        SecurityInfo? parsed = SecurityInfo.GetInstance(der);
        PACEDomainParameterInfo actual = Assert.IsType<PACEDomainParameterInfo>(parsed);
        Assert.Equal(original.GetObjectIdentifier(), actual.GetObjectIdentifier());
        Assert.Equal(original.GetParameterId(), actual.GetParameterId());
        Assert.Equal(original, actual);
    }

    [Fact(Skip = "Possible divergence from JMRTD: SecurityInfo.GetInstance lets Bouncy Castle's own ArgumentException through (catch ... when e is not ArgumentException), JMRTD wraps every exception as \"Malformed input stream.\".")]
    public void testMalformedInput()
    {
        Asn1Object nonSeq = new DerInteger(42);
        ArgumentException e1 = Assert.ThrowsAny<ArgumentException>(() => SecurityInfo.GetInstance(nonSeq));
        Assert.Equal("Malformed input stream.", e1.Message);

        var vec = new Asn1EncodableVector
        {
            new DerInteger(123), // Should be ASN1ObjectIdentifier
            new DerInteger(1),
        };
        var badSeq = new DerSequence(vec);
        ArgumentException e2 = Assert.ThrowsAny<ArgumentException>(() => SecurityInfo.GetInstance(badSeq));
        Assert.Equal("Malformed input stream.", e2.Message);
    }

    [Fact]
    public void testUnsupportedProtocolOID()
    {
        var vec = new Asn1EncodableVector
        {
            new DerObjectIdentifier("1.2.3.4.5.6.7"),
            new DerInteger(1),
        };
        var unsupportedSeq = new DerSequence(vec);
        SecurityInfo? result = SecurityInfo.GetInstance(unsupportedSeq);
        Assert.Null(result);
    }
}
