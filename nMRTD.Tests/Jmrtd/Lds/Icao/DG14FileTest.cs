using System.Text;
using nMRTD.Cbeff;
using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.Lds.Iso19794;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using nMRTD.Tests.Jmrtd.Lds.Iso19794;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using static nMRTD.Tests.Helpers.TestData;

namespace nMRTD.Tests.Jmrtd.Lds.Icao;

/// <summary>Port of JMRTD's <c>org.jmrtd.lds.icao.DG14FileTest</c>.</summary>
public class DG14FileTest
{

    [Fact]
    public void testConstruct()
    {
        var keys = new SortedDictionary<int, AsymmetricKeyParameter>();

        /* Java: a 192-bit EC key pair from Bouncy Castle. */
        AsymmetricCipherKeyPair keyPair1 = KeyPairs.EC("P-192");
        Assert.NotNull(keyPair1);

        /* Using SunJCE here, since BC sometimes hangs?!?! Bug in BC?
          *
          * FIXME: This happened to MO on WinXP, Eclipse 3.4, Sun JDK1.6.0_15,
          * not tested on other platforms... replace "SunJCE" with "BC" and see
          * if this test hangs forever.
          */
        /* Java: a default DH key pair from SunJCE; here a 1024-bit PKCS #3 group (no q), as SunJCE creates. */
        AsymmetricCipherKeyPair keyPair2 = KeyPairs.DH(TestData.DhNoQ);
        Assert.NotNull(keyPair2);

        AsymmetricKeyParameter publicKey1 = keyPair1.Public;
        Assert.NotNull(publicKey1);
        AsymmetricKeyParameter publicKey2 = keyPair2.Public;
        Assert.NotNull(publicKey2);

        keys.Add(1, publicKey1);
        keys.Add(2, publicKey2);

        //      LOGGER.info("DEBUG: publicKey1.GetAlgorithm() = " + publicKey1.GetAlgorithm());
        //      LOGGER.info("DEBUG: publicKey2.GetAlgorithm() = " + publicKey2.GetAlgorithm());

        var algs = new SortedDictionary<int, string>();
        algs.Add(1, SecurityInfo.ID_CA_DH_3DES_CBC_CBC);
        algs.Add(2, SecurityInfo.ID_CA_ECDH_3DES_CBC_CBC);

        List<SecurityInfo> securityInfos = new List<SecurityInfo>();
        securityInfos.Add(new ChipAuthenticationPublicKeyInfo(publicKey1, BigInteger.ValueOf(1)));
        securityInfos.Add(new ChipAuthenticationPublicKeyInfo(publicKey2, BigInteger.ValueOf(2)));
        securityInfos.Add(new ChipAuthenticationInfo(ChipAuthenticationInfo.ID_CA_DH_3DES_CBC_CBC, ChipAuthenticationInfo.VERSION_1, BigInteger.ValueOf(1)));
        securityInfos.Add(new ChipAuthenticationInfo(ChipAuthenticationInfo.ID_CA_ECDH_3DES_CBC_CBC, ChipAuthenticationInfo.VERSION_1, BigInteger.ValueOf(2)));
        securityInfos.Add(new TerminalAuthenticationInfo());
        DG14File dg14File2 = new DG14File(securityInfos);
        Assert.NotNull(dg14File2.GetChipAuthenticationInfos());
        Assert.NotNull(dg14File2.GetChipAuthenticationPublicKeyInfos());
        Assert.NotNull(dg14File2.GetSecurityInfos());
        Assert.NotNull(dg14File2.GetTerminalAuthenticationInfos());
    }

    [Fact]
    public void testEncodeDecode()
    {
        DG14File dg14 = GetSampleObject();
        byte[] encoded = dg14.GetEncoded()!;
        Assert.NotNull(encoded);

        DG14File copy = new DG14File(new MemoryStream(encoded));
        Assert.Equal(dg14, copy);

        byte[] copyEncoded = dg14.GetEncoded()!;
        Assert.NotNull(copyEncoded);

        DG14File copyOfCopy = new DG14File(new MemoryStream(copyEncoded));
        Assert.Equal(dg14, copyOfCopy);
        Assert.Equal(copyOfCopy, copy);
    }

    [Fact]
    public void testDecodeEncode()
    {
        DG14File dg14 = GetSampleObject();
        IReadOnlyCollection<SecurityInfo> securityInfos = dg14.GetSecurityInfos();
        Assert.NotNull(securityInfos);
        DG14File copy = new DG14File(securityInfos);
        Assert.Equal(dg14, copy);

        byte[] encoded = dg14.GetEncoded()!;
        Assert.NotNull(encoded);
        byte[] copyEncoded = copy.GetEncoded()!;
        Assert.NotNull(copyEncoded);
        Assert.True(Enumerable.SequenceEqual(encoded, copyEncoded));
    }

    [Fact]
    public void testDecodeEncode1()
    {
        DG14File dg14 = GetSampleObject();
        byte[] encoded = dg14.GetEncoded()!;
        DG14File copy = new DG14File(new MemoryStream(encoded));
        byte[] copyEncoded = copy.GetEncoded()!;
        Assert.Equal(encoded, copyEncoded); // Java: a plain assert
    }

    [Fact]
    public void testSpecSample()
    {
        byte[] specSample = GetSpecSampleDG14File();
        DG14File dg14 = new DG14File(new MemoryStream(specSample));
        byte[] encoded = dg14.GetEncoded()!;

        IReadOnlyCollection<SecurityInfo> securityInfos = dg14.GetSecurityInfos();
        foreach (SecurityInfo securityInfo in securityInfos)
        {
            //        LOGGER.info("DEBUG: securityInfo " + securityInfo);
        }

        //			Assert.True(Enumerable.SequenceEqual(specSample, encoded));
        DG14File copy = new DG14File(new MemoryStream(encoded));

        IReadOnlyCollection<SecurityInfo> copySecurityInfos = copy.GetSecurityInfos();

        foreach (SecurityInfo securityInfo in copySecurityInfos)
        {
            //        LOGGER.info("DEBUG: securityInfo " + securityInfo);
        }

        Assert.Equal(securityInfos, copySecurityInfos);

        Assert.Equal(dg14, copy);
    }

    [Fact]
    public void testSpecSample1()
    {
        byte[] encoded0 = GetSpecSampleDG14File();
        DG14File file0 = new DG14File(new MemoryStream(encoded0));
        byte[] encoded1 = file0.GetEncoded()!;
        DG14File file1 = new DG14File(new MemoryStream(encoded1));
        byte[] encoded2 = file1.GetEncoded()!;
        //      LOGGER.info("encoded0: " + encoded0.Length);
        //      LOGGER.info("encoded1: " + encoded1.Length);
        //      LOGGER.info("encoded2: " + encoded2.Length);
    }

    /** Tests a specific sample. */
    [Fact]
    public void testGWSample()
    {
        DG14File dg14 = GetGWSample();

        CheckLDS_E_3(dg14);

        //			byte[] bytes = dg14.GetEncoded()!;
        //			FileOutputStream fileOutputStream = new FileOutputStream("c:/gw_dg14.bin");
        //			fileOutputStream.Write(bytes);
        //			fileOutputStream.Flush();
        //			fileOutputStream.Close();
    }

    /*
      * Tests from TR03105.
      * See https://www.bsi.bund.de/EN/Publications/TechnicalGuidelines/TR03105/BSITR03105.html.
      */

    [Fact]
    public void testLDS_E_1()
    {
        List<DG14File> dg14s = GetSampleObjects();
        foreach (DG14File dg14 in dg14s)
        {
            CheckLDS_E_1(dg14);
        }
    }

    internal static void CheckLDS_E_1(DG14File dg14)
    {
        byte[] encoded = dg14.GetEncoded()!;
        Assert.NotNull(encoded);
        Assert.True(encoded.Length > 0);
        Assert.Equal(0x6E, encoded[0]);

        int length = dg14.GetLength();
        //		LOGGER.info("length = " + length + ", encoded length = " + encoded.Length);
        Assert.True(length > 0);
        Assert.True(length <= encoded.Length);
    }

    [Fact]
    public void testLDS_E_2()
    {
        List<DG14File> dg14s = GetSampleObjects();
        foreach (DG14File dg14 in dg14s)
        {
            CheckLDS_E_2(dg14);
        }
    }

    internal static void CheckLDS_E_2(DG14File dg14)
    {
        IReadOnlyCollection<SecurityInfo> securityInfos = dg14.GetSecurityInfos();
        int chipAuthenticationPublicKeyInfoCount = 0;
        foreach (SecurityInfo securityInfo in securityInfos)
        {
            if (securityInfo is ChipAuthenticationPublicKeyInfo)
            {
                ChipAuthenticationPublicKeyInfo chipAuthenticationPublicKeyInfo = (ChipAuthenticationPublicKeyInfo)securityInfo;
                string oid = chipAuthenticationPublicKeyInfo.GetObjectIdentifier();
                if ("0.4.0.127.0.7.2.2.1.1".Equals(oid) || "0.4.0.127.0.7.2.2.1.2".Equals(oid))
                {
                    chipAuthenticationPublicKeyInfoCount++;
                    CheckLDS_E_3(chipAuthenticationPublicKeyInfo);
                }
            }
        }

        /* For profiles CA_KAT, CA_ATGA:
          *
          * The SecurityInfos set MUST contain at least one
          * ChipAuthenticationPublicKeyInfo element with one of the protocol OID
          * defined in the EAC specification (id-PK-DH or id-PK-ECDH). The test
          * LDS_E_3 MUST be performed for each
          * ChipAuthenticationPublicKeyInfo element which has such an OID.
          */
        Assert.True(chipAuthenticationPublicKeyInfoCount > 0);
    }

    [Fact]
    public void testLDS_E_3()
    {
        List<DG14File> dg14s = GetSampleObjects();
        foreach (DG14File dg14 in dg14s)
        {
            CheckLDS_E_3(dg14);
        }
    }

    internal static void CheckLDS_E_3(DG14File dg14)
    {
        IReadOnlyCollection<SecurityInfo> securityInfos = dg14.GetSecurityInfos();
        foreach (SecurityInfo securityInfo in securityInfos)
        {
            if (securityInfo is ChipAuthenticationPublicKeyInfo)
            {
                ChipAuthenticationPublicKeyInfo chipAuthenticationPublicKeyInfo = (ChipAuthenticationPublicKeyInfo)securityInfo;
                string oid = chipAuthenticationPublicKeyInfo.GetObjectIdentifier();
                if ("0.4.0.127.0.7.2.2.1.1".Equals(oid) || "0.4.0.127.0.7.2.2.1.2".Equals(oid))
                {
                    CheckLDS_E_3(chipAuthenticationPublicKeyInfo);
                }
            }
        }
    }

    /**
      * 1. The ChipAuthenticationPublicKeyInfo element must follow the ASN.1
      *    syntax definition in the EAC specification [R2] and [R11].
      * 2. The presence of the key reference in the
      *    ChipAuthenticationPublicKeyInfo MUST be coherent with the ICS
      * 3. The algorithm identifier MUST match to the Key agreement protocol and
      *    be one of the following:
      *       - DHKeyAgreement (OID: 1.2.840.113549.1.3.1)
      *       - ecPublicKey (OID: 1.2.840.10045.2.1)
      * 4. The parameters MUST follow PKCS #3 (DH) or KAEG specification
      *    (ECDH).
      *    For DH verify that
      *       - 0 < g < p, that is both should be positive and g should be less than p.
      *       - If private value length l is present, verify that l > 0 and 2l-1 < p.
      *    In case of ECDH verify that
      *       - prime p > 2
      *       - curve parameter 0 <= a < p
      *       - curve parameter 0 <= b < p
      *       - 4*a^3 + 27*b^2 != 0
      *       - base point G is on the curve, with both coordinates in range 0 ... p - 1
      *       - Cofactor f > 0
      *       - order r of base point r > 0 , r != p
      *       - r * f <= 2p
      */
    internal static void CheckLDS_E_3(ChipAuthenticationPublicKeyInfo chipAuthenticationPublicKeyInfo)
    {
        /* Pre-conditions. */
        Assert.NotNull(chipAuthenticationPublicKeyInfo);
        string oid = chipAuthenticationPublicKeyInfo.GetObjectIdentifier();
        if (!"0.4.0.127.0.7.2.2.1.1".Equals(oid) && !"0.4.0.127.0.7.2.2.1.2".Equals(oid))
        {
            /* FIXME: Should we fail if pre-condition is false? */
            Assert.Fail("Not an appropriate ChipAuthenticationPublicKeyInfo for this test:"
                    + "was expecting 0.4.0.127.0.7.2.2.1.1 (id-PK-DH) or 0.4.0.127.0.7.2.2.1.2 (id-PK-ECDH), "
                    + "found OID " + oid);
        }

        /* 1. By definition (the fact that it is a ChipAuthenticationPublicKeyInfo object). */
        /* 2. */
        BigInteger? keyId = chipAuthenticationPublicKeyInfo.GetKeyId();
        //    Assert.NotNull(keyId);
        //    Assert.True(keyId.compareTo(BigInteger.ValueOf(-1)) == 0 || keyId.compareTo(BigInteger.ZERO) > 0);

        /* 3. */
        AsymmetricKeyParameter publicKey = chipAuthenticationPublicKeyInfo.GetSubjectPublicKey();
        Assert.NotNull(publicKey);
        // ADAPTATION: JCA's getAlgorithm() names the key type; here the Bouncy Castle key parameter type does.
        string algorithm = publicKey is DHPublicKeyParameters ? "DH" : publicKey is ECPublicKeyParameters ? "EC" : publicKey.GetType().Name;
        Assert.NotNull(algorithm);
        if ("0.4.0.127.0.7.2.2.1.1".Equals(oid)) { Assert.Equal("DH", algorithm); } // id-PK-DH
        if ("0.4.0.127.0.7.2.2.1.2".Equals(oid)) { Assert.True("EC".Equals(algorithm) || "ECDH".Equals(algorithm)); } // id-PK-ECDH

        /* 4. */
        if ("DH".Equals(algorithm))
        {
            /* DH case. */
            if (publicKey is not DHPublicKeyParameters)
            {
                Assert.Fail("Was expecting a DH public key, found " + publicKey.GetType().Name);
                /* NOTE: as in JMRTD, the parameter checks below sit inside this (unreachable) block. */
                DHPublicKeyParameters dhPublicKey = (DHPublicKeyParameters)publicKey;
                DHParameters parameters = dhPublicKey.Parameters;
                BigInteger g = parameters.G;
                int l = parameters.L;
                BigInteger p = parameters.P;

                Assert.True(BigInteger.Zero.CompareTo(g) < 0);
                Assert.True(g.CompareTo(p) < 0);

                if (l != 0)
                {
                    Assert.True(l > 0);
                    Assert.True(BigInteger.ValueOf(2 * l - 1).CompareTo(p) < 0);
                }
            }
        }
        else if ("EC".Equals(algorithm) || "ECDH".Equals(algorithm))
        {
            /* ECDH case. */
            if (publicKey is not ECPublicKeyParameters)
            {
                Assert.Fail("Was expecting an EC public key, found " + publicKey.GetType().Name);
            }
            var ecPublicKey = (ECPublicKeyParameters)publicKey;
            Org.BouncyCastle.Math.EC.ECPoint w = ecPublicKey.Q;

            ECDomainParameters parameters = ecPublicKey.Parameters;
            Assert.NotNull(parameters);
            BigInteger coFactor = parameters.H;
            BigInteger order = parameters.N;

            Org.BouncyCastle.Math.EC.ECCurve curve = parameters.Curve;
            Assert.NotNull(curve);
            BigInteger a = curve.A.ToBigInteger();
            Assert.NotNull(a);
            BigInteger b = curve.B.ToBigInteger();
            Assert.NotNull(b);

            if (curve is not Org.BouncyCastle.Math.EC.FpCurve)
            {
                Assert.Fail("Was expecting a prime field, found " + curve.GetType().Name);
            }

            BigInteger p = curve.Field.Characteristic;
            Assert.NotNull(p);
            Assert.True(p.CompareTo(BigInteger.ValueOf(2)) > 0);

            Assert.True(BigInteger.Zero.CompareTo(a) <= 0);
            Assert.True(a.CompareTo(p) < 0);
            Assert.True(BigInteger.Zero.CompareTo(b) <= 0);
            Assert.True(b.CompareTo(p) < 0);

            BigInteger sum = BigInteger.ValueOf(4).Multiply(a.Pow(3)).Add(BigInteger.ValueOf(27).Multiply(b.Pow(2)));
            Assert.True(sum.CompareTo(BigInteger.Zero) != 0);

            Assert.True(w.IsValid()); // Java: isOnCurve(w, curve)

            Assert.True(coFactor.SignValue > 0);

            Assert.True(order.CompareTo(BigInteger.Zero) > 0);
            Assert.True(order.CompareTo(p) != 0);
            Assert.True(order.Multiply(coFactor).CompareTo(p.Multiply(BigInteger.ValueOf(2))) <= 0);
        }
        else
        {
            Assert.Fail("Was expecting DH, EC or ECDH algorithm for public key. Found " + algorithm);
        }
    }

    public List<DG14File> GetSampleObjects()
    {
        List<DG14File> dg14s = new List<DG14File>();
        try
        {
            dg14s.Add(GetSampleObject());
        }
        catch (Exception)
        {
        }
        try
        {
            dg14s.Add(GetGWSample());
        }
        catch (Exception)
        {
        }
        try
        {
            dg14s.Add(new DG14File(Fixtures.GetInputStream("/lds/bsi2008/Datagroup14.bin")));
        }
        catch (Exception)
        {
        }

        return dg14s;
    }

    /** Elaborate sample. */
    public DG14File GetSampleObject()
    {
        try
        {
            /* Java: a 192-bit EC key pair from Bouncy Castle. */
            AsymmetricCipherKeyPair keyPair1 = KeyPairs.EC("P-192");

            /* Using SunJCE here, since BC sometimes hangs?!?! Bug in BC?
              *
              * FIXME: This happened to MO on WinXP, Eclipse 3.4, Sun JDK1.6.0_15,
              * not tested on other platforms... replace "SunJCE" with "BC" and see
              * if this test halts forever.
              */
            /* Java: a default DH key pair from SunJCE; here a 1024-bit PKCS #3 group (no q), as SunJCE creates. */
            AsymmetricCipherKeyPair keyPair2 = KeyPairs.DH(TestData.DhNoQ);

            AsymmetricKeyParameter publicKey1 = keyPair1.Public;
            AsymmetricKeyParameter publicKey2 = keyPair2.Public;

            List<SecurityInfo> securityInfos = new List<SecurityInfo>();
            securityInfos.Add(new ChipAuthenticationPublicKeyInfo(publicKey1, BigInteger.ValueOf(1)));
            securityInfos.Add(new ChipAuthenticationPublicKeyInfo(publicKey2, BigInteger.ValueOf(2)));
            securityInfos.Add(new ChipAuthenticationInfo(ChipAuthenticationInfo.ID_CA_DH_3DES_CBC_CBC, ChipAuthenticationInfo.VERSION_1, BigInteger.ValueOf(1)));
            securityInfos.Add(new ChipAuthenticationInfo(ChipAuthenticationInfo.ID_CA_ECDH_3DES_CBC_CBC, ChipAuthenticationInfo.VERSION_1, BigInteger.ValueOf(2)));
            securityInfos.Add(new TerminalAuthenticationInfo());
            securityInfos.Add(new PACEInfo(PACEInfo.ID_PACE_DH_GM_AES_CBC_CMAC_192, 2, PACEInfo.PARAM_ID_ECP_BRAINPOOL_P224_R1));
            DG14File dg14 = new DG14File(securityInfos);
            return dg14;
        }
        catch(Exception e)
        {
            Assert.Fail(e.Message);
            return null;
        }
    }

    /** Sanity check. */
    /** Sanity check. */
    private DG14File GetGWSample()
    {
        List<SecurityInfo> securityInfos = new List<SecurityInfo>();
        securityInfos.Add(new ChipAuthenticationInfo(ChipAuthenticationInfo.ID_CA_ECDH_3DES_CBC_CBC, ChipAuthenticationInfo.VERSION_1));
        securityInfos.Add(GetGWSampleChipAuthenticationPublicKeyInfo());
        DG14File dg14 = new DG14File(securityInfos);
        return dg14;
    }

    private ChipAuthenticationPublicKeyInfo GetGWSampleChipAuthenticationPublicKeyInfo()
    {
        AsymmetricKeyParameter publicKey = GetGWSamplePublicKey();
        ChipAuthenticationPublicKeyInfo chipAuthenticationPublicKeyInfo = new ChipAuthenticationPublicKeyInfo(publicKey);
        return chipAuthenticationPublicKeyInfo;
    }

    private static AsymmetricKeyParameter GetGWSamplePublicKey()
    {
        BigInteger n = new BigInteger("115792089210356248762697446949407573529996955224135760342422259061068512044369"); // order
        BigInteger h = BigInteger.One; // co-factor
        BigInteger a = new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853948");
        BigInteger b = new BigInteger("41058363725152142129326129780047268409114441015993725554835256314039467401291");
        BigInteger p = new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951");
        var curve = new Org.BouncyCastle.Math.EC.FpCurve(p, a, b, n, h);
        Org.BouncyCastle.Math.EC.ECPoint w = curve.CreatePoint(new BigInteger("104351772082740350592218973609013984525419572253879843433078472109506934675868"), new BigInteger("14166132649477039766003768534081831647667842724916480786968553069450191944115"));
        Org.BouncyCastle.Math.EC.ECPoint g = curve.CreatePoint(new BigInteger("48439561293906451759052585252797914202762949526041747995844080717082404635286"), new BigInteger("36134250956749795798585127919587881956611106672985015071877198253568414405109"));
        return new ECPublicKeyParameters(w, new ECDomainParameters(curve, g, n, h));
    }

    public DG14File GetSimpleObject()
    {
        try
        {
            /* Java: a 192-bit EC key pair from Bouncy Castle. */
            AsymmetricCipherKeyPair keyPair1 = KeyPairs.EC("P-192");

            /* Using SunJCE here, since BC sometimes hangs?!?! Bug in BC?
              *
              * FIXME: This happened to MO on WinXP, Eclipse 3.4, Sun JDK1.6.0_15,
              * not tested on other platforms... replace "SunJCE" with "BC" and see
              * if this test halts forever.
              */
            /* Java: a default DH key pair from SunJCE; here a 1024-bit PKCS #3 group (no q), as SunJCE creates. */
            AsymmetricCipherKeyPair keyPair2 = KeyPairs.DH(TestData.DhNoQ);

            AsymmetricKeyParameter publicKey1 = keyPair1.Public;
            AsymmetricKeyParameter publicKey2 = keyPair2.Public;

            List<SecurityInfo> securityInfos = new List<SecurityInfo>();
            securityInfos.Add(new ChipAuthenticationPublicKeyInfo(publicKey1, BigInteger.ValueOf(1)));
            securityInfos.Add(new ChipAuthenticationPublicKeyInfo(publicKey2, BigInteger.ValueOf(2)));
            securityInfos.Add(new ChipAuthenticationInfo(ChipAuthenticationInfo.ID_CA_DH_3DES_CBC_CBC, ChipAuthenticationInfo.VERSION_1, BigInteger.ValueOf(1)));
            securityInfos.Add(new ChipAuthenticationInfo(ChipAuthenticationInfo.ID_CA_ECDH_3DES_CBC_CBC, ChipAuthenticationInfo.VERSION_1, BigInteger.ValueOf(2)));
            securityInfos.Add(new TerminalAuthenticationInfo());
            securityInfos.Add(new PACEInfo(PACEInfo.ID_PACE_DH_GM_AES_CBC_CMAC_192, 2, PACEInfo.PARAM_ID_ECP_BRAINPOOL_P224_R1));
            DG14File dg14 = new DG14File(securityInfos);
            return dg14;
        }
        catch(Exception e)
        {
            Assert.Fail(e.Message);
            return null;
        }
    }

    /**
      * Figure D.3 from TR 03110 v1.11, specifies DG14 (DH).
      *
      * @return
      */
    public static byte[] GetSpecSampleDG14File()
    {
        return [
                /*0000:*/ 0x6E, 0x82, 0x01, 0xDC, 0x31, 0x82, 0x01, 0xD8, 0x30, 0x82, 0x01, 0xB4, 0x06, 0x09, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x01, 0x01, 0x30, 0x82, 0x01, 0xA5, 0x30, 0x82, 0x01, 0x1A, 0x06,
                /*0020:*/ 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x03, 0x01, 0x30, 0x82, 0x01, 0x0B, 0x02, 0x81, 0x81, 0x00, 0xDC, 0xB5, 0x54, 0xDF, 0x8C, 0x69, 0x31, 0xE8, 0x65, 0xC1, 0xB5, 0x88, 0x27, 0x3D,
                /*0040:*/ 0x80, 0xA2, 0xD8, 0x7A, 0xB5, 0x39, 0xC5, 0xE4, 0xA0, 0x74, 0xB4, 0x02, 0x49, 0xFF, 0x65, 0x5A, 0x9A, 0xB8, 0x30, 0x63, 0x3B, 0x45, 0x7C, 0x4C, 0xF8, 0x85, 0xE3, 0x1C, 0xD7, 0x9F, 0x81, 0x14,
                /*0060:*/ 0x8C, 0x8A, 0x68, 0xD1, 0xDB, 0xFC, 0x2F, 0x7B, 0x70, 0xED, 0x55, 0xC0, 0x38, 0x7C, 0x23, 0xA0, 0x47, 0x9A, 0x95, 0x72, 0xE8, 0xA6, 0x71, 0x4F, 0x41, 0x8A, 0x6B, 0xF9, 0xB0, 0x0E, 0xC5, 0xBC,
                /*0080:*/ 0x4D, 0xEF, 0x25, 0x5A, 0x94, 0x85, 0x05, 0x8A, 0x42, 0x71, 0x00, 0x8B, 0xA6, 0x94, 0xAA, 0x62, 0xCC, 0x18, 0x38, 0x5E, 0xF9, 0xD7, 0xB6, 0xE8, 0x33, 0xA7, 0x08, 0x8A, 0xC8, 0x17, 0xAA, 0x1F,
                /*00A0:*/ 0x9B, 0x93, 0xA8, 0x6B, 0x98, 0x3E, 0xAB, 0x73, 0xC1, 0x58, 0x84, 0xE7, 0x33, 0x66, 0x56, 0x59, 0xCA, 0x7D, 0x02, 0x81, 0x80, 0x2E, 0x69, 0xFE, 0x94, 0xD3, 0xC0, 0xA4, 0x37, 0x8C, 0x8A, 0x47,
                /*00C0:*/ 0x9D, 0x83, 0x09, 0x1A, 0xED, 0x41, 0x92, 0x34, 0x25, 0xC1, 0x03, 0x00, 0x8C, 0x6A, 0xB3, 0xF6, 0xE8, 0x3E, 0x20, 0xCB, 0x16, 0xC4, 0xAE, 0x0B, 0x0E, 0x28, 0xED, 0x9B, 0xC7, 0x9C, 0xD7, 0xD7,
                /*00E0:*/ 0xE9, 0xDF, 0xD3, 0x9D, 0xD0, 0xA3, 0x91, 0x41, 0xF2, 0xDD, 0x57, 0x14, 0x9A, 0xB6, 0x88, 0xDB, 0xAD, 0x17, 0x7C, 0x68, 0x6F, 0x77, 0x18, 0x28, 0xE5, 0xA0, 0x44, 0x08, 0x51, 0x2F, 0x15, 0x64,
                /*0100:*/ 0x74, 0xB0, 0xBF, 0xD4, 0x30, 0xCB, 0xBF, 0x91, 0xC0, 0x15, 0x89, 0xE7, 0x21, 0xDD, 0xDF, 0xFC, 0xDF, 0x45, 0x00, 0x43, 0xEB, 0x77, 0x1E, 0x61, 0x08, 0x4C, 0x59, 0x7F, 0x7A, 0xEA, 0x90, 0x48,
                /*0120:*/ 0x42, 0x0A, 0x21, 0x80, 0xEB, 0xFE, 0xC1, 0xB3, 0xB9, 0x3C, 0x1A, 0x6C, 0xB1, 0xAD, 0x38, 0xB3, 0x98, 0x4F, 0xF0, 0x52, 0x10, 0x02, 0x02, 0x03, 0xF9, 0x03, 0x81, 0x84, 0x00, 0x02, 0x81, 0x80,
                /*0140:*/ 0x55, 0x3C, 0xE7, 0x35, 0xEC, 0xF5, 0xCB, 0xF2, 0x02, 0x9D, 0x30, 0xFA, 0xA4, 0xF9, 0x73, 0x35, 0xDF, 0x40, 0x40, 0x47, 0xE4, 0xF8, 0x58, 0x6D, 0x76, 0xA7, 0xD2, 0x21, 0xA0, 0x9E, 0x7F, 0x55,
                /*0160:*/ 0xBB, 0xE2, 0x55, 0xC6, 0x58, 0x7B, 0xF2, 0x88, 0x5D, 0x41, 0xB7, 0x86, 0xBC, 0xEF, 0x21, 0x77, 0xD5, 0x2B, 0xF3, 0xCD, 0xBA, 0x78, 0x5D, 0x37, 0xD7, 0x0B, 0x88, 0xD6, 0xAB, 0x4E, 0x1C, 0xA6,
                /*0180:*/ 0x6A, 0x63, 0xB6, 0x01, 0x13, 0x76, 0xED, 0x44, 0x44, 0x4A, 0x66, 0x2B, 0xD0, 0xDC, 0x95, 0x24, 0x17, 0x6E, 0x97, 0x12, 0x87, 0xAD, 0x41, 0xD2, 0x9B, 0xED, 0x3D, 0x35, 0xEA, 0xC7, 0xD3, 0x9C,
                /*01A0:*/ 0xA7, 0x3E, 0xCB, 0x2A, 0x3B, 0x4D, 0x39, 0x67, 0x1C, 0xE4, 0x12, 0x5C, 0x92, 0x65, 0x8C, 0x5B, 0xF3, 0xDE, 0xDA, 0x91, 0x5E, 0xD7, 0x1B, 0x88, 0xFC, 0x03, 0x1B, 0xAB, 0x88, 0x72, 0x48, 0xA1,
                /*01C0:*/ 0x30, 0x0F, 0x06, 0x0A, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x01, 0x01, 0x02, 0x01, 0x01, 0x30, 0x0D, 0x06, 0x08, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x02, 0x01, 0x01
        ];
    }

}
