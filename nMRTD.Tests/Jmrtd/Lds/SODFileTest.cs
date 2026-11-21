using System.Text;
using nMRTD.Cbeff;
using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.Lds.Iso19794;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using nMRTD.Tests.Jmrtd.Lds.Icao;
using nMRTD.Lds.Iso39794;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;

namespace nMRTD.Tests.Jmrtd.Lds;

/// <summary>Port of JMRTD's <c>org.jmrtd.lds.SODFileTest</c>.</summary>
/// <remarks>
/// ADAPTATION: JCA key, certificate and digest APIs are Bouncy Castle's; JCA's <c>X500Principal</c> is
/// Bouncy Castle's <c>X509Name</c>. Java-only, not ported: <c>testSerializable</c> (Java serialization)
/// and <c>testBCX500Name</c> (JCA <c>X500Principal</c> RFC 1779/RFC 2253 formatting).
/// </remarks>
[Collection(nMRTD.Tests.Helpers.CbeffDataGroupCollection.Name)]
public class SODFileTest
{

    [Fact]
    public void testReflexive()
    {
        CheckReflexive(CreateTestObject("SHA-1", "SHA1WithRSA"));
        CheckReflexive(CreateTestObject("SHA-256", "SHA256WithRSA"));
        CheckReflexive(CreateTestObject("SHA-256", "SHA256WithECDSA"));
    }

    private static byte[] ReadBytes(Stream inputStream)
    {
        MemoryStream buffer = new MemoryStream();
        int nRead;
        byte[] data = new byte[16384];
        while ((nRead = inputStream.Read(data, 0, data.Length)) > 0) // Java: != -1
        {
            buffer.Write(data, 0, nRead);
        }
        buffer.Flush();
        return buffer.ToArray();
    }

    [Fact]
    public void testDecodeEncode()
    {
        CheckDecodeEncode(CreateMustermannSampleInputStream());
    }

    internal static void CheckDecodeEncode(Stream inputStream)
    {
        byte[] bytes = ReadBytes(inputStream);
        SODFile sodFile = new SODFile(new MemoryStream(bytes));
        byte[] encoded = sodFile.GetEncoded()!;

        Assert.True(Enumerable.SequenceEqual(bytes, encoded));
    }

    internal static void CheckReflexive(SODFile sodFile)
    {
        byte[] encoded = sodFile.GetEncoded()!;
        MemoryStream input = new MemoryStream(encoded);
        SODFile copy = new SODFile(input);
        Assert.Equal(sodFile, copy);
        Assert.Equal(Hex.BytesToHexString(encoded), Hex.BytesToHexString(copy.GetEncoded()!));
    }

    private static AsymmetricCipherKeyPair CreateRSATestKeyPair() => KeyPairs.Rsa(1024);

    /* Java: KeyPairGenerator.getInstance("EC") with its default size, a P-256 key. */
    private static AsymmetricCipherKeyPair CreateECTestKeyPair() => KeyPairs.EC("P-256");

    [Fact]
    public void testFields()
    {
        CheckFields(CreateTestObject("SHA-1", "SHA1WithRSA"));
        CheckFields(CreateTestObject("SHA-256", "SHA256WithRSA"));
        CheckFields(CreateTestObject("SHA-256", "SHA256WithECDSA"));
    }

    internal static void CheckFields(SODFile sodFile)
    {
        try
        {
            string? ldsVersion = sodFile.GetLDSVersion();
            Assert.True(ldsVersion == null || ldsVersion.Length == "aabb".Length);

            string? unicodeVersion = sodFile.GetUnicodeVersion();
            Assert.True(unicodeVersion == null || unicodeVersion.Length == "aabbcc".Length);

            Org.BouncyCastle.X509.X509Certificate? certificate = sodFile.GetDocSigningCertificate();

            var serialNumber = sodFile.GetSerialNumber();

            if (serialNumber != null && certificate != null)
            {
                Assert.True(serialNumber.ToString() == certificate.SerialNumber.ToString(), "serialNumber = " + serialNumber + ", certificate.SerialNumber = " + certificate.SerialNumber);
            }

            Org.BouncyCastle.Asn1.X509.X509Name? issuer = sodFile.GetIssuerName(); // Java: getIssuerX500Principal()

            string issuerName = issuer!.ToString(); // Java: getName(X500Principal.RFC2253)
            Assert.NotNull(issuerName);

            if (issuer != null && certificate != null)
            {
                Org.BouncyCastle.Asn1.X509.X509Name certIssuer = certificate.IssuerDN;
                string certIssuerName = certIssuer.ToString();
                Assert.NotNull(certIssuerName);
                //				Assert.True(//						certIssuerName.Equals(issuerName), "issuerName = \"" + issuerName + "\", certIssuerName = \"" + certIssuerName + "\"");
            }

            string? digestAlgorithm = sodFile.GetDigestAlgorithm();
            string? digestEncryptionAlgorithm = sodFile.GetDigestEncryptionAlgorithm();

            Assert.NotNull(digestAlgorithm);
            Assert.NotNull(digestEncryptionAlgorithm);
        }
        catch (Exception ce) when (ce is not Xunit.Sdk.XunitException) { Assert.Fail(ce.Message); }
    }

    [Fact]
    public void testMustermann()
    {
        CheckFile(CreateMustermannSampleInputStream());
    }

    internal static void CheckFile(Stream input)
    {
        SODFile sodFile = new SODFile(input);
        CheckReflexive(sodFile);
        CheckFields(sodFile);
    }

    [Fact]
    public void testReconstructionViaOtherConstructor()
    {
        SODFile sodFile = CreateTestObject("SHA-1", "SHA256WithRSA");
        SODFile reconstructedSODFile = new SODFile(sodFile.GetDigestAlgorithm()!, sodFile.GetDigestEncryptionAlgorithm()!, sodFile.GetDataGroupHashes()!, sodFile.GetEncryptedDigest()!, sodFile.GetDocSigningCertificate()!);
        Assert.Equal(sodFile, reconstructedSODFile);
        Assert.Equal(sodFile.GetDigestAlgorithm(), reconstructedSODFile.GetDigestAlgorithm());
        Assert.Equal(sodFile.GetDigestEncryptionAlgorithm(), reconstructedSODFile.GetDigestEncryptionAlgorithm());
        Assert.True(Enumerable.SequenceEqual(sodFile.GetEContent(), reconstructedSODFile.GetEContent()));
        Assert.Equal(new SODFile(new MemoryStream(sodFile.GetEncoded()!)), reconstructedSODFile);
        Assert.Equal(new SODFile(new MemoryStream(reconstructedSODFile.GetEncoded()!)), sodFile);
    }

    public static SODFile CreateTestObject(string digestAlgorithm, string signatureAlgorithm)
    {
        try
        {
            DateTime today = DateTime.UtcNow;
            DG1File dg1File = DG1FileTest.CreateTestObject();
            byte[] dg1Bytes = dg1File.GetEncoded()!;
            DG2File dg2File = DG2FileTest.GetDefaultTestObject();
            byte[] dg2Bytes = dg2File.GetEncoded()!;
            //			DG15File dg15File = DG15FileTest.CreateTestObject();
            //			byte[] dg15Bytes = dg15File.GetEncoded()!;

            AsymmetricCipherKeyPair keyPair = signatureAlgorithm.EndsWith("RSA") ? CreateRSATestKeyPair() : CreateECTestKeyPair();
            AsymmetricKeyParameter publicKey = keyPair.Public;
            AsymmetricKeyParameter privateKey = keyPair.Private;
            DateTime dateOfIssuing = today;
            DateTime dateOfExpiry = today;

            Org.BouncyCastle.X509.X509Certificate docSigningCert = GenerateDocSigningCert(BigInteger.One,
                    "C=NL, O=State of the Netherlands, OU=Ministry of the Interior and Kingdom Relations, CN=CSCA NL",
                    "C=NL, O=State of the Netherlands, OU=Ministry of the Interior and Kingdom Relations, CN=DS-01 NL, OID.2.5.4.5=1",
                    dateOfIssuing,
                    dateOfExpiry,
                    publicKey,
                    signatureAlgorithm,
                    privateKey);

            var hashes = new Dictionary<int, byte[]>();
            hashes.Add(1, Org.BouncyCastle.Security.DigestUtilities.CalculateDigest(digestAlgorithm, dg1Bytes));
            hashes.Add(2, Org.BouncyCastle.Security.DigestUtilities.CalculateDigest(digestAlgorithm, dg2Bytes));
            //			hashes.Add(15, digest.digest(dg15Bytes));
            //			byte[] encryptedDigest = new byte[128]; // Arbitrary value. Use a private key to generate a real signature?

            SODFile sod = new SODFile(digestAlgorithm, signatureAlgorithm, hashes, privateKey, docSigningCert);

            int[] dgPresenceList = [LDSFile.EF_DG1_TAG, LDSFile.EF_DG2_TAG];
            COMFile com = new COMFile("1.7", "4.0.0", dgPresenceList);

            //			File outputDir = new File("tmp");
            //			if (!outputDir.exists()) {
            //				if (!outputDir.mkdirs()) {
            //					Assert.Fail("Could not make output dir \"" + outputDir.GetAbsolutePath() + "\"");
            //				}
            //			}
            //			if (!outputDir.IsDirectory()) {
            //				Assert.Fail("Could not make output dir \"" + outputDir.GetAbsolutePath() + "\"");
            //			}
            //
            //
            //			FileOutputStream comOut = new FileOutputStream(new File(outputDir, "EF_COM.bin"));
            //			comOut.Write(com.GetEncoded()!);
            //			comOut.Flush();
            //			comOut.Close();

            //			FileOutputStream dg1Out = new FileOutputStream(new File(outputDir, "DataGroup1.bin"));
            //			dg1Out.Write(dg1File.GetEncoded()!);
            //			dg1Out.Flush();
            //			dg1Out.Close();
            //
            //			FileOutputStream dg2Out = new FileOutputStream(new File(outputDir, "DataGroup2.bin"));
            //			dg2Out.Write(dg2File.GetEncoded()!);
            //			dg2Out.Flush();
            //			dg2Out.Close();
            //
            //			FileOutputStream sodOut = new FileOutputStream(new File(outputDir, "EF_SOD.bin"));
            //			sodOut.Write(sod.GetEncoded()!);
            //			sodOut.Flush();
            //			sodOut.Close();

            return sod;
        }
        catch (Exception)
        {
            return null!;
        }
    }

    private static Org.BouncyCastle.X509.X509Certificate GenerateDocSigningCert(BigInteger serial, string issuerName, string subjectDN, DateTime dateOfIssuing, DateTime dateOfExpiry, AsymmetricKeyParameter publicKey, string signatureAlgorithm, AsymmetricKeyParameter privateKey)
    {
        var generator = new Org.BouncyCastle.X509.X509V3CertificateGenerator();
        generator.SetSerialNumber(serial);
        generator.SetIssuerDN(new Org.BouncyCastle.Asn1.X509.X509Name(issuerName));
        generator.SetSubjectDN(new Org.BouncyCastle.Asn1.X509.X509Name(subjectDN));
        generator.SetNotBefore(dateOfIssuing);
        generator.SetNotAfter(dateOfExpiry);
        generator.SetPublicKey(publicKey);
        return generator.Generate(new Org.BouncyCastle.Crypto.Operators.Asn1SignatureFactory(signatureAlgorithm, privateKey));
    }

    private static Stream CreateMustermannSampleInputStream()
    {
        try
        {
            return Fixtures.GetInputStream("/lds/bsi2008/EF_SOD.bin");
        }
        catch (Exception e)
        {
            Assert.Fail(e.Message);
            return null;
        }
    }
}
