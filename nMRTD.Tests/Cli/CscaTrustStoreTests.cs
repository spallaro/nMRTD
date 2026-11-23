using nMRTD.Cli;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Crypto;
using static nMRTD.Tests.EndToEnd.EndToEnd;
using static nMRTD.Tests.Helpers.TestPki;

namespace nMRTD.Tests.Cli;

/// <summary>
/// The command-line tool's check that the Document Signer certificate was issued by a trusted CSCA
/// (<see cref="CscaTrustStore"/>, <c>--csca</c>), with certificates generated at run time.
/// </summary>
public sealed class CscaTrustStoreTests : IDisposable
{
    private const string Utopia = "C=UT, O=Utopia, CN=CSCA Utopia";

    private readonly string folder = Path.Combine(Path.GetTempPath(), "nmrtd-csca-tests-" + Guid.NewGuid().ToString("N"));

    public CscaTrustStoreTests() => Directory.CreateDirectory(folder);

    public void Dispose() => Directory.Delete(folder, recursive: true);

    [Theory]
    [InlineData("SHA256WITHRSA")]
    [InlineData("SHA256WITHRSAANDMGF1")] // RSASSA-PSS, as on Italian documents
    public void DocumentSignerIssuedByATrustedRsaCsca(string signatureAlgorithm)
    {
        Issuer csca = Csca(Utopia, Rsa(), signatureAlgorithm);
        var store = new CscaTrustStore([csca.Certificate]);

        CscaTrustStore.Verification result = store.Verify(DocumentSigner(csca, Rsa().Public, signatureAlgorithm));

        Assert.True(result.Trusted);
        Assert.Same(csca.Certificate, result.Csca);
        Assert.Contains("was valid when", result.Detail);
    }

    [Fact]
    public void DocumentSignerIssuedByATrustedEcCsca()
    {
        Issuer csca = Csca(Utopia, Ec(), "SHA256WITHECDSA");

        Assert.True(new CscaTrustStore([csca.Certificate]).Verify(DocumentSigner(csca, Ec().Public, "SHA256WITHECDSA")).Trusted);
    }

    [Fact]
    public void EveryCscaKeyWithTheIssuerNameIsTried()
    {
        Issuer oldKey = Csca(Utopia, Rsa());
        Issuer newKey = Csca(Utopia, Rsa());
        // Without an authority key identifier both CSCAs are candidates; the right one is found either way.
        var store = new CscaTrustStore([oldKey.Certificate, newKey.Certificate]);

        Assert.True(store.Verify(DocumentSigner(newKey, Rsa().Public, authorityKeyId: false)).Trusted);
        Assert.True(store.Verify(DocumentSigner(oldKey, Rsa().Public, authorityKeyId: false)).Trusted);
    }

    [Fact]
    public void CscaWithTheRightNameButAnotherKeyIsNotTrusted()
    {
        Issuer real = Csca(Utopia, Rsa());
        Issuer impostor = Csca(Utopia, Rsa());

        CscaTrustStore.Verification result = new CscaTrustStore([impostor.Certificate]).Verify(DocumentSigner(real, Rsa().Public, authorityKeyId: false));

        Assert.False(result.Trusted);
        Assert.Contains("does not verify", result.Detail);
    }

    [Fact]
    public void AuthorityKeyIdentifierSelectsTheCsca()
    {
        Issuer real = Csca(Utopia, Rsa());
        Issuer other = Csca(Utopia, Rsa());

        // The other CSCA's subject key identifier differs from the certificate's authority key identifier.
        CscaTrustStore.Verification result = new CscaTrustStore([other.Certificate]).Verify(DocumentSigner(real, Rsa().Public));

        Assert.False(result.Trusted);
        Assert.Contains("no trusted CSCA", result.Detail);
    }

    [Fact]
    public void UnknownIssuerIsNotTrusted()
    {
        Issuer csca = Csca(Utopia, Rsa());
        Issuer elsewhere = Csca("C=XX, O=Elsewhere, CN=CSCA Elsewhere", Rsa());

        CscaTrustStore.Verification result = new CscaTrustStore([elsewhere.Certificate]).Verify(DocumentSigner(csca, Rsa().Public));

        Assert.False(result.Trusted);
        Assert.Contains("no trusted CSCA certificate for the issuer", result.Detail);
    }

    [Fact]
    public void CscaNotValidWhenTheDocumentSignerWasIssuedIsReported()
    {
        Issuer csca = Csca(Utopia, Rsa(), notBefore: Now.AddYears(-1), notAfter: Now.AddYears(5));

        CscaTrustStore.Verification result = new CscaTrustStore([csca.Certificate])
            .Verify(DocumentSigner(csca, Rsa().Public, notBefore: Now.AddYears(-3), notAfter: Now.AddYears(-2)));

        Assert.True(result.Trusted);
        Assert.Contains("was NOT valid", result.Detail);
    }

    [Fact]
    public void CertificatesAreLoadedFromAFolderInEveryFormat()
    {
        Issuer der = Csca("C=AA, CN=CSCA DER", Rsa());
        Issuer pem = Csca("C=BB, CN=CSCA PEM", Rsa());
        Issuer listed1 = Csca("C=CC, CN=CSCA ML 1", Rsa());
        Issuer listed2 = Csca("C=DD, CN=CSCA ML 2", Rsa());
        File.WriteAllBytes(Path.Combine(folder, "a.cer"), der.Certificate.GetEncoded());
        File.WriteAllText(Path.Combine(folder, "b.pem"), ToPem(pem.Certificate));
        File.WriteAllBytes(Path.Combine(folder, "c.ml"), MasterList(listed1.Certificate, listed2.Certificate));
        File.WriteAllText(Path.Combine(folder, "readme.txt"), "not a certificate");
        File.WriteAllText(Path.Combine(folder, "broken.crt"), "not a certificate either");

        CscaTrustStore store = CscaTrustStore.Load(folder);

        Assert.Equal(4, store.Certificates.Count);
        Assert.Single(store.Warnings); // broken.crt; readme.txt is not looked at
        Assert.Contains("broken.crt", store.Warnings[0]);
        Assert.True(store.Verify(DocumentSigner(listed2, Rsa().Public)).Trusted);
    }

    [Fact]
    public void MasterListWithAnotherContentTypeIsRejected()
    {
        var signedData = new Org.BouncyCastle.Asn1.Cms.SignedData(new Org.BouncyCastle.Asn1.DerSet(),
            new Org.BouncyCastle.Asn1.Cms.ContentInfo(Org.BouncyCastle.Asn1.Cms.CmsObjectIdentifiers.Data, new Org.BouncyCastle.Asn1.DerOctetString([1])),
            null, null, new Org.BouncyCastle.Asn1.DerSet());
        byte[] encoded = new Org.BouncyCastle.Asn1.Cms.ContentInfo(Org.BouncyCastle.Asn1.Cms.CmsObjectIdentifiers.SignedData, signedData).GetEncoded();

        Assert.Throws<ArgumentException>(() => CscaTrustStore.ReadMasterList(encoded).ToList());
    }

    [Fact]
    public void MissingPathIsAnError() =>
        Assert.Throws<FileNotFoundException>(() => CscaTrustStore.Load(Path.Combine(folder, "missing")));

    /// <summary>The whole flow on the simulated chip, with an EF.SOD signed by a Document Signer of a test CSCA.</summary>
    [Theory]
    [InlineData(true, "trusted")]
    [InlineData(false, "untrusted")]
    public void DocumentReaderChecksTheDocumentSigner(bool trustTheCsca, string expected)
    {
        Issuer csca = Csca(Utopia, Rsa());
        AsymmetricCipherKeyPair signerKey = Rsa();
        var document = new SimulatedDocument
        {
            DocumentSignerKey = signerKey.Private,
            DocumentSignerCertificate = DocumentSigner(csca, signerKey.Public),
        };
        var store = new CscaTrustStore(trustTheCsca ? [csca.Certificate] : [Csca(Utopia, Rsa()).Certificate]);
        var text = new StringWriter();
        var reader = new DocumentReader(Open(document.Build(), isSfiEnabled: true), text) { TrustStore = store };

        reader.Read(new AccessCredentials(AccessKeyMode.Mrz,
            new BacKey(SimulatedDocument.DocumentNumber, SimulatedDocument.DateOfBirth, SimulatedDocument.DateOfExpiry), null), false, folder);

        Assert.Equal("valid", reader.Report.PassiveAuthentication.Signature);
        Assert.Equal(expected, reader.Report.PassiveAuthentication.Csca);
        Assert.True(reader.Report.PassiveAuthentication.SignerCertificateValidNow);
        Assert.Contains("revocation (CRLs) is not checked", text.ToString());
        if (trustTheCsca)
        {
            Assert.Contains("CN=CSCA Utopia", reader.Report.PassiveAuthentication.CscaSubject);
        }
    }

    private static string ToPem(Org.BouncyCastle.X509.X509Certificate certificate)
    {
        var writer = new StringWriter();
        var pem = new Org.BouncyCastle.OpenSsl.PemWriter(writer);
        pem.WriteObject(certificate);
        pem.Writer.Flush();
        return writer.ToString();
    }
}
