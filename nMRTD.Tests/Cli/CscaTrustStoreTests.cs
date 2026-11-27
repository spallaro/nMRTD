using nMRTD.Cli;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
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

    [Theory]
    [InlineData("SHA256WITHRSAANDMGF1")]
    [InlineData("SHA256WITHECDSA")]
    public void ImpostorCscaIsNotTrustedWithEveryAlgorithm(string signatureAlgorithm)
    {
        bool ec = signatureAlgorithm.EndsWith("ECDSA", StringComparison.Ordinal);
        Issuer real = Csca(Utopia, ec ? Ec() : Rsa(), signatureAlgorithm);
        Issuer impostor = Csca(Utopia, ec ? Ec() : Rsa(), signatureAlgorithm);

        CscaTrustStore.Verification result = new CscaTrustStore([impostor.Certificate])
            .Verify(DocumentSigner(real, (ec ? Ec() : Rsa()).Public, signatureAlgorithm, authorityKeyId: false));

        Assert.False(result.Trusted);
    }

    [Fact]
    public void UnreadableCertificateInAMasterListIsSkipped()
    {
        Issuer good = Csca(Utopia, Rsa());
        var list = new Org.BouncyCastle.Asn1.DerSequence(new Org.BouncyCastle.Asn1.DerInteger(0),
            new Org.BouncyCastle.Asn1.DerSet(new Org.BouncyCastle.Asn1.Asn1Encodable[]
            {
                good.Certificate.CertificateStructure, new Org.BouncyCastle.Asn1.DerSequence(new Org.BouncyCastle.Asn1.DerInteger(42)),
            }));
        var content = new Org.BouncyCastle.Asn1.Cms.ContentInfo(Org.BouncyCastle.Asn1.Icao.IcaoObjectIdentifiers.IdIcaoCscaMasterList,
            new Org.BouncyCastle.Asn1.DerOctetString(list.GetEncoded()));
        var signedData = new Org.BouncyCastle.Asn1.Cms.SignedData(new Org.BouncyCastle.Asn1.DerSet(), content, null, null, new Org.BouncyCastle.Asn1.DerSet());
        File.WriteAllBytes(Path.Combine(folder, "list.ml"),
            new Org.BouncyCastle.Asn1.Cms.ContentInfo(Org.BouncyCastle.Asn1.Cms.CmsObjectIdentifiers.SignedData, signedData).GetEncoded());

        CscaTrustStore store = CscaTrustStore.Load(folder);

        Assert.Single(store.Certificates);
        Assert.Contains("1 certificate(s) of the master list could not be read", Assert.Single(store.Warnings));
    }

    /// <summary>A CSCA whose subject key identifier cannot be decoded is still matched by name and signature. Two
    /// Lithuanian CSCAs in the Italian master list put the 20 identifier bytes in the extension without the OCTET
    /// STRING around them, as here.</summary>
    [Fact]
    public void UndecodableSubjectKeyIdentifierIsIgnored()
    {
        Issuer csca = Csca(Utopia, Rsa(), rawSubjectKeyIdentifier: Convert.FromHexString("B5E23D3BA102A77B77B55B0E6AD37B8E9D434D2D"));

        CscaTrustStore.Verification result = new CscaTrustStore([csca.Certificate]).Verify(DocumentSigner(csca, Rsa().Public));

        Assert.True(result.Trusted, result.Detail);
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

        Assert.Throws<ArgumentException>(() => CscaTrustStore.ReadMasterList(encoded, out _));
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

        (ReadReport report, StringWriter log) = DocumentReaderTests.Run(document.Build(), new AccessCredentials(AccessKeyMode.Mrz,
            new BacKey(SimulatedDocument.DocumentNumber, SimulatedDocument.DateOfBirth, SimulatedDocument.DateOfExpiry), null), trustStore: store);

        Assert.Equal("valid", report.PassiveAuthentication.Signature);
        Assert.Equal(expected, report.PassiveAuthentication.Csca);
        Assert.Equal(trustTheCsca ? ExitCodes.Success : ExitCodes.DocumentSignerNotTrusted, report.ExitCode());
        Assert.True(report.PassiveAuthentication.SignerCertificateValidNow);
        Assert.Contains(trustTheCsca ? "revocation is not checked: no certificate revocation list" : "Revocation is not checked: the Document Signer certificate is not trusted", log.ToString());
        Assert.Equal("not-checked", report.PassiveAuthentication.Revocation);
        if (trustTheCsca)
        {
            Assert.Contains("CN=CSCA Utopia", report.PassiveAuthentication.CscaSubject);
        }
    }

    // ---- Revocation (certificate revocation lists in the --csca path) ----

    [Fact]
    public void DocumentSignerNotInTheCrlIsNotRevoked()
    {
        Issuer csca = Csca(Utopia, Rsa());
        X509Certificate signer = DocumentSigner(csca, Rsa().Public);
        X509Certificate other = DocumentSigner(csca, Rsa().Public);
        var store = new CscaTrustStore([csca.Certificate], [Crl(csca, revoked: other)]);

        CscaTrustStore.RevocationCheck check = store.CheckRevocation(signer, csca.Certificate);

        Assert.Equal("not-revoked", check.Status);
        Assert.Contains("not in the CRL of " + Now.AddDays(-1).ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture), check.Detail);
    }

    [Fact]
    public void DocumentSignerInTheCrlIsRevoked()
    {
        Issuer csca = Csca(Utopia, Rsa());
        X509Certificate signer = DocumentSigner(csca, Rsa().Public);
        var store = new CscaTrustStore([csca.Certificate], [Crl(csca, revoked: signer)]);

        CscaTrustStore.RevocationCheck check = store.CheckRevocation(signer, csca.Certificate);

        Assert.Equal("revoked", check.Status);
        Assert.Contains("revoked on " + Now.AddDays(-7).ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture), check.Detail);
        Assert.Contains("reason keyCompromise", check.Detail);
    }

    [Fact]
    public void NoCrlOfTheCsca()
    {
        Issuer csca = Csca(Utopia, Rsa());
        Issuer elsewhere = Csca("C=XX, O=Elsewhere, CN=CSCA Elsewhere", Rsa());
        var store = new CscaTrustStore([csca.Certificate, elsewhere.Certificate], [Crl(elsewhere)]);

        CscaTrustStore.RevocationCheck check = store.CheckRevocation(DocumentSigner(csca, Rsa().Public), csca.Certificate);

        Assert.Equal("no-crl", check.Status);
        Assert.Contains("1 CRL(s) of another name given", check.Detail);
    }

    /// <summary>After a CSCA name change (as the Italian CSCA in 2020, OU "State Police" to "Italian National
    /// Police"), the CRL of the new name does not cover certificates issued under the old one.</summary>
    [Fact]
    public void CrlOfTheRenamedCscaDoesNotCoverTheOldName()
    {
        Issuer oldName = Csca("C=UT, O=Utopia, OU=State Police, CN=CSCA Utopia", Rsa());
        Issuer newName = Csca("C=UT, O=Utopia, OU=National Police, CN=CSCA Utopia", Rsa());
        X509Certificate signer = DocumentSigner(oldName, Rsa().Public);
        var store = new CscaTrustStore([oldName.Certificate, newName.Certificate], [Crl(newName, revoked: signer)]);

        Assert.Equal("no-crl", store.CheckRevocation(signer, oldName.Certificate).Status);
    }

    /// <summary>A CRL with the CSCA's name but signed with another key counts for nothing, even if it lists the
    /// certificate.</summary>
    [Fact]
    public void CrlNotSignedByATrustedCscaIsInvalid()
    {
        Issuer csca = Csca(Utopia, Rsa());
        Issuer impostor = Csca(Utopia, Rsa());
        X509Certificate signer = DocumentSigner(csca, Rsa().Public);
        var store = new CscaTrustStore([csca.Certificate], [Crl(impostor, revoked: signer)]);

        Assert.Equal("crl-invalid", store.CheckRevocation(signer, csca.Certificate).Status);
    }

    /// <summary>After a key rollover the CRL is signed with the new key and also covers the certificates issued
    /// with the old one, as the Italian CSCA does.</summary>
    [Fact]
    public void CrlSignedWithTheNewCscaKeyCoversTheOldOne()
    {
        Issuer oldKey = Csca(Utopia, Rsa());
        Issuer newKey = Csca(Utopia, Rsa());
        X509Certificate signer = DocumentSigner(oldKey, Rsa().Public);
        var store = new CscaTrustStore([oldKey.Certificate, newKey.Certificate], [Crl(newKey, revoked: signer)]);

        Assert.Equal("revoked", store.CheckRevocation(signer, oldKey.Certificate).Status);
    }

    [Fact]
    public void TheMostRecentCrlIsUsed()
    {
        Issuer csca = Csca(Utopia, Rsa());
        X509Certificate signer = DocumentSigner(csca, Rsa().Public);
        X509Crl older = Crl(csca, Now.AddMonths(-6), Now.AddMonths(-3));
        X509Crl newer = Crl(csca, Now.AddDays(-1), Now.AddMonths(3), signer);
        var store = new CscaTrustStore([csca.Certificate], [newer, older]);

        Assert.Equal("revoked", store.CheckRevocation(signer, csca.Certificate).Status);
        Assert.Equal("not-revoked", new CscaTrustStore([csca.Certificate], [older]).CheckRevocation(signer, csca.Certificate).Status);
    }

    [Fact]
    public void OutOfDateCrlIsUsedAndReported()
    {
        Issuer csca = Csca(Utopia, Rsa());
        var store = new CscaTrustStore([csca.Certificate], [Crl(csca, Now.AddMonths(-6), Now.AddMonths(-3))]);

        CscaTrustStore.RevocationCheck check = store.CheckRevocation(DocumentSigner(csca, Rsa().Public), csca.Certificate);

        Assert.Equal("not-revoked", check.Status);
        Assert.Contains("out of date", check.Detail);
    }

    [Fact]
    public void CrlsAreLoadedFromAFolderInDerAndPem()
    {
        Issuer csca = Csca(Utopia, Rsa());
        File.WriteAllBytes(Path.Combine(folder, "csca.cer"), csca.Certificate.GetEncoded());
        File.WriteAllBytes(Path.Combine(folder, "CRL_CSCA.crl"), Crl(csca).GetEncoded());
        File.WriteAllText(Path.Combine(folder, "other.crl"), ToPem(Crl(csca)));
        File.WriteAllText(Path.Combine(folder, "broken.crl"), "not a CRL");

        CscaTrustStore store = CscaTrustStore.Load(folder);

        Assert.Equal(2, store.Crls.Count);
        Assert.Single(store.Certificates);
        Assert.Contains(store.Warnings, w => w.Contains("broken.crl", StringComparison.Ordinal));
    }

    /// <summary>The whole flow: a revoked Document Signer fails with -46; without a CRL revocation is not
    /// checked.</summary>
    [Theory]
    [InlineData("revoked", ExitCodes.DocumentSignerRevoked)]
    [InlineData("not-revoked", ExitCodes.Success)]
    [InlineData("not-checked", ExitCodes.Success)]
    public void DocumentReaderChecksTheRevocation(string revocation, int exitCode)
    {
        Issuer csca = Csca(Utopia, Rsa());
        AsymmetricCipherKeyPair signerKey = Rsa();
        X509Certificate signer = DocumentSigner(csca, signerKey.Public);
        var document = new SimulatedDocument { DocumentSignerKey = signerKey.Private, DocumentSignerCertificate = signer };
        X509Crl[] crls = revocation switch
        {
            "revoked" => [Crl(csca, revoked: signer)],
            "not-revoked" => [Crl(csca)],
            _ => [],
        };

        (ReadReport report, StringWriter log) = DocumentReaderTests.Run(document.Build(), new AccessCredentials(AccessKeyMode.Mrz,
            new BacKey(SimulatedDocument.DocumentNumber, SimulatedDocument.DateOfBirth, SimulatedDocument.DateOfExpiry), null),
            trustStore: new CscaTrustStore([csca.Certificate], crls));

        Assert.Equal("trusted", report.PassiveAuthentication.Csca);
        Assert.Equal(revocation, report.PassiveAuthentication.Revocation);
        Assert.Equal(exitCode, report.ExitCode());
        if (revocation == "revoked")
        {
            Assert.Equal([new FailedCheck(ExitCodes.DocumentSignerRevoked, "Document Signer certificate is revoked")], report.FailedChecks());
        }
        if (revocation == "not-checked")
        {
            Assert.Contains("revocation is not checked", log.ToString());
        }
    }

    private static string ToPem(object pemObject)
    {
        var writer = new StringWriter();
        var pem = new Org.BouncyCastle.OpenSsl.PemWriter(writer);
        pem.WriteObject(pemObject);
        pem.Writer.Flush();
        return writer.ToString();
    }
}
