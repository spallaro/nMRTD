using nMRTD.Cert;
using nMRTD.Protocol;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Crypto;
using static nMRTD.Cert.CVCAuthorizationTemplate;

namespace nMRTD.Tests.Jmrtd.Protocol;

/// <summary>Port of JMRTD's <c>org.jmrtd.protocol.EACTAProtocolTest</c>.</summary>
/// <remarks>
/// ADAPTATION: JUnit's <c>@BeforeClass</c> certificate set-up is a lazily created shared fixture; JMRTD
/// passes <c>null</c> for the secure messaging wrapper of <c>EACTAProtocol</c> and of the
/// <c>EACCAResult</c>, which nMRTD's signatures declare non-nullable, hence the <c>null!</c>.
/// Java-only, not ported: <c>doTASignsWithNonBouncyCastleECTerminalKey</c>,
/// <c>doTASignsWithNonExtractableECTerminalKeyUsingCustomSignatureProvider</c> and
/// <c>testDeriveIdentifierNonBouncyCastleKey</c>, which exercise JCA keys and signature providers other
/// than Bouncy Castle's.
/// </remarks>
public class EACTAProtocolTest
{
    private static readonly Lazy<Chain> Certificates = new(CreateCertificates);

    private sealed record Chain(
        CVCPrincipal FirstCVCA, CVCPrincipal SecondCVCA, CVCPrincipal ThirdCVCA,
        CardVerifiableCertificate FirstCVCACertificate, CardVerifiableCertificate FirstLinkCertificate,
        CardVerifiableCertificate SecondLinkCertificate, CardVerifiableCertificate DvCertificate,
        CardVerifiableCertificate TerminalCertificate, AsymmetricCipherKeyPair TerminalKeyPair);

    private static Chain CreateCertificates()
    {
        var validFrom = new DateOnly(2020, 1, 1);
        var validTo = new DateOnly(2030, 12, 31);
        string algorithm = "SHA256withRSA";

        var cvcaTemplate = new CVCAuthorizationTemplate(Role.Cvca, Permission.ReadAccessDg3AndDg4);
        var dvTemplate = new CVCAuthorizationTemplate(Role.DvDomestic, Permission.ReadAccessDg3AndDg4);
        var isTemplate = new CVCAuthorizationTemplate(Role.Is, Permission.ReadAccessDg3AndDg4);

        var firstCVCA = new CVCPrincipal("UTCVCA00001");
        AsymmetricCipherKeyPair firstCVCAKeyPair = KeyPairs.Rsa(1024);
        CardVerifiableCertificate firstCVCACertificate = CVCertificateBuilder.CreateCertificate(
            firstCVCAKeyPair.Public, firstCVCAKeyPair.Private, algorithm, firstCVCA, firstCVCA, cvcaTemplate, validFrom, validTo);

        var secondCVCA = new CVCPrincipal("UTCVCA00002");
        AsymmetricCipherKeyPair secondCVCAKeyPair = KeyPairs.Rsa(1024);
        CardVerifiableCertificate firstLinkCertificate = CVCertificateBuilder.CreateCertificate(
            secondCVCAKeyPair.Public, firstCVCAKeyPair.Private, algorithm, firstCVCA, secondCVCA, cvcaTemplate, validFrom, validTo);

        var thirdCVCA = new CVCPrincipal("UTCVCA00003");
        AsymmetricCipherKeyPair thirdCVCAKeyPair = KeyPairs.Rsa(1024);
        CardVerifiableCertificate secondLinkCertificate = CVCertificateBuilder.CreateCertificate(
            thirdCVCAKeyPair.Public, secondCVCAKeyPair.Private, algorithm, secondCVCA, thirdCVCA, cvcaTemplate, validFrom, validTo);

        var dv = new CVCPrincipal("UTDV00001");
        AsymmetricCipherKeyPair dvKeyPair = KeyPairs.Rsa(1024);
        CardVerifiableCertificate dvCertificate = CVCertificateBuilder.CreateCertificate(
            dvKeyPair.Public, thirdCVCAKeyPair.Private, algorithm, thirdCVCA, dv, dvTemplate, validFrom, validTo);

        var terminal = new CVCPrincipal("UTIS00001");
        AsymmetricCipherKeyPair terminalKeyPair = KeyPairs.Rsa(1024);
        CardVerifiableCertificate terminalCertificate = CVCertificateBuilder.CreateCertificate(
            terminalKeyPair.Public, dvKeyPair.Private, algorithm, dv, terminal, isTemplate, validFrom, validTo);

        return new Chain(firstCVCA, secondCVCA, thirdCVCA, firstCVCACertificate, firstLinkCertificate,
            secondLinkCertificate, dvCertificate, terminalCertificate, terminalKeyPair);
    }

    [Fact]
    public void sendsDVAndTerminalCertificateForCurrentCVCA()
    {
        Chain c = Certificates.Value;
        AssertCertificatesSent(
            c.ThirdCVCA,
            [c.DvCertificate, c.TerminalCertificate],
            c.DvCertificate, c.TerminalCertificate);
    }

    [Fact]
    public void sendsLeadingLinkCertificateForPreviousCVCA()
    {
        Chain c = Certificates.Value;
        AssertCertificatesSent(
            c.SecondCVCA,
            [c.SecondLinkCertificate, c.DvCertificate, c.TerminalCertificate],
            c.SecondLinkCertificate, c.DvCertificate, c.TerminalCertificate);
    }

    [Fact]
    public void sendsMultipleLinkCertificatesForOlderCVCA()
    {
        Chain c = Certificates.Value;
        AssertCertificatesSent(
            c.FirstCVCA,
            [c.FirstLinkCertificate, c.SecondLinkCertificate, c.DvCertificate, c.TerminalCertificate],
            c.FirstLinkCertificate, c.SecondLinkCertificate, c.DvCertificate, c.TerminalCertificate);
    }

    [Fact]
    public void omitsSelfSignedTrustAnchorWithoutMutatingInput()
    {
        Chain c = Certificates.Value;
        IReadOnlyList<CardVerifiableCertificate> input = new List<CardVerifiableCertificate>
        {
            c.FirstCVCACertificate,
            c.FirstLinkCertificate,
            c.SecondLinkCertificate,
            c.DvCertificate,
            c.TerminalCertificate,
        }.AsReadOnly();
        RecordingEACTAService service = Execute(c.FirstCVCA, input);
        Assert.Equal(5, input.Count);
        AssertSentBodies(service, c.FirstLinkCertificate, c.SecondLinkCertificate, c.DvCertificate, c.TerminalCertificate);
    }

    private static void AssertCertificatesSent(CVCPrincipal caReference, List<CardVerifiableCertificate> certificates, params CardVerifiableCertificate[] expected)
    {
        RecordingEACTAService service = Execute(caReference, certificates);
        AssertSentBodies(service, expected);
    }

    private static RecordingEACTAService Execute(CVCPrincipal caReference, IReadOnlyList<CardVerifiableCertificate> certificates)
    {
        var service = new RecordingEACTAService();
        var protocol = new EACTAProtocol(service, null!);
        var chipAuthenticationResult = new EACCAResult(null, null, [1, 2, 3, 4], null, null, null!);
        EACTAResult result = protocol.DoTA(
            caReference,
            certificates,
            Certificates.Value.TerminalKeyPair.Private,
            null,
            chipAuthenticationResult,
            new byte[] { 5, 6, 7, 8 });
        Assert.Equal(caReference, result.CAReference);
        Assert.Equal(service.CertificateBodies.Count, result.CVCertificates.Count);
        return service;
    }

    private static void AssertSentBodies(RecordingEACTAService service, params CardVerifiableCertificate[] expected)
    {
        Assert.Equal(expected.Length, service.CertificateBodies.Count);
        for (int i = 0; i < expected.Length; i++)
        {
            Assert.Equal(expected[i].GetCertBodyData(), service.CertificateBodies[i]);
        }
    }

    private sealed class RecordingEACTAService : IApduLevelEacTACapable
    {
        public List<byte[]> CertificateBodies { get; } = [];

        public void SendMseSetDst(IApduWrapper? wrapper, byte[] data)
        {
            /* Nothing to do. */
        }

        public void SendPsoExtendedLengthMode(IApduWrapper? wrapper, byte[] certBodyData, byte[] certSignatureData) =>
            CertificateBodies.Add((byte[])certBodyData.Clone());

        public void SendMseSetAtExtAuth(IApduWrapper? wrapper, byte[] data)
        {
            /* Nothing to do. */
        }

        public byte[] SendGetChallenge(IApduWrapper? wrapper) => new byte[8];

        public void SendMutualAuthenticate(IApduWrapper? wrapper, byte[] signature)
        {
            /* Nothing to do. */
        }
    }
}
