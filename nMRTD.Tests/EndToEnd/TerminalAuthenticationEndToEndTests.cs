using nMRTD.Cert;
using nMRTD.Lds;
using nMRTD.Protocol;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Crypto;
using static nMRTD.Tests.EndToEnd.EndToEnd;

namespace nMRTD.Tests.EndToEnd;

/// <summary>Terminal Authentication end to end: a CVCA -> DV -> IS chain unlocks DG3.</summary>
public class TerminalAuthenticationEndToEndTests
{
    private static (SimulatedChip Chip, PassportService Service, AsymmetricCipherKeyPair Cvca, PACEResult? Pace, EACCAResult Ca) Prepare(bool usePace, bool isSfiEnabled)
    {
        var document = new SimulatedDocument { CvcaKey = SimulatedDocument.GenerateEc(13) };
        document.Pace.Add(new SimulatedChip.PaceSupport(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, 13));
        document.ChipAuthenticationKeys.Add(new SimulatedChip.CaKey(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128, SimulatedDocument.GenerateEc(13), 1));
        SimulatedChip chip = document.Build();
        PassportService service = Open(chip, isSfiEnabled);
        PACEResult? pace = null;
        if (usePace)
        {
            pace = DoPace(service, PaceKeySpec.CreateCanKey(SimulatedDocument.Can));
        }
        else
        {
            DoBac(service);
        }
        EACCAResult ca = DoChipAuthentication(service);
        return (chip, service, document.CvcaKey, pace, ca);
    }

    private static EACTAResult DoTerminalAuthentication(PassportService service, PACEResult? pace, EACCAResult ca,
        IReadOnlyList<CardVerifiableCertificate> chain, AsymmetricKeyParameter terminalKey)
    {
        CVCPrincipal caReference = new CVCAFile(new MemoryStream(Read(service, PassportService.EF_CVCA))).GetCAReference()!;
        return pace != null
            ? service.DoEACTA(caReference, chain, terminalKey, null, ca, pace)
            : service.DoEACTA(caReference, chain, terminalKey, null, ca, SimulatedDocument.DocumentNumber);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(true, true)]
    [InlineData(false, false)]
    [InlineData(false, true)]
    public void TerminalAuthenticationGrantsAccessToDg3(bool usePace, bool isSfiEnabled)
    {
        (SimulatedChip chip, PassportService service, AsymmetricCipherKeyPair cvca, PACEResult? pace, EACCAResult ca) = Prepare(usePace, isSfiEnabled);
        Assert.ThrowsAny<CardServiceException>(() => Read(service, PassportService.EF_DG3));

        (CardVerifiableCertificate dv, CardVerifiableCertificate @is, AsymmetricCipherKeyPair isKey) =
            SimulatedDocument.CreateTerminalChain(cvca, CVCAuthorizationTemplate.Permission.ReadAccessDg3);
        EACTAResult result = DoTerminalAuthentication(service, pace, ca, [dv, @is], isKey.Private);

        Assert.True(chip.TerminalAuthenticated);
        Assert.Equal(SimulatedDocument.CvcaReference, result.CAReference?.Name);
        Assert.Equal(2, result.CVCertificates.Count);
        Assert.Equal(SimulatedDocument.Dg3, Read(service, PassportService.EF_DG3));
    }

    [Fact]
    public void ExternalSignerProducesTheTerminalSignature()
    {
        (SimulatedChip chip, PassportService service, AsymmetricCipherKeyPair cvca, PACEResult? pace, EACCAResult ca) = Prepare(true, false);
        (CardVerifiableCertificate dv, CardVerifiableCertificate @is, AsymmetricCipherKeyPair isKey) =
            SimulatedDocument.CreateTerminalChain(cvca, CVCAuthorizationTemplate.Permission.ReadAccessDg3);
        CVCPrincipal caReference = new(SimulatedDocument.CvcaReference);

        byte[] Sign(string algorithm, byte[] data)
        {
            ISigner signer = Org.BouncyCastle.Security.SignerUtilities.GetSigner(algorithm);
            signer.Init(true, isKey.Private);
            signer.BlockUpdate(data, 0, data.Length);
            return signer.GenerateSignature();
        }

        service.DoEACTA(caReference, [dv, @is], null, null, ca, pace!, Sign,
            ((Org.BouncyCastle.Crypto.Parameters.ECPublicKeyParameters)isKey.Public).Parameters);

        Assert.True(chip.TerminalAuthenticated);
        Assert.Equal(SimulatedDocument.Dg3, Read(service, PassportService.EF_DG3));
    }

    [Fact]
    public void CertificateNotSignedByTheDocumentVerifierIsRejected()
    {
        (SimulatedChip chip, PassportService service, AsymmetricCipherKeyPair cvca, PACEResult? pace, EACCAResult ca) = Prepare(true, false);
        AsymmetricCipherKeyPair forger = SimulatedDocument.GenerateEc(13);
        (CardVerifiableCertificate dv, CardVerifiableCertificate @is, AsymmetricCipherKeyPair isKey) =
            SimulatedDocument.CreateTerminalChain(cvca, CVCAuthorizationTemplate.Permission.ReadAccessDg3, forger.Private);

        Assert.ThrowsAny<CardServiceException>(() => DoTerminalAuthentication(service, pace, ca, [dv, @is], isKey.Private));

        Assert.False(chip.TerminalAuthenticated);
        Assert.ThrowsAny<CardServiceException>(() => Read(service, PassportService.EF_DG3));
    }

    [Fact]
    public void SignatureWithTheWrongTerminalKeyIsRejected()
    {
        (SimulatedChip chip, PassportService service, AsymmetricCipherKeyPair cvca, PACEResult? pace, EACCAResult ca) = Prepare(false, false);
        (CardVerifiableCertificate dv, CardVerifiableCertificate @is, _) =
            SimulatedDocument.CreateTerminalChain(cvca, CVCAuthorizationTemplate.Permission.ReadAccessDg3);

        Assert.ThrowsAny<CardServiceException>(() =>
            DoTerminalAuthentication(service, pace, ca, [dv, @is], SimulatedDocument.GenerateEc(13).Private));

        Assert.False(chip.TerminalAuthenticated);
        Assert.ThrowsAny<CardServiceException>(() => Read(service, PassportService.EF_DG3));
    }

    [Fact]
    public void TerminalWithoutDg3RightsStillCannotReadDg3()
    {
        (SimulatedChip chip, PassportService service, AsymmetricCipherKeyPair cvca, PACEResult? pace, EACCAResult ca) = Prepare(true, false);
        (CardVerifiableCertificate dv, CardVerifiableCertificate @is, AsymmetricCipherKeyPair isKey) =
            SimulatedDocument.CreateTerminalChain(cvca, CVCAuthorizationTemplate.Permission.ReadAccessDg4);

        DoTerminalAuthentication(service, pace, ca, [dv, @is], isKey.Private);

        Assert.True(chip.TerminalAuthenticated);
        Assert.ThrowsAny<CardServiceException>(() => Read(service, PassportService.EF_DG3));
    }
}
