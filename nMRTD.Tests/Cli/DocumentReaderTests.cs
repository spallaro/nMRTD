using nMRTD.SmartCards;
using nMRTD.Cli;
using nMRTD.Lds;
using nMRTD.Tests.Helpers;
using static nMRTD.Tests.EndToEnd.EndToEnd;

namespace nMRTD.Tests.Cli;

/// <summary>The command-line tool's reading flow (<see cref="DocumentReader"/>) on the simulated chip, and the
/// exit code each outcome gives.</summary>
public sealed class DocumentReaderTests
{
    private static readonly AccessCredentials Mrz =
        new(AccessKeyMode.Mrz, new BacKey(SimulatedDocument.DocumentNumber, SimulatedDocument.DateOfBirth, SimulatedDocument.DateOfExpiry), null);

    private static readonly AccessCredentials WrongMrz =
        new(AccessKeyMode.Mrz, new BacKey(SimulatedDocument.DocumentNumber, SimulatedDocument.DateOfBirth, "301231"), null);

    private static readonly AccessCredentials Can = new(AccessKeyMode.Can, null, SimulatedDocument.Can);

    /// <summary>Reads the chip as the tool does, catching a <see cref="ReadFailure"/> into the report.</summary>
    internal static (ReadReport Report, StringWriter Log) Run(SimulatedChip chip, AccessCredentials credentials,
        AccessMode mode = AccessMode.Auto, bool skipPassiveAuthentication = false, CscaTrustStore? trustStore = null)
    {
        var log = new StringWriter();
        var reader = new DocumentReader(Open(chip, isSfiEnabled: true), log) { TrustStore = trustStore };
        try
        {
            reader.Read(credentials, mode, skipPassiveAuthentication);
        }
        catch (ReadFailure e)
        {
            reader.Report.FailureExitCode = e.ExitCode;
            reader.Report.Error = e.Message;
        }
        return (reader.Report, log);
    }

    private static SimulatedDocument WithPace()
    {
        var document = new SimulatedDocument();
        document.Pace.Add(new SimulatedChip.PaceSupport(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, 13));
        return document;
    }

    [Fact]
    public void BacDocumentIsReadAndPassesEveryCheck()
    {
        (ReadReport report, StringWriter log) = Run(new SimulatedDocument().Build(), Mrz);

        Assert.Equal("BAC", report.AccessProtocol);
        Assert.Equal("3B80800101", report.Atr);
        Assert.Equal([1, 2], report.DataGroups.Where(d => d.Present).Select(d => d.Number));
        Assert.All(report.DataGroups.Where(d => d.Present), d => Assert.Equal("match", d.Hash));
        Assert.DoesNotContain(report.DataGroups, d => d.Number is 3 or 4); // need Terminal Authentication
        Assert.Equal("valid", report.PassiveAuthentication.Signature);
        Assert.Equal("not-checked", report.PassiveAuthentication.Csca);
        Assert.Equal("not-available", report.ChipAuthentication.Status);
        Assert.Equal("not-available", report.ActiveAuthentication.Status);
        // Without Chip Authentication EF.COM is read on its own.
        Assert.Equal("P", report.Document.DocumentCode);
        Assert.Equal("UTO", report.Document.IssuingState);
        Assert.NotNull(report.Document.LdsVersion);
        Assert.NotNull(report.Document.UnicodeVersion);
        Assert.Null(report.PaceProtocolName);
        Assert.Empty(report.FailedChecks());
        Assert.Equal(ExitCodes.Success, report.ExitCode());
        Assert.Contains("BAC completed.", log.ToString());
    }

    [Fact]
    public void PaceAndChipAuthentication()
    {
        SimulatedDocument document = WithPace();
        document.ChipAuthenticationKeys.Add(new SimulatedChip.CaKey(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128, SimulatedDocument.GenerateEc(13), 1));

        (ReadReport report, _) = Run(document.Build(), Can);

        Assert.Equal("PACE", report.AccessProtocol);
        Assert.Equal(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, report.PaceProtocol);
        Assert.Equal("id-PACE-ECDH-GM-AES-CBC-CMAC-128", report.PaceProtocolName);
        Assert.Equal(13, report.PaceParameterId);
        Assert.Equal("succeeded", report.ChipAuthentication.Status);
        Assert.Equal("id-CA-ECDH-AES-CBC-CMAC-128", report.ChipAuthentication.ProtocolName);
        Assert.StartsWith("EC", report.ChipAuthentication.PublicKey);
        Assert.NotNull(report.Document.LdsVersion); // EF.COM, read by Chip Authentication
        Assert.True(report.ChipAuthentication.KeyAuthenticated);
        Assert.Equal(ExitCodes.Success, report.ExitCode());
    }

    [Fact]
    public void BacModeSkipsPace()
    {
        (ReadReport report, _) = Run(WithPace().Build(), Mrz, AccessMode.Bac);

        Assert.Equal("BAC", report.AccessProtocol);
    }

    [Fact]
    public void AutoModeFallsBackToBacWithTheMrz()
    {
        (ReadReport report, StringWriter log) = Run(new SimulatedDocument().Build(), Mrz);

        Assert.Equal("BAC", report.AccessProtocol);
        Assert.Contains("falling back to BAC", log.ToString());
    }

    [Fact]
    public void PaceModeOnADocumentWithoutPaceFails()
    {
        (ReadReport report, _) = Run(new SimulatedDocument().Build(), Mrz, AccessMode.Pace);

        Assert.Equal(ExitCodes.PaceNotAvailable, report.ExitCode());
        Assert.Null(report.AccessProtocol);
    }

    [Fact]
    public void CanOnADocumentWithoutPaceFails() =>
        Assert.Equal(ExitCodes.PaceNotAvailable, Run(new SimulatedDocument().Build(), Can).Report.ExitCode());

    /// <summary>A wrong access key: the chip refuses the terminal's token in the last step of PACE.</summary>
    [Fact]
    public void WrongKeyFailsPace()
    {
        ReadReport report = Run(WithPace().Build(), new AccessCredentials(AccessKeyMode.Can, null, "654321")).Report;

        Assert.Equal(ExitCodes.PaceFailed, report.ExitCode());
        Assert.Contains("did not authenticate each other, status word 6300 (check the access key)", report.Error);
        Assert.Contains("PICC side exception in authentication token step", report.Error);
    }

    /// <summary>A refused MSE:Set AT (as an Italian passport answers to a CAN) suggests the kind of access key.</summary>
    [Fact]
    public void RefusedMseSetAtSuggestsTheKindOfAccessKey()
    {
        var refused = new CardServiceProtocolException("PICC side error in MSE:Set AT step", 0,
            new CardServiceException("Sending MSE:Set AT failed", 0x6A80));

        string message = DocumentReader.DescribePaceFailure(refused);

        Assert.StartsWith("PACE failed: the document refused MSE:Set AT, status word 6A80 (it may not accept this kind of access key", message);
        Assert.Equal("PACE failed (check the access key): no", DocumentReader.DescribePaceFailure(new CardServiceException("no")));
    }

    [Fact]
    public void WrongKeyFailsBac() =>
        Assert.Equal(ExitCodes.BacFailed, Run(new SimulatedDocument().Build(), WrongMrz).Report.ExitCode());

    [Fact]
    public void ChangedDataGroupIsAHashMismatch()
    {
        SimulatedChip chip = new SimulatedDocument().Build();
        chip.ApplicationFiles[PassportService.EF_DG2][^1] ^= 0x01;

        (ReadReport report, _) = Run(chip, Mrz);

        Assert.Equal("mismatch", report.DataGroups.Single(d => d.Number == 2).Hash);
        Assert.Equal([new FailedCheck(ExitCodes.HashMismatch, "DG2 hash does not match EF.SOD")], report.FailedChecks());
        Assert.Equal(ExitCodes.HashMismatch, report.ExitCode());
    }

    [Fact]
    public void SkippedPassiveAuthenticationChecksNothingAgainstEfSod()
    {
        SimulatedChip chip = new SimulatedDocument().Build();
        chip.ApplicationFiles[PassportService.EF_DG2][^1] ^= 0x01;

        (ReadReport report, _) = Run(chip, Mrz, skipPassiveAuthentication: true);

        Assert.Equal("skipped", report.PassiveAuthentication.Signature);
        Assert.All(report.DataGroups, d => Assert.Null(d.Hash));
        Assert.Equal(ExitCodes.Success, report.ExitCode());
    }

    [Theory]
    [InlineData("RSA-1024", false, "SHA-1")]
    [InlineData("RSA-2048", true, "SHA-256")]
    [InlineData("ECDSA", false, "SHA256withECDSA")]
    public void ActiveAuthenticationIsVerified(string keyKind, bool rsaSha256, string algorithm)
    {
        var document = new SimulatedDocument
        {
            ActiveAuthenticationKey = keyKind switch
            {
                "RSA-1024" => SimulatedDocument.RsaKey1024,
                "RSA-2048" => SimulatedDocument.RsaKey2048,
                _ => SimulatedDocument.GenerateEc(12),
            },
        };
        SimulatedChip chip = document.Build();
        chip.ActiveAuthenticationRsaSha256 = rsaSha256;

        (ReadReport report, _) = Run(chip, Mrz);

        Assert.Equal("succeeded", report.ActiveAuthentication.Status);
        Assert.True(report.ActiveAuthentication.KeyAuthenticated);
        Assert.Contains(algorithm, report.ActiveAuthentication.Protocol);
        Assert.StartsWith(keyKind == "ECDSA" ? "EC" : "RSA", report.ActiveAuthentication.PublicKey);
        Assert.Equal(ExitCodes.Success, report.ExitCode());
    }

    [Theory]
    [InlineData("RSA-1024")]
    [InlineData("ECDSA")]
    public void WrongActiveAuthenticationSignatureFails(string keyKind)
    {
        SimulatedChip chip = new SimulatedDocument
        {
            ActiveAuthenticationKey = keyKind == "ECDSA" ? SimulatedDocument.GenerateEc(12) : SimulatedDocument.RsaKey1024,
        }.Build();
        chip.Fault = SimulatedChip.ChipFault.ActiveAuthenticationSignature;

        (ReadReport report, _) = Run(chip, Mrz);

        Assert.Equal("failed", report.ActiveAuthentication.Status);
        Assert.Equal(ExitCodes.ActiveAuthenticationFailed, report.ExitCode());
    }

    /// <summary>A chip that answers Active Authentication with a key that is not the one in EF.SOD.</summary>
    [Fact]
    public void ActiveAuthenticationWithAKeyNotCoveredByTheSodFails()
    {
        SimulatedChip chip = new SimulatedDocument { ActiveAuthenticationKey = SimulatedDocument.RsaKey1024 }.Build();
        var hashes = new Dictionary<int, byte[]>
        {
            [1] = Org.BouncyCastle.Security.DigestUtilities.CalculateDigest("SHA-256", chip.ApplicationFiles[PassportService.EF_DG1]),
            [2] = Org.BouncyCastle.Security.DigestUtilities.CalculateDigest("SHA-256", chip.ApplicationFiles[PassportService.EF_DG2]),
            [15] = Org.BouncyCastle.Security.DigestUtilities.CalculateDigest("SHA-256", new byte[] { 0x42 }),
        };
        chip.ApplicationFiles[PassportService.EF_SOD] = new SODFile("SHA-256", "SHA256withRSA", hashes,
            SigningFixtures.KeyPair.Private, SigningFixtures.Certificate).GetEncoded()!;

        (ReadReport report, _) = Run(chip, Mrz);

        Assert.Equal("succeeded", report.ActiveAuthentication.Status);
        Assert.False(report.ActiveAuthentication.KeyAuthenticated);
        // The DG15 hash mismatch comes first in the order of the exit codes.
        Assert.Equal([ExitCodes.HashMismatch, ExitCodes.KeyNotAuthenticated], report.FailedChecks().Select(c => c.Code));
        Assert.Equal(ExitCodes.HashMismatch, report.ExitCode());
    }

    [Theory]
    [InlineData("error")]
    [InlineData("unverifiable")]
    [InlineData("not-available")]
    public void InconclusiveActiveAuthenticationIsNotAFailure(string status)
    {
        var report = new ReadReport();
        report.ActiveAuthentication.Status = status;

        Assert.Equal(ExitCodes.Success, report.ExitCode());
    }

    [Fact]
    public void DataGroupWithoutAHashInTheSodIsNotAFailure()
    {
        var report = new ReadReport();
        report.PassiveAuthentication.Signature = "valid";
        report.DataGroups.Add(new DataGroupResult(11) { Present = true, Hash = "not-in-sod" });

        Assert.Empty(report.FailedChecks());
    }

    [Fact]
    public void ProblemThatStoppedReadingWinsOverFailedChecks()
    {
        var report = new ReadReport { FailureExitCode = ExitCodes.CommunicationError };
        report.DataGroups.Add(new DataGroupResult(1) { Present = true, Hash = "mismatch" });

        Assert.Equal(ExitCodes.CommunicationError, report.ExitCode());
    }

    [Fact]
    public void EcdsaResponseWithoutTheHashAlgorithmIsUnverifiable() =>
        Assert.Null(ActiveAuthenticationVerifier.Verify(SimulatedDocument.GenerateEc(12).Public, null, new byte[8], new byte[64]).Valid);

    [Fact]
    public void EmptyResponseIsNeverValid()
    {
        Assert.False(ActiveAuthenticationVerifier.Verify(SimulatedDocument.RsaKey1024.Public, null, new byte[8], []).Valid);
        Assert.False(ActiveAuthenticationVerifier.Verify(SimulatedDocument.GenerateEc(12).Public,
            ActiveAuthenticationInfo.ECDSA_PLAIN_SHA256_OID, new byte[8], []).Valid);
    }

    /// <summary>A malformed EF.CardAccess offers no PACE: with the MRZ the tool falls back to BAC, a CAN cannot be
    /// used.</summary>
    [Fact]
    public void MalformedCardAccessFallsBackToBac()
    {
        SimulatedChip chip = WithPace().Build();
        chip.MasterFiles[PassportService.EF_CARD_ACCESS] = [0x31, 0x03, 0x30, 0x01, 0x06];

        (ReadReport report, StringWriter log) = Run(chip, Mrz);

        Assert.Equal("BAC", report.AccessProtocol);
        Assert.Contains("EF.CardAccess is malformed", log.ToString());
        Assert.Equal(ExitCodes.PaceNotAvailable, Run(chip, Can).Report.ExitCode());
    }

    /// <summary>A malformed EF.SOD fails Passive Authentication; the other protocols still run.</summary>
    [Fact]
    public void MalformedSodFailsPassiveAuthentication()
    {
        SimulatedChip chip = new SimulatedDocument { ActiveAuthenticationKey = SimulatedDocument.RsaKey1024 }.Build();
        chip.ApplicationFiles[PassportService.EF_SOD] = [0x77, 0x03, 0x30, 0x01, 0x05];

        (ReadReport report, _) = Run(chip, Mrz);

        Assert.Equal("invalid", report.PassiveAuthentication.Signature);
        Assert.Contains("EF.SOD is malformed", report.PassiveAuthentication.Error);
        Assert.Equal("succeeded", report.ActiveAuthentication.Status);
        Assert.Equal(ExitCodes.SodSignatureInvalid, report.ExitCode());
        Assert.Null(report.FailureExitCode);
    }

    /// <summary>A data group read that fails without an error status word (here a wrong MAC) stops reading with a
    /// communication error; it used to be reported as not present, and the document as valid.</summary>
    [Fact]
    public void FailedDataGroupReadIsACommunicationError()
    {
        SimulatedChip chip = new SimulatedDocument().Build();
        chip.CorruptNextResponseMac = true; // the first protected response is the read of DG1

        ReadReport report = Run(chip, Mrz).Report;

        Assert.Equal(ExitCodes.CommunicationError, report.ExitCode());
        Assert.StartsWith("DG1 could not be read", report.Error);
    }
}
