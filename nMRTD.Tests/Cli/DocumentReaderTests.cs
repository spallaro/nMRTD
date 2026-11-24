using nMRTD.Cli;
using nMRTD.Lds;
using nMRTD.Tests.Helpers;
using static nMRTD.Tests.EndToEnd.EndToEnd;

namespace nMRTD.Tests.Cli;

/// <summary>The command-line tool's reading flow (<see cref="DocumentReader"/>) on the simulated chip.</summary>
public sealed class DocumentReaderTests : IDisposable
{
    private readonly string outDir = Path.Combine(Path.GetTempPath(), "nmrtd-cli-tests-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(outDir))
        {
            Directory.Delete(outDir, recursive: true);
        }
    }

    private static readonly AccessCredentials Mrz =
        new(AccessKeyMode.Mrz, new BacKey(SimulatedDocument.DocumentNumber, SimulatedDocument.DateOfBirth, SimulatedDocument.DateOfExpiry), null);

    private static readonly AccessCredentials Can = new(AccessKeyMode.Can, null, SimulatedDocument.Can);

    private (DocumentReader Reader, StringWriter Text, bool Read) Run(SimulatedDocument document, AccessCredentials credentials, bool forceBac = false)
    {
        PassportService service = Open(document.Build(), isSfiEnabled: true);
        var text = new StringWriter();
        var reader = new DocumentReader(service, text);
        bool read = reader.Read(credentials, forceBac, outDir);
        return (reader, text, read);
    }

    [Fact]
    public void BacDocumentIsReadAndPassiveAuthenticationHolds()
    {
        (DocumentReader reader, StringWriter text, bool read) = Run(new SimulatedDocument(), Mrz);

        Assert.True(read);
        ReadReport report = reader.Report;
        Assert.Equal("BAC", report.AccessProtocol);
        Assert.Equal(SimulatedDocument.DocumentNumber, report.Mrz!.DocumentNumber);
        Assert.Equal("SPECIMEN", report.Mrz.PrimaryIdentifier);
        Assert.Equal([1, 2], report.DataGroups.Where(d => d.Present).Select(d => d.Number));
        Assert.All(report.DataGroups.Where(d => d.Present), d => Assert.Equal("match", d.Hash));
        Assert.DoesNotContain(report.DataGroups, d => d.Number is 3 or 4); // EAC protected, never read
        Assert.Equal("valid", report.PassiveAuthentication.Signature);
        Assert.Contains("CN=Document Signer", report.PassiveAuthentication.Signer);
        Assert.Equal("not-checked", report.PassiveAuthentication.Csca);
        Assert.Equal("not-available", report.ChipAuthentication.Status);
        ImageSummary face = Assert.Single(report.DataGroups.Single(d => d.Number == 2).Images);
        Assert.Equal("image/jpeg", face.MimeType);
        Assert.Equal(SimulatedDocument.FaceImage, report.DataGroups.Single(d => d.Number == 2).Content!.AsSpan(face.Offset, face.Length).ToArray());
        Assert.True(File.Exists(Path.Combine(outDir, "dg2_face_0.jpg")));
        Assert.Contains("EF.SOD signature is VALID", text.ToString());
        Assert.Contains("BAC completed.", text.ToString());
    }

    [Fact]
    public void PaceAndChipAuthenticationAreReported()
    {
        var document = new SimulatedDocument();
        document.Pace.Add(new SimulatedChip.PaceSupport(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, 13));
        document.ChipAuthenticationKeys.Add(new SimulatedChip.CaKey(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128, SimulatedDocument.GenerateEc(13), 1));

        (DocumentReader reader, StringWriter text, bool read) = Run(document, Can);

        Assert.True(read);
        Assert.Equal("PACE", reader.Report.AccessProtocol);
        Assert.Equal(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, reader.Report.PaceProtocol);
        Assert.False(reader.Report.ExplicitPaceParameters);
        Assert.Equal("match", reader.Report.DataGroups.Single(d => d.Number == 14).Hash);
        Assert.Equal("succeeded", reader.Report.ChipAuthentication.Status);
        Assert.True(reader.Report.ChipAuthentication.KeyAuthenticated);
        Assert.Equal(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128, reader.Report.ChipAuthentication.Protocol);
        Assert.Contains("Chip Authentication succeeded", text.ToString());
    }

    [Fact]
    public void ForcedBacSkipsPace()
    {
        var document = new SimulatedDocument();
        document.Pace.Add(new SimulatedChip.PaceSupport(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, 13));

        (DocumentReader reader, StringWriter text, _) = Run(document, Mrz, forceBac: true);

        Assert.Equal("BAC", reader.Report.AccessProtocol);
        Assert.Contains("Skipping PACE (--bac)", text.ToString());
    }

    [Fact]
    public void CanWithoutPaceCannotReadTheDocument()
    {
        (DocumentReader reader, _, bool read) = Run(new SimulatedDocument(), Can);

        Assert.False(read);
        Assert.Null(reader.Report.AccessProtocol);
    }

    [Fact]
    public void ModifiedDataGroupIsReportedAsAHashMismatch()
    {
        var document = new SimulatedDocument();
        SimulatedChip chip = document.Build();
        chip.ApplicationFiles[PassportService.EF_DG2][^1] ^= 0x01;
        PassportService service = Open(chip, isSfiEnabled: true);
        var reader = new DocumentReader(service, new StringWriter());

        reader.Read(Mrz, forceBac: false, outDir);

        Assert.Equal("mismatch", reader.Report.DataGroups.Single(d => d.Number == 2).Hash);
        Assert.Equal("match", reader.Report.DataGroups.Single(d => d.Number == 1).Hash);
    }

    [Fact]
    public void ReportIsWrittenAsJson()
    {
        var document = new SimulatedDocument();
        document.Pace.Add(new SimulatedChip.PaceSupport(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, 13));
        (DocumentReader reader, _, _) = Run(document, Can);
        var buffer = new MemoryStream();

        ReadReportJson.Write(reader.Report, buffer);

        using var json = System.Text.Json.JsonDocument.Parse(buffer.ToArray());
        System.Text.Json.JsonElement root = json.RootElement;
        Assert.Equal("PACE", root.GetProperty("accessProtocol").GetString());
        Assert.Equal(SimulatedDocument.DocumentNumber, root.GetProperty("mrz").GetProperty("documentNumber").GetString());
        Assert.StartsWith("F", root.GetProperty("mrz").GetProperty("gender").GetString());
        System.Text.Json.JsonElement dg1 = root.GetProperty("dataGroups").EnumerateArray().First(d => d.GetProperty("number").GetInt32() == 1);
        Assert.True(dg1.GetProperty("present").GetBoolean());
        Assert.Equal("match", dg1.GetProperty("hash").GetString());
        Assert.Equal("valid", root.GetProperty("passiveAuthentication").GetProperty("signature").GetString());
        Assert.Equal("not-checked", root.GetProperty("passiveAuthentication").GetProperty("csca").GetString());
        Assert.Equal("not-available", root.GetProperty("chipAuthentication").GetProperty("status").GetString());
        Assert.False(root.GetProperty("activeAuthentication").GetProperty("keyAuthenticated").GetBoolean());
        Assert.Equal(System.Text.Json.JsonValueKind.Null, root.GetProperty("error").ValueKind);
        Assert.False(root.TryGetProperty("savedFiles", out _));
        System.Text.Json.JsonElement dg2 = root.GetProperty("dataGroups").EnumerateArray().First(d => d.GetProperty("number").GetInt32() == 2);
        System.Text.Json.JsonElement image = Assert.Single(dg2.GetProperty("images").EnumerateArray());
        Assert.Equal("image/jpeg", image.GetProperty("mimeType").GetString());
        Assert.Equal(SimulatedDocument.FaceImage.Length, image.GetProperty("length").GetInt32());
        Assert.DoesNotContain("\"can\"", System.Text.Encoding.UTF8.GetString(buffer.ToArray()), StringComparison.OrdinalIgnoreCase); // no access key in the output
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
        var text = new StringWriter();
        var reader = new DocumentReader(Open(chip, isSfiEnabled: true), text);

        reader.Read(Mrz, forceBac: false, outDir);

        Assert.Equal("succeeded", reader.Report.ActiveAuthentication.Status);
        Assert.True(reader.Report.ActiveAuthentication.KeyAuthenticated);
        Assert.Contains(algorithm, reader.Report.ActiveAuthentication.Protocol);
        Assert.Equal("match", reader.Report.DataGroups.Single(d => d.Number == 15).Hash);
        Assert.Contains("Active Authentication succeeded", text.ToString());
    }

    [Theory]
    [InlineData("RSA-1024")]
    [InlineData("ECDSA")]
    public void WrongActiveAuthenticationSignatureFails(string keyKind)
    {
        var document = new SimulatedDocument
        {
            ActiveAuthenticationKey = keyKind == "ECDSA" ? SimulatedDocument.GenerateEc(12) : SimulatedDocument.RsaKey1024,
        };
        SimulatedChip chip = document.Build();
        chip.Fault = SimulatedChip.ChipFault.ActiveAuthenticationSignature;
        var reader = new DocumentReader(Open(chip, isSfiEnabled: true), new StringWriter());

        reader.Read(Mrz, forceBac: false, outDir);

        Assert.Equal("failed", reader.Report.ActiveAuthentication.Status);
    }

    [Fact]
    public void DocumentWithoutDg15HasNoActiveAuthentication()
    {
        (DocumentReader reader, StringWriter text, _) = Run(new SimulatedDocument(), Mrz);

        Assert.Equal("not-available", reader.Report.ActiveAuthentication.Status);
        Assert.Contains("DG15 not present", text.ToString());
    }

    [Fact]
    public void EcdsaResponseWithoutTheHashAlgorithmIsUnverifiable()
    {
        var key = SimulatedDocument.GenerateEc(12);

        ActiveAuthenticationVerifier.Result result = ActiveAuthenticationVerifier.Verify(key.Public, null, new byte[8], new byte[64]);

        Assert.Null(result.Valid);
    }

    [Fact]
    public void EmptyResponseIsNeverValid()
    {
        Assert.False(ActiveAuthenticationVerifier.Verify(SimulatedDocument.RsaKey1024.Public, null, new byte[8], []).Valid);
        Assert.False(ActiveAuthenticationVerifier.Verify(SimulatedDocument.GenerateEc(12).Public,
            ActiveAuthenticationInfo.ECDSA_PLAIN_SHA256_OID, new byte[8], []).Valid);
    }

    /// <summary>A chip that answers Active Authentication with a key that is not the one in EF.SOD: the
    /// protocol succeeds, but the key is not authenticated, which the report must make visible.</summary>
    [Fact]
    public void ActiveAuthenticationWithAKeyNotCoveredByTheSodIsFlagged()
    {
        var document = new SimulatedDocument { ActiveAuthenticationKey = SimulatedDocument.RsaKey1024 };
        SimulatedChip chip = document.Build();
        // A validly signed EF.SOD whose DG15 hash is not the hash of DG15.
        var hashes = new Dictionary<int, byte[]>
        {
            [1] = Org.BouncyCastle.Security.DigestUtilities.CalculateDigest("SHA-256", chip.ApplicationFiles[PassportService.EF_DG1]),
            [2] = Org.BouncyCastle.Security.DigestUtilities.CalculateDigest("SHA-256", chip.ApplicationFiles[PassportService.EF_DG2]),
            [15] = Org.BouncyCastle.Security.DigestUtilities.CalculateDigest("SHA-256", new byte[] { 0x42 }),
        };
        chip.ApplicationFiles[PassportService.EF_SOD] = new SODFile("SHA-256", "SHA256withRSA", hashes,
            SigningFixtures.KeyPair.Private, SigningFixtures.Certificate).GetEncoded()!;
        var text = new StringWriter();
        var reader = new DocumentReader(Open(chip, isSfiEnabled: true), text);

        reader.Read(Mrz, forceBac: false, outDir);

        Assert.Equal("valid", reader.Report.PassiveAuthentication.Signature);
        Assert.Equal("mismatch", reader.Report.DataGroups.Single(d => d.Number == 15).Hash);
        Assert.Equal("succeeded", reader.Report.ActiveAuthentication.Status);
        Assert.False(reader.Report.ActiveAuthentication.KeyAuthenticated);
        Assert.Contains("not covered by a valid EF.SOD signature", text.ToString());
    }

    [Fact]
    public void GenuineDocumentFailsNoCheck()
    {
        var document = new SimulatedDocument { ActiveAuthenticationKey = SimulatedDocument.RsaKey1024 };
        document.ChipAuthenticationKeys.Add(new SimulatedChip.CaKey(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128, SimulatedDocument.GenerateEc(13), 1));

        (DocumentReader reader, _, _) = Run(document, Mrz);

        Assert.Empty(reader.Report.FailedChecks());
    }

    [Fact]
    public void ProtocolsTheDocumentDoesNotOfferAreNotFailures()
    {
        (DocumentReader reader, _, _) = Run(new SimulatedDocument(), Mrz); // no DG14, no DG15

        Assert.Equal("not-available", reader.Report.ChipAuthentication.Status);
        Assert.Equal("not-available", reader.Report.ActiveAuthentication.Status);
        Assert.Empty(reader.Report.FailedChecks());
    }

    [Fact]
    public void ChangedDataGroupIsAFailedCheck()
    {
        SimulatedChip chip = new SimulatedDocument().Build();
        chip.ApplicationFiles[PassportService.EF_DG2][^1] ^= 0x01;
        var reader = new DocumentReader(Open(chip, isSfiEnabled: true), new StringWriter());

        reader.Read(Mrz, forceBac: false, outDir);

        Assert.Equal(["DG2 hash does not match EF.SOD"], reader.Report.FailedChecks());
    }

    [Fact]
    public void WrongActiveAuthenticationSignatureIsAFailedCheck()
    {
        SimulatedChip chip = new SimulatedDocument { ActiveAuthenticationKey = SimulatedDocument.RsaKey1024 }.Build();
        chip.Fault = SimulatedChip.ChipFault.ActiveAuthenticationSignature;
        var reader = new DocumentReader(Open(chip, isSfiEnabled: true), new StringWriter());

        reader.Read(Mrz, forceBac: false, outDir);

        Assert.Equal(["Active Authentication failed"], reader.Report.FailedChecks());
    }

    [Fact]
    public void ProtocolWithAKeyNotCoveredByTheSodIsAFailedCheck()
    {
        var report = new ReadReport();
        report.PassiveAuthentication.Signature = "valid";
        report.DataGroups.Add(new DataGroupResult(15) { Present = true, Hash = "not-in-sod" });
        report.ActiveAuthentication.Status = "succeeded";

        Assert.Equal(["Active Authentication used a key not covered by a valid EF.SOD signature"], report.FailedChecks());
    }

    [Theory]
    [InlineData("error")]
    [InlineData("unverifiable")]
    [InlineData("not-available")]
    public void InconclusiveActiveAuthenticationIsNotAFailure(string status)
    {
        var report = new ReadReport();
        report.ActiveAuthentication.Status = status;

        Assert.Empty(report.FailedChecks());
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
    public void DataGroupContentsAreInTheJsonOnlyWhenAsked()
    {
        var document = new SimulatedDocument();
        SimulatedChip chip = document.Build();
        var reader = new DocumentReader(Open(chip, isSfiEnabled: true), new StringWriter());
        reader.Read(Mrz, forceBac: false, outDir);
        var without = new MemoryStream();
        var with = new MemoryStream();

        ReadReportJson.Write(reader.Report, without);
        ReadReportJson.Write(reader.Report, with, includeDataGroupContent: true);

        using var plain = System.Text.Json.JsonDocument.Parse(without.ToArray());
        using var full = System.Text.Json.JsonDocument.Parse(with.ToArray());
        Assert.All(plain.RootElement.GetProperty("dataGroups").EnumerateArray(), d => Assert.False(d.TryGetProperty("data", out _)));
        foreach (System.Text.Json.JsonElement dataGroup in full.RootElement.GetProperty("dataGroups").EnumerateArray())
        {
            int number = dataGroup.GetProperty("number").GetInt32();
            if (dataGroup.GetProperty("present").GetBoolean())
            {
                Assert.Equal(chip.ApplicationFiles[(short)(0x0100 + number)], dataGroup.GetProperty("data").GetBytesFromBase64());
            }
            else
            {
                Assert.False(dataGroup.TryGetProperty("data", out _));
            }
        }
    }
}
