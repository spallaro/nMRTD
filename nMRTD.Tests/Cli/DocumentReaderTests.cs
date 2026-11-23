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
        Assert.Single(report.SavedFiles); // the DG2 face image
        Assert.True(File.Exists(report.SavedFiles[0].Path));
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
        Assert.Equal("F", root.GetProperty("mrz").GetProperty("gender").GetString()[..1]);
        System.Text.Json.JsonElement dg1 = root.GetProperty("dataGroups").EnumerateArray().First(d => d.GetProperty("number").GetInt32() == 1);
        Assert.True(dg1.GetProperty("present").GetBoolean());
        Assert.Equal("match", dg1.GetProperty("hash").GetString());
        Assert.Equal("valid", root.GetProperty("passiveAuthentication").GetProperty("signature").GetString());
        Assert.Equal("not-checked", root.GetProperty("passiveAuthentication").GetProperty("csca").GetString());
        Assert.Equal("not-available", root.GetProperty("chipAuthentication").GetProperty("status").GetString());
        Assert.Equal(System.Text.Json.JsonValueKind.Null, root.GetProperty("error").ValueKind);
        Assert.Single(root.GetProperty("savedFiles").EnumerateArray());
        Assert.DoesNotContain("\"can\"", System.Text.Encoding.UTF8.GetString(buffer.ToArray()), StringComparison.OrdinalIgnoreCase); // no access key in the output
    }
}
