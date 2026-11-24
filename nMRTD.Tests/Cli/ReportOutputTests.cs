using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using nMRTD.Cli;
using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.Tests.Helpers;

namespace nMRTD.Tests.Cli;

/// <summary>The result as text, JSON or XML, with or without the parsed information, the raw bytes and the
/// personal data (<see cref="ReportOutput"/>, <see cref="DataGroupFields"/>).</summary>
public class ReportOutputTests
{
    private static readonly AccessCredentials Mrz =
        new(AccessKeyMode.Mrz, new BacKey(SimulatedDocument.DocumentNumber, SimulatedDocument.DateOfBirth, SimulatedDocument.DateOfExpiry), null);

    private static readonly byte[] Front = [0xFF, 0xD8, 0xFF, 0xE0, 0x01, 0x02];
    private static readonly byte[] Rear = [0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A];

    private static readonly Lazy<(ReadReport Report, SimulatedChip Chip)> Document = new(() =>
    {
        var document = new SimulatedDocument { ActiveAuthenticationKey = SimulatedDocument.RsaKey1024 };
        document.ChipAuthenticationKeys.Add(new SimulatedChip.CaKey(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128, SimulatedDocument.GenerateEc(13), 1));
        SimulatedChip chip = document.Build();
        chip.ApplicationFiles[PassportService.EF_DG11] = new DG11File("SPECIMEN<<TEST", ["TESTER"], "1234567", (string?)null,
            ["UTOPIA CITY"], ["1 MAIN STREET", "UTOPIA"], null, "ENGINEER", null, null, null, null, null).GetEncoded()!;
        chip.ApplicationFiles[PassportService.EF_DG12] = new DG12File("MINISTRY OF UTOPIA", "20260101", null, null, null,
            Front, Rear, "20260102101112", "SN-1").GetEncoded()!;
        return (DocumentReaderTests.Run(chip, Mrz).Report, chip);
    });

    private static string Render(OutputFormat format, OutputOptions options)
    {
        var buffer = new MemoryStream();
        ReportOutput.Write(Document.Value.Report, options, format, buffer);
        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    private static JsonElement DataGroup(JsonDocument json, int number) =>
        json.RootElement.GetProperty("dataGroups").EnumerateArray().First(d => d.GetProperty("number").GetInt32() == number);

    [Fact]
    public void JsonWithoutOptionsHasOnlyTheOutcomes()
    {
        using var json = JsonDocument.Parse(Render(OutputFormat.Json, new OutputOptions()));
        JsonElement root = json.RootElement;

        Assert.Equal("3B80800101", root.GetProperty("atr").GetString());
        Assert.Equal("BAC", root.GetProperty("accessProtocol").GetString());
        Assert.Equal("match", DataGroup(json, 1).GetProperty("hash").GetString());
        Assert.False(DataGroup(json, 1).TryGetProperty("information", out _));
        Assert.False(DataGroup(json, 1).TryGetProperty("raw", out _));
        Assert.Equal("succeeded", root.GetProperty("activeAuthentication").GetProperty("status").GetString());
        // DG11 and DG12 were added after EF.SOD was signed: no hash to compare, which is not a failure.
        Assert.Equal("not-in-sod", DataGroup(json, 11).GetProperty("hash").GetString());
        Assert.Equal(ExitCodes.Success, root.GetProperty("exitCode").GetInt32());
        Assert.Equal(0, root.GetProperty("failedChecks").GetArrayLength());
    }

    [Fact]
    public void InformationHasTheParsedFieldsAndTheImages()
    {
        using var json = JsonDocument.Parse(Render(OutputFormat.Json, new OutputOptions(IncludeInformation: true)));

        JsonElement dg1 = DataGroup(json, 1).GetProperty("information");
        Assert.Equal(SimulatedDocument.DocumentNumber, dg1.GetProperty("documentNumber").GetString());
        Assert.Equal("TEST", dg1.GetProperty("secondaryIdentifiers")[0].GetString());

        JsonElement face = DataGroup(json, 2).GetProperty("information").GetProperty("faces")[0];
        Assert.Equal("ISO/IEC 39794-5", face.GetProperty("format").GetString());
        Assert.Equal("image/jpeg", face.GetProperty("mimeType").GetString());
        Assert.Equal(SimulatedDocument.FaceImage, face.GetProperty("image").GetBytesFromBase64());

        JsonElement dg11 = DataGroup(json, 11).GetProperty("information");
        Assert.Equal("ENGINEER", dg11.GetProperty("profession").GetString());
        Assert.False(dg11.TryGetProperty("telephone", out _));

        JsonElement dg12 = DataGroup(json, 12).GetProperty("information");
        Assert.Equal("image/jpeg", dg12.GetProperty("imageOfFront").GetProperty("mimeType").GetString());
        Assert.Equal(Front, dg12.GetProperty("imageOfFront").GetProperty("image").GetBytesFromBase64());
        Assert.Equal("image/jp2", dg12.GetProperty("imageOfRear").GetProperty("mimeType").GetString());

        JsonElement infos = DataGroup(json, 14).GetProperty("information").GetProperty("securityInfos");
        Assert.Contains(infos.EnumerateArray(), i => i.GetProperty("type").GetString() == "ChipAuthenticationInfo");
        Assert.Equal("RSA [1024 bit]", DataGroup(json, 15).GetProperty("information").GetProperty("publicKey").GetString());
    }

    [Fact]
    public void RawHasEachDataGroupsBytes()
    {
        string output = Render(OutputFormat.Json, new OutputOptions(IncludeRaw: true));
        using var json = JsonDocument.Parse(output);

        Assert.DoesNotContain("\\u002B", output); // '+' of Base64 as it is

        foreach (JsonElement dataGroup in json.RootElement.GetProperty("dataGroups").EnumerateArray().Where(d => d.GetProperty("present").GetBoolean()))
        {
            short fid = (short)(0x0100 + dataGroup.GetProperty("number").GetInt32());
            Assert.Equal(Document.Value.Chip.ApplicationFiles[fid], dataGroup.GetProperty("raw").GetBytesFromBase64());
        }
    }

    [Fact]
    public void ShareLeavesOutWhatIdentifiesTheHolderOrTheDocument()
    {
        string output = Render(OutputFormat.Json, new OutputOptions(IncludeInformation: true, Share: true));
        using var json = JsonDocument.Parse(output);

        foreach (string personal in new[] { SimulatedDocument.DocumentNumber, "SPECIMEN", "ENGINEER", "MAIN STREET",
                     "\"" + SimulatedDocument.DateOfBirth, "\"" + SimulatedDocument.DateOfExpiry, "Document Signer", Convert.ToBase64String(Front) })
        {
            Assert.False(output.Contains(personal, StringComparison.Ordinal), personal);
        }
        JsonElement dg1 = DataGroup(json, 1).GetProperty("information");
        Assert.Equal("UTO", dg1.GetProperty("issuingState").GetString());
        Assert.Equal(["issuingState", "documentCode"], dg1.EnumerateObject().Select(p => p.Name).OrderByDescending(n => n));
        JsonElement face = DataGroup(json, 2).GetProperty("information").GetProperty("faces")[0];
        Assert.Equal("image/jpeg", face.GetProperty("mimeType").GetString());
        Assert.False(face.TryGetProperty("image", out _));
        Assert.Contains("profession", DataGroup(json, 11).GetProperty("information").GetProperty("presentFields").EnumerateArray().Select(f => f.GetString()));
        Assert.True(DataGroup(json, 14).GetProperty("information").TryGetProperty("securityInfos", out _));
        Assert.Equal("3B80800101", json.RootElement.GetProperty("atr").GetString());
        Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("passiveAuthentication").GetProperty("signer").ValueKind);
    }

    [Fact]
    public void XmlHasTheSameContent()
    {
        XDocument xml = XDocument.Parse(Render(OutputFormat.Xml, new OutputOptions(IncludeInformation: true)));
        XElement root = xml.Root!;

        Assert.Equal("nmrtdReport", root.Name.LocalName);
        Assert.Equal("BAC", root.Element("accessProtocol")!.Value);
        XElement dg1 = root.Element("dataGroups")!.Elements("dataGroup").First(d => d.Element("number")!.Value == "1");
        Assert.Equal("match", dg1.Element("hash")!.Value);
        Assert.Equal(SimulatedDocument.DocumentNumber, dg1.Element("information")!.Element("documentNumber")!.Value);
        Assert.Equal("TEST", dg1.Element("information")!.Element("secondaryIdentifiers")!.Element("secondaryIdentifier")!.Value);
        Assert.Equal("image/jpeg", root.Element("dataGroups")!.Elements("dataGroup").First(d => d.Element("number")!.Value == "2")
            .Element("information")!.Element("faces")!.Element("face")!.Element("mimeType")!.Value);
        Assert.Empty(root.Element("failedChecks")!.Elements());
        Assert.Null(root.Element("error")); // null fields are left out
    }

    [Fact]
    public void TextIsReadable()
    {
        string text = Render(OutputFormat.Text, new OutputOptions(IncludeInformation: true));

        Assert.Contains("ATR: 3B80800101", text);
        Assert.Contains("Access protocol: BAC", text);
        Assert.Contains("  DG1" + Environment.NewLine + "    Length: 93", text);
        Assert.Contains("  DG5: not present", text);
        Assert.Contains("Document number: " + SimulatedDocument.DocumentNumber, text);
        Assert.Contains("Secondary identifiers: TEST", text);
        Assert.Contains("Failed checks: none", text);
        Assert.Contains("Exit code: 0", text);
    }

    [Fact]
    public void FailedChecksAreListedWithTheirCodes()
    {
        SimulatedChip chip = new SimulatedDocument().Build();
        chip.ApplicationFiles[PassportService.EF_DG2][^1] ^= 0x01;
        var buffer = new MemoryStream();

        ReportOutput.Write(DocumentReaderTests.Run(chip, Mrz).Report, new OutputOptions(), OutputFormat.Text, buffer);

        string text = Encoding.UTF8.GetString(buffer.ToArray());
        Assert.Contains("  [-40] DG2 hash does not match EF.SOD", text);
        Assert.Contains("Exit code: -40", text);
    }

    [Fact]
    public void Iso19794FaceRecordIsDescribed()
    {
        var information = DataGroupFields.For(2, Fixtures.GetBytes("/lds/bsi2008/Datagroup2.bin"))!;

        JsonElement face = JsonDocument.Parse(information.ToJsonString()).RootElement.GetProperty("faces")[0];

        Assert.Equal("ISO/IEC 19794-5", face.GetProperty("format").GetString());
        Assert.True(face.GetProperty("width").GetInt32() > 0);
        Assert.Equal(3, face.GetProperty("poseAngle").GetArrayLength());
        Assert.True(face.GetProperty("image").GetBytesFromBase64().Length > 0);
    }

    [Fact]
    public void DataGroupsWithoutAParserHaveNoInformation() =>
        Assert.Null(DataGroupFields.For(16, [0x70, 0x00]));

    [Fact]
    public void ErrorOnlyReport()
    {
        var report = new ReadReport { FailureExitCode = ExitCodes.ReaderNotFound, Error = "No PC/SC reader found." };
        var buffer = new MemoryStream();

        ReportOutput.Write(report, new OutputOptions(), OutputFormat.Json, buffer);

        using var json = JsonDocument.Parse(buffer.ToArray());
        Assert.Equal(ExitCodes.ReaderNotFound, json.RootElement.GetProperty("exitCode").GetInt32());
        Assert.Equal("No PC/SC reader found.", json.RootElement.GetProperty("error").GetString());
    }
}
