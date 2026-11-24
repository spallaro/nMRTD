using System.Text.Json;
using nMRTD.Cli;
using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.Tests.Helpers;
using static nMRTD.Tests.EndToEnd.EndToEnd;

namespace nMRTD.Tests.Cli;

/// <summary>The parsed data group fields in the JSON (<c>--json-fields</c>).</summary>
public sealed class DataGroupFieldsTests : IDisposable
{
    private readonly string outDir = Path.Combine(Path.GetTempPath(), "nmrtd-fields-tests-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(outDir))
        {
            Directory.Delete(outDir, recursive: true);
        }
    }

    private static readonly AccessCredentials Mrz =
        new(AccessKeyMode.Mrz, new BacKey(SimulatedDocument.DocumentNumber, SimulatedDocument.DateOfBirth, SimulatedDocument.DateOfExpiry), null);

    private static readonly byte[] Front = [0xFF, 0xD8, 0xFF, 0xE0, 0x01, 0x02];
    private static readonly byte[] Rear = [0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A];

    private (ReadReport Report, byte[] Dg12) Read()
    {
        var document = new SimulatedDocument { ActiveAuthenticationKey = SimulatedDocument.RsaKey1024 };
        document.ChipAuthenticationKeys.Add(new SimulatedChip.CaKey(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128, SimulatedDocument.GenerateEc(13), 1));
        SimulatedChip chip = document.Build();
        byte[] dg11 = new DG11File("SPECIMEN<<TEST", ["TESTER"], "1234567", (string?)null, ["UTOPIA CITY"], ["1 MAIN STREET", "UTOPIA"],
            null, "ENGINEER", null, null, null, null, null).GetEncoded()!;
        byte[] dg12 = new DG12File("MINISTRY OF UTOPIA", "20260101", null, null, null, Front, Rear, "20260102101112", "SN-1").GetEncoded()!;
        chip.ApplicationFiles[PassportService.EF_DG11] = dg11;
        chip.ApplicationFiles[PassportService.EF_DG12] = dg12;
        var reader = new DocumentReader(Open(chip, isSfiEnabled: true), new StringWriter());
        reader.Read(Mrz, forceBac: false, outDir);
        return (reader.Report, dg12);
    }

    private static JsonElement DataGroup(JsonDocument json, int number) =>
        json.RootElement.GetProperty("dataGroups").EnumerateArray().First(d => d.GetProperty("number").GetInt32() == number);

    private static JsonDocument Json(ReadReport report, bool fields)
    {
        var buffer = new MemoryStream();
        ReadReportJson.Write(report, buffer, includeDataGroupFields: fields);
        return JsonDocument.Parse(buffer.ToArray());
    }

    [Fact]
    public void FieldsAreInTheJsonOnlyWhenAsked()
    {
        (ReadReport report, _) = Read();

        using JsonDocument plain = Json(report, fields: false);
        using JsonDocument full = Json(report, fields: true);

        Assert.All(plain.RootElement.GetProperty("dataGroups").EnumerateArray(), d => Assert.False(d.TryGetProperty("fields", out _)));

        JsonElement dg1 = DataGroup(full, 1).GetProperty("fields");
        Assert.Equal(SimulatedDocument.DocumentNumber, dg1.GetProperty("documentNumber").GetString());
        Assert.Equal("SPECIMEN", dg1.GetProperty("primaryIdentifier").GetString());
        Assert.Equal("TEST", dg1.GetProperty("secondaryIdentifiers")[0].GetString());

        JsonElement face = DataGroup(full, 2).GetProperty("fields").GetProperty("faces")[0];
        Assert.Equal("ISO/IEC 39794-5", face.GetProperty("format").GetString());
        Assert.Equal("image/jpeg", face.GetProperty("mimeType").GetString());

        JsonElement dg11 = DataGroup(full, 11).GetProperty("fields");
        Assert.Equal("SPECIMEN<<TEST", dg11.GetProperty("nameOfHolder").GetString());
        Assert.Equal(2, dg11.GetProperty("permanentAddress").GetArrayLength());
        Assert.Equal("ENGINEER", dg11.GetProperty("profession").GetString());
        Assert.False(dg11.TryGetProperty("telephone", out _)); // absent fields are left out

        JsonElement dg12 = DataGroup(full, 12).GetProperty("fields");
        Assert.Equal("MINISTRY OF UTOPIA", dg12.GetProperty("issuingAuthority").GetString());
        Assert.Equal(Front.Length, dg12.GetProperty("imageOfFrontLength").GetInt32());

        JsonElement infos = DataGroup(full, 14).GetProperty("fields").GetProperty("securityInfos");
        Assert.Contains(infos.EnumerateArray(), i => i.GetProperty("type").GetString() == "ChipAuthenticationInfo" && i.GetProperty("keyId").GetString() == "1");
        Assert.Contains(infos.EnumerateArray(), i => i.GetProperty("type").GetString() == "ChipAuthenticationPublicKeyInfo"
            && i.GetProperty("publicKey").GetString()!.StartsWith("EC", StringComparison.Ordinal));

        Assert.Equal("RSA [1024 bit]", DataGroup(full, 15).GetProperty("fields").GetProperty("publicKey").GetString());
    }

    [Fact]
    public void DocumentImagesOfDg12AreListedWithTheirFormat()
    {
        (ReadReport report, byte[] dg12) = Read();

        List<ImageSummary> images = report.DataGroups.Single(d => d.Number == 12).Images;

        Assert.Equal(["image/jpeg", "image/jp2"], images.Select(i => i.MimeType));
        Assert.Equal(Front, dg12.AsSpan(images[0].Offset, images[0].Length).ToArray());
        Assert.Equal(Rear, dg12.AsSpan(images[1].Offset, images[1].Length).ToArray());
    }

    [Fact]
    public void Iso19794FaceRecordIsDescribed()
    {
        var fields = DataGroupFields.For(2, Fixtures.GetBytes("/lds/bsi2008/Datagroup2.bin"))!;

        JsonElement face = JsonDocument.Parse(fields.ToJsonString()).RootElement.GetProperty("faces")[0];

        Assert.Equal("ISO/IEC 19794-5", face.GetProperty("format").GetString());
        Assert.True(face.GetProperty("width").GetInt32() > 0);
        Assert.Equal(3, face.GetProperty("poseAngle").GetArrayLength());
        Assert.Equal(JsonValueKind.Array, face.GetProperty("featurePoints").ValueKind);
    }

    [Fact]
    public void DataGroupsWithoutAParserHaveNoFields() =>
        Assert.Null(DataGroupFields.For(16, [0x70, 0x00]));

    [Fact]
    public void UnparseableDataGroupIsReported()
    {
        var report = new ReadReport();
        var dataGroup = new DataGroupResult(11) { Present = true, Length = 2, FieldsError = "bad DG11" };
        report.DataGroups.Add(dataGroup);

        using JsonDocument json = Json(report, fields: true);

        Assert.Equal("bad DG11", DataGroup(json, 11).GetProperty("fieldsError").GetString());
    }
}
