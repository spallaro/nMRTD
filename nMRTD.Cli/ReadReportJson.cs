/*
 * nMRTD - A .Net API for accessing Machine Readable Travel Documents.
 *
 * Copyright (C) Sebastiano Pallaro.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * Distributed under the terms of GNU LGPL v3.
 * See LICENSE for more information.
 */

using System.Text.Json;

namespace nMRTD.Cli;

/// <summary>
/// Writes a <see cref="ReadReport"/> as JSON (the <c>--json</c> output). Written field by field with
/// <see cref="Utf8JsonWriter"/>, which needs no reflection, so it also works in the Native AOT build.
/// </summary>
public static class ReadReportJson
{
    /// <param name="report">the results</param>
    /// <param name="output">where to write the JSON</param>
    /// <param name="includeDataGroupContent">whether to add each data group's bytes, in Base64, as <c>data</c>
    /// (<c>--json-data</c>)</param>
    /// <param name="includeDataGroupFields">whether to add each data group's parsed fields as <c>fields</c>
    /// (<c>--json-fields</c>)</param>
    public static void Write(ReadReport report, Stream output, bool includeDataGroupContent = false, bool includeDataGroupFields = false)
    {
        using var json = new Utf8JsonWriter(output, new JsonWriterOptions { Indented = true });
        json.WriteStartObject();
        json.WriteString("accessProtocol", report.AccessProtocol);
        json.WriteString("paceProtocol", report.PaceProtocol);
        json.WriteBoolean("explicitPaceParameters", report.ExplicitPaceParameters);

        if (report.Mrz is { } mrz)
        {
            json.WriteStartObject("mrz");
            json.WriteString("documentCode", mrz.DocumentCode);
            json.WriteString("documentNumber", mrz.DocumentNumber);
            json.WriteString("primaryIdentifier", mrz.PrimaryIdentifier);
            json.WriteString("secondaryIdentifier", mrz.SecondaryIdentifier);
            json.WriteString("nationality", mrz.Nationality);
            json.WriteString("issuingState", mrz.IssuingState);
            json.WriteString("dateOfBirth", mrz.DateOfBirth);
            json.WriteString("dateOfExpiry", mrz.DateOfExpiry);
            json.WriteString("gender", mrz.Gender);
            json.WriteEndObject();
        }
        else
        {
            json.WriteNull("mrz");
        }

        json.WriteStartArray("dataGroups");
        foreach (DataGroupResult dataGroup in report.DataGroups)
        {
            json.WriteStartObject();
            json.WriteNumber("number", dataGroup.Number);
            json.WriteBoolean("present", dataGroup.Present);
            if (dataGroup.Present)
            {
                json.WriteNumber("length", dataGroup.Length);
                json.WriteString("hash", dataGroup.Hash);
                if (dataGroup.Images.Count > 0)
                {
                    json.WriteStartArray("images");
                    foreach (ImageSummary image in dataGroup.Images)
                    {
                        json.WriteStartObject();
                        json.WriteString("mimeType", image.MimeType);
                        json.WriteNumber("offset", image.Offset);
                        json.WriteNumber("length", image.Length);
                        json.WriteEndObject();
                    }
                    json.WriteEndArray();
                }
                if (includeDataGroupFields && dataGroup.Fields != null)
                {
                    json.WritePropertyName("fields");
                    dataGroup.Fields.WriteTo(json);
                }
                if (includeDataGroupFields && dataGroup.FieldsError != null)
                {
                    json.WriteString("fieldsError", dataGroup.FieldsError);
                }
                if (includeDataGroupContent && dataGroup.Content != null)
                {
                    json.WriteBase64String("data", dataGroup.Content);
                }
            }
            json.WriteEndObject();
        }
        json.WriteEndArray();

        PassiveAuthenticationResult pa = report.PassiveAuthentication;
        json.WriteStartObject("passiveAuthentication");
        json.WriteString("signature", pa.Signature);
        json.WriteString("digestAlgorithm", pa.DigestAlgorithm);
        json.WriteString("signatureAlgorithm", pa.SignatureAlgorithm);
        json.WriteString("signer", pa.Signer);
        json.WriteString("error", pa.Error);
        json.WriteString("csca", pa.Csca);
        json.WriteString("cscaSubject", pa.CscaSubject);
        json.WriteString("cscaDetail", pa.CscaDetail);
        if (pa.SignerCertificateValidNow is bool validNow)
        {
            json.WriteBoolean("signerCertificateValidNow", validNow);
        }
        else
        {
            json.WriteNull("signerCertificateValidNow");
        }
        json.WriteEndObject();

        WriteProtocol(json, "chipAuthentication", report.ChipAuthentication);
        WriteProtocol(json, "activeAuthentication", report.ActiveAuthentication);
        json.WriteString("error", report.Error);
        json.WriteStartArray("failedChecks");
        foreach (string check in report.FailedChecks())
        {
            json.WriteStringValue(check);
        }
        json.WriteEndArray();
        json.WriteEndObject();
        json.Flush();
    }

    private static void WriteProtocol(Utf8JsonWriter json, string name, ProtocolResult result)
    {
        json.WriteStartObject(name);
        json.WriteString("status", result.Status);
        json.WriteBoolean("keyAuthenticated", result.KeyAuthenticated);
        json.WriteString("protocol", result.Protocol);
        json.WriteString("error", result.Error);
        json.WriteEndObject();
    }
}
