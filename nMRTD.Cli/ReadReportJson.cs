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
    public static void Write(ReadReport report, Stream output)
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
            }
            json.WriteEndObject();
        }
        json.WriteEndArray();

        json.WriteStartArray("savedFiles");
        foreach (SavedFile file in report.SavedFiles)
        {
            json.WriteStartObject();
            json.WriteString("path", file.Path);
            json.WriteString("mimeType", file.MimeType);
            json.WriteNumber("length", file.Length);
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
