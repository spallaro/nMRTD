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

using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Encodings.Web;
using System.Text.Json.Nodes;
using System.Xml;

namespace nMRTD.Cli;

/// <summary>The output formats.</summary>
public enum OutputFormat
{
    /// <summary>Human readable text (the default).</summary>
    Text,

    /// <summary>JSON (<c>--output-json</c>).</summary>
    Json,

    /// <summary>XML (<c>--output-xml</c>).</summary>
    Xml,
}

/// <summary>What the output contains besides the outcome of each step.</summary>
/// <param name="IncludeInformation">the parsed data group information, images in Base64 (<c>--include-information</c>)</param>
/// <param name="IncludeRaw">each data group's bytes in Base64 (<c>--include-raw</c>)</param>
/// <param name="Share">leave out everything that identifies the holder or the document (<c>--share</c>)</param>
public sealed record OutputOptions(bool IncludeInformation = false, bool IncludeRaw = false, bool Share = false);

/// <summary>
/// Turns a <see cref="ReadReport"/> into one tree of values, then writes that tree as text, JSON or XML, so the
/// three formats always carry the same content. Only primitive values are used, so no reflection is needed
/// (Native AOT).
/// </summary>
public static class ReportOutput
{
    // ---- The tree ----

    /// <summary>The report as a tree of values, with the contents chosen by <paramref name="options"/>.</summary>
    public static JsonObject ToTree(ReadReport report, OutputOptions options)
    {
        var tree = new JsonObject
        {
            ["atr"] = report.Atr,
            ["accessProtocol"] = report.AccessProtocol,
            ["paceProtocol"] = report.PaceProtocol,
            ["explicitPaceParameters"] = report.ExplicitPaceParameters,
        };

        var dataGroups = new JsonArray();
        foreach (DataGroupResult dataGroup in report.DataGroups)
        {
            var node = new JsonObject
            {
                ["number"] = dataGroup.Number,
                ["present"] = dataGroup.Present,
            };
            if (dataGroup.Present)
            {
                node["length"] = dataGroup.Length;
                node["hash"] = dataGroup.Hash;
                if (options.IncludeInformation)
                {
                    if (dataGroup.Information != null)
                    {
                        node["information"] = options.Share
                            ? Redact(dataGroup.Number, dataGroup.Information)
                            : (JsonObject)Clone(dataGroup.Information)!;
                    }
                    if (dataGroup.InformationError != null)
                    {
                        node["informationError"] = dataGroup.InformationError;
                    }
                }
                if (options.IncludeRaw && !options.Share && dataGroup.Content != null)
                {
                    node["raw"] = Convert.ToBase64String(dataGroup.Content);
                }
            }
            dataGroups.Add((JsonNode)node);
        }
        tree["dataGroups"] = dataGroups;

        PassiveAuthenticationResult pa = report.PassiveAuthentication;
        tree["passiveAuthentication"] = new JsonObject
        {
            ["signature"] = pa.Signature,
            ["digestAlgorithm"] = pa.DigestAlgorithm,
            ["signatureAlgorithm"] = pa.SignatureAlgorithm,
            ["signer"] = options.Share ? null : pa.Signer,
            ["error"] = pa.Error,
            ["csca"] = pa.Csca,
            ["cscaSubject"] = options.Share ? null : pa.CscaSubject,
            ["cscaDetail"] = options.Share ? null : pa.CscaDetail, // may name the certificates
            ["signerCertificateValidNow"] = pa.SignerCertificateValidNow,
        };
        tree["chipAuthentication"] = Protocol(report.ChipAuthentication);
        tree["activeAuthentication"] = Protocol(report.ActiveAuthentication);

        var failedChecks = new JsonArray();
        foreach (FailedCheck check in report.FailedChecks())
        {
            failedChecks.Add((JsonNode)new JsonObject { ["code"] = check.Code, ["description"] = check.Description });
        }
        tree["failedChecks"] = failedChecks;
        tree["exitCode"] = report.ExitCode();
        tree["error"] = report.Error;
        return tree;
    }

    /// <summary>A copy of a node (a node can have only one parent); JsonNode.DeepClone needs .NET 8.</summary>
    private static JsonNode? Clone(JsonNode? node) => node == null ? null : JsonNode.Parse(node.ToJsonString());

    private static JsonObject Protocol(ProtocolResult result) => new()
    {
        ["status"] = result.Status,
        ["keyAuthenticated"] = result.KeyAuthenticated,
        ["protocol"] = result.Protocol,
        ["error"] = result.Error,
    };

    /// <summary>
    /// The information of a data group without what identifies the holder or the document (<c>--share</c>): DG1
    /// keeps the document code and the issuing state; DG2 and DG5-DG7 keep the image formats, sizes and kinds,
    /// without the images; DG11 and DG12 keep only the names of the fields present; DG14 and DG15 (keys and
    /// protocols) are kept.
    /// </summary>
    private static JsonObject Redact(int number, JsonObject information)
    {
        switch (number)
        {
            case 1:
                return Keep(information, "documentCode", "issuingState");
            case 2:
                return MapArray(information, "faces", face => Keep(face,
                    "format", "mimeType", "width", "height", "faceImageKind", "faceImageType", "colorSpace", "sourceType", "quality"));
            case 5:
            case 6:
            case 7:
                return MapArray(information, "images", image => Keep(image, "mimeType", "width", "height"));
            case 11:
            case 12:
                var names = new JsonArray();
                foreach (KeyValuePair<string, JsonNode?> field in information)
                {
                    names.Add((JsonNode?)field.Key);
                }
                return new JsonObject { ["presentFields"] = names };
            default:
                return (JsonObject)Clone(information)!;
        }
    }

    private static JsonObject Keep(JsonObject source, params string[] names)
    {
        var result = new JsonObject();
        foreach (string name in names)
        {
            if (source.TryGetPropertyValue(name, out JsonNode? value))
            {
                result[name] = Clone(value);
            }
        }
        return result;
    }

    private static JsonObject MapArray(JsonObject source, string name, Func<JsonObject, JsonObject> map)
    {
        var array = new JsonArray();
        if (source[name] is JsonArray items)
        {
            foreach (JsonNode? item in items)
            {
                array.Add((JsonNode?)(item is JsonObject itemObject ? map(itemObject) : null));
            }
        }
        return new JsonObject { [name] = array };
    }

    // ---- Writing ----

    public static void Write(ReadReport report, OutputOptions options, OutputFormat format, Stream output)
    {
        JsonObject tree = ToTree(report, options);
        switch (format)
        {
            case OutputFormat.Json:
                WriteJson(tree, output);
                break;
            case OutputFormat.Xml:
                WriteXml(tree, output);
                break;
            default:
                WriteText(tree, output);
                break;
        }
    }

    private static void WriteJson(JsonObject tree, Stream output)
    {
        // Not for HTML: '+' (Base64) and accented letters (names) are written as they are, not as \uXXXX.
        using var json = new Utf8JsonWriter(output, new JsonWriterOptions
        {
            Indented = true,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        });
        tree.WriteTo(json);
        json.Flush();
        output.WriteByte((byte)'\n');
    }

    /// <summary>XML with the same structure as the JSON: an element per field (null fields left out); an array
    /// is an element holding one element per item, named after the array (singular).</summary>
    private static void WriteXml(JsonObject tree, Stream output)
    {
        var settings = new XmlWriterSettings { Indent = true, Encoding = new UTF8Encoding(false) };
        using XmlWriter xml = XmlWriter.Create(output, settings);
        xml.WriteStartDocument();
        WriteXmlObject(xml, "nmrtdReport", tree);
        xml.WriteEndDocument();
        xml.Flush();
    }

    private static void WriteXmlObject(XmlWriter xml, string name, JsonObject node)
    {
        xml.WriteStartElement(name);
        foreach (KeyValuePair<string, JsonNode?> field in node)
        {
            WriteXmlNode(xml, field.Key, field.Value);
        }
        xml.WriteEndElement();
    }

    private static void WriteXmlNode(XmlWriter xml, string name, JsonNode? node)
    {
        switch (node)
        {
            case null:
                return;
            case JsonObject obj:
                WriteXmlObject(xml, name, obj);
                return;
            case JsonArray array:
                xml.WriteStartElement(name);
                string itemName = name.Length > 1 && name.EndsWith('s') ? name[..^1] : "item";
                foreach (JsonNode? item in array)
                {
                    WriteXmlNode(xml, itemName, item);
                }
                xml.WriteEndElement();
                return;
            default:
                xml.WriteElementString(name, Scalar(node));
                return;
        }
    }

    /// <summary>Human readable text: a line per field, nested values indented, labels from the field names.</summary>
    private static void WriteText(JsonObject tree, Stream output)
    {
        var text = new StringBuilder();
        WriteTextObject(text, tree, 0);
        byte[] bytes = new UTF8Encoding(false).GetBytes(text.ToString());
        output.Write(bytes, 0, bytes.Length);
    }

    private static void WriteTextObject(StringBuilder text, JsonObject node, int indent)
    {
        foreach (KeyValuePair<string, JsonNode?> field in node)
        {
            WriteTextField(text, Label(field.Key), field.Key, field.Value, indent);
        }
    }

    private static void WriteTextField(StringBuilder text, string label, string key, JsonNode? value, int indent)
    {
        string pad = new(' ', indent * 2);
        switch (value)
        {
            case null:
                return;
            case JsonObject obj:
                text.Append(pad).Append(label).AppendLine(":");
                WriteTextObject(text, obj, indent + 1);
                return;
            case JsonArray array:
                if (array.Count == 0)
                {
                    text.Append(pad).Append(label).AppendLine(": none");
                    return;
                }
                if (array.All(item => item is JsonValue))
                {
                    text.Append(pad).Append(label).Append(": ").AppendLine(string.Join(", ", array.Select(Scalar)));
                    return;
                }
                text.Append(pad).Append(label).AppendLine(":");
                int index = 1;
                foreach (JsonNode? item in array)
                {
                    if (item is not JsonObject itemObject)
                    {
                        continue;
                    }
                    if (key == "dataGroups" && itemObject["number"] is JsonValue number)
                    {
                        if (Scalar(itemObject["present"]) != "true")
                        {
                            text.Append(pad).Append("  DG").Append(Scalar(number)).AppendLine(": not present");
                        }
                        else
                        {
                            text.Append(pad).Append("  DG").AppendLine(Scalar(number));
                            WriteTextObject(text, Without(itemObject, "number", "present"), indent + 2);
                        }
                    }
                    else if (key == "failedChecks")
                    {
                        text.Append(pad).Append("  [").Append(Scalar(itemObject["code"])).Append("] ").AppendLine(Scalar(itemObject["description"]));
                    }
                    else
                    {
                        text.Append(pad).Append("  ").Append(index).AppendLine(".");
                        WriteTextObject(text, itemObject, indent + 2);
                    }
                    index++;
                }
                return;
            default:
                text.Append(pad).Append(label).Append(": ").AppendLine(Scalar(value));
                return;
        }
    }

    private static JsonObject Without(JsonObject source, params string[] names)
    {
        var result = new JsonObject();
        foreach (KeyValuePair<string, JsonNode?> field in source)
        {
            if (!names.Contains(field.Key))
            {
                result[field.Key] = Clone(field.Value);
            }
        }
        return result;
    }

    private static string Scalar(JsonNode? node)
    {
        if (node is not JsonValue value)
        {
            return "";
        }
        if (value.TryGetValue(out bool boolean))
        {
            return boolean ? "true" : "false";
        }
        if (value.TryGetValue(out string? text))
        {
            return text ?? "";
        }
        if (value.TryGetValue(out int number))
        {
            return number.ToString(CultureInfo.InvariantCulture);
        }
        return value.ToJsonString();
    }

    private static readonly Dictionary<string, string> Acronyms = new(StringComparer.Ordinal)
    {
        ["atr"] = "ATR", ["pace"] = "PACE", ["csca"] = "CSCA", ["sod"] = "SOD", ["dg"] = "DG", ["mrz"] = "MRZ",
        ["id"] = "ID", ["oid"] = "OID", ["mime"] = "MIME",
    };

    /// <summary>"accessProtocol" -> "Access protocol"; acronyms are kept upper case.</summary>
    private static string Label(string key)
    {
        var words = new List<string>();
        var word = new StringBuilder();
        foreach (char c in key)
        {
            if (char.IsUpper(c) && word.Length > 0)
            {
                words.Add(word.ToString());
                word.Clear();
            }
            word.Append(char.ToLowerInvariant(c));
        }
        words.Add(word.ToString());
        for (int i = 0; i < words.Count; i++)
        {
            words[i] = Acronyms.TryGetValue(words[i], out string? acronym) ? acronym : words[i];
        }
        string label = string.Join(" ", words);
        return char.ToUpperInvariant(label[0]) + label[1..];
    }
}
