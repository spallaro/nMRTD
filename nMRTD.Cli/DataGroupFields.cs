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
using System.Text.Json.Nodes;

using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.Lds.Iso19794;
using nMRTD.Lds.Iso39794;

using Org.BouncyCastle.Crypto;

namespace nMRTD.Cli;

/// <summary>
/// The parsed contents of a data group (<c>--include-information</c>): the MRZ (DG1), the face image records
/// (DG2), the displayed images (DG5-DG7), the additional personal and document details (DG11, DG12), the
/// security infos (DG14) and the Active Authentication key (DG15). Images are included in Base64 with their
/// format. Only primitive values are used, so writing it needs no reflection.
/// </summary>
public static class DataGroupFields
{
    /// <summary>The fields of the data group, or <c>null</c> for a data group without a parser (DG8-DG10,
    /// DG13, DG16).</summary>
    /// <exception cref="Exception">if the data group cannot be parsed</exception>
    public static JsonObject? For(int number, byte[] bytes) => number switch
    {
        1 => Dg1(new DG1File(new MemoryStream(bytes)).GetMRZInfo()),
        2 => Dg2(new DG2File(new MemoryStream(bytes))),
        5 => DisplayedImages(new DG5File(new MemoryStream(bytes)).GetImages()),
        6 => DisplayedImages(new DG6File(new MemoryStream(bytes)).GetImages()),
        7 => DisplayedImages(new DG7File(new MemoryStream(bytes)).GetImages()),
        11 => Dg11(new DG11File(new MemoryStream(bytes))),
        12 => Dg12(new DG12File(new MemoryStream(bytes))),
        14 => Dg14(new DG14File(new MemoryStream(bytes))),
        15 => Dg15(new DG15File(new MemoryStream(bytes))),
        _ => null,
    };

    private static JsonObject Dg1(MRZInfo mrz)
    {
        var fields = new JsonObject();
        Add(fields, "documentCode", mrz.GetDocumentCode());
        Add(fields, "issuingState", mrz.GetIssuingState());
        Add(fields, "documentNumber", mrz.GetDocumentNumber());
        Add(fields, "primaryIdentifier", mrz.GetPrimaryIdentifier());
        Add(fields, "secondaryIdentifiers", mrz.GetSecondaryIdentifierComponents());
        Add(fields, "nationality", mrz.GetNationality());
        Add(fields, "dateOfBirth", mrz.GetDateOfBirth());
        Add(fields, "gender", mrz.GetGenderCode().ToString());
        Add(fields, "dateOfExpiry", mrz.GetDateOfExpiry());
        Add(fields, "optionalData1", mrz.GetOptionalData1());
        Add(fields, "optionalData2", mrz.GetOptionalData2());
        Add(fields, "personalNumber", mrz.GetPersonalNumber());
        return fields;
    }

    private static JsonObject Dg2(DG2File dg2)
    {
        var faces = new JsonArray();
        foreach (var record in dg2.GetSubRecords())
        {
            switch (record)
            {
                case FaceInfo faceInfo:
                    foreach (FaceImageInfo image in faceInfo.GetFaceImageInfos())
                    {
                        faces.Add((JsonNode)Iso19794Face(image));
                    }
                    break;
                case FaceImageDataBlock dataBlock:
                    foreach (FaceImageRepresentationBlock representation in dataBlock.GetRepresentationBlocks())
                    {
                        faces.Add((JsonNode)Iso39794Face(representation));
                    }
                    break;
            }
        }
        return new JsonObject { ["faces"] = faces };
    }

    private static JsonObject Iso19794Face(FaceImageInfo image)
    {
        var face = new JsonObject
        {
            ["format"] = "ISO/IEC 19794-5",
            ["mimeType"] = image.GetMimeType(),
            ["width"] = image.GetWidth(),
            ["height"] = image.GetHeight(),
            ["gender"] = image.GetGender().ToString(),
            ["eyeColor"] = image.GetEyeColor().ToString(),
            ["hairColor"] = image.GetHairColor(),
            ["featureMask"] = image.GetFeatureMask(),
            ["expression"] = image.GetExpression(),
            ["poseAngle"] = Numbers(image.GetPoseAngle()),
            ["poseAngleUncertainty"] = Numbers(image.GetPoseAngleUncertainty()),
            ["faceImageType"] = image.GetFaceImageType(),
            ["colorSpace"] = image.GetColorSpace(),
            ["sourceType"] = image.GetSourceType(),
            ["deviceType"] = image.GetDeviceType(),
            ["quality"] = image.GetQuality(),
            ["image"] = Base64(image),
        };
        var points = new JsonArray();
        foreach (FaceImageInfo.FeaturePoint point in image.GetFeaturePoints())
        {
            points.Add((JsonNode)new JsonObject
            {
                ["type"] = point.GetPointType(),
                ["majorCode"] = point.GetMajorCode(),
                ["minorCode"] = point.GetMinorCode(),
                ["x"] = point.GetX(),
                ["y"] = point.GetY(),
            });
        }
        face["featurePoints"] = points;
        return face;
    }

    private static JsonObject Iso39794Face(FaceImageRepresentationBlock representation)
    {
        var face = new JsonObject
        {
            ["format"] = "ISO/IEC 39794-5",
            ["mimeType"] = representation.GetMimeType(),
            ["width"] = representation.GetWidth(),
            ["height"] = representation.GetHeight(),
        };
        FaceImageInformation2DBlock? information = representation.GetImageRepresentation2DBlock()?.GetImageInformation2DBlock();
        if (information?.GetFaceImageKind2DCode() is { } kind)
        {
            face["faceImageKind"] = kind.ToString();
        }
        if (representation.GetIdentityMetadataBlock() is { } identity)
        {
            if (identity.GetGenderCode() is { } gender)
            {
                face["gender"] = gender.ToString();
            }
            if (identity.GetEyeColourCode() is { } eyes)
            {
                face["eyeColour"] = eyes.ToString();
            }
            if (identity.GetHairColourCode() is { } hair)
            {
                face["hairColour"] = hair.ToString();
            }
        }
        if (representation.GetCaptureDateTimeBlock() is { } captured)
        {
            face["captureDateTime"] = string.Format(CultureInfo.InvariantCulture, "{0:D4}-{1:D2}-{2:D2}T{3:D2}:{4:D2}:{5:D2}",
                captured.GetYear(), captured.GetMonth(), captured.GetDay(), captured.GetHour(), captured.GetMinute(), captured.GetSecond());
        }
        if (representation.GetLandmarkBlocks() is { } landmarks)
        {
            face["landmarks"] = landmarks.Count;
        }
        if (representation.GetImageRepresentation2DBlock() != null)
        {
            face["image"] = Base64(representation);
        }
        return face;
    }

    private static JsonObject Dg11(DG11File dg11)
    {
        var fields = new JsonObject();
        Add(fields, "nameOfHolder", dg11.GetNameOfHolder());
        Add(fields, "otherNames", dg11.GetOtherNames());
        Add(fields, "personalNumber", dg11.GetPersonalNumber());
        Add(fields, "fullDateOfBirth", dg11.GetFullDateOfBirth());
        Add(fields, "placeOfBirth", dg11.GetPlaceOfBirth());
        Add(fields, "permanentAddress", dg11.GetPermanentAddress());
        Add(fields, "telephone", dg11.GetTelephone());
        Add(fields, "profession", dg11.GetProfession());
        Add(fields, "title", dg11.GetTitle());
        Add(fields, "personalSummary", dg11.GetPersonalSummary());
        if (dg11.GetProofOfCitizenship() is { } proof)
        {
            fields["proofOfCitizenship"] = Image(proof);
        }
        Add(fields, "otherValidTravelDocumentNumbers", dg11.GetOtherValidTDNumbers());
        Add(fields, "custodyInformation", dg11.GetCustodyInformation());
        return fields;
    }

    private static JsonObject Dg12(DG12File dg12)
    {
        var fields = new JsonObject();
        Add(fields, "issuingAuthority", dg12.GetIssuingAuthority());
        Add(fields, "dateOfIssue", dg12.GetDateOfIssue());
        Add(fields, "namesOfOtherPersons", dg12.GetNamesOfOtherPersons());
        Add(fields, "endorsementsAndObservations", dg12.GetEndorsementsAndObservations());
        Add(fields, "taxOrExitRequirements", dg12.GetTaxOrExitRequirements());
        if (dg12.GetImageOfFront() is { } front)
        {
            fields["imageOfFront"] = Image(front);
        }
        if (dg12.GetImageOfRear() is { } rear)
        {
            fields["imageOfRear"] = Image(rear);
        }
        Add(fields, "dateAndTimeOfPersonalization", dg12.GetDateAndTimeOfPersonalization());
        Add(fields, "personalizationSystemSerialNumber", dg12.GetPersonalizationSystemSerialNumber());
        return fields;
    }

    private static JsonObject Dg14(DG14File dg14)
    {
        var infos = new JsonArray();
        foreach (SecurityInfo info in dg14.GetSecurityInfos())
        {
            var entry = new JsonObject
            {
                ["type"] = info.GetType().Name,
                ["objectIdentifier"] = info.GetObjectIdentifier(),
                ["protocol"] = info.GetProtocolOIDString(),
            };
            switch (info)
            {
                case ChipAuthenticationInfo ca:
                    entry["version"] = ca.GetVersion();
                    AddNumber(entry, "keyId", ca.GetKeyId());
                    break;
                case ChipAuthenticationPublicKeyInfo publicKey:
                    AddNumber(entry, "keyId", publicKey.GetKeyId());
                    entry["publicKey"] = KeyDescription.Of(publicKey.GetSubjectPublicKey());
                    break;
                case PACEInfo pace:
                    entry["version"] = pace.GetVersion();
                    AddNumber(entry, "parameterId", pace.GetParameterId());
                    break;
                case PACEDomainParameterInfo domain:
                    AddNumber(entry, "parameterId", domain.GetParameterId());
                    break;
                case TerminalAuthenticationInfo ta:
                    entry["version"] = ta.GetVersion();
                    break;
                case ActiveAuthenticationInfo aa:
                    entry["version"] = aa.GetVersion();
                    Add(entry, "signatureAlgorithm", aa.GetSignatureAlgorithmOID());
                    break;
            }
            infos.Add((JsonNode)entry);
        }
        return new JsonObject { ["securityInfos"] = infos };
    }

    private static JsonObject Dg15(DG15File dg15)
    {
        AsymmetricKeyParameter? key = dg15.GetPublicKey();
        return new JsonObject { ["publicKey"] = key == null ? null : KeyDescription.Of(key) };
    }

    private static JsonObject DisplayedImages(List<DisplayedImageInfo> images)
    {
        var array = new JsonArray();
        foreach (DisplayedImageInfo image in images)
        {
            array.Add((JsonNode)new JsonObject
            {
                ["mimeType"] = image.GetMimeType(),
                ["width"] = image.GetWidth(),
                ["height"] = image.GetHeight(),
                ["image"] = Base64(image),
            });
        }
        return new JsonObject { ["images"] = array };
    }

    /// <summary>An image stored as bare bytes (DG11, DG12), with its format recognized from its first bytes.</summary>
    private static JsonObject Image(byte[] bytes) => new()
    {
        ["mimeType"] = MimeType(bytes),
        ["image"] = Convert.ToBase64String(bytes),
    };

    /// <summary>JPEG, JPEG 2000 (file or codestream), or <c>null</c>.</summary>
    public static string? MimeType(byte[] bytes) => bytes switch
    {
        [0xFF, 0xD8, ..] => "image/jpeg",
        [0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, ..] or [0xFF, 0x4F, 0xFF, 0x51, ..] => "image/jp2",
        _ => null,
    };

    private static string Base64(ImageInfo image)
    {
        using Stream stream = image.GetImageInputStream();
        using var buffer = new MemoryStream();
        stream.CopyTo(buffer);
        return Convert.ToBase64String(buffer.ToArray());
    }

    private static void Add(JsonObject fields, string name, string? value)
    {
        if (!string.IsNullOrEmpty(value))
        {
            fields[name] = value;
        }
    }

    private static void Add(JsonObject fields, string name, IEnumerable<string>? values)
    {
        if (values == null)
        {
            return;
        }
        var array = new JsonArray();
        foreach (string value in values)
        {
            array.Add((JsonNode?)value);
        }
        if (array.Count > 0)
        {
            fields[name] = array;
        }
    }

    private static void AddNumber(JsonObject fields, string name, Org.BouncyCastle.Math.BigInteger? value)
    {
        if (value != null)
        {
            fields[name] = value.ToString();
        }
    }

    private static JsonArray Numbers(int[] values)
    {
        var array = new JsonArray();
        foreach (int value in values)
        {
            array.Add((JsonNode?)value);
        }
        return array;
    }
}
