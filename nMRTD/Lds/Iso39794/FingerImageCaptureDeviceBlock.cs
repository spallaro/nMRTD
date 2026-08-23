/*
 * nMRTD - A .Net API for accessing Machine Readable Travel Documents.
 *
 * Copyright (C) Sebastiano Pallaro.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * This is a porting from jMRTD, Copyright (C) The jMRTD Team (https://jmrtd.org/).
 *
 * Distributed under the terms of GNU LGPL v3.
 * See LICENSE for more information.
 */

using Org.BouncyCastle.Asn1;

namespace nMRTD.Lds.Iso39794;

//  CaptureDeviceBlock ::= SEQUENCE {
//    modelIdBlock [0] RegistryIdBlock,
//    technologyId [1] CaptureDeviceTechnologyId OPTIONAL,
//    certificationIdBlocks [2] CertificationIdBlocks OPTIONAL,
//    ...
//  }

/// <summary>
/// Port of <c>org.jmrtd.lds.iso39794.FingerImageCaptureDeviceBlock</c>. Java's <c>Serializable</c> marker
/// is dropped (no reflection-based serialization is needed in this port).
///
/// ADAPTATION: Java's version is a top-level <c>public class</c>, but this is <c>internal</c> since its
/// base class <see cref="Block"/> is <c>internal</c> in this port (see <c>VersionBlock</c>'s doc comment).
/// </summary>
internal class FingerImageCaptureDeviceBlock : Block
{
    /// <summary>
    /// ADAPTATION: Java's version is <c>enum CaptureDeviceTechnologyIdCode implements
    /// EncodableEnum&lt;CaptureDeviceTechnologyIdCode&gt;</c>, using reflection-based
    /// <c>EncodableEnum.fromCode</c> lookup keyed on each constant's own <c>getCode()</c>. Ported as a plain
    /// enum with explicit numeric values matching each Java constant's <c>getCode()</c> (declaration order
    /// and code do NOT coincide here -- code 8 is skipped); see <c>ScoreOrError.ScoringErrorCode</c>'s doc
    /// comment for the fuller rationale and <see cref="FromCode"/> for the shared "decode from code"
    /// replacement.
    /// </summary>
    public enum CaptureDeviceTechnologyIdCode
    {
        UnknownCaptureDeviceTechnology = 0,
        OtherCaptureDeviceTechnology = 1,
        ScannedInkOnPaper = 2,
        OpticalTirBrightField = 3,
        OpticalTirDarkField = 4,
        OpticalImage = 5,
        OpticalLowFrequency3DMapped = 6,
        OpticalHighFrequency3DMapped = 7,
        Capacitive = 9,
        CapacitiveRf = 10,
        ElectroLuminescence = 11,
        ReflectedUltrasonic = 12,
        ImpediographicUltrasonic = 13,
        Thermal = 14,
        DirectPressure = 15,
        IndirectPressure = 16,
        LiveTape = 17,
        LatentImpression = 18,
        LatentPhoto = 19,
        LatentMolded = 20,
        LatentTracing = 21,
        LatentLift = 22,
    }

    private static CaptureDeviceTechnologyIdCode? FromCode(int code) =>
        Enum.IsDefined(typeof(CaptureDeviceTechnologyIdCode), code) ? (CaptureDeviceTechnologyIdCode)code : null;

    /// <summary>Identification of the model capture device.</summary>
    private readonly RegistryIdBlock? _model;

    private readonly CaptureDeviceTechnologyIdCode? _captureDeviceTechnologyIdCode;

    /// <summary>Identification of certifications.</summary>
    private readonly List<RegistryIdBlock>? _certifications;

    public FingerImageCaptureDeviceBlock(RegistryIdBlock? model,
        CaptureDeviceTechnologyIdCode? captureDeviceTechnologyIdCode, List<RegistryIdBlock>? certifications)
    {
        _model = model;
        _captureDeviceTechnologyIdCode = captureDeviceTechnologyIdCode;
        _certifications = certifications;
    }

    internal FingerImageCaptureDeviceBlock(Asn1Encodable? asn1Encodable)
    {
        if (asn1Encodable == null)
        {
            throw new ArgumentException("Cannot decode null!");
        }

        Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
        if (taggedObjects.TryGetValue(0, out Asn1Encodable? modelObject))
        {
            _model = new RegistryIdBlock(modelObject);
        }
        if (taggedObjects.TryGetValue(1, out Asn1Encodable? technologyIdObject))
        {
            _captureDeviceTechnologyIdCode = FromCode(ISO39794Util.DecodeCodeFromChoiceExtensionBlockFallback(technologyIdObject)!.Value);
        }
        if (taggedObjects.TryGetValue(2, out Asn1Encodable? certificationsObject))
        {
            _certifications = RegistryIdBlock.DecodeRegistryIdBlocks(certificationsObject);
        }
    }

    public RegistryIdBlock? GetModel() => _model;

    public CaptureDeviceTechnologyIdCode? GetCaptureDeviceTechnologyIdCode() => _captureDeviceTechnologyIdCode;

    public List<RegistryIdBlock>? GetCertifications() => _certifications;

    public override int GetHashCode() =>
        HashCode.Combine(_captureDeviceTechnologyIdCode, JavaListHashCode(_certifications), _model);

    public override bool Equals(object? other)
    {
        if (ReferenceEquals(this, other))
        {
            return true;
        }
        if (other == null || GetType() != other.GetType())
        {
            return false;
        }

        var otherBlock = (FingerImageCaptureDeviceBlock)other;
        return _captureDeviceTechnologyIdCode == otherBlock._captureDeviceTechnologyIdCode
            && ListEquals(_certifications, otherBlock._certifications)
            && Equals(_model, otherBlock._model);
    }

    public override string ToString() =>
        "FingerImageCaptureDeviceBlock ["
        + $"model: {_model}"
        + $", captureDeviceTechnologyIdCode: {ToStringOrNull(_captureDeviceTechnologyIdCode)}"
        + $", certifications: {JavaListToString(_certifications)}"
        + "]";

    /* PACKAGE */

    internal override Asn1Encodable GetAsn1Object()
    {
        var taggedObjects = new Dictionary<int, Asn1Encodable>();
        if (_model != null)
        {
            taggedObjects[0] = _model.GetAsn1Object();
        }
        if (_captureDeviceTechnologyIdCode != null)
        {
            taggedObjects[1] = ISO39794Util.EncodeCodeAsChoiceExtensionBlockFallback((int)_captureDeviceTechnologyIdCode.Value);
        }
        if (_certifications != null)
        {
            taggedObjects[2] = ISO39794Util.EncodeBlocks([.. _certifications.Cast<Block>()])!;
        }
        return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
    }

    /* PRIVATE */

    private static string ToStringOrNull<T>(T? value) where T : struct => value?.ToString() ?? "null";

    private static string JavaListToString<T>(List<T>? list) => list == null ? "null" : $"[{string.Join(", ", list)}]";

    private static bool ListEquals<T>(List<T>? list1, List<T>? list2)
    {
        if (ReferenceEquals(list1, list2))
        {
            return true;
        }
        if (list1 == null || list2 == null)
        {
            return false;
        }

        return list1.SequenceEqual(list2);
    }

    private static int JavaListHashCode<T>(List<T>? list)
    {
        if (list == null)
        {
            return 0;
        }

        int hash = 1;
        foreach (T? element in list)
        {
            hash = (31 * hash) + (element?.GetHashCode() ?? 0);
        }

        return hash;
    }
}
