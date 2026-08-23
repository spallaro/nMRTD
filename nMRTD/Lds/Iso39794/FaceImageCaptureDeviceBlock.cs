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
//    modelIdBlock [0] RegistryIdBlock OPTIONAL,
//    certificationIdBlocks [1] CertificationIdBlocks OPTIONAL,
//    ...
//  }

/// <summary>
/// Port of <c>org.jmrtd.lds.iso39794.FaceImageCaptureDeviceBlock</c>. Java's <c>Serializable</c> marker is
/// dropped (no reflection-based serialization is needed in this port).
///
/// ADAPTATION: Java's version is also a top-level <c>public class</c>, but this is <c>internal</c> since its
/// base class <see cref="Block"/> is <c>internal</c> in this port (see <c>VersionBlock</c>'s doc comment).
/// </summary>
internal class FaceImageCaptureDeviceBlock : Block
{
    /// <summary>Identification of the model capture device.</summary>
    private readonly RegistryIdBlock? _model;

    /// <summary>Identification of certifications.</summary>
    private readonly List<RegistryIdBlock>? _certifications;

    public FaceImageCaptureDeviceBlock(RegistryIdBlock? model, List<RegistryIdBlock>? certifications)
    {
        _model = model;
        _certifications = certifications;
    }

    internal FaceImageCaptureDeviceBlock(Asn1Encodable? asn1Encodable)
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
        if (taggedObjects.TryGetValue(1, out Asn1Encodable? certificationsObject))
        {
            _certifications = RegistryIdBlock.DecodeRegistryIdBlocks(certificationsObject);
        }
    }

    public RegistryIdBlock? GetModel() => _model;

    public List<RegistryIdBlock>? GetCertifications() => _certifications;

    public override int GetHashCode() => HashCode.Combine(_certifications, _model);

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

        var otherBlock = (FaceImageCaptureDeviceBlock)other;
        return ListEquals(_certifications, otherBlock._certifications) && Equals(_model, otherBlock._model);
    }

    public override string ToString() =>
        $"FaceImageCaptureDeviceBlock [model: {_model}, certifications: {JavaListToString(_certifications)}]";

    /* PACKAGE */

    internal override Asn1Encodable GetAsn1Object()
    {
        var taggedObjects = new Dictionary<int, Asn1Encodable>();
        if (_model != null)
        {
            taggedObjects[0] = _model.GetAsn1Object();
        }
        if (_certifications != null)
        {
            taggedObjects[1] = ISO39794Util.EncodeBlocks([.. _certifications.Cast<Block>()])!;
        }
        return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
    }

    /* PRIVATE */

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

    private static string JavaListToString<T>(List<T>? list) => list == null ? "null" : $"[{string.Join(", ", list)}]";
}
