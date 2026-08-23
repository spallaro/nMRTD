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

//  CaptureDeviceSpectral2DBlock ::= SEQUENCE {
//    whiteLight [0] BOOLEAN OPTIONAL,
//    nearInfrared [1] BOOLEAN OPTIONAL,
//    thermal [2] BOOLEAN OPTIONAL,
//    ...
//  }

/// <summary>
/// Port of <c>org.jmrtd.lds.iso39794.FaceImageCaptureDeviceSpectral2DBlock</c>. Java's <c>Serializable</c>
/// marker is dropped (no reflection-based serialization is needed in this port).
///
/// ADAPTATION: Java's version is also a top-level <c>public class</c>, but this is <c>internal</c> since its
/// base class <see cref="Block"/> is <c>internal</c> in this port (see <c>VersionBlock</c>'s doc comment).
/// </summary>
internal class FaceImageCaptureDeviceSpectral2DBlock : Block
{
    private readonly bool? _isWhiteLight;
    private readonly bool? _isNearInfrared;
    private readonly bool? _isThermal;

    public FaceImageCaptureDeviceSpectral2DBlock(bool? isWhiteLight, bool? isNearInfrared, bool? isThermal)
    {
        _isWhiteLight = isWhiteLight;
        _isNearInfrared = isNearInfrared;
        _isThermal = isThermal;
    }

    internal FaceImageCaptureDeviceSpectral2DBlock(Asn1Encodable asn1Encodable)
    {
        if (asn1Encodable is not Asn1Sequence && asn1Encodable is not Asn1TaggedObject)
        {
            throw new ArgumentException("Cannot decode!");
        }

        Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
        if (taggedObjects.TryGetValue(0, out Asn1Encodable? whiteLightObject))
        {
            _isWhiteLight = ASN1Util.DecodeBoolean(whiteLightObject);
        }
        if (taggedObjects.TryGetValue(1, out Asn1Encodable? nearInfraredObject))
        {
            _isNearInfrared = ASN1Util.DecodeBoolean(nearInfraredObject);
        }
        if (taggedObjects.TryGetValue(2, out Asn1Encodable? thermalObject))
        {
            _isThermal = ASN1Util.DecodeBoolean(thermalObject);
        }
    }

    public bool? IsWhiteLight() => _isWhiteLight;

    public bool? IsNearInfrared() => _isNearInfrared;

    public bool? IsThermal() => _isThermal;

    public override int GetHashCode() => HashCode.Combine(_isNearInfrared, _isThermal, _isWhiteLight);

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

        var otherBlock = (FaceImageCaptureDeviceSpectral2DBlock)other;
        return _isNearInfrared == otherBlock._isNearInfrared
            && _isThermal == otherBlock._isThermal
            && _isWhiteLight == otherBlock._isWhiteLight;
    }

    public override string ToString() =>
        $"FaceImageCaptureDeviceSpectral2DBlock [isWhiteLight: {_isWhiteLight}, isNearInfrared: {_isNearInfrared}, isThermal: {_isThermal}]";

    /* PACKAGE */

    internal override Asn1Encodable GetAsn1Object()
    {
        var taggedObjects = new Dictionary<int, Asn1Encodable>();
        if (_isWhiteLight != null)
        {
            taggedObjects[0] = ASN1Util.EncodeBoolean(_isWhiteLight.Value);
        }
        if (_isNearInfrared != null)
        {
            taggedObjects[1] = ASN1Util.EncodeBoolean(_isNearInfrared.Value);
        }
        if (_isThermal != null)
        {
            taggedObjects[2] = ASN1Util.EncodeBoolean(_isThermal.Value);
        }
        return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
    }
}
