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

//  PropertiesBlock ::= SEQUENCE {
//    glasses [0] BOOLEAN OPTIONAL,
//    moustache [1] BOOLEAN OPTIONAL,
//    beard [2] BOOLEAN OPTIONAL,
//    teethVisible [3] BOOLEAN OPTIONAL,
//    pupilOrIrisNotVisible [4] BOOLEAN OPTIONAL,
//    mouthOpen [5] BOOLEAN OPTIONAL,
//    leftEyePatch [6] BOOLEAN OPTIONAL,
//    rightEyePatch [7] BOOLEAN OPTIONAL,
//    darkGlasses [8] BOOLEAN OPTIONAL,
//    biometricAbsent [9] BOOLEAN OPTIONAL,
//    headCoveringsPresent [10] BOOLEAN OPTIONAL,
//    ...
//  }

/// <summary>
/// Port of <c>org.jmrtd.lds.iso39794.FaceImagePropertiesBlock</c>. Java's <c>Serializable</c> marker is
/// dropped (no reflection-based serialization is needed in this port).
/// </summary>
public class FaceImagePropertiesBlock : Block
{
    private readonly bool? _hasGlasses;
    private readonly bool? _hasMoustache;
    private readonly bool? _hasBeard;
    private readonly bool? _isTeethVisible;
    private readonly bool? _isPupilOrIrisNotVisible;
    private readonly bool? _isMouthOpen;
    private readonly bool? _hasLeftEyePatch;
    private readonly bool? _hasRightEyePatch;
    private readonly bool? _hasDarkGlasses;
    private readonly bool? _isBiometricAbsent;
    private readonly bool? _isHeadCoveringsPresent;

    public FaceImagePropertiesBlock(bool? hasGlasses, bool? hasMoustache, bool? hasBeard, bool? isTeethVisible,
        bool? isPupilOrIrisNotVisible, bool? isMouthOpen, bool? hasLeftEyePatch, bool? hasRightEyePatch,
        bool? hasDarkGlasses, bool? isBiometricAbsent, bool? isHeadCoveringsPresent)
    {
        _hasGlasses = hasGlasses;
        _hasMoustache = hasMoustache;
        _hasBeard = hasBeard;
        _isTeethVisible = isTeethVisible;
        _isPupilOrIrisNotVisible = isPupilOrIrisNotVisible;
        _isMouthOpen = isMouthOpen;
        _hasLeftEyePatch = hasLeftEyePatch;
        _hasRightEyePatch = hasRightEyePatch;
        _hasDarkGlasses = hasDarkGlasses;
        _isBiometricAbsent = isBiometricAbsent;
        _isHeadCoveringsPresent = isHeadCoveringsPresent;
    }

    internal FaceImagePropertiesBlock(Asn1Encodable asn1Encodable)
    {
        Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
        if (taggedObjects.TryGetValue(0, out Asn1Encodable? glassesObject))
        {
            _hasGlasses = ASN1Util.DecodeBoolean(glassesObject);
        }
        if (taggedObjects.TryGetValue(1, out Asn1Encodable? moustacheObject))
        {
            _hasMoustache = ASN1Util.DecodeBoolean(moustacheObject);
        }
        if (taggedObjects.TryGetValue(2, out Asn1Encodable? beardObject))
        {
            _hasBeard = ASN1Util.DecodeBoolean(beardObject);
        }
        if (taggedObjects.TryGetValue(3, out Asn1Encodable? teethVisibleObject))
        {
            _isTeethVisible = ASN1Util.DecodeBoolean(teethVisibleObject);
        }
        if (taggedObjects.TryGetValue(4, out Asn1Encodable? pupilOrIrisNotVisibleObject))
        {
            _isPupilOrIrisNotVisible = ASN1Util.DecodeBoolean(pupilOrIrisNotVisibleObject);
        }
        if (taggedObjects.TryGetValue(5, out Asn1Encodable? mouthOpenObject))
        {
            _isMouthOpen = ASN1Util.DecodeBoolean(mouthOpenObject);
        }
        if (taggedObjects.TryGetValue(6, out Asn1Encodable? leftEyePatchObject))
        {
            _hasLeftEyePatch = ASN1Util.DecodeBoolean(leftEyePatchObject);
        }
        if (taggedObjects.TryGetValue(7, out Asn1Encodable? rightEyePatchObject))
        {
            _hasRightEyePatch = ASN1Util.DecodeBoolean(rightEyePatchObject);
        }
        if (taggedObjects.TryGetValue(8, out Asn1Encodable? darkGlassesObject))
        {
            _hasDarkGlasses = ASN1Util.DecodeBoolean(darkGlassesObject);
        }
        if (taggedObjects.TryGetValue(9, out Asn1Encodable? biometricAbsentObject))
        {
            _isBiometricAbsent = ASN1Util.DecodeBoolean(biometricAbsentObject);
        }
        if (taggedObjects.TryGetValue(10, out Asn1Encodable? headCoveringsPresentObject))
        {
            _isHeadCoveringsPresent = ASN1Util.DecodeBoolean(headCoveringsPresentObject);
        }
    }

    public bool? HasGlasses() => _hasGlasses;

    public bool? HasMoustache() => _hasMoustache;

    public bool? HasBeard() => _hasBeard;

    public bool? IsTeethVisible() => _isTeethVisible;

    public bool? IsPupilOrIrisNotVisible() => _isPupilOrIrisNotVisible;

    public bool? IsMouthOpen() => _isMouthOpen;

    public bool? HasLeftEyePatch() => _hasLeftEyePatch;

    public bool? HasRightEyePatch() => _hasRightEyePatch;

    public bool? HasDarkGlasses() => _hasDarkGlasses;

    public bool? IsBiometricAbsent() => _isBiometricAbsent;

    public bool? IsHeadCoveringsPresent() => _isHeadCoveringsPresent;

    public override int GetHashCode() =>
        HashCode.Combine(
            HashCode.Combine(_hasBeard, _hasDarkGlasses, _hasGlasses, _hasLeftEyePatch, _hasMoustache, _hasRightEyePatch),
            _isBiometricAbsent, _isHeadCoveringsPresent, _isMouthOpen, _isPupilOrIrisNotVisible, _isTeethVisible);

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

        var otherBlock = (FaceImagePropertiesBlock)other;
        return _hasBeard == otherBlock._hasBeard
            && _hasDarkGlasses == otherBlock._hasDarkGlasses
            && _hasGlasses == otherBlock._hasGlasses
            && _hasLeftEyePatch == otherBlock._hasLeftEyePatch
            && _hasMoustache == otherBlock._hasMoustache
            && _hasRightEyePatch == otherBlock._hasRightEyePatch
            && _isBiometricAbsent == otherBlock._isBiometricAbsent
            && _isHeadCoveringsPresent == otherBlock._isHeadCoveringsPresent
            && _isMouthOpen == otherBlock._isMouthOpen
            && _isPupilOrIrisNotVisible == otherBlock._isPupilOrIrisNotVisible
            && _isTeethVisible == otherBlock._isTeethVisible;
    }

    public override string ToString() =>
        "FaceImagePropertiesBlock ["
        + $"hasGlasses: {_hasGlasses}"
        + $", hasMoustache: {_hasMoustache}"
        + $", hasBeard: {_hasBeard}"
        + $", isTeethVisible: {_isTeethVisible}"
        + $", isPupilOrIrisNotVisible: {_isPupilOrIrisNotVisible}"
        + $", isMouthOpen: {_isMouthOpen}"
        + $", hasLeftEyePatch: {_hasLeftEyePatch}"
        + $", hasRightEyePatch: {_hasRightEyePatch}"
        + $", hasDarkGlasses: {_hasDarkGlasses}"
        + $", isBiometricAbsent: {_isBiometricAbsent}"
        + $", isHeadCoveringsPresent: {_isHeadCoveringsPresent}"
        + "]";

    /* PACKAGE */

    internal override Asn1Encodable GetAsn1Object()
    {
        var taggedObjects = new Dictionary<int, Asn1Encodable>();
        if (_hasGlasses != null)
        {
            taggedObjects[0] = ASN1Util.EncodeBoolean(_hasGlasses.Value);
        }
        if (_hasMoustache != null)
        {
            taggedObjects[1] = ASN1Util.EncodeBoolean(_hasMoustache.Value);
        }
        if (_hasBeard != null)
        {
            taggedObjects[2] = ASN1Util.EncodeBoolean(_hasBeard.Value);
        }
        if (_isTeethVisible != null)
        {
            taggedObjects[3] = ASN1Util.EncodeBoolean(_isTeethVisible.Value);
        }
        if (_isPupilOrIrisNotVisible != null)
        {
            taggedObjects[4] = ASN1Util.EncodeBoolean(_isPupilOrIrisNotVisible.Value);
        }
        if (_isMouthOpen != null)
        {
            taggedObjects[5] = ASN1Util.EncodeBoolean(_isMouthOpen.Value);
        }
        if (_hasLeftEyePatch != null)
        {
            taggedObjects[6] = ASN1Util.EncodeBoolean(_hasLeftEyePatch.Value);
        }
        if (_hasRightEyePatch != null)
        {
            taggedObjects[7] = ASN1Util.EncodeBoolean(_hasRightEyePatch.Value);
        }
        if (_hasDarkGlasses != null)
        {
            taggedObjects[8] = ASN1Util.EncodeBoolean(_hasDarkGlasses.Value);
        }
        if (_isBiometricAbsent != null)
        {
            taggedObjects[9] = ASN1Util.EncodeBoolean(_isBiometricAbsent.Value);
        }
        if (_isHeadCoveringsPresent != null)
        {
            taggedObjects[10] = ASN1Util.EncodeBoolean(_isHeadCoveringsPresent.Value);
        }
        return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
    }
}
