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

//  CaptureDevice2DBlock ::= SEQUENCE {
//    captureDeviceSpectral2DBlock [0] CaptureDeviceSpectral2DBlock OPTIONAL,
//    captureDeviceTechnologyId2D [1] CaptureDeviceTechnologyId2D OPTIONAL,
//    ...
//  }

/// <summary>
/// Port of <c>org.jmrtd.lds.iso39794.FaceImageCaptureDevice2DBlock</c>. Java's <c>Serializable</c> marker
/// is dropped (no reflection-based serialization is needed in this port).
/// </summary>
public class FaceImageCaptureDevice2DBlock : Block
{
    /// <summary>
    /// ADAPTATION: Java's version is <c>enum CaptureDeviceTechnologyId2DCode implements
    /// EncodableEnum&lt;CaptureDeviceTechnologyId2DCode&gt;</c>, using reflection-based
    /// <c>EncodableEnum.fromCode</c> lookup keyed on each constant's own <c>getCode()</c>. Ported as a plain
    /// enum with explicit numeric values matching each Java constant's <c>getCode()</c> (declaration order
    /// and code coincide here). See <see cref="ScoreOrError.ScoringErrorCode"/>'s doc comment for the fuller
    /// rationale behind this port's EncodableEnum-replacement convention.
    /// </summary>
    public enum CaptureDeviceTechnologyId2DCode
    {
        Unknown = 0,
        StaticPhotographFromUnknownSource = 1,
        StaticPhotographFromDigitalStillImageCamera = 2,
        StaticPhotographFromScanner = 3,
        VideoFrameFromUnknownSource = 4,
        VideoFrameFromAnalogueVideoCamera = 5,
        VideoFrameFromDigitalVideoCamera = 6,
    }

    private static CaptureDeviceTechnologyId2DCode? FromCode(int code) =>
        Enum.IsDefined(typeof(CaptureDeviceTechnologyId2DCode), code) ? (CaptureDeviceTechnologyId2DCode)code : null;

    private readonly FaceImageCaptureDeviceSpectral2DBlock? _captureDeviceSpectral2DBlock;
    private readonly CaptureDeviceTechnologyId2DCode? _captureDeviceTechnologyId2D;

    public FaceImageCaptureDevice2DBlock(FaceImageCaptureDeviceSpectral2DBlock? captureDeviceSpectral2DBlock,
        CaptureDeviceTechnologyId2DCode? captureDeviceTechnologyId2D)
    {
        _captureDeviceSpectral2DBlock = captureDeviceSpectral2DBlock;
        _captureDeviceTechnologyId2D = captureDeviceTechnologyId2D;
    }

    /// <summary>NOTE: preserved Java quirk -- when <paramref name="asn1Encodable"/> is non-null but is not
    /// an <see cref="Asn1Sequence"/>, Java silently leaves both fields unset (<see langword="null"/>)
    /// instead of throwing, unlike the null-input case just above. Kept as-is.</summary>
    internal FaceImageCaptureDevice2DBlock(Asn1Encodable? asn1Encodable)
    {
        if (asn1Encodable == null)
        {
            throw new ArgumentException("Cannot decode null!");
        }

        if (asn1Encodable is Asn1Sequence asn1Sequence)
        {
            Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Sequence);
            if (taggedObjects.TryGetValue(0, out Asn1Encodable? spectralObject))
            {
                _captureDeviceSpectral2DBlock = new FaceImageCaptureDeviceSpectral2DBlock(spectralObject);
            }

            if (taggedObjects.TryGetValue(1, out Asn1Encodable? technologyObject))
            {
                _captureDeviceTechnologyId2D = FromCode(ISO39794Util.DecodeCodeFromChoiceExtensionBlockFallback(technologyObject)!.Value);
            }
        }
    }

    public FaceImageCaptureDeviceSpectral2DBlock? GetCaptureDeviceSpectral2DBlock() => _captureDeviceSpectral2DBlock;

    public CaptureDeviceTechnologyId2DCode? GetCaptureDeviceTechnologyId2D() => _captureDeviceTechnologyId2D;

    public override int GetHashCode() => HashCode.Combine(_captureDeviceSpectral2DBlock, _captureDeviceTechnologyId2D);

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

        var otherBlock = (FaceImageCaptureDevice2DBlock)other;
        return Equals(_captureDeviceSpectral2DBlock, otherBlock._captureDeviceSpectral2DBlock)
            && _captureDeviceTechnologyId2D == otherBlock._captureDeviceTechnologyId2D;
    }

    public override string ToString() =>
        $"FaceImageCaptureDevice2DBlock [captureDeviceSpectral2DBlock: {_captureDeviceSpectral2DBlock}, captureDeviceTechnologyId2D: {_captureDeviceTechnologyId2D}]";

    /* PACKAGE */

    internal override Asn1Encodable GetAsn1Object() => GetAsn1Object(ISO39794EncodingProfile.Base);

    internal override Asn1Encodable GetAsn1Object(ISO39794EncodingProfile profile)
    {
        var taggedObjects = new Dictionary<int, Asn1Encodable>();
        if (_captureDeviceSpectral2DBlock != null)
        {
            taggedObjects[0] = _captureDeviceSpectral2DBlock.GetAsn1Object();
        }
        if (_captureDeviceTechnologyId2D != null)
        {
            taggedObjects[1] = ISO39794Util.EncodeCodeAsChoiceExtensionBlockFallback((int)_captureDeviceTechnologyId2D.Value, profile,
                ChoiceType.CaptureDeviceTechnology2D);
        }
        return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
    }
}
