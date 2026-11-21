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

//  ImageRepresentation2DBlock ::= SEQUENCE {
//    representationData2D [0] OCTET STRING,
//    imageInformation2DBlock [1] ImageInformation2DBlock,
//    captureDevice2DBlock [2] CaptureDevice2DBlock OPTIONAL,
//    ...
//  }

/// <summary>
/// Port of <c>org.jmrtd.lds.iso39794.FaceImageRepresentation2DBlock</c>. Java's <c>Serializable</c> marker
/// is dropped (no reflection-based serialization is needed in this port).
///
/// <see cref="GetImageInformation2DBlock"/> is also used by
/// <see cref="ISO39794EncodingProfileExtensions.Validate"/>.
/// </summary>
public class FaceImageRepresentation2DBlock : Block
{
    private readonly byte[] _representationData2DBytes;
    private readonly FaceImageInformation2DBlock _imageInformation2DBlock;
    private readonly FaceImageCaptureDevice2DBlock? _captureDevice2DBlock;

    public FaceImageRepresentation2DBlock(byte[] representationData2DBytes,
        FaceImageInformation2DBlock imageInformation2DBlock, FaceImageCaptureDevice2DBlock? captureDevice2DBlock)
    {
        _representationData2DBytes = representationData2DBytes;
        _imageInformation2DBlock = imageInformation2DBlock;
        _captureDevice2DBlock = captureDevice2DBlock;
    }

    /// <summary>NOTE: like <c>QualityBlock</c>/<c>DateTimeBlock</c>/<c>VersionBlock</c>'s established
    /// pattern, the two mandatory tags below (0, 1) are read via a direct dictionary indexer rather than
    /// reproducing Java's "missing tag yields <see langword="null"/>, which then throws deeper inside the
    /// nested decode constructor" chain -- both translations throw on malformed/incomplete input, just with a
    /// different exception type (<see cref="KeyNotFoundException"/> here vs. Java's
    /// <c>IllegalArgumentException</c>/NPE).</summary>
    internal FaceImageRepresentation2DBlock(Asn1Encodable? asn1Encodable)
    {
        if (asn1Encodable is not Asn1Sequence && asn1Encodable is not Asn1TaggedObject)
        {
            throw new ArgumentException("Cannot decode!");
        }

        Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
        _representationData2DBytes = Asn1OctetString.GetInstance(taggedObjects[0]).GetOctets();
        _imageInformation2DBlock = new FaceImageInformation2DBlock(taggedObjects[1]);
        if (taggedObjects.TryGetValue(2, out Asn1Encodable? captureDeviceObject))
        {
            _captureDevice2DBlock = new FaceImageCaptureDevice2DBlock(captureDeviceObject);
        }
    }

    public long GetRepresentationData2DInputLength() =>
        _representationData2DBytes == null ? 0 : _representationData2DBytes.Length;

    public string GetRepresentationData2DInputMimeType() =>
        FaceImageInformation2DBlock.ToMimeType(_imageInformation2DBlock.GetImageDataFormatCode());

    public Stream GetRepresentationData2DInputStream() => new MemoryStream(_representationData2DBytes);

    public FaceImageInformation2DBlock GetImageInformation2DBlock() => _imageInformation2DBlock;

    public FaceImageCaptureDevice2DBlock? GetCaptureDevice2DBlock() => _captureDevice2DBlock;

    public override int GetHashCode()
    {
        const int prime = 31;
        int result = 1;
        result = (prime * result) + JavaArrayHashCode(_representationData2DBytes);
        result = (prime * result) + HashCode.Combine(_captureDevice2DBlock, _imageInformation2DBlock);
        return result;
    }

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

        var otherBlock = (FaceImageRepresentation2DBlock)other;
        return Equals(_captureDevice2DBlock, otherBlock._captureDevice2DBlock)
            && Equals(_imageInformation2DBlock, otherBlock._imageInformation2DBlock)
            && ByteArraysEqual(_representationData2DBytes, otherBlock._representationData2DBytes);
    }

    public override string ToString() =>
        "FaceImageRepresentation2DBlock ["
        + $"representationData2DBytes: {(_representationData2DBytes == null ? "-" : _representationData2DBytes.Length.ToString())}"
        + $", imageInformation2DBlock: {_imageInformation2DBlock}"
        + $", captureDevice2DBlock: {_captureDevice2DBlock}"
        + "]";

    /* PACKAGE */

    internal override Asn1Encodable GetAsn1Object() => GetAsn1Object(ISO39794EncodingProfile.Base);

    internal override Asn1Encodable GetAsn1Object(ISO39794EncodingProfile profile)
    {
        var taggedObjects = new Dictionary<int, Asn1Encodable>
        {
            [0] = new DerOctetString(_representationData2DBytes),
            [1] = _imageInformation2DBlock.GetAsn1Object(profile),
        };
        if (_captureDevice2DBlock != null)
        {
            taggedObjects[2] = _captureDevice2DBlock.GetAsn1Object(profile);
        }
        return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
    }

    /* PRIVATE */

    private static bool ByteArraysEqual(byte[]? array1, byte[]? array2)
    {
        if (array1 == null || array2 == null)
        {
            return array1 == array2;
        }

        return array1.SequenceEqual(array2);
    }

    /// <summary>Java-style <c>Arrays.hashCode(byte[])</c> for a (possibly <see langword="null"/>) byte
    /// array -- see the established pattern in e.g. <c>PADDataBlock.cs</c>.</summary>
    private static int JavaArrayHashCode(byte[]? array)
    {
        if (array == null)
        {
            return 0;
        }

        int result = 1;
        foreach (byte b in array)
        {
            result = (31 * result) + (sbyte)b;
        }

        return result;
    }
}
