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

//  LandmarkCoordinates ::= CHOICE {
//    base [0] LandmarkCoordinatesBase,
//    extensionBlock [1] LandmarkCoordinatesExtensionBlock
//  }
//
//  LandmarkCoordinatesBase ::= CHOICE {
//    coordinateCartesian2DBlock [0] CoordinateCartesian2DUnsignedShortBlock,
//    coordinateTextureImageBlock [1] CoordinateTextureImageBlock,
//    coordinateCartesian3DBlock [2] CoordinateCartesian3DUnsignedShortBlock
//  }

/// <summary>
/// Port of <c>org.jmrtd.lds.iso39794.FaceImageLandmarkCoordinates</c>: a marker interface for the three
/// concrete "landmark coordinates" block shapes -- <see cref="CoordinateCartesian2DUnsignedShortBlock"/>,
/// <see cref="FaceImageCoordinateTextureImageBlock"/>, and <see cref="CoordinateCartesian3DUnsignedShortBlock"/>
/// -- plus the CHOICE-with-extension-block-fallback decode/encode dispatch shared by all three.
///
/// ADAPTATION: Java's version declares <c>hashCode()</c>/<c>equals(Object)</c> purely as documentation
/// (every Java <c>Object</c> already has them); omitted here since every C# object has the same guarantee.
/// Java's <c>Serializable</c> super-interface is dropped for the same reason as elsewhere in this port.
/// Java's version is a top-level <c>public interface</c>, and so is this one.
///
/// The two static factory methods (<c>decodeLandmarkCoordinates</c>/<c>encodeLandmarkCoordinates</c>) are in
/// <see cref="FaceImageLandmarkCoordinatesCodec"/>: .NET Framework does not allow static members in interfaces.
/// </summary>
public interface FaceImageLandmarkCoordinates
{
#if !NETFRAMEWORK
    // The decode and encode are in FaceImageLandmarkCoordinatesCodec: .NET Framework does not allow static members in
    // interfaces. These forwarders keep existing code compiling on the other targets.

    /// <summary>See <see cref="FaceImageLandmarkCoordinatesCodec.DecodeLandmarkCoordinates"/>.</summary>
    [Obsolete("Use FaceImageLandmarkCoordinatesCodec.DecodeLandmarkCoordinates.")]
    static FaceImageLandmarkCoordinates? DecodeLandmarkCoordinates(Asn1Encodable asn1Encodable) =>
        FaceImageLandmarkCoordinatesCodec.DecodeLandmarkCoordinates(asn1Encodable);

    /// <summary>See <see cref="FaceImageLandmarkCoordinatesCodec.EncodeLandmarkCoordinates"/>.</summary>
    [Obsolete("Use FaceImageLandmarkCoordinatesCodec.EncodeLandmarkCoordinates.")]
    static Asn1Encodable EncodeLandmarkCoordinates(FaceImageLandmarkCoordinates landmarkCoordinates) =>
        FaceImageLandmarkCoordinatesCodec.EncodeLandmarkCoordinates(landmarkCoordinates);
#endif
}
