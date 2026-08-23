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

namespace nMRTD.Lds;

/// <summary>
/// Port of <c>org.jmrtd.lds.ImageInfo</c>: common interface for records containing an encoded image.
/// </summary>
public interface ImageInfo : LDSElement
{
    /// <summary>Mime-type.</summary>
    public const string JPEG_MIME_TYPE = "image/jpeg";

    /// <summary>Mime-type.</summary>
    public const string JPEG2000_MIME_TYPE = "image/jp2";

    /// <summary>Mime-type.</summary>
    public const string WSQ_MIME_TYPE = "image/x-wsq";

    /// <summary>Type of image.</summary>
    public const int TYPE_UNKNOWN = -1;

    /// <summary>Type of image.</summary>
    public const int TYPE_PORTRAIT = 0;

    /// <summary>Type of image.</summary>
    public const int TYPE_SIGNATURE_OR_MARK = 1;

    /// <summary>Type of image.</summary>
    public const int TYPE_FINGER = 2;

    /// <summary>Type of image.</summary>
    public const int TYPE_IRIS = 3;

    /// <summary>
    /// Returns the (biometric) type of the image. One of <see cref="TYPE_PORTRAIT"/>,
    /// <see cref="TYPE_SIGNATURE_OR_MARK"/>, <see cref="TYPE_FINGER"/>, <see cref="TYPE_IRIS"/>.
    /// Named <c>GetImageType</c> rather than Java's <c>getType()</c>, which would collide with
    /// <see cref="object.GetType"/> in C#.
    /// </summary>
    int GetImageType();

    /// <summary>Returns the mime-type of the encoded image.</summary>
    string? GetMimeType();

    /// <summary>Returns the width of the image in pixels.</summary>
    int GetWidth();

    /// <summary>Returns the height of the image in pixels.</summary>
    int GetHeight();

    /// <summary>Returns the length of the total record (header and data) in bytes.</summary>
    long GetRecordLength();

    /// <summary>Returns the length of the encoded image in bytes.</summary>
    int GetImageLength();

    /// <summary>Returns a stream from which the image bytes can be read.</summary>
    Stream GetImageInputStream();
}
