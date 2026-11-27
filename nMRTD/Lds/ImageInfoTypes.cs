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

/// <summary>The MIME types and the types of the images of an <see cref="ImageInfo"/>. They were on the
/// <see cref="ImageInfo"/> interface, as in JMRTD, where .NET Framework cannot have them.</summary>
public static class ImageInfoTypes
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
}
