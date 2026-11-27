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

using nMRTD.Lds;

namespace nMRTD.Lds.Iso19794;

/// <summary>
/// Port of <c>org.jmrtd.lds.iso19794.IrisImageInfo</c>: iris image header and image data based on
/// Section 6.5.3 and Table 4 of ISO/IEC 19794-6 2005.
/// </summary>
public class IrisImageInfo : AbstractImageInfo
{
    /* TODO: proper enums for data types (matches upstream JMRTD TODO). */

    /// <summary>Image quality, based on Table 3 in Section 5.5 of ISO 19794-6.</summary>
    public const int IMAGE_QUAL_UNDEF = 0xFE; /* (decimal 254) */

    /// <summary>Image quality, based on Table 3 in Section 5.5 of ISO 19794-6.</summary>
    public const int IMAGE_QUAL_LOW_LO = 0x1A;

    /// <summary>Image quality, based on Table 3 in Section 5.5 of ISO 19794-6.</summary>
    public const int IMAGE_QUAL_LOW_HI = 0x32; /* (decimal 26-50) */

    /// <summary>Image quality, based on Table 3 in Section 5.5 of ISO 19794-6.</summary>
    public const int IMAGE_QUAL_MED_LO = 0x33;

    /// <summary>Image quality, based on Table 3 in Section 5.5 of ISO 19794-6.</summary>
    public const int IMAGE_QUAL_MED_HI = 0x4B; /* (decimal 51-75) */

    /// <summary>Image quality, based on Table 3 in Section 5.5 of ISO 19794-6.</summary>
    public const int IMAGE_QUAL_HIGH_LO = 0x4C;

    /// <summary>Image quality, based on Table 3 in Section 5.5 of ISO 19794-6.</summary>
    public const int IMAGE_QUAL_HIGH_HI = 0x64; /* (decimal 76-100) */

    private const int ROT_ANGLE_UNDEF = 0xFFFF;
    private const int ROT_UNCERTAIN_UNDEF = 0xFFFF;

    /// <summary>The image format (is more precise than mime-type). Constants are in <see cref="IrisInfo"/>.</summary>
    private int _imageFormat;

    private int _imageNumber;
    private int _quality;

    // TODO: rotation angle of eye and rotation uncertainty as angles, instead of encoded (matches upstream JMRTD TODO).
    private int _rotationAngle;
    private int _rotationAngleUncertainty;

    /// <summary>Constructs an iris image info.</summary>
    /// <param name="imageNumber">the image number</param>
    /// <param name="quality">quality</param>
    /// <param name="rotationAngle">rotation angle</param>
    /// <param name="rotationAngleUncertainty">rotation angle uncertainty</param>
    /// <param name="width">width</param>
    /// <param name="height">height</param>
    /// <param name="imageBytes">a stream positioned at the encoded image</param>
    /// <param name="imageLength">the length of the encoded image</param>
    /// <param name="imageFormat">the image format used for encoding</param>
    public IrisImageInfo(int imageNumber, int quality, int rotationAngle, int rotationAngleUncertainty,
        int width, int height, Stream imageBytes, int imageLength, int imageFormat)
        : base(ImageInfoTypes.TYPE_IRIS, width, height, imageBytes, imageLength, GetMimeTypeFromImageFormat(imageFormat))
    {
        /* NOTE: preserved Java quirk -- this null check runs after the base constructor already
         * consumed imageBytes (ReadImage reads from it immediately), so a null imageBytes throws inside
         * the base constructor (NullReferenceException here, NullPointerException in Java) before this
         * check is ever reached. Ported verbatim as dead code rather than "fixed" by reordering, since
         * base-first construction order can't be changed in C# either. */
        if (imageBytes == null)
        {
            throw new ArgumentException("Null image bytes");
        }

        _imageNumber = imageNumber;
        _quality = quality;
        _rotationAngle = rotationAngle;
        _rotationAngleUncertainty = rotationAngleUncertainty;
        _imageFormat = imageFormat;
    }

    /// <summary>Constructs an iris image info.</summary>
    /// <param name="imageNumber">the image number</param>
    /// <param name="width">width</param>
    /// <param name="height">height</param>
    /// <param name="imageBytes">a stream positioned at the encoded image</param>
    /// <param name="imageLength">the length of the encoded image</param>
    /// <param name="imageFormat">the image format used for encoding</param>
    public IrisImageInfo(int imageNumber, int width, int height, Stream imageBytes, int imageLength, int imageFormat)
        : this(imageNumber, IMAGE_QUAL_UNDEF, ROT_ANGLE_UNDEF, ROT_UNCERTAIN_UNDEF,
            width, height, imageBytes, imageLength, imageFormat)
    {
    }

    /// <summary>Constructs a new iris image record from binary encoding. Java package-only visibility;
    /// <c>internal</c> here since this assembly is the closest C# equivalent -- called by
    /// <see cref="IrisBiometricSubtypeInfo"/>, which shares the same image format for all of its images.</summary>
    /// <param name="inputStream">input stream</param>
    /// <param name="imageFormat">the image format used for encoding</param>
    internal IrisImageInfo(Stream inputStream, int imageFormat)
        : base(ImageInfoTypes.TYPE_IRIS)
    {
        _imageFormat = imageFormat;
        SetMimeType(GetMimeTypeFromImageFormat(imageFormat));
        ReadObject(inputStream);
    }

    /// <summary>Returns the image format.</summary>
    public int GetImageFormat() => _imageFormat;

    /// <summary>Returns the image number.</summary>
    public int GetImageNumber() => _imageNumber;

    /// <summary>Returns the quality.</summary>
    public int GetQuality() => _quality;

    /// <summary>Returns the rotation angle.</summary>
    public int GetRotationAngle() => _rotationAngle;

    /// <summary>Returns the rotation angle uncertainty.</summary>
    public int GetRotationAngleUncertainty() => _rotationAngleUncertainty;

    /// <inheritdoc/>
    public override long GetRecordLength() => 11L + GetImageLength();

    /// <summary>
    /// Writes this iris image info into a stream shared with sibling images (used by
    /// <see cref="IrisBiometricSubtypeInfo"/>, which writes several of these back to back into the same
    /// underlying stream). Named distinctly from the protected <see cref="WriteObject"/> override this
    /// forwards to, because C# has no package-private access level to reuse the same member the way
    /// JMRTD's own same-package-protected call (<c>irisImageInfo.writeObject(dataOut)</c>) does -- same
    /// accessibility workaround as <c>DisplayedImageInfo.WriteObject(TlvOutputStream)</c>.
    /// </summary>
    internal void WriteTo(Stream outputStream) => WriteObject(outputStream);

    public override int GetHashCode()
    {
        const int prime = 31;
        int result = base.GetHashCode();
        result = (prime * result) + _imageFormat;
        result = (prime * result) + _imageNumber;
        result = (prime * result) + _quality;
        result = (prime * result) + _rotationAngle;
        result = (prime * result) + _rotationAngleUncertainty;
        return result;
    }

    public override bool Equals(object? obj)
    {
        if (ReferenceEquals(this, obj))
        {
            return true;
        }
        if (!base.Equals(obj))
        {
            return false;
        }
        if (obj is null || GetType() != obj.GetType())
        {
            return false;
        }

        var other = (IrisImageInfo)obj;
        return _imageFormat == other._imageFormat
            && _imageNumber == other._imageNumber
            && _quality == other._quality
            && _rotationAngle == other._rotationAngle
            && _rotationAngleUncertainty == other._rotationAngleUncertainty;
    }

    /// <summary>Generates a textual representation of this object.</summary>
    public override string ToString() =>
        /* NOTE: preserved Java quirk -- missing ", " separator between the height value and
         * "mime-type: " in the original StringBuilder chain, so the rendered string reads e.g.
         * "... 10 x 20mime-type: image/jpeg]" with no space/comma before "mime-type:". */
        new System.Text.StringBuilder()
            .Append("IrisImageInfo [")
            .Append("image number: ").Append(_imageNumber).Append(", ")
            .Append("quality: ").Append(_quality).Append(", ")
            .Append("image: ")
            .Append(GetWidth()).Append(" x ").Append(GetHeight())
            .Append("mime-type: ").Append(GetMimeTypeFromImageFormat(_imageFormat))
            .Append(']')
            .ToString();

    /// <inheritdoc/>
    protected override void ReadObject(Stream inputStream)
    {
        _imageNumber = ReadUnsignedShort(inputStream);              /* 2 */
        _quality = ReadUnsignedByte(inputStream);                   /* + 1 = 3 */

        /*
         * (65536*angle/360) modulo 65536
         * ROT_ANGLE_UNDEF = 0xFFFF
         * Where angle is measured in degrees from
         * horizontal
         * Used only for rectilinear images. For polar images
         * entry shall be ROT_ANGLE_UNDEF
         */
        _rotationAngle = ReadShort(inputStream);                    /* + 2 = 5 */

        /*
         * Rotation uncertainty = (unsigned short) round
         * (65536 * uncertainty/180)
         * Where 0 <= uncertainty < 180
         * ROT_UNCERTAIN_UNDEF = 0xFFFF
         * Where uncertainty is measured in degrees and is
         * the absolute value of maximum error
         */
        _rotationAngleUncertainty = ReadUnsignedShort(inputStream); /* + 2 = 7 */

        /*
         * Size of image data, bytes, 0 - 4294967295.
         */
        long imageLength = ReadInt(inputStream) & 0x00000000FFFFFFFFL; /* + 4 = 11 */

        ReadImage(inputStream, imageLength);
    }

    /// <inheritdoc/>
    protected override void WriteObject(Stream outputStream)
    {
        WriteShort(outputStream, _imageNumber);                    /* 2 */
        WriteByte(outputStream, _quality);                         /* + 1 = 3 */

        /*
         * (65536*angle/360) modulo 65536
         * ROT_ANGLE_UNDEF = 0xFFFF
         * Where angle is measured in degrees from
         * horizontal
         * Used only for rectilinear images. For polar images
         * entry shall be ROT_ANGLE_UNDEF
         */
        WriteShort(outputStream, _rotationAngle);                  /* + 2 = 5 */

        /*
         * Rotation uncertainty = (unsigned short) round
         * (65536 * uncertainty/180)
         * Where 0 <= uncertainty < 180
         * ROT_UNCERTAIN_UNDEF = 0xFFFF
         * Where uncertainty is measured in degrees and is
         * the absolute value of maximum error
         */
        WriteShort(outputStream, _rotationAngleUncertainty);       /* + 2 = 7 */

        WriteInt(outputStream, GetImageLength());                  /* + 4 = 11 */
        WriteImage(outputStream);
    }

    /* ONLY PRIVATE METHODS BELOW */

    /// <summary>Returns a mime-type for the given image format code.</summary>
    private static string? GetMimeTypeFromImageFormat(int imageFormat) => imageFormat switch
    {
        IrisInfo.IMAGEFORMAT_MONO_RAW or IrisInfo.IMAGEFORMAT_RGB_RAW => ImageInfoTypes.WSQ_MIME_TYPE,
        IrisInfo.IMAGEFORMAT_MONO_JPEG or IrisInfo.IMAGEFORMAT_RGB_JPEG
            or IrisInfo.IMAGEFORMAT_MONO_JPEG_LS or IrisInfo.IMAGEFORMAT_RGB_JPEG_LS => ImageInfoTypes.JPEG_MIME_TYPE,
        IrisInfo.IMAGEFORMAT_MONO_JPEG2000 or IrisInfo.IMAGEFORMAT_RGB_JPEG2000 => ImageInfoTypes.JPEG2000_MIME_TYPE,
        _ => null,
    };

    private static int ReadUnsignedByte(Stream inputStream)
    {
        int b = inputStream.ReadByte();
        if (b < 0)
        {
            throw new EndOfStreamException("Unexpected end of stream while reading iris image info.");
        }
        return b;
    }

    private static int ReadUnsignedShort(Stream inputStream)
    {
        int b1 = ReadUnsignedByte(inputStream);
        int b2 = ReadUnsignedByte(inputStream);
        return (b1 << 8) | b2;
    }

    private static int ReadShort(Stream inputStream)
    {
        int b1 = ReadUnsignedByte(inputStream);
        int b2 = ReadUnsignedByte(inputStream);
        return (short)((b1 << 8) | b2);
    }

    private static int ReadInt(Stream inputStream)
    {
        int b1 = ReadUnsignedByte(inputStream);
        int b2 = ReadUnsignedByte(inputStream);
        int b3 = ReadUnsignedByte(inputStream);
        int b4 = ReadUnsignedByte(inputStream);
        return (b1 << 24) | (b2 << 16) | (b3 << 8) | b4;
    }

    private static void WriteByte(Stream outputStream, int value) => outputStream.WriteByte((byte)value);

    private static void WriteShort(Stream outputStream, int value)
    {
        outputStream.WriteByte((byte)((value >> 8) & 0xFF));
        outputStream.WriteByte((byte)(value & 0xFF));
    }

    private static void WriteInt(Stream outputStream, int value)
    {
        outputStream.WriteByte((byte)((value >> 24) & 0xFF));
        outputStream.WriteByte((byte)((value >> 16) & 0xFF));
        outputStream.WriteByte((byte)((value >> 8) & 0xFF));
        outputStream.WriteByte((byte)(value & 0xFF));
    }
}
