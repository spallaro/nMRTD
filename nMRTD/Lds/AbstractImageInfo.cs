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
/// Port of <c>org.jmrtd.lds.AbstractImageInfo</c>: base class for image infos.
/// </summary>
public abstract class AbstractImageInfo : ImageInfo
{
    private int _type;
    private string? _mimeType;
    private byte[]? _imageBytes;

    /* NOTE: JMRTD also keeps a "splittable input stream" fast path (splittableInputStream,
     * imagePositionInInputStream, imageLength), but its readImage(...) has the code that sets them
     * commented out, so the image is always read into memory and that path is dead. It is not ported:
     * its fields were never assigned here either. */

    private int _width;
    private int _height;

    /// <summary>Constructs a default abstract image info. Java package-only visibility; <c>internal</c> here since this assembly is the closest C# equivalent.</summary>
    internal AbstractImageInfo()
        : this(ImageInfoTypes.TYPE_UNKNOWN, 0, 0, null)
    {
    }

    /// <summary>Constructs an abstract image info with a type.</summary>
    protected AbstractImageInfo(int type)
        : this(type, 0, 0, null)
    {
    }

    /// <summary>Constructs an abstract image info with a type and a mime-type.</summary>
    protected AbstractImageInfo(int type, string? mimeType)
        : this(type, 0, 0, mimeType)
    {
    }

    private AbstractImageInfo(int type, int width, int height, string? mimeType)
    {
        _type = type;
        _mimeType = mimeType;
        _width = width;
        _height = height;
    }

    /// <summary>Constructs an abstract image info with full parameters.</summary>
    /// <param name="type">type of image info</param>
    /// <param name="width">width of image</param>
    /// <param name="height">height of image</param>
    /// <param name="inputStream">encoded image</param>
    /// <param name="imageLength">length of encoded image</param>
    /// <param name="mimeType">mime-type of encoded image</param>
    protected AbstractImageInfo(int type, int width, int height, Stream inputStream, long imageLength, string? mimeType)
        : this(type, width, height, mimeType)
    {
        ReadImage(inputStream, imageLength);
    }

    /// <inheritdoc/>
    public int GetImageType() => _type;

    /// <inheritdoc/>
    public string? GetMimeType() => _mimeType;

    /// <inheritdoc/>
    public int GetWidth() => _width;

    /// <inheritdoc/>
    public int GetHeight() => _height;

    /// <inheritdoc/>
    public abstract long GetRecordLength();

    /// <inheritdoc/>
    public int GetImageLength()
    {
        if (_imageBytes == null)
        {
            throw new InvalidOperationException("Cannot get length of null");
        }

        return _imageBytes.Length;
    }

    /// <summary>Returns a textual representation of this image info.</summary>
    public override string ToString() => $"{GetType().Name} [type: {TypeToString(_type)}, size: {GetImageLength()}]";

    public override int GetHashCode()
    {
        int result = 1234567891;
        result = 3 * result + 5 * _type;
        result += 5 * (_mimeType == null ? 1337 : _mimeType.GetHashCode(StringComparison.Ordinal)) + 7;
        result += 7 * GetImageLength() + 11;
        return result;
    }

    public override bool Equals(object? other)
    {
        try
        {
            if (other == null)
            {
                return false;
            }
            if (ReferenceEquals(other, this))
            {
                return true;
            }
            if (other.GetType() != GetType())
            {
                return false;
            }

            var otherImageInfo = (AbstractImageInfo)other;
            return GetImageBytes().AsSpan().SequenceEqual(otherImageInfo.GetImageBytes())
                && ((_mimeType == null && otherImageInfo._mimeType == null) || (_mimeType != null && _mimeType == otherImageInfo._mimeType))
                && _type == otherImageInfo._type;
        }
        catch (IOException)
        {
            return false;
        }
    }

    /// <inheritdoc/>
    public byte[]? GetEncoded()
    {
        using var outputStream = new MemoryStream();
        try
        {
            WriteObject(outputStream);
        }
        catch (IOException)
        {
            return null;
        }
        return outputStream.ToArray();
    }

    /// <inheritdoc/>
    public Stream GetImageInputStream()
    {
        if (_imageBytes != null)
        {
            return new MemoryStream(_imageBytes, writable: false);
        }

        throw new InvalidOperationException("Both the byte buffer and the stream are null");
    }

    /// <summary>Clients should call this method after positioning the input stream to the image bytes.</summary>
    protected void ReadImage(Stream inputStream, long imageLength)
    {
        // The length comes from the input, so it is not allocated up front (JMRTD 0.8.10, a4b9e9e2).
        _imageBytes = Io.InputStreams.ReadFully(inputStream, imageLength);
    }

    /// <summary>Writes this image to a stream.</summary>
    protected void WriteImage(Stream outputStream)
    {
        byte[] bytes = GetImageBytes();
        outputStream.Write(bytes, 0, bytes.Length);
    }

    /// <summary>Sets the mime-type.</summary>
    protected void SetMimeType(string? mimeType) => _mimeType = mimeType;

    /// <summary>Sets the type.</summary>
    protected void SetType(int type) => _type = type;

    /// <summary>Sets the width of this image.</summary>
    protected void SetWidth(int width) => _width = width;

    /// <summary>Sets the height of this image.</summary>
    protected void SetHeight(int height) => _height = height;

    /// <summary>Sets the encoded image bytes of this image.</summary>
    protected void SetImageBytes(byte[] imageBytes)
    {
        ArgumentNullException.ThrowIfNull(imageBytes);
        ReadImage(new MemoryStream(imageBytes, writable: false), imageBytes.Length);
    }

    /// <summary>Reads this object from a stream.</summary>
    protected abstract void ReadObject(Stream inputStream);

    /// <summary>Writes this object to a stream.</summary>
    protected abstract void WriteObject(Stream outputStream);

    private byte[] GetImageBytes()
    {
        int length = GetImageLength();
        byte[] imageBytes = new byte[length];
        using Stream inputStream = GetImageInputStream();
        ReadFully(inputStream, imageBytes);
        return imageBytes;
    }

    private static void ReadFully(Stream stream, byte[] buffer)
    {
        int totalRead = 0;
        while (totalRead < buffer.Length)
        {
            int read = stream.Read(buffer, totalRead, buffer.Length - totalRead);
            if (read <= 0)
            {
                throw new EndOfStreamException();
            }
            totalRead += read;
        }
    }

    private static string TypeToString(int type) => type switch
    {
        ImageInfoTypes.TYPE_PORTRAIT => "Portrait",
        ImageInfoTypes.TYPE_SIGNATURE_OR_MARK => "Signature or usual mark",
        ImageInfoTypes.TYPE_FINGER => "Finger",
        ImageInfoTypes.TYPE_IRIS => "Iris",
        ImageInfoTypes.TYPE_UNKNOWN => "Unknown",
        _ => throw new FormatException($"Unknown type: {type:X}"),
    };
}
