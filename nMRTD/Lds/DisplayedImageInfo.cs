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

using nMRTD.SmartCards;

namespace nMRTD.Lds;

/// <summary>
/// Port of <c>org.jmrtd.lds.DisplayedImageInfo</c>: data structure for storing either a
/// <i>Portrait</i> (as used in DG5) or a <i>Signature or mark</i> (as used in DG7).
/// </summary>
public sealed class DisplayedImageInfo : AbstractImageInfo
{
    public const int DISPLAYED_PORTRAIT_TAG = 0x5F40;

    public const int DISPLAYED_SIGNATURE_OR_MARK_TAG = 0x5F43;

    private int _displayedImageTag;

    /// <summary>Constructs a displayed image info from the image bytes.</summary>
    /// <param name="type">one of <see cref="ImageInfo.TYPE_PORTRAIT"/> or <see cref="ImageInfo.TYPE_SIGNATURE_OR_MARK"/></param>
    /// <param name="imageBytes">encoded image, for <i>Portrait</i> and <i>Signature or mark</i> use JPEG encoding</param>
    public DisplayedImageInfo(int type, byte[] imageBytes)
        : base(type, GetMimeTypeFromType(type))
    {
        _displayedImageTag = GetDisplayedImageTagFromType(type);
        SetImageBytes(imageBytes);
    }

    /// <summary>Constructs a displayed image info from binary encoding.</summary>
    public DisplayedImageInfo(Stream inputStream)
    {
        ReadObject(inputStream);
    }

    /// <summary>
    /// Constructs a displayed image info reading from an already-open TLV stream shared with sibling
    /// images (used by <see cref="DisplayedImageDataGroup"/>, which reads several of these back to back
    /// from the same underlying stream). Does not dispose <paramref name="tlvIn"/>.
    /// </summary>
    internal DisplayedImageInfo(TlvInputStream tlvIn)
    {
        ReadObject(tlvIn);
    }

    /// <summary>
    /// Reads the displayed image. The 5F40/5F43 tag and the length are read here (unlike the abstract
    /// base's usual per-subclass split, since JMRTD's own version reads tag+length itself too).
    /// </summary>
    protected override void ReadObject(Stream inputStream)
    {
        using var tlvIn = new TlvInputStream(inputStream);
        ReadObject(tlvIn);
    }

    private void ReadObject(TlvInputStream tlvIn)
    {
        _displayedImageTag = tlvIn.ReadTag();
        if (_displayedImageTag != DISPLAYED_PORTRAIT_TAG && _displayedImageTag != DISPLAYED_SIGNATURE_OR_MARK_TAG)
        {
            throw new ArgumentException($"Expected tag 0x5F40 or 0x5F43, found {_displayedImageTag:X}");
        }

        int type = GetTypeFromDisplayedImageTag(_displayedImageTag);
        SetType(type);
        SetMimeType(GetMimeTypeFromType(type));

        int imageLength = tlvIn.ReadLength();

        using var valueStream = new MemoryStream(tlvIn.ReadValue(), writable: false);
        ReadImage(valueStream, imageLength);
    }

    protected override void WriteObject(Stream outputStream)
    {
        using var tlvOut = new TlvOutputStream(outputStream);
        WriteObject(tlvOut);
    }

    /// <summary>
    /// Writes this displayed image into an already-open TLV stream shared with sibling images (used by
    /// <see cref="DisplayedImageDataGroup"/>). Does not dispose <paramref name="tlvOut"/>.
    /// </summary>
    internal void WriteObject(TlvOutputStream tlvOut)
    {
        tlvOut.WriteTag(GetDisplayedImageTagFromType(GetImageType()));

        /* TlvOutputStream isn't a Stream (see its own doc comment), so WriteImage(Stream) -- which the
         * abstract base defines in terms of Stream.Write -- can't be handed tlvOut directly. Buffer via
         * a MemoryStream and forward the bytes into the currently open TLV frame instead. */
        using var buffer = new MemoryStream();
        WriteImage(buffer);
        tlvOut.Write(buffer.ToArray());
        tlvOut.WriteValueEnd();
    }

    /// <summary>
    /// Returns the displayed image tag. Either <see cref="DISPLAYED_PORTRAIT_TAG"/> or
    /// <see cref="DISPLAYED_SIGNATURE_OR_MARK_TAG"/>, depending on the type of image.
    /// </summary>
    internal int GetDisplayedImageTag() => _displayedImageTag;

    /// <inheritdoc/>
    public override long GetRecordLength()
    {
        long length = 0;
        int imageLength = GetImageLength();
        length += TlvUtil.GetTagLength(GetDisplayedImageTagFromType(GetImageType()));
        length += TlvUtil.GetLengthLength(imageLength);
        length += imageLength;
        return length;
    }

    public override int GetHashCode()
    {
        const int prime = 31;
        int result = base.GetHashCode();
        result = (prime * result) + _displayedImageTag;
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

        var other = (DisplayedImageInfo)obj;
        return _displayedImageTag == other._displayedImageTag;
    }

    /* ONLY PRIVATE METHODS BELOW */

    /// <summary>
    /// As per A1.11.4 in Doc 9303 Part 3 Vol 2: Displayed Facial Image and Displayed Signature/usual
    /// mark both use ISO 10918, JFIF option (JPEG); Displayed Finger uses ANSI/NIST-ITL 1-2000 (WSQ).
    /// </summary>
    private static string GetMimeTypeFromType(int type) => type switch
    {
        ImageInfo.TYPE_PORTRAIT => "image/jpeg",
        ImageInfo.TYPE_FINGER => "image/x-wsq",
        ImageInfo.TYPE_SIGNATURE_OR_MARK => "image/jpeg",
        _ => throw new FormatException($"Unknown type: {type:X}"),
    };

    /// <summary>Derives the displayed image info tag from the image type.</summary>
    private static int GetDisplayedImageTagFromType(int type) => type switch
    {
        ImageInfo.TYPE_PORTRAIT => DISPLAYED_PORTRAIT_TAG,
        ImageInfo.TYPE_SIGNATURE_OR_MARK => DISPLAYED_SIGNATURE_OR_MARK_TAG,
        _ => throw new FormatException($"Unknown type: {type:X}"),
    };

    /// <summary>Derives the image info type from the given tag.</summary>
    private static int GetTypeFromDisplayedImageTag(int tag) => tag switch
    {
        DISPLAYED_PORTRAIT_TAG => ImageInfo.TYPE_PORTRAIT,
        DISPLAYED_SIGNATURE_OR_MARK_TAG => ImageInfo.TYPE_SIGNATURE_OR_MARK,
        _ => throw new FormatException($"Unknown tag: {tag:X}"),
    };
}
