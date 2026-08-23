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
/// Port of <c>org.jmrtd.lds.DisplayedImageDataGroup</c>: file structure for image template files that
/// can be displayed. Abstract super class for ICAO LDS EF_DG5 - EF_DG7.
/// </summary>
public abstract class DisplayedImageDataGroup : DataGroup
{
    private const int DISPLAYED_IMAGE_COUNT_TAG = 0x02;

    private int _displayedImageTagToUse;

    /// <remarks>
    /// Deliberately left without an inline initializer: for the "parse from stream" constructor, the
    /// base <c>AbstractTaggedLDSFile</c> constructor invokes <see cref="ReadContent"/> virtually before
    /// this constructor's own body runs, which populates this field via <see cref="Add"/> -- an inline
    /// initializer here would execute afterwards and silently wipe out what ReadContent just built.
    /// </remarks>
    private List<DisplayedImageInfo> _imageInfos = null!;

    /// <summary>
    /// Constructs a displayed image data group from a list of displayed images. The list should not be
    /// <c>null</c> or contain <c>null</c> valued displayed images.
    /// </summary>
    /// <param name="dataGroupTag">a tag indicating DG5, DG6, or DG7</param>
    /// <param name="imageInfos">a list of displayed images</param>
    /// <param name="displayedImageTagToUse">a tag indicating <i>Portrait</i> or <i>Signature or mark</i></param>
    protected DisplayedImageDataGroup(int dataGroupTag, List<DisplayedImageInfo> imageInfos, int displayedImageTagToUse)
        : base(dataGroupTag)
    {
        ArgumentNullException.ThrowIfNull(imageInfos);
        _displayedImageTagToUse = displayedImageTagToUse;
        _imageInfos = [.. imageInfos];
        CheckTypesConsistentWithTag();
    }

    /// <summary>Constructs a displayed image data group from binary representation.</summary>
    /// <param name="dataGroupTag">a tag indicating DG5, DG6, or DG7</param>
    /// <param name="inputStream">an input stream</param>
    protected DisplayedImageDataGroup(int dataGroupTag, Stream inputStream)
        : base(dataGroupTag, inputStream)
    {
        _imageInfos ??= [];
        CheckTypesConsistentWithTag();
    }

    protected override void ReadContent(Stream inputStream)
    {
        using var tlvIn = new TlvInputStream(inputStream, leaveOpen: true);
        int countTag = tlvIn.ReadTag();
        if (countTag != DISPLAYED_IMAGE_COUNT_TAG) /* 02 */
        {
            throw new ArgumentException($"Expected tag 0x02 in displayed image structure, found {countTag:X}");
        }
        int countLength = tlvIn.ReadLength();
        if (countLength != 1)
        {
            throw new ArgumentException("DISPLAYED_IMAGE_COUNT should have length 1");
        }
        int count = tlvIn.ReadValue()[0] & 0xFF;
        for (int i = 0; i < count; i++)
        {
            var imageInfo = new DisplayedImageInfo(tlvIn);
            if (i == 0)
            {
                _displayedImageTagToUse = imageInfo.GetDisplayedImageTag();
            }
            else if (imageInfo.GetDisplayedImageTag() != _displayedImageTagToUse)
            {
                throw new IOException("Found images with different displayed image tags inside displayed image datagroup");
            }
            Add(imageInfo);
        }
    }

    /// <summary>Writes the contents of this structure to a stream.</summary>
    protected override void WriteContent(Stream outputStream)
    {
        using var tlvOut = new TlvOutputStream(outputStream, leaveOpen: true);
        tlvOut.WriteTag(DISPLAYED_IMAGE_COUNT_TAG);
        tlvOut.WriteValue([(byte)_imageInfos.Count]);
        foreach (DisplayedImageInfo imageInfo in _imageInfos)
        {
            imageInfo.WriteObject(tlvOut);
        }
    }

    public override string ToString()
    {
        var result = new System.Text.StringBuilder();
        result.Append(GetType().Name);
        result.Append(" [");
        bool isFirst = true;
        if (_imageInfos == null)
        {
            throw new InvalidOperationException("imageInfos cannot be null");
        }
        foreach (DisplayedImageInfo info in _imageInfos)
        {
            if (isFirst)
            {
                isFirst = false;
            }
            else
            {
                result.Append(", ");
            }
            result.Append(info.ToString());
        }
        result.Append(']');
        return result.ToString();
    }

    public override int GetHashCode() => 1337 + (_imageInfos == null ? 1 : _imageInfos.GetHashCode()) + 31337;

    public override bool Equals(object? other)
    {
        if (other == null)
        {
            return false;
        }
        if (ReferenceEquals(other, this))
        {
            return true;
        }
        if (GetType() != other.GetType())
        {
            return false;
        }

        var otherDg = (DisplayedImageDataGroup)other;
        return ReferenceEquals(_imageInfos, otherDg._imageInfos) || (_imageInfos != null && _imageInfos.SequenceEqual(otherDg._imageInfos));
    }

    /// <summary>Returns the image infos.</summary>
    public List<DisplayedImageInfo> GetImages() => [.. _imageInfos];

    /// <summary>Adds an image info to this data group.</summary>
    private void Add(DisplayedImageInfo image)
    {
        _imageInfos ??= [];
        _imageInfos.Add(image);
    }

    /// <summary>
    /// Checks whether the type of image infos is consistent with the type and throws an
    /// <see cref="ArgumentException"/> if not.
    /// </summary>
    private void CheckTypesConsistentWithTag()
    {
        foreach (DisplayedImageInfo imageInfo in _imageInfos)
        {
            if (imageInfo == null)
            {
                throw new ArgumentException("Found a null image info");
            }
            switch (imageInfo.GetImageType())
            {
                case ImageInfo.TYPE_SIGNATURE_OR_MARK:
                    if (_displayedImageTagToUse != DisplayedImageInfo.DISPLAYED_SIGNATURE_OR_MARK_TAG)
                    {
                        throw new ArgumentException("'Portrait' image cannot be part of a 'Signature or usual mark' displayed image datagroup");
                    }
                    break;
                case ImageInfo.TYPE_PORTRAIT:
                    if (_displayedImageTagToUse != DisplayedImageInfo.DISPLAYED_PORTRAIT_TAG)
                    {
                        throw new ArgumentException("'Signature or usual mark' image cannot be part of a 'Portrait' displayed image datagroup");
                    }
                    break;
                default:
                    /* NOTE: JMRTD logs a warning here (LOGGER.warning("Unsupported image type")); per
                     * porting-conventions.md this non-essential warning branch is not worth pulling in
                     * Microsoft.Extensions.Logging.Abstractions for, so it's simply not logged. */
                    break;
            }
        }
    }
}
