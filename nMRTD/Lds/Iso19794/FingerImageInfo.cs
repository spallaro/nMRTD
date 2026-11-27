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

using nMRTD.Cbeff;
using nMRTD.Lds;

namespace nMRTD.Lds.Iso19794;

/// <summary>
/// Port of <c>org.jmrtd.lds.iso19794.FingerImageInfo</c>: data structure for storing a view of a single
/// finger image, multi-finger image, or palm. This represents a finger image record header as specified
/// in Section 7.2 of ISO/IEC FCD 19794-4 aka Annex F.
/// </summary>
public class FingerImageInfo : AbstractImageInfo
{
    /* NOTE: in comment: max image area in sq mm, sq in, with in mm, in, length in mm, in */
    /// <summary>Finger code, according to Table 5, 7.2.2, ISO 19794-4.</summary>
    public const int POSITION_UNKNOWN_FINGER = 0; /* 1745 40.6 1.6 38.1 1.5 */

    /// <summary>Finger code, according to Table 5, 7.2.2, ISO 19794-4.</summary>
    public const int POSITION_RIGHT_THUMB = 1; /* 1745 40.6 1.6 38.1 1.5 */

    /// <summary>Finger code, according to Table 5, 7.2.2, ISO 19794-4.</summary>
    public const int POSITION_RIGHT_INDEX_FINGER = 2; /* 1640 40.6 1.6 38.1 1.5 */

    /// <summary>Finger code, according to Table 5, 7.2.2, ISO 19794-4.</summary>
    public const int POSITION_RIGHT_MIDDLE_FINGER = 3; /* 1640 40.6 1.6 38.1 1.5 */

    /// <summary>Finger code, according to Table 5, 7.2.2, ISO 19794-4.</summary>
    public const int POSITION_RIGHT_RING_FINGER = 4; /* 1640 40.6 1.6 38.1 1.5 */

    /// <summary>Finger code, according to Table 5, 7.2.2, ISO 19794-4.</summary>
    public const int POSITION_RIGHT_LITTLE_FINGER = 5; /* 1640 40.6 1.6 38.1 1.5 */

    /// <summary>Finger code, according to Table 5, 7.2.2, ISO 19794-4.</summary>
    public const int POSITION_LEFT_THUMB = 6; /* 1745 40.6 1.6 38.1 1.5 */

    /// <summary>Finger code, according to Table 5, 7.2.2, ISO 19794-4.</summary>
    public const int POSITION_LEFT_INDEX_FINGER = 7; /* 1640 40.6 1.6 38.1 1.5 */

    /// <summary>Finger code, according to Table 5, 7.2.2, ISO 19794-4.</summary>
    public const int POSITION_LEFT_MIDDLE_FINGER = 8; /* 1640 40.6 1.6 38.1 1.5 */

    /// <summary>Finger code, according to Table 5, 7.2.2, ISO 19794-4.</summary>
    public const int POSITION_LEFT_RING_FINGER = 9; /* 1640 40.6 1.6 38.1 1.5 */

    /// <summary>Finger code, according to Table 5, 7.2.2, ISO 19794-4.</summary>
    public const int POSITION_LEFT_LITTLE_FINGER = 10; /* 1640 40.6 1.6 38.1 1.5 */

    /// <summary>Finger code, according to Table 5, 7.2.2, ISO 19794-4.</summary>
    public const int POSITION_PLAIN_RIGHT_FOUR_FINGERS = 13; /* 6800 83.8 3.3 76.2 3.0 */

    /// <summary>Finger code, according to Table 5, 7.2.2, ISO 19794-4.</summary>
    public const int POSITION_PLAIN_LEFT_FOUR_FINGERS = 14; /* 6800 83.8 3.3 76.2 3.0 */

    /// <summary>Finger code, according to Table 5, 7.2.2, ISO 19794-4.</summary>
    public const int POSITION_PLAIN_THUMBS = 15; /* 4800 50.8 2.0 76.2 3.0 */

    /* NOTE: in comment: max image area in sq mm, sq in, with in mm, in, length in mm, in */
    /// <summary>Palm code, according to Table 6, 7.2.2, ISO 19794-4.</summary>
    public const int POSITION_UNKNOWN_PALM = 20; /* 283.87 13.97 5.5 20.32 8.0 */

    /// <summary>Palm code, according to Table 6, 7.2.2, ISO 19794-4.</summary>
    public const int POSITION_RIGHT_FULL_PALM = 21; /* 283.87 13.97 5.5 20.32 8.0 */

    /// <summary>Palm code, according to Table 6, 7.2.2, ISO 19794-4.</summary>
    public const int POSITION_RIGHT_WRITER_S_PALM = 22; /* 58.06 4.57 1.8 12.70 5.0 */

    /// <summary>Palm code, according to Table 6, 7.2.2, ISO 19794-4.</summary>
    public const int POSITION_LEFT_FULL_PALM = 23; /* 283.87 13.97 5.5 20.32 8.0 */

    /// <summary>Palm code, according to Table 6, 7.2.2, ISO 19794-4.</summary>
    public const int POSITION_LEFT_WRITER_S_PALM = 24; /* 58.06 4.57 1.8 12.70 5.0 */

    /// <summary>Palm code, according to Table 6, 7.2.2, ISO 19794-4.</summary>
    public const int POSITION_RIGHT_LOWER_PALM = 25; /* 195.16 13.97 5.5 13.97 5.5 */

    /// <summary>Palm code, according to Table 6, 7.2.2, ISO 19794-4.</summary>
    public const int POSITION_RIGHT_UPPER_PALM = 26; /* 195.16 13.97 5.5 13.97 5.5 */

    /// <summary>Palm code, according to Table 6, 7.2.2, ISO 19794-4.</summary>
    public const int POSITION_LEFT_LOWER_PALM = 27; /* 195.16 13.97 5.5 13.97 5.5 */

    /// <summary>Palm code, according to Table 6, 7.2.2, ISO 19794-4.</summary>
    public const int POSITION_LEFT_UPPER_PALM = 28; /* 195.16 13.97 5.5 13.97 5.5 */

    /// <summary>Palm code, according to Table 6, 7.2.2, ISO 19794-4.</summary>
    public const int POSITION_RIGHT_OTHER = 29; /* 283.87 13.97 5.5 20.32 8.0 */

    /// <summary>Palm code, according to Table 6, 7.2.2, ISO 19794-4.</summary>
    public const int POSITION_LEFT_OTHER = 30; /* 283.87 13.97 5.5 20.32 8.0 */

    /// <summary>Palm code, according to Table 6, 7.2.2, ISO 19794-4.</summary>
    public const int POSITION_RIGHT_INTERDIGITAL = 31; /* 106.45 13.97 5.5 7.62 3.0 */

    /// <summary>Palm code, according to Table 6, 7.2.2, ISO 19794-4.</summary>
    public const int POSITION_RIGHT_THENAR = 32; /* 77.42 7.62 3.0 10.16 4.0 */

    /// <summary>Palm code, according to Table 6, 7.2.2, ISO 19794-4.</summary>
    public const int POSITION_RIGHT_HYPOTHENAR = 33; /* 106.45 7.62 3.0 13.97 5.5 */

    /// <summary>Palm code, according to Table 6, 7.2.2, ISO 19794-4.</summary>
    public const int POSITION_LEFT_INTERDIGITAL = 34; /* 106.45 13.97 5.5 7.62 3.0 */

    /// <summary>Palm code, according to Table 6, 7.2.2, ISO 19794-4.</summary>
    public const int POSITION_LEFT_THENAR = 35; /* 77.42 7.62 3.0 10.16 4.0 */

    /// <summary>Palm code, according to Table 6, 7.2.2, ISO 19794-4.</summary>
    public const int POSITION_LEFT_HYPOTHENAR = 36; /* 106.45 7.62 3.0 13.97 5.5 */

    /// <summary>Finger or palm impression type, according to Table 7 in ISO 19794-4.</summary>
    public const int IMPRESSION_TYPE_LIVE_SCAN_PLAIN = 0;

    /// <summary>Finger or palm impression type, according to Table 7 in ISO 19794-4.</summary>
    public const int IMPRESSION_TYPE_LIVE_SCAN_ROLLED = 1;

    /// <summary>Finger or palm impression type, according to Table 7 in ISO 19794-4.</summary>
    public const int IMPRESSION_TYPE_NON_LIVE_SCAN_PLAIN = 2;

    /// <summary>Finger or palm impression type, according to Table 7 in ISO 19794-4.</summary>
    public const int IMPRESSION_TYPE_NON_LIVE_SCAN_ROLLED = 3;

    /// <summary>Finger or palm impression type, according to Table 7 in ISO 19794-4.</summary>
    public const int IMPRESSION_TYPE_LATENT = 7;

    /// <summary>Finger or palm impression type, according to Table 7 in ISO 19794-4.</summary>
    public const int IMPRESSION_TYPE_SWIPE = 8;

    /// <summary>Finger or palm impression type, according to Table 7 in ISO 19794-4.</summary>
    public const int IMPRESSION_TYPE_LIVE_SCAN_CONTACTLESS = 9;

    private static readonly byte[] FORMAT_TYPE_VALUE = [0x00, 0x09];

    private long _recordLength;
    private int _position;
    private int _viewCount;
    private int _viewNumber;
    private int _quality;
    private int _impressionType;

    private int _compressionAlgorithm;

    /// <summary>Constructs a finger image info.</summary>
    /// <param name="position">finger position according to ISO 19794-4</param>
    /// <param name="viewCount">number of views</param>
    /// <param name="viewNumber">the view number</param>
    /// <param name="quality">quality</param>
    /// <param name="impressionType">impression type according to ISO 19794-4</param>
    /// <param name="width">width</param>
    /// <param name="height">height</param>
    /// <param name="imageStream">encoded image bytes</param>
    /// <param name="imageLength">length of encoded image</param>
    /// <param name="compressionAlgorithm">image encoding type according to ISO 19794-4</param>
    public FingerImageInfo(int position,
        int viewCount, int viewNumber, int quality, int impressionType,
        int width, int height, Stream imageStream, int imageLength, int compressionAlgorithm)
        : base(ImageInfoTypes.TYPE_FINGER, width, height, imageStream, imageLength, FingerInfo.ToMimeType(compressionAlgorithm))
    {
        if (0 > quality || quality > 100)
        {
            throw new ArgumentException("Quality needs to be a number between 0 and 100");
        }

        /* NOTE: preserved Java quirk -- Java's constructor calls super(...) (which already reads the
         * image bytes) before this null check, so a null stream would already have thrown a
         * NullPointerException inside the base constructor; this check is therefore dead code in the
         * original, and stays dead code here (base(...) runs before this body in C# too). */
        if (imageStream == null)
        {
            throw new ArgumentException("Null image");
        }

        _position = position;
        _viewCount = viewCount;
        _viewNumber = viewNumber;
        _quality = quality;
        _impressionType = impressionType;
        _compressionAlgorithm = compressionAlgorithm;
        _recordLength = imageLength + 14L;
    }

    /// <summary>Constructs a new finger information record.</summary>
    /// <param name="inputStream">input stream</param>
    /// <param name="compressionAlgorithm">image format type (which is given in the general record header, not for each individual image)</param>
    public FingerImageInfo(Stream inputStream, int compressionAlgorithm)
        : base(ImageInfoTypes.TYPE_FINGER, FingerInfo.ToMimeType(compressionAlgorithm))
    {
        _compressionAlgorithm = compressionAlgorithm;
        ReadObject(inputStream);
    }

    /// <summary>
    /// Returns the quality of the overall scanned finger/palm image as a number between 0 and 100. As
    /// specified in 7.2.5 of ISO 19794-4.
    /// </summary>
    public int GetQuality() => _quality;

    /// <summary>Returns the finger/palm position. As specified in Section 7.2.2 of ISO 19794-4.</summary>
    /// <returns>a constant representing the position (see constant definitions starting with <c>POSITION_</c>)</returns>
    public int GetPosition() => _position;

    /// <summary>
    /// Returns the compression algorithm. One of <see cref="FingerInfo.COMPRESSION_UNCOMPRESSED_BIT_PACKED"/>,
    /// <see cref="FingerInfo.COMPRESSION_UNCOMPRESSED_NO_BIT_PACKING"/>, <see cref="FingerInfo.COMPRESSION_JPEG"/>,
    /// <see cref="FingerInfo.COMPRESSION_JPEG2000"/>, <see cref="FingerInfo.COMPRESSION_PNG"/>,
    /// <see cref="FingerInfo.COMPRESSION_WSQ"/>. As specified in Section 7.1.13 of ISO 19794-4.
    /// </summary>
    public int GetCompressionAlgorithm() => _compressionAlgorithm;

    /// <summary>
    /// Returns the total number of specific views available for this finger. As specified in Section
    /// 7.2.3 of ISO 19794-4.
    /// </summary>
    public int GetViewCount() => _viewCount;

    /// <summary>
    /// Returns the specific image view number associated with the finger. As specified in Section 7.2.4
    /// of ISO 19794-4.
    /// </summary>
    public int GetViewNumber() => _viewNumber;

    /// <summary>Returns the impression type. As specified in Section 7.2.6 of ISO 19794-4.</summary>
    /// <returns>a constant indicating the impression type (see constant definitions starting with <c>IMPRESSION_TYPE_</c>)</returns>
    public int GetImpressionType() => _impressionType;

    /// <inheritdoc/>
    protected override void ReadObject(Stream inputStream)
    {
        /* Finger image header (14), see Table 4, 7.2 in Annex F. */
        /* NOTE: sometimes called "finger header", "finger record header" */
        _recordLength = ReadUInt32BigEndian(inputStream);
        _position = ReadUnsignedByte(inputStream);
        _viewCount = ReadUnsignedByte(inputStream);
        _viewNumber = ReadUnsignedByte(inputStream);
        _quality = ReadUnsignedByte(inputStream);
        _impressionType = ReadUnsignedByte(inputStream);
        SetWidth(ReadUnsignedShort(inputStream));
        SetHeight(ReadUnsignedShort(inputStream));
        _ = ReadUnsignedByte(inputStream); /* RFU, should be 0x00 */

        long imageLength = _recordLength - 14;

        ReadImage(inputStream, imageLength);
    }

    /// <summary>
    /// Writes the biometric data to <paramref name="outputStream"/>. Based on Table 4 in Section 8.3 of
    /// ISO/IEC FCD 19794-4.
    /// </summary>
    protected override void WriteObject(Stream outputStream)
    {
        using var imageBuffer = new MemoryStream();
        WriteImage(imageBuffer);
        byte[] imageBytes = imageBuffer.ToArray();

        long fingerDataBlockLength = imageBytes.Length + 14L;

        /* Finger Information (14) */
        WriteInt32BigEndian(outputStream, unchecked((int)(fingerDataBlockLength & 0xFFFFFFFFL)));
        outputStream.WriteByte((byte)_position);
        outputStream.WriteByte((byte)_viewCount);
        outputStream.WriteByte((byte)_viewNumber);
        outputStream.WriteByte((byte)_quality);
        outputStream.WriteByte((byte)_impressionType);
        WriteUnsignedShort(outputStream, GetWidth());
        WriteUnsignedShort(outputStream, GetHeight());
        outputStream.WriteByte(0x00); /* RFU */

        outputStream.Write(imageBytes, 0, imageBytes.Length);
    }

    /// <summary>
    /// Writes this finger image info to a stream. Forwards to the protected <see cref="WriteObject(Stream)"/>
    /// override. Java's <c>FingerInfo.writeObject(...)</c> calls <c>fingerImageInfo.writeObject(dataOut)</c>
    /// directly -- legal there because Java's <c>protected</c> also grants same-package access, which
    /// <see cref="FingerInfo"/> (same package/namespace) has. C#'s <c>protected</c> only grants access to
    /// derived classes, so <see cref="FingerInfo"/> (an unrelated type) needs this <c>internal</c> forwarder
    /// instead -- same pattern as <c>DisplayedImageInfo.WriteObject(TlvOutputStream)</c>.
    /// </summary>
    internal void WriteFingerImageObject(Stream outputStream) => WriteObject(outputStream);

    /// <summary>Returns the record length.</summary>
    /// <returns>the record length</returns>
    public override long GetRecordLength() =>
        /* Should be equal to (getImageLength() + 14) */
        _recordLength;

    /// <summary>Returns the format type.</summary>
    /// <returns>a byte array of length 2</returns>
    public byte[] GetFormatType() => FORMAT_TYPE_VALUE;

    /// <summary>Returns the biometric sub-type.</summary>
    /// <returns>the ICAO/CBEFF (BHT) biometric sub-type</returns>
    public int GetBiometricSubtype() => ToBiometricSubtype(_position);

    public override int GetHashCode()
    {
        const int prime = 31;
        int result = base.GetHashCode();
        result = (prime * result) + _compressionAlgorithm;
        result = (prime * result) + _impressionType;
        result = (prime * result) + _position;
        result = (prime * result) + _quality;
        result = (prime * result) + (int)(_recordLength ^ (_recordLength >>> 32));
        result = (prime * result) + _viewCount;
        result = (prime * result) + _viewNumber;
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

        var other = (FingerImageInfo)obj;
        return _compressionAlgorithm == other._compressionAlgorithm
            && _impressionType == other._impressionType
            && _position == other._position
            && _quality == other._quality
            && _recordLength == other._recordLength
            && _viewCount == other._viewCount
            && _viewNumber == other._viewNumber;
    }

    /// <summary>Generates a textual representation of this object.</summary>
    /// <returns>a textual representation of this object</returns>
    public override string ToString()
    {
        /* NOTE: preserved Java quirk -- Java's StringBuilder.append(String) appends the literal text
         * "null" when given a null reference. positionToString/impressionTypeToString/ToMimeType can all
         * return null for unrecognized codes, so an unrecognized code shows up as the substring "null" in
         * the result rather than an empty string (which is what plain C# string interpolation of a null
         * value would silently produce). Preserved via explicit "?? "null"" below. */
        return "FingerImageInfo ["
            + "quality: " + _quality + ", "
            + "position: " + (PositionToString(_position) ?? "null") + ", "
            + "impression type: " + (ImpressionTypeToString(_impressionType) ?? "null") + ", "
            + "horizontal line length: " + GetWidth() + ", "
            + "vertical line length: " + GetHeight() + ", "
            + "image: " + GetWidth() + " x " + GetHeight()
            + " \"" + (FingerInfo.ToMimeType(_compressionAlgorithm) ?? "null") + "\""
            + "]";
    }

    /* ONLY PRIVATE METHODS BELOW */

    /// <summary>Returns a human readable string for the given position code.</summary>
    /// <param name="position">an ISO finger position code</param>
    /// <returns>a human readable string</returns>
    private static string? PositionToString(int position) => position switch
    {
        POSITION_UNKNOWN_FINGER => "Unknown finger",
        POSITION_RIGHT_THUMB => "Right thumb",
        POSITION_RIGHT_INDEX_FINGER => "Right index finger",
        POSITION_RIGHT_MIDDLE_FINGER => "Right middle finger",
        POSITION_RIGHT_RING_FINGER => "Right ring finger",
        POSITION_RIGHT_LITTLE_FINGER => "Right little finger",
        POSITION_LEFT_THUMB => "Left thumb",
        POSITION_LEFT_INDEX_FINGER => "Left index finger",
        POSITION_LEFT_MIDDLE_FINGER => "Left middle finger",
        POSITION_LEFT_RING_FINGER => "Left ring finger",
        POSITION_LEFT_LITTLE_FINGER => "Left little finger",
        POSITION_PLAIN_RIGHT_FOUR_FINGERS => "Right four fingers",
        POSITION_PLAIN_LEFT_FOUR_FINGERS => "Left four fingers",
        POSITION_PLAIN_THUMBS => "Plain thumbs",
        POSITION_UNKNOWN_PALM => "Unknown palm",
        POSITION_RIGHT_FULL_PALM => "Right full palm",
        POSITION_RIGHT_WRITER_S_PALM => "Right writer's palm",
        POSITION_LEFT_FULL_PALM => "Left full palm",
        POSITION_LEFT_WRITER_S_PALM => "Left writer's palm",
        POSITION_RIGHT_LOWER_PALM => "Right lower palm",
        POSITION_RIGHT_UPPER_PALM => "Right upper palm",
        POSITION_LEFT_LOWER_PALM => "Left lower palm",
        POSITION_LEFT_UPPER_PALM => "Left upper palm",
        POSITION_RIGHT_OTHER => "Right other",
        POSITION_LEFT_OTHER => "Left other",
        POSITION_RIGHT_INTERDIGITAL => "Right interdigital",
        POSITION_RIGHT_THENAR => "Right thenar",
        POSITION_RIGHT_HYPOTHENAR => "Right hypothenar",
        POSITION_LEFT_INTERDIGITAL => "Left interdigital",
        POSITION_LEFT_THENAR => "Left thenar",
        POSITION_LEFT_HYPOTHENAR => "Left hypothenar",
        _ => null,
    };

    /// <summary>Returns a human readable string for the given impression type code.</summary>
    /// <param name="impressionType">the impression type code</param>
    /// <returns>a human readable string for the given impression type code</returns>
    private static string? ImpressionTypeToString(int impressionType) => impressionType switch
    {
        IMPRESSION_TYPE_LIVE_SCAN_PLAIN => "Live scan plain",
        IMPRESSION_TYPE_LIVE_SCAN_ROLLED => "Live scan rolled",
        IMPRESSION_TYPE_NON_LIVE_SCAN_PLAIN => "Non-live scan plain",
        IMPRESSION_TYPE_NON_LIVE_SCAN_ROLLED => "Non-live scan rolled",
        IMPRESSION_TYPE_LATENT => "Latent",
        IMPRESSION_TYPE_SWIPE => "Swipe",
        IMPRESSION_TYPE_LIVE_SCAN_CONTACTLESS => "Live scan contactless",
        _ => null,
    };

    /// <summary>
    /// Converts from ISO (FRH) coding to ICAO/CBEFF (BHT) coding.
    /// <list type="table">
    /// <listheader><term>Finger</term><description>BHT coding / FRH coding</description></listheader>
    /// <item><term>Right thumb</term><description> 5 / 1</description></item>
    /// <item><term>Right index</term><description> 9 / 2</description></item>
    /// <item><term>Right middle</term><description>13 / 3</description></item>
    /// <item><term>Right ring</term><description>17 / 4</description></item>
    /// <item><term>Right little</term><description>21 / 5</description></item>
    /// <item><term>Left thumb</term><description> 6 / 6</description></item>
    /// <item><term>Left index</term><description>10 / 7</description></item>
    /// <item><term>Left middle</term><description>14 / 8</description></item>
    /// <item><term>Left ring</term><description>18 / 9</description></item>
    /// <item><term>Left little</term><description>22 / 10</description></item>
    /// </list>
    /// </summary>
    /// <param name="position">an ISO finger position code</param>
    /// <returns>an ICAO biometric subtype</returns>
    private static int ToBiometricSubtype(int position) => position switch
    {
        POSITION_UNKNOWN_FINGER => CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_NONE,
        POSITION_RIGHT_THUMB => CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_NONE | CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_RIGHT | CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_THUMB,
        POSITION_RIGHT_INDEX_FINGER => CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_NONE | CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_RIGHT | CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_POINTER_FINGER,
        POSITION_RIGHT_MIDDLE_FINGER => CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_NONE | CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_RIGHT | CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_MIDDLE_FINGER,
        POSITION_RIGHT_RING_FINGER => CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_NONE | CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_RIGHT | CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_RING_FINGER,
        POSITION_RIGHT_LITTLE_FINGER => CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_NONE | CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_RIGHT | CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_LITTLE_FINGER,
        POSITION_LEFT_THUMB => CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_NONE | CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_LEFT | CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_THUMB,
        POSITION_LEFT_INDEX_FINGER => CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_NONE | CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_LEFT | CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_POINTER_FINGER,
        POSITION_LEFT_MIDDLE_FINGER => CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_NONE | CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_LEFT | CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_MIDDLE_FINGER,
        POSITION_LEFT_RING_FINGER => CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_NONE | CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_LEFT | CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_RING_FINGER,
        POSITION_LEFT_LITTLE_FINGER => CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_NONE | CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_LEFT | CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_LITTLE_FINGER,
        POSITION_PLAIN_RIGHT_FOUR_FINGERS => CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_NONE | CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_RIGHT,
        POSITION_PLAIN_LEFT_FOUR_FINGERS => CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_NONE | CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_LEFT,
        POSITION_PLAIN_THUMBS => CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_NONE | CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_THUMB,
        POSITION_UNKNOWN_PALM => CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_NONE,
        POSITION_RIGHT_FULL_PALM => CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_NONE | CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_RIGHT,
        // Divergence from JMRTD: JMRTD returns BIOMETRIC_SUBTYPE_NONE here, without the "right" bit that
        // every other right-hand position (and the left writer's palm, with "left") has.
        POSITION_RIGHT_WRITER_S_PALM => CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_NONE | CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_RIGHT,
        POSITION_LEFT_FULL_PALM => CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_NONE | CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_LEFT,
        POSITION_LEFT_WRITER_S_PALM => CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_NONE | CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_LEFT,
        POSITION_RIGHT_LOWER_PALM => CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_NONE | CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_RIGHT,
        POSITION_RIGHT_UPPER_PALM => CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_NONE | CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_RIGHT,
        POSITION_LEFT_LOWER_PALM => CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_NONE | CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_LEFT,
        POSITION_LEFT_UPPER_PALM => CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_NONE | CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_LEFT,
        POSITION_RIGHT_OTHER => CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_NONE | CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_RIGHT,
        POSITION_LEFT_OTHER => CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_NONE | CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_LEFT,
        POSITION_RIGHT_INTERDIGITAL => CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_NONE | CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_RIGHT,
        POSITION_RIGHT_THENAR => CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_NONE | CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_RIGHT,
        POSITION_RIGHT_HYPOTHENAR => CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_NONE | CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_RIGHT,
        POSITION_LEFT_INTERDIGITAL => CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_NONE | CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_LEFT,
        POSITION_LEFT_THENAR => CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_NONE | CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_LEFT,
        POSITION_LEFT_HYPOTHENAR => CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_NONE | CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_MASK_LEFT,
        _ => CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_NONE,
    };

    /* Minimal big-endian binary I/O helpers (this port has no shared DataInputStream/DataOutputStream
     * equivalent, so these mirror only what this record's fixed-width 14-byte header needs). */

    private static int ReadUnsignedByte(Stream inputStream)
    {
        int b = inputStream.ReadByte();
        if (b < 0)
        {
            throw new EndOfStreamException();
        }
        return b;
    }

    private static int ReadUnsignedShort(Stream inputStream)
    {
        int hi = ReadUnsignedByte(inputStream);
        int lo = ReadUnsignedByte(inputStream);
        return (hi << 8) | lo;
    }

    private static long ReadUInt32BigEndian(Stream inputStream)
    {
        long result = 0;
        for (int i = 0; i < 4; i++)
        {
            result = (result << 8) | (uint)ReadUnsignedByte(inputStream);
        }
        return result;
    }

    private static void WriteUnsignedShort(Stream outputStream, int value)
    {
        outputStream.WriteByte((byte)((value >> 8) & 0xFF));
        outputStream.WriteByte((byte)(value & 0xFF));
    }

    private static void WriteInt32BigEndian(Stream outputStream, int value)
    {
        outputStream.WriteByte((byte)((value >> 24) & 0xFF));
        outputStream.WriteByte((byte)((value >> 16) & 0xFF));
        outputStream.WriteByte((byte)((value >> 8) & 0xFF));
        outputStream.WriteByte((byte)(value & 0xFF));
    }
}
