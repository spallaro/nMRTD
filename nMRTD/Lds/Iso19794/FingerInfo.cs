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
/// Port of <c>org.jmrtd.lds.iso19794.FingerInfo</c>: fingerprint general record header and finger image
/// data blocks based on Section 7 and Table 2 of ISO/IEC FCD 19794-4 aka Annex F.
/// </summary>
public class FingerInfo : AbstractListInfo<FingerImageInfo>, BiometricDataBlock
{
    /// <summary>Format identifier 'F', 'I', 'R', 0x00. Specified in ISO/IEC 19794-4 Section 7.1, Table 2.</summary>
    private const int FORMAT_IDENTIFIER = 0x46495200;

    /// <summary>Version number '0', '1', '0', 0x00. Specified in ISO/IEC 19794-4 Section 7.1, Table 2.</summary>
    private const int VERSION_NUMBER = 0x30313000;

    /// <summary>Scale units points per inch.</summary>
    public const int SCALE_UNITS_PPI = 1;

    /// <summary>Scale units points per centimeter.</summary>
    public const int SCALE_UNITS_PPCM = 2;

    /// <summary>Image compression algorithm type as specified in Section 7.1.13 and Table 3 of ISO 19794-4.</summary>
    public const int COMPRESSION_UNCOMPRESSED_NO_BIT_PACKING = 0;

    /// <summary>Image compression algorithm type as specified in Section 7.1.13 and Table 3 of ISO 19794-4.</summary>
    public const int COMPRESSION_UNCOMPRESSED_BIT_PACKED = 1;

    /// <summary>Image compression algorithm type as specified in Section 7.1.13 and Table 3 of ISO 19794-4.</summary>
    public const int COMPRESSION_WSQ = 2;

    /// <summary>Image compression algorithm type as specified in Section 7.1.13 and Table 3 of ISO 19794-4.</summary>
    public const int COMPRESSION_JPEG = 3;

    /// <summary>Image compression algorithm type as specified in Section 7.1.13 and Table 3 of ISO 19794-4.</summary>
    public const int COMPRESSION_JPEG2000 = 4;

    /// <summary>Image compression algorithm type as specified in Section 7.1.13 and Table 3 of ISO 19794-4.</summary>
    public const int COMPRESSION_PNG = 5;

    private int _captureDeviceId;
    private int _acquisitionLevel;
    private int _scaleUnits;
    private int _scanResolutionHorizontal;
    private int _scanResolutionVertical;
    private int _imageResolutionHorizontal;
    private int _imageResolutionVertical;
    private int _depth;
    private int _compressionAlgorithm;

    private StandardBiometricHeader? _sbh;

    /// <summary>Constructs a finger info record.</summary>
    /// <param name="captureDeviceId">capture device identifier</param>
    /// <param name="acquisitionLevel">acquisition level</param>
    /// <param name="scaleUnits">scale units, one of <see cref="SCALE_UNITS_PPI"/>, <see cref="SCALE_UNITS_PPCM"/></param>
    /// <param name="scanResolutionHorizontal">horizontal scan resolution</param>
    /// <param name="scanResolutionVertical">vertical scan resolution</param>
    /// <param name="imageResolutionHorizontal">horizontal image resolution</param>
    /// <param name="imageResolutionVertical">vertical image resolution</param>
    /// <param name="depth">image depth</param>
    /// <param name="compressionAlgorithm">compression algorithm, see <see cref="GetCompressionAlgorithm"/> for valid values</param>
    /// <param name="fingerImageInfos">the image records</param>
    public FingerInfo(int captureDeviceId, int acquisitionLevel, int scaleUnits,
        int scanResolutionHorizontal, int scanResolutionVertical,
        int imageResolutionHorizontal, int imageResolutionVertical,
        int depth, int compressionAlgorithm,
        List<FingerImageInfo> fingerImageInfos)
        : this(null, captureDeviceId, acquisitionLevel, scaleUnits,
            scanResolutionHorizontal, scanResolutionVertical,
            imageResolutionHorizontal, imageResolutionVertical,
            depth, compressionAlgorithm, fingerImageInfos)
    {
    }

    /// <summary>Constructs a finger info record.</summary>
    /// <param name="sbh">standard biometric header to use</param>
    /// <param name="captureDeviceId">capture device identifier</param>
    /// <param name="acquisitionLevel">acquisition level</param>
    /// <param name="scaleUnits">scale units, one of <see cref="SCALE_UNITS_PPI"/>, <see cref="SCALE_UNITS_PPCM"/></param>
    /// <param name="scanResolutionHorizontal">horizontal scan resolution</param>
    /// <param name="scanResolutionVertical">vertical scan resolution</param>
    /// <param name="imageResolutionHorizontal">horizontal image resolution</param>
    /// <param name="imageResolutionVertical">vertical image resolution</param>
    /// <param name="depth">image depth</param>
    /// <param name="compressionAlgorithm">compression algorithm, see <see cref="GetCompressionAlgorithm"/> for valid values</param>
    /// <param name="fingerImageInfos">the image records</param>
    public FingerInfo(StandardBiometricHeader? sbh,
        int captureDeviceId, int acquisitionLevel, int scaleUnits,
        int scanResolutionHorizontal, int scanResolutionVertical,
        int imageResolutionHorizontal, int imageResolutionVertical,
        int depth, int compressionAlgorithm,
        List<FingerImageInfo> fingerImageInfos)
    {
        _sbh = sbh;
        _captureDeviceId = captureDeviceId;
        _acquisitionLevel = acquisitionLevel;
        _scaleUnits = scaleUnits;
        _scanResolutionHorizontal = scanResolutionHorizontal;
        _scanResolutionVertical = scanResolutionVertical;
        _imageResolutionHorizontal = imageResolutionHorizontal;
        _imageResolutionVertical = imageResolutionVertical;
        _depth = depth;
        _compressionAlgorithm = compressionAlgorithm;
        AddAll(fingerImageInfos);
    }

    /// <summary>Constructs a finger info record.</summary>
    /// <param name="inputStream">input stream</param>
    public FingerInfo(Stream inputStream)
        : this(null, inputStream)
    {
    }

    /// <summary>Constructs a finger info record.</summary>
    /// <param name="sbh">standard biometric header to use</param>
    /// <param name="inputStream">input stream</param>
    public FingerInfo(StandardBiometricHeader? sbh, Stream inputStream)
    {
        _sbh = sbh;
        ReadObject(inputStream);
    }

    /// <summary>
    /// Returns the capture device identifier as specified in Section 7.1.4 of ISO 19794-4. Only the
    /// low-order 12 bits are significant.
    /// </summary>
    public int GetCaptureDeviceId() => _captureDeviceId;

    /// <summary>
    /// Returns the image acquisition level as specified in Section 7.1.5 and Table 1 of ISO 19794-4.
    /// Valid settings are: 10 (125 ppi), 20 (250 ppi), 30 (500 ppi), 31 (500 ppi), 40 (1000 ppi), 41
    /// (1000 ppi).
    /// </summary>
    public int GetAcquisitionLevel() => _acquisitionLevel;

    /// <summary>
    /// Returns the units used to describe the scanning and resolution of the image. Either <c>PPI</c> or
    /// <c>PPCM</c>. As specified in Section 7.1.7 of ISO 19794-4.
    /// </summary>
    public int GetScaleUnits() => _scaleUnits;

    /// <summary>
    /// Returns the rounded scanning resolution used in the horizontal direction. As specified in
    /// Section 7.1.8 of ISO 19794-4. Depending on <see cref="GetScaleUnits"/> the result is either in
    /// PPI or PPCM.
    /// </summary>
    public int GetHorizontalScanningResolution() => _scanResolutionHorizontal;

    /// <summary>
    /// Returns the rounded scanning resolution used in the vertical direction. As specified in Section
    /// 7.1.9 of ISO 19794-4. Depending on <see cref="GetScaleUnits"/> the result is either in PPI or
    /// PPCM.
    /// </summary>
    public int GetVerticalScanningResolution() => _scanResolutionVertical;

    /// <summary>
    /// Returns the rounded image resolution used in the horizontal direction as specified in Section
    /// 7.1.10 of ISO 19794-4. Depending on <see cref="GetScaleUnits"/> the result is either in PPI or
    /// PPCM.
    /// </summary>
    public int GetHorizontalImageResolution() => _imageResolutionHorizontal;

    /// <summary>
    /// Returns the rounded image resolution used in the vertical direction as specified in Section
    /// 7.1.11 of ISO 19794-4. Depending on <see cref="GetScaleUnits"/> the result is either in PPI or
    /// PPCM.
    /// </summary>
    public int GetVerticalImageResolution() => _imageResolutionVertical;

    /// <summary>
    /// Returns the pixel depth. As specified in Section 7.1.12 of ISO 19794-4. Valid values are between
    /// <c>0x01</c> to <c>0x10</c>.
    /// </summary>
    public int GetDepth() => _depth;

    /// <summary>
    /// Returns the compression algorithm as specified in Section 7.1.13 of ISO 19794-4. One of
    /// <see cref="COMPRESSION_UNCOMPRESSED_BIT_PACKED"/>, <see cref="COMPRESSION_UNCOMPRESSED_NO_BIT_PACKING"/>,
    /// <see cref="COMPRESSION_JPEG"/>, <see cref="COMPRESSION_JPEG2000"/>, <see cref="COMPRESSION_PNG"/>,
    /// <see cref="COMPRESSION_WSQ"/>.
    /// </summary>
    public int GetCompressionAlgorithm() => _compressionAlgorithm;

    /// <summary>Reads a finger info from an input stream.</summary>
    public override void ReadObject(Stream inputStream)
    {
        /* General record header (32) according to Table 2 in Section 7.1 of ISO/IEC 19794-4. */

        int fir0 = ReadInt32BigEndian(inputStream); /* header (e.g. "FIR", 0x00) (4) */
        if (fir0 != FORMAT_IDENTIFIER)
        {
            throw new ArgumentException($"'FIR' marker expected! Found {fir0:x}");
        }

        int version = ReadInt32BigEndian(inputStream); /* version in ASCII (e.g. "010" 0x00) (4) */
        if (version != VERSION_NUMBER)
        {
            throw new ArgumentException($"'010' version number expected! Found {version:x}");
        }

        long recordLength = ReadUnsignedLong(inputStream, 6); // & 0xFFFFFFFFFFFFL;
        _captureDeviceId = ReadUnsignedShort(inputStream); /* all zeros means 'unreported', only lower 12-bits used, see 7.1.4 ISO/IEC 19794-4. */
        _acquisitionLevel = ReadUnsignedShort(inputStream);
        int count = ReadUnsignedByte(inputStream);
        _scaleUnits = ReadUnsignedByte(inputStream); /* 1 -> PPI, 2 -> PPCM */
        _scanResolutionHorizontal = ReadUnsignedShort(inputStream);
        _scanResolutionVertical = ReadUnsignedShort(inputStream);
        _imageResolutionHorizontal = ReadUnsignedShort(inputStream); /* should be <= scanResH */
        _imageResolutionVertical = ReadUnsignedShort(inputStream); /* should be <= scanResV */
        _depth = ReadUnsignedByte(inputStream); /* 1 - 16 bits, i.e. 2 - 65546 gray levels */
        _compressionAlgorithm = ReadUnsignedByte(inputStream); /* 0 Uncompressed, no bit packing
                                                                  * 1 Uncompressed, bit packed
                                                                  * 2 Compressed, WSQ
                                                                  * 3 Compressed, JPEG
                                                                  * 4 Compressed, JPEG2000
                                                                  * 5 PNG
                                                                  */
        _ = ReadUnsignedShort(inputStream); /* RFU, should be 0x0000 */

        const long headerLength = 4L + 4L + 6L + 2L + 2L + 1L + 1L + 2L + 2L + 2L + 2L + 1L + 1L + 2L;
        long dataLength = recordLength - headerLength;

        long constructedDataLength = 0L;

        for (int i = 0; i < count; i++)
        {
            var imageInfo = new FingerImageInfo(inputStream, _compressionAlgorithm);
            constructedDataLength += imageInfo.GetRecordLength();
            Add(imageInfo);
        }

        // NOTE: Java logs a warning here (dataLength != constructedDataLength mismatch); omitted per
        // precedent (see D:\GIT\nMRTD\src\nMRTD\Lds\Icao\DG11File.cs and porting-conventions.md).
        _ = dataLength;
        _ = constructedDataLength;
    }

    /// <summary>Writes this finger info to an output stream.</summary>
    public override void WriteObject(Stream outputStream)
    {
        const long headerLength = 32; /* 4 + 4 + 6 + 2 + 2 + 1 + 1 + 2 + 2 + 2 + 2 + 1 + 1 + 2 */

        long dataLength = 0;
        List<FingerImageInfo> fingerImageInfos = GetSubRecords();
        foreach (FingerImageInfo fingerImageInfo in fingerImageInfos)
        {
            dataLength += fingerImageInfo.GetRecordLength();
        }

        long recordLength = headerLength + dataLength;

        /* General record header, should be 32... */

        WriteInt32BigEndian(outputStream, FORMAT_IDENTIFIER); /* 4 */
        WriteInt32BigEndian(outputStream, VERSION_NUMBER);    /* + 4 = 8 */

        WriteLong(recordLength, outputStream, 6);              /* + 6 = 14 */

        WriteUnsignedShort(outputStream, _captureDeviceId);           /* + 2 = 16 */
        WriteUnsignedShort(outputStream, _acquisitionLevel);          /* + 2 = 18 */
        outputStream.WriteByte((byte)fingerImageInfos.Count);         /* + 1 = 19 */
        outputStream.WriteByte((byte)_scaleUnits);                    /* + 1 = 20 */
        WriteUnsignedShort(outputStream, _scanResolutionHorizontal);  /* + 2 = 22 */
        WriteUnsignedShort(outputStream, _scanResolutionVertical);    /* + 2 = 24 */
        WriteUnsignedShort(outputStream, _imageResolutionHorizontal); /* + 2 = 26 */
        WriteUnsignedShort(outputStream, _imageResolutionVertical);   /* + 2 = 28 */
        outputStream.WriteByte((byte)_depth);                         /* + 1 = 29 */

        outputStream.WriteByte((byte)_compressionAlgorithm);          /* + 1 = 30 */
        WriteUnsignedShort(outputStream, 0x0000); /* RFU */           /* + 2 = 32 */

        foreach (FingerImageInfo fingerImageInfo in fingerImageInfos)
        {
            fingerImageInfo.WriteFingerImageObject(outputStream);
        }
    }

    public override int GetHashCode()
    {
        const int prime = 31;
        int result = base.GetHashCode();
        result = (prime * result) + _acquisitionLevel;
        result = (prime * result) + _captureDeviceId;
        result = (prime * result) + _compressionAlgorithm;
        result = (prime * result) + _depth;
        result = (prime * result) + _imageResolutionHorizontal;
        result = (prime * result) + _imageResolutionVertical;
        result = (prime * result) + (_sbh == null ? 0 : _sbh.GetHashCode());
        result = (prime * result) + _scaleUnits;
        result = (prime * result) + _scanResolutionHorizontal;
        result = (prime * result) + _scanResolutionVertical;
        return result;
    }

    // NOTE: preserved Java quirk -- _sbh contributes to GetHashCode() above but is not compared in
    // Equals() below, an equals/hashCode contract asymmetry already present in the original JMRTD code
    // (two records differing only in sbh would hash differently yet still compare equal).
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

        var other = (FingerInfo)obj;
        return _acquisitionLevel == other._acquisitionLevel
            && _captureDeviceId == other._captureDeviceId
            && _compressionAlgorithm == other._compressionAlgorithm
            && _depth == other._depth
            && _imageResolutionHorizontal == other._imageResolutionHorizontal
            && _imageResolutionVertical == other._imageResolutionVertical
            && _scaleUnits == other._scaleUnits
            && _scanResolutionHorizontal == other._scanResolutionHorizontal
            && _scanResolutionVertical == other._scanResolutionVertical;
    }

    public override string ToString()
    {
        var result = new System.Text.StringBuilder();
        result.Append("FingerInfo [");
        List<FingerImageInfo> records = GetSubRecords();
        foreach (FingerImageInfo record in records)
        {
            result.Append(record.ToString());
        }
        result.Append(']');
        return result.ToString();
    }

    /// <summary>Returns the standard biometric header of this biometric data block.</summary>
    /// <returns>the standard biometric header</returns>
    public StandardBiometricHeader GetStandardBiometricHeader()
    {
        if (_sbh == null)
        {
            byte[] biometricType = [(byte)CBEFFBiometricTypes.BIOMETRIC_TYPE_FINGERPRINT];
            byte[] biometricSubtype = [(byte)GetBiometricSubtype()];
            byte[] formatOwner =
            [
                (byte)((StandardBiometricHeader.JTC1_SC37_FORMAT_OWNER_VALUE & 0xFF00) >> 8),
                (byte)(StandardBiometricHeader.JTC1_SC37_FORMAT_OWNER_VALUE & 0xFF),
            ];
            byte[] formatType =
            [
                (byte)((StandardBiometricHeader.ISO_19794_FINGER_IMAGE_FORMAT_TYPE_VALUE & 0xFF00) >> 8),
                (byte)(StandardBiometricHeader.ISO_19794_FINGER_IMAGE_FORMAT_TYPE_VALUE & 0xFF),
            ];

            var elements = new SortedDictionary<int, byte[]>
            {
                [ISO781611.BIOMETRIC_TYPE_TAG] = biometricType,
                [ISO781611.BIOMETRIC_SUBTYPE_TAG] = biometricSubtype,
                [ISO781611.FORMAT_OWNER_TAG] = formatOwner,
                [ISO781611.FORMAT_TYPE_TAG] = formatType,
            };

            _sbh = new StandardBiometricHeader(elements);
        }
        return _sbh;
    }

    /// <summary>Returns the finger image infos embedded in this finger info.</summary>
    /// <returns>the embedded finger image infos</returns>
    public List<FingerImageInfo> GetFingerImageInfos() => GetSubRecords();

    /// <summary>Adds a finger image info to this finger info.</summary>
    /// <param name="fingerImageInfo">the finger image info to add</param>
    public void AddFingerImageInfo(FingerImageInfo fingerImageInfo) => Add(fingerImageInfo);

    /// <summary>Removes a finger image info from this finger info.</summary>
    /// <param name="index">the index of the finger image info to remove</param>
    public void RemoveFingerImageInfo(int index) => Remove(index);

    /* ONLY PRIVATE BELOW */

    /// <summary>Returns the biometric sub-type bit mask for the fingers in this finger info.</summary>
    /// <returns>a biometric sub-type bit mask</returns>
    private int GetBiometricSubtype()
    {
        int result = CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_NONE;
        bool isFirst = true;
        List<FingerImageInfo> fingerImageInfos = GetSubRecords();
        foreach (FingerImageInfo fingerImageInfo in fingerImageInfos)
        {
            int fingerImageInfoSubType = fingerImageInfo.GetBiometricSubtype();
            if (isFirst)
            {
                result = fingerImageInfoSubType;
                isFirst = false;
            }
            else
            {
                result &= fingerImageInfoSubType;
            }
        }
        return result;
    }

    /// <summary>
    /// Converts an image data type code to a mime-type. Compression algorithm codes based on Table 3 in
    /// Section 7.1.13 of 19794-4.
    /// <para>
    /// 0 Uncompressed, no bit packing; 1 Uncompressed, bit packed; 2 Compressed, WSQ; 3 Compressed,
    /// JPEG; 4 Compressed, JPEG2000; 5 PNG.
    /// </para>
    /// </summary>
    /// <param name="imageDataType">an image data type constant, one of <see cref="COMPRESSION_UNCOMPRESSED_NO_BIT_PACKING"/>,
    /// <see cref="COMPRESSION_UNCOMPRESSED_BIT_PACKED"/>, <see cref="COMPRESSION_WSQ"/>, <see cref="COMPRESSION_JPEG"/>,
    /// <see cref="COMPRESSION_JPEG2000"/>, or <see cref="COMPRESSION_PNG"/></param>
    /// <returns>a mime-type string</returns>
    /// <remarks>
    /// Java package-private (called cross-class from <see cref="FingerImageInfo"/>, same package there);
    /// <c>internal</c> is the closest C# equivalent since C#'s <c>protected</c>/no-modifier access rules
    /// differ from Java's (see <see cref="FingerImageInfo.WriteFingerImageObject"/> for the same
    /// same-package-access gap on the write side).
    /// </remarks>
    internal static string? ToMimeType(int imageDataType) => imageDataType switch
    {
        COMPRESSION_UNCOMPRESSED_NO_BIT_PACKING => "image/raw",
        COMPRESSION_UNCOMPRESSED_BIT_PACKED => "image/raw",
        COMPRESSION_WSQ => "image/x-wsq",
        COMPRESSION_JPEG => "image/jpeg",
        COMPRESSION_JPEG2000 => "image/jpeg2000",
        COMPRESSION_PNG => "image/png",
        _ => null,
    };

    /// <summary>Converts a mime-type to an image data (compression) type.</summary>
    /// <param name="mimeType">the mime-type to convert</param>
    /// <returns>the image data (compression) type</returns>
    internal static int FromMimeType(string mimeType)
    {
        if ("image/x-wsq".Equals(mimeType, StringComparison.Ordinal))
        {
            return COMPRESSION_WSQ;
        }
        if ("image/jpeg".Equals(mimeType, StringComparison.Ordinal))
        {
            return COMPRESSION_JPEG;
        }
        if ("image/jpeg2000".Equals(mimeType, StringComparison.Ordinal))
        {
            return COMPRESSION_JPEG2000;
        }

        // NOTE: preserved Java quirk -- the original compares against "images/png" (extra 's'), not
        // "image/png", so this branch can never match a correctly-formed PNG mime-type and
        // FromMimeType("image/png") always falls through to the exception below, same as upstream JMRTD.
        if ("images/png".Equals(mimeType, StringComparison.Ordinal))
        {
            return COMPRESSION_PNG;
        }

        throw new ArgumentException("Did not recognize mimeType");
    }

    /// <summary>Reads a long from a stream.</summary>
    /// <param name="inputStream">the stream to read from</param>
    /// <param name="byteCount">the number of bytes to read</param>
    /// <returns>the resulting long</returns>
    private static long ReadUnsignedLong(Stream inputStream, int byteCount)
    {
        byte[] buffer = new byte[byteCount];
        ReadFully(inputStream, buffer);
        long result = 0L;
        for (int i = 0; i < byteCount; i++)
        {
            result <<= 8;
            result += buffer[i];
        }
        return result;
    }

    /// <summary>Writes a long to a stream.</summary>
    /// <param name="value">the long value to write</param>
    /// <param name="outputStream">the stream to write to</param>
    /// <param name="byteCount">the number of bytes to use</param>
    private static void WriteLong(long value, Stream outputStream, int byteCount)
    {
        if (byteCount <= 0)
        {
            return;
        }

        for (int i = 0; i < byteCount - 8; i++)
        {
            outputStream.WriteByte(0);
        }
        if (byteCount > 8)
        {
            byteCount = 8;
        }
        for (int i = byteCount - 1; i >= 0; i--)
        {
            long mask = 0xFFL << (i * 8);
            byte b = (byte)((value & mask) >> (i * 8));
            outputStream.WriteByte(b);
        }
    }

    /* Minimal big-endian binary I/O helpers (this port has no shared DataInputStream/DataOutputStream
     * equivalent; see also the smaller sibling set in FingerImageInfo.cs). */

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

    private static int ReadInt32BigEndian(Stream inputStream)
    {
        int result = 0;
        for (int i = 0; i < 4; i++)
        {
            result = (result << 8) | ReadUnsignedByte(inputStream);
        }
        return result;
    }

    private static void ReadFully(Stream inputStream, byte[] buffer)
    {
        int totalRead = 0;
        while (totalRead < buffer.Length)
        {
            int read = inputStream.Read(buffer, totalRead, buffer.Length - totalRead);
            if (read <= 0)
            {
                throw new EndOfStreamException();
            }
            totalRead += read;
        }
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
