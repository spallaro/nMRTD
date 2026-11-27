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

namespace nMRTD.Lds.Iso19794;

/// <summary>
/// Port of <c>org.jmrtd.lds.iso19794.IrisInfo</c>: iris record header and biometric subtype blocks
/// based on Section 6.5.3 and Table 2 of ISO/IEC 19794-6 2005.
///
/// TODO: proper enums for fields (matches upstream JMRTD TODO).
/// </summary>
public class IrisInfo : AbstractListInfo<IrisBiometricSubtypeInfo>, BiometricDataBlock
{
    /// <summary>Format identifier 'I', 'I', 'R', 0x00.</summary>
    private const int FORMAT_IDENTIFIER = 0x49495200;

    /// <summary>Version number.</summary>
    private const int VERSION_NUMBER = 0x30313000;

    /// <summary>Image format.</summary>
    public const int IMAGEFORMAT_MONO_RAW = 2; /* (0x0002) */

    /// <summary>Image format.</summary>
    public const int IMAGEFORMAT_RGB_RAW = 4; /* (0x0004) */

    /// <summary>Image format.</summary>
    public const int IMAGEFORMAT_MONO_JPEG = 6; /* (0x0006) */

    /// <summary>Image format.</summary>
    public const int IMAGEFORMAT_RGB_JPEG = 8; /* (0x0008) */

    /// <summary>Image format.</summary>
    public const int IMAGEFORMAT_MONO_JPEG_LS = 10; /* (0x000A) */

    /// <summary>Image format.</summary>
    public const int IMAGEFORMAT_RGB_JPEG_LS = 12; /* (0x000C) */

    /// <summary>Image format.</summary>
    public const int IMAGEFORMAT_MONO_JPEG2000 = 14; /* (0x000E) */

    /// <summary>Image format.</summary>
    public const int IMAGEFORMAT_RGB_JPEG2000 = 16; /* (0x0010) */

    /// <summary>Constant for capture device Id, based on Table 2 in Section 5.5 in ISO 19794-6.</summary>
    public const int CAPTURE_DEVICE_UNDEF = 0;

    /// <summary>Constant for horizontal and vertical orientation, based on Table 2 in Section 5.5 in ISO 19794-6.</summary>
    public const int ORIENTATION_UNDEF = 0;

    /// <summary>Constant for horizontal and vertical orientation, based on Table 2 in Section 5.5 in ISO 19794-6.</summary>
    public const int ORIENTATION_BASE = 1;

    /// <summary>Constant for horizontal and vertical orientation, based on Table 2 in Section 5.5 in ISO 19794-6.</summary>
    public const int ORIENTATION_FLIPPED = 2;

    /// <summary>Scan type (rectilinear only), based on Table 2 in Section 5.5 in ISO 19794-6.</summary>
    public const int SCAN_TYPE_UNDEF = 0;

    /// <summary>Scan type (rectilinear only), based on Table 2 in Section 5.5 in ISO 19794-6.</summary>
    public const int SCAN_TYPE_PROGRESSIVE = 1;

    /// <summary>Scan type (rectilinear only), based on Table 2 in Section 5.5 in ISO 19794-6.</summary>
    public const int SCAN_TYPE_INTERLACE_FRAME = 2;

    /// <summary>Scan type (rectilinear only), based on Table 2 in Section 5.5 in ISO 19794-6.</summary>
    public const int SCAN_TYPE_INTERLACE_FIELD = 3;

    /// <summary>Scan type (rectilinear only), based on Table 2 in Section 5.5 in ISO 19794-6.</summary>
    public const int SCAN_TYPE_CORRECTED = 4;

    /// <summary>Iris occlusion (polar only), based on Table 2 in Section 5.5 in ISO 19794-6.</summary>
    public const int IROCC_UNDEF = 0;

    /// <summary>Iris occlusion (polar only), based on Table 2 in Section 5.5 in ISO 19794-6.</summary>
    public const int IROCC_PROCESSED = 1;

    /// <summary>Iris occlusion filling (polar only), based on Table 2 in Section 5.5 in ISO 19794-6.</summary>
    public const int IROCC_ZEROFILL = 0;

    /// <summary>Iris occlusion filling (polar only), based on Table 2 in Section 5.5 in ISO 19794-6. Name
    /// kept identical to the upstream JMRTD constant (missing the second 'C' in "IROCC") for cross-reference
    /// traceability -- not "fixed" to <c>IROCC_UNITFILL</c>.</summary>
    public const int IROC_UNITFILL = 1;

    /* TODO: reference to specification (matches upstream JMRTD TODO). */
    public const int INTENSITY_DEPTH_UNDEF = 0;

    /* TODO: reference to specification (matches upstream JMRTD TODO). */
    public const int TRANS_UNDEF = 0;
    public const int TRANS_STD = 1;

    /* TODO: reference to specification (matches upstream JMRTD TODO). */
    public const int IRBNDY_UNDEF = 0;
    public const int IRBNDY_PROCESSED = 1;

    private long _recordLength;

    /* 16 bit */
    private int _captureDeviceId;

    private int _horizontalOrientation;
    private int _verticalOrientation;
    private int _scanType;
    private int _irisOcclusion;
    private int _occlusionFilling;
    private int _boundaryExtraction;

    private int _irisDiameter;
    private int _imageFormat;
    private int _rawImageWidth;
    private int _rawImageHeight;
    private int _intensityDepth;
    private int _imageTransformation;

    /*
     * Length 16, starts with 'D' (serial), 'M' (MAC address) or 'P' (processor Id),
     * or all zeroes (indicating no serial number).
     */
    private byte[] _deviceUniqueId = null!;

    private StandardBiometricHeader? _sbh;

    /// <summary>Constructs a new iris info object.</summary>
    /// <param name="captureDeviceId">capture device identifier assigned by vendor</param>
    /// <param name="horizontalOrientation">horizontal orientation: <see cref="ORIENTATION_UNDEF"/>, <see cref="ORIENTATION_BASE"/>, or <see cref="ORIENTATION_FLIPPED"/></param>
    /// <param name="verticalOrientation">vertical orientation: <see cref="ORIENTATION_UNDEF"/>, <see cref="ORIENTATION_BASE"/>, or <see cref="ORIENTATION_FLIPPED"/></param>
    /// <param name="scanType">scan type</param>
    /// <param name="irisOcclusion">iris occlusion (polar only)</param>
    /// <param name="occlusionFilling">occlusion filling (polar only)</param>
    /// <param name="boundaryExtraction">boundary extraction (polar only)</param>
    /// <param name="irisDiameter">expected iris diameter in pixels (rectilinear only)</param>
    /// <param name="imageFormat">image format of data blob (JPEG, raw, etc.)</param>
    /// <param name="rawImageWidth">raw image width, pixels</param>
    /// <param name="rawImageHeight">raw image height, pixels</param>
    /// <param name="intensityDepth">intensity depth, bits, per color</param>
    /// <param name="imageTransformation">transformation to polar image (polar only)</param>
    /// <param name="deviceUniqueId">a 16 character string uniquely identifying the device or source of that data</param>
    /// <param name="irisBiometricSubtypeInfos">the iris biometric subtype records</param>
    public IrisInfo(int captureDeviceId, int horizontalOrientation, int verticalOrientation,
        int scanType, int irisOcclusion, int occlusionFilling,
        int boundaryExtraction, int irisDiameter, int imageFormat,
        int rawImageWidth, int rawImageHeight, int intensityDepth, int imageTransformation,
        byte[]? deviceUniqueId,
        List<IrisBiometricSubtypeInfo>? irisBiometricSubtypeInfos)
        : this(null, captureDeviceId, horizontalOrientation, verticalOrientation,
            scanType, irisOcclusion, occlusionFilling,
            boundaryExtraction, irisDiameter, imageFormat,
            rawImageWidth, rawImageHeight, intensityDepth, imageTransformation,
            deviceUniqueId, irisBiometricSubtypeInfos)
    {
    }

    /// <summary>Constructs a new iris info object.</summary>
    /// <param name="sbh">standard biometric header to use</param>
    /// <param name="captureDeviceId">capture device identifier assigned by vendor</param>
    /// <param name="horizontalOrientation">horizontal orientation: <see cref="ORIENTATION_UNDEF"/>, <see cref="ORIENTATION_BASE"/>, or <see cref="ORIENTATION_FLIPPED"/></param>
    /// <param name="verticalOrientation">vertical orientation: <see cref="ORIENTATION_UNDEF"/>, <see cref="ORIENTATION_BASE"/>, or <see cref="ORIENTATION_FLIPPED"/></param>
    /// <param name="scanType">scan type</param>
    /// <param name="irisOcclusion">iris occlusion (polar only)</param>
    /// <param name="occlusionFilling">occlusion filling (polar only)</param>
    /// <param name="boundaryExtraction">boundary extraction (polar only)</param>
    /// <param name="irisDiameter">expected iris diameter in pixels (rectilinear only)</param>
    /// <param name="imageFormat">image format of data blob (JPEG, raw, etc.)</param>
    /// <param name="rawImageWidth">raw image width, pixels</param>
    /// <param name="rawImageHeight">raw image height, pixels</param>
    /// <param name="intensityDepth">intensity depth, bits, per color</param>
    /// <param name="imageTransformation">transformation to polar image (polar only)</param>
    /// <param name="deviceUniqueId">a 16 character string uniquely identifying the device or source of that data</param>
    /// <param name="irisBiometricSubtypeInfos">the iris biometric subtype records</param>
    public IrisInfo(StandardBiometricHeader? sbh,
        int captureDeviceId, int horizontalOrientation, int verticalOrientation,
        int scanType, int irisOcclusion, int occlusionFilling,
        int boundaryExtraction, int irisDiameter, int imageFormat,
        int rawImageWidth, int rawImageHeight, int intensityDepth, int imageTransformation,
        byte[]? deviceUniqueId,
        List<IrisBiometricSubtypeInfo>? irisBiometricSubtypeInfos)
    {
        _sbh = sbh;
        if (irisBiometricSubtypeInfos == null)
        {
            throw new ArgumentException("Null irisBiometricSubtypeInfos");
        }

        _captureDeviceId = captureDeviceId;
        _horizontalOrientation = horizontalOrientation;
        _verticalOrientation = verticalOrientation;
        _scanType = scanType;
        _irisOcclusion = irisOcclusion;
        _occlusionFilling = occlusionFilling;
        _boundaryExtraction = boundaryExtraction;
        _irisDiameter = irisDiameter;
        _imageFormat = imageFormat;
        _rawImageWidth = rawImageWidth;
        _rawImageHeight = rawImageHeight;
        _intensityDepth = intensityDepth;
        _imageTransformation = imageTransformation;

        long headerLength = 45;
        long dataLength = 0;
        foreach (IrisBiometricSubtypeInfo irisBiometricSubtypeInfo in irisBiometricSubtypeInfos)
        {
            dataLength += irisBiometricSubtypeInfo.GetRecordLength();
            Add(irisBiometricSubtypeInfo);
        }

        if (deviceUniqueId == null || deviceUniqueId.Length != 16)
        {
            throw new ArgumentException("deviceUniqueId invalid");
        }

        _deviceUniqueId = new byte[16];
        Array.Copy(deviceUniqueId, 0, _deviceUniqueId, 0, deviceUniqueId.Length);
        _recordLength = headerLength + dataLength;
    }

    /// <summary>Constructs an iris info from binary encoding.</summary>
    /// <param name="inputStream">an input stream</param>
    public IrisInfo(Stream inputStream)
        : this(null, inputStream)
    {
    }

    /// <summary>Constructs an iris info from binary encoding.</summary>
    /// <param name="sbh">standard biometric header to use</param>
    /// <param name="inputStream">an input stream</param>
    public IrisInfo(StandardBiometricHeader? sbh, Stream inputStream)
    {
        _sbh = sbh;
        ReadObject(inputStream);
    }

    /// <summary>Reads this iris info from an input stream.</summary>
    public override void ReadObject(Stream inputStream)
    {
        /* Iris Record Header (45) */

        int iir0 = ReadInt(inputStream); /* format id (e.g. "IIR" 0x00) */                /* 4 */
        if (iir0 != FORMAT_IDENTIFIER)
        {
            throw new ArgumentException($"'IIR' marker expected! Found {iir0:x}");
        }

        int version = ReadInt(inputStream); /* version (e.g. "010" 0x00) */               /* + 4 = 8 */
        if (version != VERSION_NUMBER)
        {
            throw new ArgumentException($"'010' version number expected! Found {version:x}");
        }

        // NOTE: preserved Java quirk -- upstream's own trailing comment ("& 0x00000000FFFFFFFFL", now
        // removed here) suggests masking to an unsigned 32-bit value, but the mask itself is commented
        // out there, so this sign-extends the 32-bit read into the 64-bit field if the top bit is set --
        // unlike IrisImageInfo's imageLength field, which does apply the equivalent mask.
        _recordLength = ReadInt(inputStream);                                              /* + 4 = 12 */
        long headerLength = 45;
        long dataLength = _recordLength - headerLength;

        _captureDeviceId = ReadUnsignedShort(inputStream);                                 /* + 2 = 14 */
        int count = ReadUnsignedByte(inputStream);                                         /* + 1 = 15 */

        int recordHeaderLength = ReadUnsignedShort(inputStream); /* Should be 45. */       /* + 2 = 17 */
        if (recordHeaderLength != headerLength)
        {
            throw new ArgumentException($"Expected header length {headerLength}, found {recordHeaderLength}");
        }

        /*
         *  16 15 14 13 12 11 10  9  8  7  6  5  4  3  2  1
         * [  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  ]
         *                                             1  1  = 0x0003 horizontalOrientation (>> 0)
         *                                       1  1  0  0  = 0x000C verticalOrientation (>> 2)
         *                              1  1  1  0  0  0  0  = 0x0070 scanType (>> 4)
         *                           1  0  0  0  0  0  0  0  = 0x0080 irisOcclusion (>> 7)
         *                        1  0  0  0  0  0  0  0  0  = 0x0100 occlusionFilling (>> 8)
         *                     1  0  0  0  0  0  0  0  0  0  = 0x0200 boundaryExtraction (>> 9)
         */
        int imagePropertiesBits = ReadUnsignedShort(inputStream);                          /* + 2 = 19 */
        _horizontalOrientation = imagePropertiesBits & 0x0003;
        _verticalOrientation = (imagePropertiesBits & 0x00C) >> 2;
        _scanType = (imagePropertiesBits & 0x0070) >> 4;
        _irisOcclusion = (imagePropertiesBits & 0x0080) >> 7;
        _occlusionFilling = (imagePropertiesBits & 0x0100) >> 8;
        _boundaryExtraction = (imagePropertiesBits & 0x0200) >> 9;

        _irisDiameter = ReadUnsignedShort(inputStream);                                    /* + 2 = 21 */
        _imageFormat = ReadUnsignedShort(inputStream);                                     /* + 2 = 23 */
        _rawImageWidth = ReadUnsignedShort(inputStream);                                   /* + 2 = 25 */
        _rawImageHeight = ReadUnsignedShort(inputStream);                                  /* + 2 = 27 */
        _intensityDepth = ReadUnsignedByte(inputStream);                                   /* + 1 = 28 */
        _imageTransformation = ReadUnsignedByte(inputStream);                              /* + 1 = 29 */

        /*
         * A 16 character string uniquely identifying the
         * device or source of the data. This data can be
         * one of:
         * Device Serial number, identified by the first character "D"
         * Host PC Mac address, identified by the first character "M"
         * Host PC processor ID, identified by the first character "P"
         * No serial number, identified by all zeros
         */
        _deviceUniqueId = new byte[16];                                                    /* + 16 = 45 */
        ReadFully(inputStream, _deviceUniqueId);

        long constructedDataLength = 0L;

        /* A record contains biometric subtype (or: 'feature') blocks (which contain image data blocks)... */
        for (int i = 0; i < count; i++)
        {
            var biometricSubtypeInfo = new IrisBiometricSubtypeInfo(inputStream, _imageFormat);
            constructedDataLength += biometricSubtypeInfo.GetRecordLength();
            Add(biometricSubtypeInfo);
        }

        if (dataLength != constructedDataLength)
        {
            /* NOTE: Java logs a warning here; omitted per precedent. */
        }
    }

    /// <summary>Writes this iris info to an output stream.</summary>
    public override void WriteObject(Stream outputStream)
    {
        int headerLength = 45;

        int dataLength = 0;
        List<IrisBiometricSubtypeInfo> biometricSubtypeInfos = GetSubRecords();
        foreach (IrisBiometricSubtypeInfo biometricSubtypeInfo in biometricSubtypeInfos)
        {
            /* NOTE: preserved Java quirk -- compound assignment narrows GetRecordLength()'s long result
             * back to int, mirroring upstream's `dataLength += biometricSubtypeInfo.getRecordLength()`
             * with `int dataLength`. */
            dataLength += (int)biometricSubtypeInfo.GetRecordLength();
        }

        /* NOTE: preserved Java quirk -- this local shadows/replaces the this.recordLength field entirely:
         * WriteObject always recomputes the record length fresh from the current sub-records rather than
         * writing back whatever was read into (or passed into) the recordLength field. So the field is
         * effectively write-only for hashCode/equals purposes and never round-trips through Write. */
        int recordLength = headerLength + dataLength;

        /* Iris Record Header (45) */

        WriteInt(outputStream, FORMAT_IDENTIFIER); /* header (e.g. "IIR", 0x00) */          /* 4 */
        WriteInt(outputStream, VERSION_NUMBER); /* version in ASCII (e.g. "010" 0x00) */    /* + 4 = 8 */

        WriteInt(outputStream, recordLength); /* NOTE: bytes 9-12, i.e. 4 bytes, despite "unsigned long" in ISO/IEC FCD 19749-6. */ /* + 4 = 12 */

        WriteShort(outputStream, _captureDeviceId);                                        /* + 2 = 14 */

        WriteByte(outputStream, biometricSubtypeInfos.Count);                              /* + 1 = 15 */
        WriteShort(outputStream, headerLength);                                            /* + 2 = 17 */

        int imagePropertiesBits = 0;
        imagePropertiesBits |= _horizontalOrientation & 0x0003;
        imagePropertiesBits |= (_verticalOrientation << 2) & 0x00C;
        imagePropertiesBits |= (_scanType << 4) & 0x0070;
        imagePropertiesBits |= (_irisOcclusion << 7) & 0x0080;
        imagePropertiesBits |= (_occlusionFilling << 8) & 0x0100;
        imagePropertiesBits |= (_boundaryExtraction << 9) & 0x0200;
        WriteShort(outputStream, imagePropertiesBits);                                     /* + 2 = 19 */

        WriteShort(outputStream, _irisDiameter);                                           /* + 2 = 21 */
        WriteShort(outputStream, _imageFormat);                                            /* + 2 = 23 */
        WriteShort(outputStream, _rawImageWidth);                                          /* + 2 = 25 */
        WriteShort(outputStream, _rawImageHeight);                                         /* + 2 = 27 */
        WriteByte(outputStream, _intensityDepth);                                          /* + 1 = 28 */
        WriteByte(outputStream, _imageTransformation);                                     /* + 1 = 29 */
        outputStream.Write(_deviceUniqueId, 0, _deviceUniqueId.Length); /* array of length 16 */ /* + 16 = 45 */

        foreach (IrisBiometricSubtypeInfo biometricSubtypeInfo in biometricSubtypeInfos)
        {
            biometricSubtypeInfo.WriteObject(outputStream);
        }
    }

    /// <summary>Returns the capture device identifier.</summary>
    public int GetCaptureDeviceId() => _captureDeviceId;

    /// <summary>Returns the horizontal orientation, one of <see cref="ORIENTATION_UNDEF"/>, <see cref="ORIENTATION_BASE"/>, or <see cref="ORIENTATION_FLIPPED"/>.</summary>
    public int GetHorizontalOrientation() => _horizontalOrientation;

    /// <summary>Returns the vertical orientation, one of <see cref="ORIENTATION_UNDEF"/>, <see cref="ORIENTATION_BASE"/>, or <see cref="ORIENTATION_FLIPPED"/>.</summary>
    public int GetVerticalOrientation() => _verticalOrientation;

    /// <summary>
    /// Returns the scan type. One of <see cref="SCAN_TYPE_UNDEF"/>, <see cref="SCAN_TYPE_PROGRESSIVE"/>,
    /// <see cref="SCAN_TYPE_INTERLACE_FRAME"/>, <see cref="SCAN_TYPE_INTERLACE_FIELD"/>, or
    /// <see cref="SCAN_TYPE_CORRECTED"/>.
    /// </summary>
    public int GetScanType() => _scanType;

    /// <summary>Returns the iris occlusion.</summary>
    public int GetIrisOcclusion() => _irisOcclusion;

    /// <summary>Returns the iris occlusion filling.</summary>
    public int GetOcclusionFilling() => _occlusionFilling;

    /// <summary>Returns the boundary extraction.</summary>
    public int GetBoundaryExtraction() => _boundaryExtraction;

    /// <summary>Returns the iris diameter.</summary>
    public int GetIrisDiameter() => _irisDiameter;

    /// <summary>Returns the image format.</summary>
    public int GetImageFormat() => _imageFormat;

    /// <summary>Returns the raw image width.</summary>
    public int GetRawImageWidth() => _rawImageWidth;

    /// <summary>Returns the raw image height.</summary>
    public int GetRawImageHeight() => _rawImageHeight;

    /// <summary>Returns the intensity depth.</summary>
    public int GetIntensityDepth() => _intensityDepth;

    /// <summary>Returns the image transformation.</summary>
    public int GetImageTransformation() => _imageTransformation;

    /// <summary>Returns the device unique id.</summary>
    public byte[] GetDeviceUniqueId() => _deviceUniqueId;

    /// <summary>Returns the standard biometric header of this iris info.</summary>
    public StandardBiometricHeader GetStandardBiometricHeader()
    {
        if (_sbh == null)
        {
            /* NOTE: preserved Java quirk -- upstream uses CBEFFBiometricTypes.BIOMETRIC_TYPE_FINGERPRINT here
             * instead of CBEFFBiometricTypes.BIOMETRIC_TYPE_IRIS, so a generated (not caller-supplied) SBH for an
             * iris record is mislabeled as a fingerprint record's biometric type. */
            byte[] biometricType = { (byte)CBEFFBiometricTypes.BIOMETRIC_TYPE_FINGERPRINT };
            byte[] biometricSubtype = { (byte)GetBiometricSubtype() };
            byte[] formatOwner =
            {
                (byte)((StandardBiometricHeader.JTC1_SC37_FORMAT_OWNER_VALUE & 0xFF00) >> 8),
                (byte)(StandardBiometricHeader.JTC1_SC37_FORMAT_OWNER_VALUE & 0xFF),
            };
            byte[] formatType =
            {
                (byte)((StandardBiometricHeader.ISO_19794_IRIS_IMAGE_FORMAT_TYPE_VALUE & 0xFF00) >> 8),
                (byte)(StandardBiometricHeader.ISO_19794_IRIS_IMAGE_FORMAT_TYPE_VALUE & 0xFF),
            };

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

    public override int GetHashCode()
    {
        const int prime = 31;
        int result = base.GetHashCode();
        result = (prime * result) + _boundaryExtraction;
        result = (prime * result) + _captureDeviceId;
        result = (prime * result) + JavaArrayHashCode(_deviceUniqueId);
        result = (prime * result) + _horizontalOrientation;
        result = (prime * result) + _imageFormat;
        result = (prime * result) + _imageTransformation;
        result = (prime * result) + _intensityDepth;
        result = (prime * result) + _irisDiameter;
        result = (prime * result) + _irisOcclusion;
        result = (prime * result) + _occlusionFilling;
        result = (prime * result) + _rawImageHeight;
        result = (prime * result) + _rawImageWidth;
        result = (prime * result) + (int)(_recordLength ^ (_recordLength >>> 32));
        result = (prime * result) + (_sbh == null ? 0 : _sbh.GetHashCode());
        result = (prime * result) + _scanType;
        result = (prime * result) + _verticalOrientation;
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

        var other = (IrisInfo)obj;
        if (_sbh == null)
        {
            if (other._sbh != null)
            {
                return false;
            }
        }
        else if (!_sbh.Equals(other._sbh))
        {
            return false;
        }
        if (_boundaryExtraction != other._boundaryExtraction)
        {
            return false;
        }
        if (_captureDeviceId != other._captureDeviceId)
        {
            return false;
        }
        if (!_deviceUniqueId.AsSpan().SequenceEqual(other._deviceUniqueId))
        {
            return false;
        }
        if (_horizontalOrientation != other._horizontalOrientation)
        {
            return false;
        }
        if (_imageFormat != other._imageFormat)
        {
            return false;
        }
        if (_imageTransformation != other._imageTransformation)
        {
            return false;
        }
        if (_intensityDepth != other._intensityDepth)
        {
            return false;
        }
        if (_irisDiameter != other._irisDiameter)
        {
            return false;
        }
        if (_irisOcclusion != other._irisOcclusion)
        {
            return false;
        }
        if (_occlusionFilling != other._occlusionFilling)
        {
            return false;
        }
        if (_rawImageHeight != other._rawImageHeight)
        {
            return false;
        }
        if (_rawImageWidth != other._rawImageWidth)
        {
            return false;
        }
        if (_recordLength != other._recordLength)
        {
            return false;
        }
        if (_scanType != other._scanType)
        {
            return false;
        }
        if (_verticalOrientation != other._verticalOrientation)
        {
            return false;
        }
        return true;
    }

    /// <summary>Generates a textual representation of this object.</summary>
    public override string ToString()
    {
        var result = new System.Text.StringBuilder();
        result.Append("IrisInfo [");
        // TODO: contents (matches upstream JMRTD TODO -- toString() is unimplemented there too).
        result.Append(']');
        return result.ToString();
    }

    /// <summary>Returns the iris biometric subtype infos embedded in this iris info.</summary>
    public List<IrisBiometricSubtypeInfo> GetIrisBiometricSubtypeInfos() => GetSubRecords();

    /// <summary>Adds an iris biometric subtype info to this iris info.</summary>
    public void AddIrisBiometricSubtypeInfo(IrisBiometricSubtypeInfo irisBiometricSubtypeInfo) => Add(irisBiometricSubtypeInfo);

    /// <summary>Removes an iris biometric subtype info from this iris info.</summary>
    public void RemoveIrisBiometricSubtypeInfo(int index) => Remove(index);

    /* ONLY PRIVATE METHODS BELOW */

    /// <summary>Returns a bit-mask for the biometric sub-types found in this iris info.</summary>
    private int GetBiometricSubtype()
    {
        /* NOTE: preserved Java quirk -- starts from BIOMETRIC_SUBTYPE_NONE (0x00) and folds in each
         * sub-record's biometric subtype with bitwise AND (&=). Since 0 AND anything is always 0, this
         * unconditionally returns 0 regardless of the actual subtypes present; it reads like a bug (an
         * OR-based bitmask accumulation was presumably intended) but is preserved verbatim. */
        int result = CBEFFBiometricTypes.BIOMETRIC_SUBTYPE_NONE;
        List<IrisBiometricSubtypeInfo> irisBiometricSubtypeInfos = GetSubRecords();
        foreach (IrisBiometricSubtypeInfo irisBiometricSubtypeInfo in irisBiometricSubtypeInfos)
        {
            result &= irisBiometricSubtypeInfo.GetBiometricSubtype();
        }
        return result;
    }

    /// <summary>
    /// Replicates <c>java.util.Arrays.hashCode(byte[])</c>'s exact algorithm (Java's <c>byte</c> is
    /// signed, so each element is sign-extended before folding into the running hash).
    /// </summary>
    private static int JavaArrayHashCode(byte[] array)
    {
        int result = 1;
        foreach (byte b in array)
        {
            result = (31 * result) + (sbyte)b;
        }
        return result;
    }

    private static int ReadUnsignedByte(Stream inputStream)
    {
        int b = inputStream.ReadByte();
        if (b < 0)
        {
            throw new EndOfStreamException("Unexpected end of stream while reading iris info.");
        }
        return b;
    }

    private static int ReadUnsignedShort(Stream inputStream)
    {
        int b1 = ReadUnsignedByte(inputStream);
        int b2 = ReadUnsignedByte(inputStream);
        return (b1 << 8) | b2;
    }

    private static int ReadInt(Stream inputStream)
    {
        int b1 = ReadUnsignedByte(inputStream);
        int b2 = ReadUnsignedByte(inputStream);
        int b3 = ReadUnsignedByte(inputStream);
        int b4 = ReadUnsignedByte(inputStream);
        return (b1 << 24) | (b2 << 16) | (b3 << 8) | b4;
    }

    private static void ReadFully(Stream inputStream, byte[] buffer)
    {
        int totalRead = 0;
        while (totalRead < buffer.Length)
        {
            int read = inputStream.Read(buffer, totalRead, buffer.Length - totalRead);
            if (read <= 0)
            {
                throw new EndOfStreamException("Unexpected end of stream while reading iris info.");
            }
            totalRead += read;
        }
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
