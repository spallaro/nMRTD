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
using nMRTD.SmartCards;

namespace nMRTD.Lds.Iso19794;

/// <summary>
/// Port of <c>org.jmrtd.lds.iso19794.FaceInfo</c>: a facial record consists of a facial record header
/// and one or more facial record datas. See 5.1 of ISO 19794-5.
/// </summary>
public class FaceInfo : AbstractListInfo<FaceImageInfo>, BiometricDataBlock
{
    /// <summary>Facial Record Header 'F', 'A', 'C', 0x00. Section 5.4, Table 2 of ISO/IEC 19794-5.</summary>
    private const int FORMAT_IDENTIFIER = 0x46414300;

    /// <summary>Version number '0', '1', '0', 0x00. Section 5.4, Table 2 of ISO/IEC 19794-5.</summary>
    private const int VERSION_NUMBER = 0x30313000;

    private StandardBiometricHeader? _sbh;

    /// <summary>Constructs a face info from a list of face image infos.</summary>
    /// <param name="faceImageInfos">face image infos</param>
    public FaceInfo(List<FaceImageInfo> faceImageInfos)
        : this(null, faceImageInfos)
    {
    }

    /// <summary>Constructs a face info from a list of face image infos.</summary>
    /// <param name="sbh">the standard biometric header to use</param>
    /// <param name="faceImageInfos">face image infos</param>
    public FaceInfo(StandardBiometricHeader? sbh, List<FaceImageInfo> faceImageInfos)
    {
        _sbh = sbh;
        AddAll(faceImageInfos);
    }

    /// <summary>Constructs a face info from binary encoding.</summary>
    /// <param name="inputStream">an input stream</param>
    public FaceInfo(Stream inputStream)
        : this(null, inputStream)
    {
    }

    /// <summary>Constructs a face info from binary encoding.</summary>
    /// <param name="sbh">the standard biometric header to use</param>
    /// <param name="inputStream">an input stream</param>
    public FaceInfo(StandardBiometricHeader? sbh, Stream inputStream)
    {
        _sbh = sbh;
        ReadObject(inputStream);
    }

    /// <summary>
    /// Reads the facial record from an input stream. Note that the standard biometric header has
    /// already been read.
    /// </summary>
    public override void ReadObject(Stream inputStream)
    {
        /* Facial Record Header (14) */

        int fac0 = ReadInt32BigEndian(inputStream); /* header (e.g. "FAC", 0x00) */ /* 4 */

        // NOTE: Java logs a warning here ("'FAC' marker expected!..."); omitted per precedent (see
        // D:\GIT\nMRTD\src\nMRTD\Lds\Icao\DG11File.cs and porting-conventions.md).
        if (fac0 != FORMAT_IDENTIFIER)
        {
            if (fac0 == 0x0000000C)
            {
                /* Magic JP2 header. Best effort, assume this is a single image. */

                using var bOut = new MemoryStream();
                WriteInt32BigEndian(bOut, fac0);

                /* NOTE: preserved Java quirk -- Java reads this length via the SIGNED readShort(), not an
                 * unsigned read (unlike every other 16-bit field in this file family); ported with a
                 * dedicated signed helper rather than the usual ReadUnsignedShort. */
                int imageLength = ReadInt16BigEndianSigned(inputStream);

                WriteUnsignedShort(bOut, imageLength);

                int totalBytesRead = 0;
                while (totalBytesRead < imageLength)
                {
                    byte[] buffer = new byte[2048];
                    int chunkSize = inputStream.Read(buffer, 0, buffer.Length);
                    if (chunkSize <= 0)
                    {
                        break;
                    }
                    bOut.Write(buffer, 0, chunkSize);
                    totalBytesRead += chunkSize;
                }

                /* Construct header with default values. */
                using var imageStream = new MemoryStream(bOut.ToArray(), writable: false);

                // NOTE: preserved Java quirk -- the *faceImageType* argument below (position 8) is
                // passed FaceImageInfo.IMAGE_DATA_TYPE_JPEG2000 (0x01) rather than a FACE_IMAGE_TYPE_*
                // constant. This is what upstream JMRTD literally does; the numeric value happens to
                // coincide with FACE_IMAGE_TYPE_FULL_FRONTAL (also 0x01), so the effective decoded
                // faceImageType is "full frontal" purely by coincidence. Ported byte-for-byte rather than
                // "corrected" to the presumably-intended FACE_IMAGE_TYPE_FULL_FRONTAL constant.
                var imageInfo = new FaceImageInfo(
                    SmartCards.Gender.Unknown,
                    FaceImageInfo.EyeColor.Unspecified,
                    0x00,
                    FaceImageInfo.HAIR_COLOR_UNSPECIFIED,
                    FaceImageInfo.EXPRESSION_UNSPECIFIED,
                    [0, 0, 0], [0, 0, 0],
                    FaceImageInfo.IMAGE_DATA_TYPE_JPEG2000,
                    FaceImageInfo.IMAGE_COLOR_SPACE_UNSPECIFIED,
                    FaceImageInfo.SOURCE_TYPE_UNSPECIFIED,
                    0x00,
                    0,
                    [],
                    0, 0,
                    imageStream, (int)bOut.Length, FaceImageInfo.IMAGE_DATA_TYPE_JPEG2000);
                Add(imageInfo);
                return;
            }

            // NOTE: preserved Java quirk -- when fac0 matches neither the "FAC" marker nor the magic JP2
            // marker, Java does NOT throw here: it falls through and keeps parsing the rest of the header
            // as if fac0 had been a valid "FAC" marker (only a mismatched version number below actually
            // throws). Ported as-is: no exception is raised for this case.
        }

        int version = ReadInt32BigEndian(inputStream); /* version in ASCII (e.g. "010" 0x00) */ /* + 4 = 8 */
        if (version != VERSION_NUMBER)
        {
            throw new ArgumentException($"'010' version number expected! Found {version:x}");
        }

        long recordLength = ReadUInt32BigEndian(inputStream); /* + 4 = 12 */
        const long headerLength = 14; /* 4 + 4 + 4 + 2 */
        long dataLength = recordLength - headerLength;

        long constructedDataLength = 0L;

        int count = ReadUnsignedShort(inputStream); /* + 2 = 14 */

        for (int i = 0; i < count; i++)
        {
            var imageInfo = new FaceImageInfo(inputStream);
            constructedDataLength += imageInfo.GetRecordLength();
            Add(imageInfo);
        }

        // NOTE: Java logs a warning here (dataLength != constructedDataLength mismatch); omitted per
        // precedent (see D:\GIT\nMRTD\src\nMRTD\Lds\Icao\DG11File.cs and porting-conventions.md).
        _ = dataLength;
        _ = constructedDataLength;
    }

    /// <summary>
    /// Writes the facial record to an output stream. Note that the standard biometric header (part of
    /// CBEFF structure) is not written here.
    /// </summary>
    public override void WriteObject(Stream outputStream)
    {
        const int headerLength = 14; /* 4 + 4 + 4 + 2 (Section 5.4 of ISO/IEC 19794-5) */

        long dataLength = 0;
        List<FaceImageInfo> faceImageInfos = GetSubRecords();
        foreach (FaceImageInfo faceImageInfo in faceImageInfos)
        {
            dataLength += faceImageInfo.GetRecordLength();
        }

        long recordLength = headerLength + dataLength;

        WriteInt32BigEndian(outputStream, FORMAT_IDENTIFIER); /* 4 */
        WriteInt32BigEndian(outputStream, VERSION_NUMBER);    /* + 4 = 8 */

        /*
         * The (4 byte) Length of Record field shall be the combined length in bytes for the record.
         * This is the entire length of the record including the Facial Record Header and Facial Record
         * Data.
         */
        WriteInt32BigEndian(outputStream, unchecked((int)(recordLength & 0xFFFFFFFFL))); /* + 4 = 12 */

        /* Number of facial record data blocks. */
        WriteUnsignedShort(outputStream, faceImageInfos.Count); /* + 2 = 14 */

        foreach (FaceImageInfo faceImageInfo in faceImageInfos)
        {
            faceImageInfo.WriteFaceImageObject(outputStream);
        }
    }

    /// <summary>Returns the standard biometric header of this biometric data block.</summary>
    /// <returns>the standard biometric header</returns>
    public StandardBiometricHeader GetStandardBiometricHeader()
    {
        if (_sbh == null)
        {
            byte[] biometricType = [(byte)CBEFFInfo<BiometricDataBlock>.BIOMETRIC_TYPE_FACIAL_FEATURES];
            byte[] biometricSubtype = [(byte)CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_NONE];
            byte[] formatOwner =
            [
                (byte)((StandardBiometricHeader.JTC1_SC37_FORMAT_OWNER_VALUE & 0xFF00) >> 8),
                (byte)(StandardBiometricHeader.JTC1_SC37_FORMAT_OWNER_VALUE & 0xFF),
            ];
            byte[] formatType =
            [
                (byte)((StandardBiometricHeader.ISO_19794_FACE_IMAGE_FORMAT_TYPE_VALUE & 0xFF00) >> 8),
                (byte)(StandardBiometricHeader.ISO_19794_FACE_IMAGE_FORMAT_TYPE_VALUE & 0xFF),
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

    /// <summary>Returns the face image infos embedded in this face info.</summary>
    /// <returns>the embedded face image infos</returns>
    public List<FaceImageInfo> GetFaceImageInfos() => GetSubRecords();

    /// <summary>Adds a face image info to this face info.</summary>
    /// <param name="faceImageInfo">the face image info to add</param>
    public void AddFaceImageInfo(FaceImageInfo faceImageInfo) => Add(faceImageInfo);

    /// <summary>Removes a face image info from this face info.</summary>
    /// <param name="index">the index of the face image info to remove</param>
    public void RemoveFaceImageInfo(int index) => Remove(index);

    public override string ToString()
    {
        var result = new System.Text.StringBuilder();
        result.Append("FaceInfo [");
        List<FaceImageInfo> records = GetSubRecords();
        foreach (FaceImageInfo record in records)
        {
            result.Append(record.ToString());
        }
        result.Append(']');
        return result.ToString();
    }

    public override int GetHashCode()
    {
        const int prime = 31;
        int result = base.GetHashCode();
        result = (prime * result) + (_sbh == null ? 0 : _sbh.GetHashCode());
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

        var other = (FaceInfo)obj;
        if (_sbh == null)
        {
            return other._sbh == null;
        }

        return ReferenceEquals(_sbh, other._sbh) || _sbh.Equals(other._sbh);
    }

    /* ONLY PRIVATE METHODS BELOW */

    /* Minimal big-endian binary I/O helpers (this port has no shared DataInputStream/DataOutputStream
     * equivalent; see the sibling set in FingerInfo.cs/FingerImageInfo.cs/FaceImageInfo.cs). */

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

    /// <summary>Reads a big-endian signed 16-bit value, matching Java's <c>DataInputStream.readShort()</c>.</summary>
    private static int ReadInt16BigEndianSigned(Stream inputStream)
    {
        int hi = ReadUnsignedByte(inputStream);
        int lo = ReadUnsignedByte(inputStream);
        return (short)((hi << 8) | lo);
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
