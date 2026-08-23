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

namespace nMRTD.Lds.Iso19794;

/// <summary>
/// Port of <c>org.jmrtd.lds.iso19794.IrisBiometricSubtypeInfo</c>: iris biometric subtype data block
/// (containing iris image data blocks) based on Section 6.5.3 and Table 3 of ISO/IEC 19794-6 2005.
/// </summary>
public class IrisBiometricSubtypeInfo : AbstractListInfo<IrisImageInfo>
{
    /// <summary>Biometric subtype value.</summary>
    public const int EYE_UNDEF = 0;

    /// <summary>Biometric subtype value.</summary>
    public const int EYE_RIGHT = 1;

    /// <summary>Biometric subtype value.</summary>
    public const int EYE_LEFT = 2;

    private int _imageFormat;
    private int _biometricSubtype;

    /// <summary>Constructs a biometric subtype info.</summary>
    /// <param name="biometricSubtype">one of <see cref="EYE_UNDEF"/>, <see cref="EYE_RIGHT"/>, <see cref="EYE_LEFT"/></param>
    /// <param name="imageFormat">the image format as specified in the <see cref="IrisInfo"/> of which this is a part</param>
    /// <param name="irisImageInfos">the iris image info records</param>
    public IrisBiometricSubtypeInfo(int biometricSubtype, int imageFormat, List<IrisImageInfo> irisImageInfos)
    {
        _biometricSubtype = biometricSubtype;
        _imageFormat = imageFormat;
        AddAll(irisImageInfos);
    }

    /// <summary>Constructs an iris biometric subtype from binary encoding.</summary>
    /// <param name="inputStream">an input stream</param>
    /// <param name="imageFormat">the image format used</param>
    public IrisBiometricSubtypeInfo(Stream inputStream, int imageFormat)
    {
        _imageFormat = imageFormat;
        ReadObject(inputStream);
    }

    /// <summary>Reads an iris biometric subtype from an input stream.</summary>
    public override void ReadObject(Stream inputStream)
    {
        /* Iris biometric subtype header */
        _biometricSubtype = ReadUnsignedByte(inputStream);      /* 1 */
        int count = ReadUnsignedShort(inputStream);              /* + 2 = 3 */

        for (int i = 0; i < count; i++)
        {
            var imageInfo = new IrisImageInfo(inputStream, _imageFormat);
            Add(imageInfo);
        }

        /* NOTE: preserved Java quirk -- upstream computes constructedDataLength from each image info's
         * GetRecordLength() but the comparison against the caller-supplied dataLength is commented out
         * in JMRTD itself, so no validation actually happens here. Not ported (nothing to port: it's
         * dead code in the original too). */
    }

    /// <summary>Writes an iris biometric subtype to an output stream.</summary>
    public override void WriteObject(Stream outputStream)
    {
        WriteByte(outputStream, _biometricSubtype & 0xFF);              /* 1 */

        List<IrisImageInfo> irisImageInfos = GetSubRecords();
        WriteShort(outputStream, irisImageInfos.Count & 0xFFFF);        /* + 2 = 3 */
        foreach (IrisImageInfo irisImageInfo in irisImageInfos)
        {
            irisImageInfo.WriteTo(outputStream);
        }
    }

    /// <summary>Returns the record length.</summary>
    public long GetRecordLength()
    {
        long result = 3;
        List<IrisImageInfo> irisImageInfos = GetSubRecords();
        foreach (IrisImageInfo irisImageInfo in irisImageInfos)
        {
            result += irisImageInfo.GetRecordLength();
        }
        return result;
    }

    public override int GetHashCode()
    {
        const int prime = 31;
        int result = base.GetHashCode();
        result = (prime * result) + _biometricSubtype;
        result = (prime * result) + _imageFormat;
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

        var other = (IrisBiometricSubtypeInfo)obj;
        return _biometricSubtype == other._biometricSubtype
            && _imageFormat == other._imageFormat;
    }

    public override string ToString()
    {
        List<IrisImageInfo> irisImageInfos = GetSubRecords();
        return "IrisBiometricSubtypeInfo ["
            + "biometric subtype: " + BiometricSubtypeToString(_biometricSubtype)
            + ", imageCount = " + irisImageInfos.Count
            + "]";
    }

    /// <summary>
    /// The biometric subtype (feature identifier). Result is one of <see cref="EYE_UNDEF"/>,
    /// <see cref="EYE_RIGHT"/>, <see cref="EYE_LEFT"/>.
    /// </summary>
    public int GetBiometricSubtype() => _biometricSubtype;

    /// <summary>Returns the image format used in the images encoded in this record.</summary>
    public int GetImageFormat() => _imageFormat;

    /// <summary>Returns the iris image infos embedded in this iris biometric subtype info.</summary>
    public List<IrisImageInfo> GetIrisImageInfos() => GetSubRecords();

    /// <summary>Adds an iris image info to this iris biometric subtype info.</summary>
    public void AddIrisImageInfo(IrisImageInfo irisImageInfo) => Add(irisImageInfo);

    /// <summary>Removes an iris image info from this iris biometric subtype info.</summary>
    public void RemoveIrisImageInfo(int index) => Remove(index);

    /* ONLY PRIVATE METHODS BELOW */

    /// <summary>
    /// Returns a textual representation of the given biometric sub-type code, such as
    /// <c>"Left eye"</c>, <c>"Right eye"</c>, or <c>"Undefined"</c>.
    /// </summary>
    private static string BiometricSubtypeToString(int biometricSubtype) => biometricSubtype switch
    {
        EYE_LEFT => "Left eye",
        EYE_RIGHT => "Right eye",
        EYE_UNDEF => "Undefined",
        _ => throw new FormatException($"Unknown biometric subtype: {biometricSubtype:x}"),
    };

    private static int ReadUnsignedByte(Stream inputStream)
    {
        int b = inputStream.ReadByte();
        if (b < 0)
        {
            throw new EndOfStreamException("Unexpected end of stream while reading iris biometric subtype info.");
        }
        return b;
    }

    private static int ReadUnsignedShort(Stream inputStream)
    {
        int b1 = ReadUnsignedByte(inputStream);
        int b2 = ReadUnsignedByte(inputStream);
        return (b1 << 8) | b2;
    }

    private static void WriteByte(Stream outputStream, int value) => outputStream.WriteByte((byte)value);

    private static void WriteShort(Stream outputStream, int value)
    {
        outputStream.WriteByte((byte)((value >> 8) & 0xFF));
        outputStream.WriteByte((byte)(value & 0xFF));
    }
}
