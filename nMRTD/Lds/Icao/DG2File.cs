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
using nMRTD.Lds.Iso19794;
using nMRTD.Lds.Iso39794;
using nMRTD.SmartCards;

namespace nMRTD.Lds.Icao;

/// <summary>
/// Port of <c>org.jmrtd.lds.icao.DG2File</c>: file structure for the EF.DG2 file. Data group 2 contains
/// the facial features of the document holder. Based on ISO/IEC 19794-5 and ISO/IEC 39794-5.
/// </summary>
public class DG2File : CBEFFDataGroup
{
    private static readonly ISO781611Decoder<BiometricDataBlock> Decoder = new(GetDecoderMap());

    private static readonly ISO781611Encoder<BiometricDataBlock> Iso19794EncoderInstance = new(new Iso19794FaceEncoder());

    private static readonly ISO781611Encoder<BiometricDataBlock> Iso39794EncoderInstance =
        CreateISO39794Encoder(ISO39794EncodingProfile.Base);

    private static readonly ISO781611Encoder<BiometricDataBlock> Icao39794_5EncoderInstance =
        CreateISO39794Encoder(ISO39794EncodingProfile.Icao39794_5EmrtdV1);

    /// <summary>The profile used to select between <see cref="Iso39794EncoderInstance"/> and
    /// <see cref="Icao39794_5EncoderInstance"/> when <see cref="CBEFFDataGroup.EncodingType"/> is
    /// <see cref="BiometricEncodingType.Iso39794"/>. Unused (kept at its <see cref="ISO39794EncodingProfile.Base"/>
    /// default) for ISO-19794-encoded files.</summary>
    private ISO39794EncodingProfile _iso39794EncodingProfile = ISO39794EncodingProfile.Base;

    private static Dictionary<int, BiometricDataBlockDecoder<BiometricDataBlock>> GetDecoderMap() =>
        new()
        {
            [ISO781611.BIOMETRIC_DATA_BLOCK_TAG] = new Iso19794FaceDecoder(), /* 5F2E */
            [ISO781611.BIOMETRIC_DATA_BLOCK_CONSTRUCTED_TAG] = new DualFaceDecoder(), /* 7F2E */
        };

    /// <summary>Decodes a primitive-tagged (0x5F2E) biometric data block, always ISO-19794.</summary>
    private sealed class Iso19794FaceDecoder : BiometricDataBlockDecoder<BiometricDataBlock>
    {
        public BiometricDataBlock Decode(Stream inputStream, StandardBiometricHeader sbh, int index, int length) =>
            new FaceInfo(sbh, inputStream);
    }

    /// <summary>Decodes a constructed-tagged (0x7F2E) biometric data block: ISO-19794 if the standard
    /// biometric header says so, otherwise ISO-39794.</summary>
    private sealed class DualFaceDecoder : BiometricDataBlockDecoder<BiometricDataBlock>
    {
        public BiometricDataBlock Decode(Stream inputStream, StandardBiometricHeader sbh, int index, int length)
        {
            // NOTE: preserved Java quirk -- sbh is null-checked even though the interface parameter type
            // is non-nullable; the runtime can still pass null in practice (nullable annotations are
            // compile-time only), matching this port's established convention elsewhere (e.g. PACEAPDUSender.cs).
            if (sbh != null && sbh.HasFormatType(StandardBiometricHeader.ISO_19794_FACE_IMAGE_FORMAT_TYPE_VALUE))
            {
                return new FaceInfo(sbh, inputStream);
            }

            // NOTE: Java logs a warning here when the format type doesn't even match ISO-39794 either;
            // omitted per this port's established non-essential-warning-omission precedent.
            using var tlvInputStream = new TlvInputStream(inputStream, leaveOpen: true);
            int tag = tlvInputStream.ReadTag(); // 0xA1
            if (tag != ISO781611.BIOMETRIC_HEADER_TEMPLATE_BASE_TAG)
            {
                // NOTE: Java logs a warning here; omitted per this port's established precedent.
                // ISO/IEC 39794-5 Application Profile for eMRTDs Version 1.00: Table 2: Data Structure under DO7F2E.
            }
            tlvInputStream.ReadLength();
            return new FaceImageDataBlock(sbh, inputStream);
        }
    }

    private sealed class Iso19794FaceEncoder : BiometricDataBlockEncoder<BiometricDataBlock>
    {
        public void Encode(BiometricDataBlock bdb, Stream outputStream)
        {
            if (bdb is FaceInfo faceInfo)
            {
                faceInfo.WriteObject(outputStream);
            }
        }

        public BiometricEncodingType GetEncodingType() => BiometricEncodingType.Iso19794;
    }

    /// <summary>Encodes an ISO/IEC 39794 <see cref="FaceImageDataBlock"/> using the given encoding profile,
    /// wrapping its raw ASN.1 DER encoding in the <c>0xA1</c> biometric-header-template-base tag expected
    /// under the constructed (<c>0x7F2E</c>) biometric data block tag.</summary>
    private sealed class Iso39794FaceEncoder(ISO39794EncodingProfile profile) : BiometricDataBlockEncoder<BiometricDataBlock>
    {
        public void Encode(BiometricDataBlock bdb, Stream outputStream)
        {
            if (bdb is FaceImageDataBlock faceImageDataBlock)
            {
                using var tlvOutputStream = new TlvOutputStream(outputStream, leaveOpen: true);
                byte[]? encoded = faceImageDataBlock.GetEncoded(profile);
                tlvOutputStream.WriteTag(ISO781611.BIOMETRIC_HEADER_TEMPLATE_BASE_TAG);
                tlvOutputStream.WriteValue(encoded!);
            }
        }

        public BiometricEncodingType GetEncodingType() => BiometricEncodingType.Iso39794;
    }

    private static ISO781611Encoder<BiometricDataBlock> CreateISO39794Encoder(ISO39794EncodingProfile profile) =>
        new(new Iso39794FaceEncoder(profile));

    /// <summary>Creates a new file with the specified records.</summary>
    /// <param name="faceInfos">records</param>
    [Obsolete("Use CreateISO19794DG2File instead.")]
    public DG2File(List<FaceInfo> faceInfos)
        : this(BiometricEncodingType.Iso19794, faceInfos)
    {
    }

    /// <summary>Creates a new file based on an input stream.</summary>
    /// <param name="inputStream">an input stream</param>
    public DG2File(Stream inputStream)
        : base(LDSFile.EF_DG2_TAG, inputStream, false)
    {
    }

    private DG2File(BiometricEncodingType encodingType, IEnumerable<BiometricDataBlock> biometricDataBlocks)
        : this(encodingType, biometricDataBlocks, ISO39794EncodingProfile.Base)
    {
    }

    private DG2File(BiometricEncodingType encodingType, IEnumerable<BiometricDataBlock> biometricDataBlocks, ISO39794EncodingProfile iso39794EncodingProfile)
        : base(LDSFile.EF_DG2_TAG, encodingType, [.. biometricDataBlocks], false)
    {
        // NOTE: Java null-checks iso39794EncodingProfile here and throws IllegalArgumentException; omitted
        // since ISO39794EncodingProfile is a C# enum (a value type) and so cannot be null in the first place
        // (see Block.cs's own note on the same elision).
        _iso39794EncodingProfile = iso39794EncodingProfile;
    }

    /// <summary>Creates an ISO/IEC 19794 DG2 file.</summary>
    public static DG2File CreateISO19794DG2File(List<FaceInfo> faceInfos) => new(BiometricEncodingType.Iso19794, faceInfos);

    /// <summary>Creates an ISO/IEC 39794 DG2 file using the unconstrained base-standard encoding.</summary>
    public static DG2File CreateISO39794DG2File(List<FaceImageDataBlock> faceImageDataBlocks) =>
        new(BiometricEncodingType.Iso39794, faceImageDataBlocks);

    /// <summary>Creates an ISO/IEC 39794 DG2 file using the specified encoding profile.</summary>
    /// <param name="faceImageDataBlocks">face image records</param>
    /// <param name="profile">encoding profile</param>
    public static DG2File CreateISO39794DG2File(List<FaceImageDataBlock> faceImageDataBlocks, ISO39794EncodingProfile profile) =>
        new(BiometricEncodingType.Iso39794, faceImageDataBlocks, profile);

    public override ISO781611Decoder<BiometricDataBlock> GetDecoder() => Decoder;

    public override ISO781611Encoder<BiometricDataBlock> GetEncoder() =>
        EncodingType switch
        {
            BiometricEncodingType.Iso19794 => Iso19794EncoderInstance,
            BiometricEncodingType.Iso39794 => _iso39794EncodingProfile == ISO39794EncodingProfile.Icao39794_5EmrtdV1
                ? Icao39794_5EncoderInstance
                : Iso39794EncoderInstance,
            _ => Iso19794EncoderInstance,
        };

    /// <summary>Returns a textual representation of this file.</summary>
    public override string ToString() => $"DG2File [{base.ToString()}]";

    /// <summary>Returns the face infos embedded in this file.</summary>
    [Obsolete("Use GetSubRecords() and check with the is operator instead.")]
    public List<FaceInfo> GetFaceInfos() => ToFaceInfos(GetSubRecords());

    private static List<FaceInfo> ToFaceInfos(List<BiometricDataBlock> records)
    {
        var faceInfos = new List<FaceInfo>(records.Count);
        foreach (BiometricDataBlock record in records)
        {
            if (record is FaceInfo faceInfo)
            {
                faceInfos.Add(faceInfo);
            }
        }

        return faceInfos;
    }
}
