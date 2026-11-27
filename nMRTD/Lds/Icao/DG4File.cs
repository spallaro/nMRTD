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
/// Port of <c>org.jmrtd.lds.icao.DG4File</c>: file structure for the EF.DG4 file, based on ISO/IEC 19794-6
/// and ISO/IEC 39794-6.
/// </summary>
public class DG4File : CBEFFDataGroup
{
    /// <summary>The per-tag BDB decoders, stateless and shared. JMRTD shares one static
    /// <c>ISO781611Decoder</c> per data group, but that decoder keeps the encoding type of the last block
    /// it read in a field, so concurrent decodes could see each other's value; nMRTD creates one per
    /// <see cref="GetDecoder"/> call instead.</summary>
    private static readonly Dictionary<int, BiometricDataBlockDecoder<BiometricDataBlock>> DecoderMap = GetDecoderMap();

    private static readonly ISO781611Encoder<BiometricDataBlock> Iso19794EncoderInstance = new(new Iso19794IrisEncoder());

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
            [ISO781611.BIOMETRIC_DATA_BLOCK_TAG] = new Iso19794IrisDecoder(), /* 5F2E */
            [ISO781611.BIOMETRIC_DATA_BLOCK_CONSTRUCTED_TAG] = new DualIrisDecoder(), /* 7F2E */
        };

    /// <summary>Decodes a primitive-tagged (0x5F2E) biometric data block, always ISO-19794.</summary>
    private sealed class Iso19794IrisDecoder : BiometricDataBlockDecoder<BiometricDataBlock>
    {
        public BiometricDataBlock Decode(Stream inputStream, StandardBiometricHeader sbh, int index, int length) =>
            new IrisInfo(sbh, inputStream);
    }

    /// <summary>Decodes a constructed-tagged (0x7F2E) biometric data block: ISO-19794 if the standard
    /// biometric header says so, otherwise ISO-39794.</summary>
    private sealed class DualIrisDecoder : BiometricDataBlockDecoder<BiometricDataBlock>
    {
        public BiometricDataBlock Decode(Stream inputStream, StandardBiometricHeader sbh, int index, int length)
        {
            // NOTE: preserved Java quirk -- sbh is null-checked even though the interface parameter type
            // is non-nullable; the runtime can still pass null in practice (nullable annotations are
            // compile-time only), matching this port's established convention elsewhere (e.g. PACEAPDUSender.cs).
            if (sbh != null && sbh.HasFormatType(StandardBiometricHeader.ISO_19794_IRIS_IMAGE_FORMAT_TYPE_VALUE))
            {
                return new IrisInfo(sbh, inputStream);
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
            return new IrisImageDataBlock(sbh, inputStream);
        }
    }

    private sealed class Iso19794IrisEncoder : BiometricDataBlockEncoder<BiometricDataBlock>
    {
        public void Encode(BiometricDataBlock bdb, Stream outputStream)
        {
            if (bdb is IrisInfo irisInfo)
            {
                irisInfo.WriteObject(outputStream);
            }
        }

        public BiometricEncodingType GetEncodingType() => BiometricEncodingType.Iso19794;
    }

    /// <summary>Encodes an ISO/IEC 39794 <see cref="IrisImageDataBlock"/> using the given encoding profile,
    /// wrapping its raw ASN.1 DER encoding in the <c>0xA1</c> biometric-header-template-base tag expected
    /// under the constructed (<c>0x7F2E</c>) biometric data block tag.</summary>
    private sealed class Iso39794IrisEncoder(ISO39794EncodingProfile profile) : BiometricDataBlockEncoder<BiometricDataBlock>
    {
        public void Encode(BiometricDataBlock bdb, Stream outputStream)
        {
            if (bdb is IrisImageDataBlock irisImageDataBlock)
            {
                using var tlvOutputStream = new TlvOutputStream(outputStream, leaveOpen: true);
                byte[]? encoded = irisImageDataBlock.GetEncoded(profile);
                tlvOutputStream.WriteTag(ISO781611.BIOMETRIC_HEADER_TEMPLATE_BASE_TAG);
                tlvOutputStream.WriteValue(encoded!);
            }
        }

        public BiometricEncodingType GetEncodingType() => BiometricEncodingType.Iso39794;
    }

    private static ISO781611Encoder<BiometricDataBlock> CreateISO39794Encoder(ISO39794EncodingProfile profile) =>
        new(new Iso39794IrisEncoder(profile));

    /// <summary>Creates a new file with the specified records.</summary>
    /// <param name="irisInfos">records</param>
    // NOTE: preserved Java quirk -- unlike DG2File/DG3File (whose single-List-argument constructors are
    // themselves [Obsolete]), Java's own DG4File leaves this constructor un-deprecated even though it
    // delegates to the deprecated 2-arg overload below. The #pragma below only suppresses the resulting
    // CS0618 for that intentional same-class call, matching upstream's (javac-silent) behavior exactly.
#pragma warning disable CS0618
    public DG4File(List<IrisInfo> irisInfos)
        : this(irisInfos, true)
    {
    }
#pragma warning restore CS0618

    /// <summary>Creates a new file with the specified records.</summary>
    /// <param name="irisInfos">records</param>
    /// <param name="shouldAddRandomDataIfEmpty">indicates whether the encoder should add random data when no templates are present</param>
    [Obsolete("Use CreateISO19794DG4File instead.")]
    public DG4File(List<IrisInfo> irisInfos, bool shouldAddRandomDataIfEmpty)
        : base(LDSFileTags.EF_DG4_TAG, BiometricEncodingType.Iso19794, [.. irisInfos], shouldAddRandomDataIfEmpty)
    {
        // NOTE: preserved Java quirk -- redundantly re-assigns ShouldAddRandomDataIfEmpty to the same
        // value the base constructor already set it to.
        ShouldAddRandomDataIfEmpty = shouldAddRandomDataIfEmpty;
    }

    private DG4File(BiometricEncodingType encodingType, IEnumerable<BiometricDataBlock> dataBlocks, bool shouldAddRandomDataIfEmpty)
        : this(encodingType, dataBlocks, shouldAddRandomDataIfEmpty, ISO39794EncodingProfile.Base)
    {
    }

    private DG4File(BiometricEncodingType encodingType, IEnumerable<BiometricDataBlock> dataBlocks, bool shouldAddRandomDataIfEmpty, ISO39794EncodingProfile iso39794EncodingProfile)
        : base(LDSFileTags.EF_DG4_TAG, encodingType, [.. dataBlocks], shouldAddRandomDataIfEmpty)
    {
        // NOTE: Java null-checks iso39794EncodingProfile here and throws IllegalArgumentException; omitted
        // since ISO39794EncodingProfile is a C# enum (a value type) and so cannot be null in the first place
        // (see Block.cs's own note on the same elision).
        _iso39794EncodingProfile = iso39794EncodingProfile;
    }

    /// <summary>Constructs a new file based on an input stream.</summary>
    /// <param name="inputStream">an input stream</param>
    public DG4File(Stream inputStream)
        : base(LDSFileTags.EF_DG4_TAG, inputStream, false)
    {
    }

    /// <summary>Creates an ISO/IEC 19794 DG4 file.</summary>
    public static DG4File CreateISO19794DG4File(List<IrisInfo> irisInfos) =>
        new(BiometricEncodingType.Iso19794, irisInfos, false);

    /// <summary>Creates an ISO/IEC 39794 DG4 file using the unconstrained base-standard encoding.</summary>
    public static DG4File CreateISO39794DG4File(List<IrisImageDataBlock> irisImageDataBlocks) =>
        new(BiometricEncodingType.Iso39794, irisImageDataBlocks, false);

    /// <summary>Creates an ISO/IEC 39794 DG4 file using the specified encoding profile.</summary>
    /// <param name="irisImageDataBlocks">iris image records</param>
    /// <param name="profile">encoding profile</param>
    public static DG4File CreateISO39794DG4File(List<IrisImageDataBlock> irisImageDataBlocks, ISO39794EncodingProfile profile) =>
        new(BiometricEncodingType.Iso39794, irisImageDataBlocks, false, profile);

    public override ISO781611Decoder<BiometricDataBlock> GetDecoder() => new(DecoderMap);

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
    public override string ToString() => $"DG4File [{base.ToString()}]";

    /// <summary>Returns the embedded iris infos in this file.</summary>
    [Obsolete("Use GetSubRecords() and check with the is operator instead.")]
    public List<IrisInfo> GetIrisInfos() => ToIrisInfos(GetSubRecords());

    public override int GetHashCode()
    {
        int result = base.GetHashCode();
        result = (31 * result) + (ShouldAddRandomDataIfEmpty ? 1231 : 1237);
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

        if (GetType() != obj?.GetType())
        {
            return false;
        }

        var other = (DG4File)obj;
        return ShouldAddRandomDataIfEmpty == other.ShouldAddRandomDataIfEmpty;
    }

    private static List<IrisInfo> ToIrisInfos(List<BiometricDataBlock> records)
    {
        var irisInfos = new List<IrisInfo>(records.Count);
        foreach (BiometricDataBlock record in records)
        {
            if (record is IrisInfo irisInfo)
            {
                irisInfos.Add(irisInfo);
            }
        }

        return irisInfos;
    }
}
