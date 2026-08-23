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
using nMRTD.SmartCards;

namespace nMRTD.Lds;

/// <summary>
/// Port of <c>org.jmrtd.lds.CBEFFDataGroup</c>: data group containing a list of biometric information
/// templates (BITs). The <c>DG2File</c>, <c>DG3File</c>, and <c>DG4File</c> data groups are based on
/// this type.
/// </summary>
/// <remarks>
/// KNOWN GAP: this file depends on <c>nMRTD.Cbeff</c> (port of <c>org.jmrtd.cbeff</c>, 11 Java source
/// files: <c>BiometricDataBlock</c>, <c>BiometricDataBlockDecoder</c>, <c>BiometricDataBlockEncoder</c>,
/// <c>BiometricEncodingType</c>, <c>CBEFFInfo</c>, <c>ComplexCBEFFInfo</c>, <c>ISO781611</c>,
/// <c>ISO781611Decoder</c>, <c>ISO781611Encoder</c>, <c>SimpleCBEFFInfo</c>, <c>StandardBiometricHeader</c>),
/// which is not part of the <c>nMRTD.Lds</c> porting task this file was written under and does not exist
/// in this codebase yet -- it is also not one of the DG2File/DG3File/DG4File consumers of this class
/// (those aren't ported yet either). This is analogous to the parallel agent's not-yet-existing types
/// (forward-referenced by name per the porting instructions), except <c>nMRTD.Cbeff</c> has no assigned
/// owner at all yet. Referencing the (Java-equivalent) type/member names here by name so this file
/// compiles as-is once a future phase ports <c>org.jmrtd.cbeff</c> to <c>nMRTD.Cbeff</c>.
/// </remarks>
public abstract class CBEFFDataGroup : DataGroup
{
    /* NOTE: JMRTD uses a cryptographically strong SecureRandom in the "build from data" constructor but
     * a plain (non-cryptographic) Random in the "parse from stream" constructor -- an asymmetry that
     * doesn't actually matter here since this Random is only ever used to fill 8 bytes of non-secret
     * padding (see WriteOptionalRandomData), never security-sensitive material. A single Random suffices
     * for both constructors in the C# port. */
    /// <summary>For writing the optional random data block.</summary>
    private readonly Random _random = new();

    /// <summary>Records in the BIT group. Each record represents a single BIT.</summary>
    /// <remarks>
    /// Deliberately left without an inline initializer: for the "parse from stream" constructor, the
    /// base <c>AbstractTaggedLDSFile</c> constructor invokes <see cref="ReadContent"/> virtually before
    /// this constructor's own body runs, which populates this field via <see cref="Add"/> -- an inline
    /// initializer here would execute afterwards (per C# field-initializer-then-constructor-body
    /// ordering) and silently wipe out what ReadContent just built.
    /// </remarks>
    private List<BiometricDataBlock> _subRecords = null!;

    protected bool ShouldAddRandomDataIfEmpty { get; set; }

    protected BiometricEncodingType EncodingType { get; set; }

    /// <summary>Creates a CBEFF data group.</summary>
    /// <param name="dataGroupTag">the data group tag</param>
    /// <param name="encodingType">encoding type, either ISO19794 or ISO39794</param>
    /// <param name="subRecords">the sub-records contained in this data group</param>
    /// <param name="shouldAddRandomDataIfEmpty">whether to include random data if there are no records</param>
    protected CBEFFDataGroup(int dataGroupTag, BiometricEncodingType encodingType, List<BiometricDataBlock> subRecords, bool shouldAddRandomDataIfEmpty)
        : base(dataGroupTag)
    {
        _subRecords = [];
        AddAll(subRecords);
        EncodingType = encodingType;
        ShouldAddRandomDataIfEmpty = shouldAddRandomDataIfEmpty;
    }

    /// <summary>Constructs an instance.</summary>
    /// <param name="dataGroupTag">the datagroup tag to use</param>
    /// <param name="inputStream">an input stream</param>
    /// <param name="shouldAddRandomDataIfEmpty">whether to include random data if there are no records</param>
    protected CBEFFDataGroup(int dataGroupTag, Stream inputStream, bool shouldAddRandomDataIfEmpty)
        : base(dataGroupTag, inputStream)
    {
        _subRecords ??= [];
        ShouldAddRandomDataIfEmpty = shouldAddRandomDataIfEmpty;
    }

    public abstract ISO781611Decoder<BiometricDataBlock> GetDecoder();

    public abstract ISO781611Encoder<BiometricDataBlock> GetEncoder();

    public BiometricEncodingType GetEncodingType() => EncodingType;

    protected override void ReadContent(Stream inputStream)
    {
        ISO781611Decoder<BiometricDataBlock> decoder = GetDecoder();
        EncodingType = decoder.GetEncodingType();
        ComplexCBEFFInfo<BiometricDataBlock> complexCbeffInfo = decoder.Decode(inputStream);
        List<CBEFFInfo<BiometricDataBlock>> records = complexCbeffInfo.GetSubRecords();
        foreach (CBEFFInfo<BiometricDataBlock> cbeffInfo in records)
        {
            if (cbeffInfo is not SimpleCBEFFInfo<BiometricDataBlock> simpleCbeffInfo)
            {
                throw new IOException($"Was expecting a SimpleCBEFFInfo, found {cbeffInfo.GetType().Name}");
            }
            BiometricDataBlock bdb = simpleCbeffInfo.GetBiometricDataBlock();
            Add(bdb);
        }
        EncodingType = decoder.GetEncodingType();

        /* NOTE: JMRTD's own FIXME: "by symmetry, shouldn't there be a readOptionalRandomData here?" -- ported as-is. */
    }

    protected override void WriteContent(Stream outputStream)
    {
        ISO781611Encoder<BiometricDataBlock> encoder = GetEncoder();
        var cbeffInfo = new ComplexCBEFFInfo<BiometricDataBlock>();
        List<BiometricDataBlock> records = GetSubRecords();
        foreach (BiometricDataBlock record in records)
        {
            var simpleCbeffInfo = new SimpleCBEFFInfo<BiometricDataBlock>(record);
            cbeffInfo.Add(simpleCbeffInfo);
        }
        encoder.Encode(cbeffInfo, outputStream);

        /* NOTE: Supplement to ICAO Doc 9303 R7-p1_v2_sIII_0057. */
        if (ShouldAddRandomDataIfEmpty)
        {
            WriteOptionalRandomData(outputStream);
        }
    }

    /// <summary>Returns a textual representation of this data group.</summary>
    public override string ToString()
    {
        var result = new System.Text.StringBuilder();
        result.Append("CBEFFDataGroup [");
        if (_subRecords == null)
        {
            result.Append("null");
        }
        else
        {
            bool isFirst = true;
            foreach (BiometricDataBlock subRecord in _subRecords)
            {
                if (!isFirst)
                {
                    result.Append(", ");
                }
                else
                {
                    isFirst = false;
                }
                result.Append(subRecord == null ? "null" : subRecord.ToString());
            }
        }
        result.Append(']');
        return result.ToString();
    }

    /// <summary>Returns the records in this data group.</summary>
    public List<BiometricDataBlock> GetSubRecords()
    {
        _subRecords ??= [];
        return [.. _subRecords];
    }

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
        if (other is not CBEFFDataGroup otherDg)
        {
            return false;
        }

        List<BiometricDataBlock> subRecords = GetSubRecords();
        List<BiometricDataBlock> otherSubRecords = otherDg.GetSubRecords();
        int subRecordCount = subRecords.Count;
        if (subRecordCount != otherSubRecords.Count)
        {
            return false;
        }

        for (int i = 0; i < subRecordCount; i++)
        {
            BiometricDataBlock subRecord = subRecords[i];
            BiometricDataBlock otherSubRecord = otherSubRecords[i];
            if (subRecord == null)
            {
                if (otherSubRecord != null)
                {
                    return false;
                }
            }
            else if (!subRecord.Equals(otherSubRecord))
            {
                return false;
            }
        }

        return true;
    }

    public override int GetHashCode()
    {
        int result = 1234567891;
        List<BiometricDataBlock> subRecords = GetSubRecords();
        foreach (BiometricDataBlock record in subRecords)
        {
            result = record == null ? (3 * result) + 5 : 5 * (result + record.GetHashCode()) + 7;
        }
        result = ShouldAddRandomDataIfEmpty ? (13 * result) + 111 : (17 * result) + 123;
        return (7 * result) + 11;
    }

    /// <summary>
    /// Concrete implementations of EAC protected CBEFF DataGroups should call this method at the end of
    /// their <see cref="WriteContent"/> method to add some random data if the record contains zero
    /// biometric templates. See supplement to ICAO Doc 9303 R7-p1_v2_sIII_0057.
    /// </summary>
    protected void WriteOptionalRandomData(Stream outputStream)
    {
        if (_subRecords.Count != 0)
        {
            return;
        }

        using var tlvOut = new TlvOutputStream(outputStream, leaveOpen: true);
        tlvOut.WriteTag(ISO781611.DISCRETIONARY_DATA_FOR_PAYLOAD_TAG);
        byte[] value = new byte[8];
        _random.NextBytes(value);
        tlvOut.WriteValue(value);
    }

    /// <summary>Adds a record to this data group.</summary>
    private void Add(BiometricDataBlock record)
    {
        _subRecords ??= [];
        _subRecords.Add(record);
    }

    /// <summary>Adds all records in a list to this data group.</summary>
    private void AddAll(List<BiometricDataBlock> records)
    {
        _subRecords ??= [];
        _subRecords.AddRange(records);
    }
}
