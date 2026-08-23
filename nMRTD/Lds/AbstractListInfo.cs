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

namespace nMRTD.Lds;

/// <summary>Port of <c>org.jmrtd.lds.AbstractListInfo&lt;R&gt;</c>: abstract base class for several data
/// structures used in the LDS containing a list of elements.
///
/// NOTE: the Java type parameter is bounded by <c>Serializable</c>; that bound is dropped here since
/// nMRTD does not need Java-style binary serialization (per porting conventions).</summary>
/// <typeparam name="TRecord">the type of the elements</typeparam>
public abstract class AbstractListInfo<TRecord> : AbstractLDSInfo
{
    private List<TRecord>? subRecords;

    /// <summary>Returns the sub-records of this list.</summary>
    protected List<TRecord> GetSubRecords()
    {
        subRecords ??= [];
        return [.. subRecords];
    }

    /// <summary>Adds a sub-record to this list.</summary>
    protected void Add(TRecord subRecord)
    {
        subRecords ??= [];
        subRecords.Add(subRecord);
    }

    /// <summary>Adds all sub-records in a collection.</summary>
    protected void AddAll(List<TRecord> subRecords)
    {
        this.subRecords ??= [];
        this.subRecords.AddRange(subRecords);
    }

    /// <summary>Removes a sub-record at a given index.</summary>
    protected void Remove(int index)
    {
        subRecords ??= [];
        subRecords.RemoveAt(index);
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
        if (other is not AbstractListInfo<TRecord> otherRecord)
        {
            return false;
        }

        List<TRecord> records = GetSubRecords();
        List<TRecord> otherRecords = otherRecord.GetSubRecords();
        int subRecordCount = records.Count;
        if (subRecordCount != otherRecords.Count)
        {
            return false;
        }

        for (int i = 0; i < subRecordCount; i++)
        {
            TRecord subRecord = records[i];
            TRecord otherSubRecord = otherRecords[i];
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
        List<TRecord> records = GetSubRecords();
        foreach (TRecord record in records)
        {
            result = record == null ? 3 * result + 5 : 5 * (result + record.GetHashCode()) + 7;
        }
        return 7 * result + 11;
    }

    /// <summary>Reads this value from a stream.</summary>
    public abstract void ReadObject(Stream inputStream);
}
