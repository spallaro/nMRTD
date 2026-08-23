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

namespace nMRTD.Cbeff;

/// <summary>
/// Port of <c>org.jmrtd.cbeff.ComplexCBEFFInfo</c>: complex (nested) CBEFF BIR. Specified in ISO
/// 19785-1 (version 2.0) and NISTIR 6529-A (version 1.1).
/// </summary>
/// <typeparam name="R">the type of biometric data block referenced by the sub-records</typeparam>
public class ComplexCBEFFInfo<R> : CBEFFInfo<R> where R : BiometricDataBlock
{
    private readonly List<CBEFFInfo<R>> _subRecords;

    /// <summary>Constructs a default complex info, with an empty list of sub-records.</summary>
    public ComplexCBEFFInfo()
    {
        _subRecords = [];
    }

    /// <summary>Returns the records inside this complex CBEFF info.</summary>
    /// <returns>a list of CBEFF infos</returns>
    public List<CBEFFInfo<R>> GetSubRecords() => [.. _subRecords];

    /// <summary>Adds a record to this complex CBEFF info.</summary>
    /// <param name="subRecord">the CBEFF info to add</param>
    public void Add(CBEFFInfo<R> subRecord) => _subRecords.Add(subRecord);

    /// <summary>Adds all records in a list to this complex CBEFF info.</summary>
    /// <param name="subRecords">a list of CBEFF infos</param>
    public void AddAll(List<CBEFFInfo<R>> subRecords) => _subRecords.AddRange(subRecords);

    /// <summary>Removes a record in this complex CBEFF info.</summary>
    /// <param name="index">the index of the CBEFF info to remove</param>
    public void Remove(int index) => _subRecords.RemoveAt(index);

    /// <summary>Tests whether the parameter equals this complex CBEFF info.</summary>
    /// <param name="other">some other object</param>
    /// <returns>whether the other object is equal to this complex CBEFF info</returns>
    /* NOTE: Java's version compares raw `other.getClass().equals(ComplexCBEFFInfo.class)`, which -- due
     * to Java generic type erasure -- treats ComplexCBEFFInfo<X> and ComplexCBEFFInfo<Y> as the exact
     * same runtime class regardless of X/Y, so two instances with different type arguments can compare
     * equal as long as their sub-record lists are equal. C# generics are reified (not erased), so
     * `GetType()` naturally distinguishes ComplexCBEFFInfo<X> from ComplexCBEFFInfo<Y>; the `is
     * ComplexCBEFFInfo<R>` pattern below only matches the same R as `this`, which is the closest sound
     * equivalent and the only one expressible without reflection tricks. */
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
        if (other is not ComplexCBEFFInfo<R> otherRecord)
        {
            return false;
        }

        return _subRecords.SequenceEqual(otherRecord.GetSubRecords());
    }

    /// <summary>Computes a hash code.</summary>
    /// <returns>the hash code for this complex CBEFF info</returns>
    public override int GetHashCode() => (7 * JavaListHashCode(_subRecords)) + 11;

    /* Java's java.util.List.hashCode() contract is content-based (1, then 31*hash + element.hashCode()
     * per element, in order), unlike C#'s List<T>.GetHashCode() which is identity-based. Replicating the
     * Java List contract here so that Equals()-equal instances also produce equal hash codes (unlike the
     * genuine equals/hashCode bug preserved in StandardBiometricHeader, getting this wrong here would be
     * a *new* bug of the C# port's own making, not a faithful translation of Java's well-defined List
     * semantics). */
    private static int JavaListHashCode(List<CBEFFInfo<R>> list)
    {
        int hash = 1;
        foreach (CBEFFInfo<R> element in list)
        {
            hash = (31 * hash) + (element?.GetHashCode() ?? 0);
        }
        return hash;
    }
}
