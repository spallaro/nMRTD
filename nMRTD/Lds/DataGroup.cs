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

/// <summary>Port of <c>org.jmrtd.lds.DataGroup</c>: base class for data group files.</summary>
public abstract class DataGroup : AbstractTaggedLDSFile
{
    /// <summary>Constructs a data group. This constructor is only visible to other classes in this
    /// namespace, mirroring the Java <c>protected</c> visibility.</summary>
    /// <param name="dataGroupTag">data group tag</param>
    protected DataGroup(int dataGroupTag)
        : base(dataGroupTag)
    {
    }

    /// <summary>Constructs a data group from the DER encoded data in the given input stream. Tag and
    /// length are read, so the input stream is positioned just before the value.</summary>
    /// <param name="dataGroupTag">data group tag</param>
    /// <param name="inputStream">an input stream</param>
    protected DataGroup(int dataGroupTag, Stream inputStream)
        : base(dataGroupTag, inputStream)
    {
    }

    /// <summary>Returns a textual representation of this file.</summary>
    public override string ToString() => $"DataGroup [{GetTag():x} ({GetLength()})]";
}
