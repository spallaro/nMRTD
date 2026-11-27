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

using nMRTD.Lds;
using nMRTD.SmartCards;

namespace nMRTD.Lds.Icao;

/// <summary>
/// Port of <c>org.jmrtd.lds.icao.DG1File</c>: file structure for the EF.DG1 file. Data group 1 contains
/// the Machine Readable Zone information.
/// </summary>
public class DG1File : DataGroup
{
    private const short MRZ_INFO_TAG = 0x5F1F;

    /// <remarks>
    /// Deliberately given an inline <c>null!</c> initializer rather than being left assigned only in the
    /// constructor bodies below: for the "parse from stream" constructor, the base <c>DataGroup</c>
    /// constructor invokes <see cref="ReadContent"/> virtually (which sets this field) before this
    /// derived class's own field initializers or constructor body run -- but derived-class field
    /// initializers themselves run *before* the base constructor call, not after (confirmed empirically;
    /// this is not the C#-textbook-obvious ordering), so this initializer is harmless -- it merely
    /// establishes the value the compiler's definite-assignment analysis expects before ReadContent
    /// overwrites it moments later. Matches the identical pattern/reasoning in <c>CBEFFDataGroup.cs</c>'s
    /// <c>_subRecords</c> field. Do NOT move this null-assignment into the stream constructor's body: a
    /// bare `mrzInfo = null!;` there would run *after* ReadContent and silently wipe out the parsed MRZ
    /// (this was a real, shipped bug caught via real-hardware testing -- DG1 parsed successfully but
    /// GetMRZInfo() always returned null).
    /// </remarks>
    private MRZInfo mrzInfo = null!;

    /// <summary>Creates a new file based on MRZ information.</summary>
    public DG1File(MRZInfo mrzInfo)
        : base(LDSFileTags.EF_DG1_TAG)
    {
        this.mrzInfo = mrzInfo;
    }

    /// <summary>Creates a new file based on an input stream.</summary>
    public DG1File(Stream inputStream)
        : base(LDSFileTags.EF_DG1_TAG, inputStream)
    {
        // mrzInfo is assigned by ReadContent, invoked (virtually) from the base constructor above,
        // before this body runs -- see the field's own doc comment for why nothing more is needed here.
    }

    protected override void ReadContent(Stream inputStream)
    {
        using var tlvIn = new TlvInputStream(inputStream, leaveOpen: true);
        tlvIn.SkipToTag(MRZ_INFO_TAG);
        int length = tlvIn.ReadLength();
        byte[] value = tlvIn.ReadValue();
        try
        {
            mrzInfo = new MRZInfo(new MemoryStream(value, writable: false), length);
        }
        catch (ArgumentException e)
        {
            // An MRZ of an unsupported length is malformed (JMRTD 0.8.10, 737881b8).
            throw new IOException("Malformed MRZ", e);
        }
    }

    /// <summary>Returns the MRZ information stored in this file.</summary>
    public MRZInfo GetMRZInfo() => mrzInfo;

    public override string ToString() => "DG1File " + mrzInfo.ToString().Replace("\n", "").Trim();

    public override bool Equals(object? obj)
    {
        if (obj == null)
        {
            return false;
        }
        if (obj.GetType() != GetType())
        {
            return false;
        }

        var other = (DG1File)obj;
        return mrzInfo.Equals(other.mrzInfo);
    }

    public override int GetHashCode() => 3 * mrzInfo.GetHashCode() + 57;

    protected override void WriteContent(Stream outputStream)
    {
        using var tlvOut = new TlvOutputStream(outputStream, leaveOpen: true);
        tlvOut.WriteTag(MRZ_INFO_TAG);
        byte[] value = mrzInfo.GetEncoded() ?? [];
        tlvOut.WriteValue(value);
    }
}
