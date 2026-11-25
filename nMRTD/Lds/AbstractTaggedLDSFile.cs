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

using nMRTD.SmartCards;

namespace nMRTD.Lds;

/// <summary>Port of <c>org.jmrtd.lds.AbstractTaggedLDSFile</c>: base class for TLV based LDS files.</summary>
public abstract class AbstractTaggedLDSFile : AbstractLDSFile
{
    private int tag;
    /// <summary>The length of the value, -1 while not yet known. A length of 0 read from the input is a valid
    /// length (JMRTD 0.8.10, cf340d7d).</summary>
    private int length = -1;

    /// <summary>Constructs a data group. This constructor is only visible to other classes in this
    /// namespace, mirroring the Java <c>protected</c> visibility.</summary>
    /// <param name="dataGroupTag">data group tag</param>
    protected AbstractTaggedLDSFile(int dataGroupTag)
    {
        tag = dataGroupTag;
    }

    /// <summary>Constructs a data group from the DER encoded data in the given input stream.</summary>
    /// <param name="tag">the tag</param>
    /// <param name="inputStream">an input stream</param>
    protected AbstractTaggedLDSFile(int tag, Stream inputStream)
    {
        this.tag = tag;
        ReadObject(inputStream);
    }

    /// <summary>Reads the contents of this LDS file, including tag and length, from an input stream.</summary>
    /// <remarks>
    /// Java's <c>TLVInputStream extends InputStream</c>, so <c>readContent(tlvIn)</c> hands subclasses the
    /// same <c>TLVInputStream</c> this method already opened, and subclasses detect that ("instanceof
    /// TLVInputStream") to avoid double-wrapping. Our <see cref="TlvInputStream"/> does not extend
    /// <see cref="Stream"/> (see its own doc comment), so that reuse trick doesn't carry over structurally;
    /// instead <see cref="ReadContent"/> receives the original <paramref name="inputStream"/> (whose
    /// position <see cref="TlvInputStream"/> has already advanced past the tag/length octets, since it reads
    /// byte-by-byte with no internal buffering) and wraps it in its own fresh <see cref="TlvInputStream"/>,
    /// same as every already-ported subclass (e.g. <c>COMFile.ReadContent</c>) already does.
    /// </remarks>
    protected override void ReadObject(Stream inputStream)
    {
        var tlvIn = new TlvInputStream(inputStream, leaveOpen: true);
        try
        {
            int inputTag = tlvIn.ReadTag();
            if (inputTag != tag)
            {
                throw new ArgumentException($"Was expecting tag {tag:x}, found {inputTag:x}");
            }
            length = tlvIn.ReadLength();
            ReadContent(inputStream);
        }
        finally
        {
            tlvIn.Dispose();
        }
    }

    /// <summary>Writes the tag, length, and content of this LDS file to an output stream.</summary>
    protected override void WriteObject(Stream outputStream)
    {
        var tlvOut = new TlvOutputStream(outputStream, leaveOpen: true);
        try
        {
            int ourTag = GetTag();
            if (tag != ourTag)
            {
                tag = ourTag;
            }
            tlvOut.WriteTag(ourTag);
            byte[] value = GetContent();
            int ourLength = value.Length;
            if (length != ourLength)
            {
                length = ourLength;
            }
            tlvOut.WriteValue(value);
        }
        finally
        {
            tlvOut.Dispose();
        }
    }

    /// <summary>Reads the contents of the data group from an input stream. Client code implementing this
    /// method should only read the contents from the input stream, not the tag or length of the data
    /// group.</summary>
    protected abstract void ReadContent(Stream inputStream);

    /// <summary>Writes the contents of the data group to an output stream. Client code implementing this
    /// method should only write the contents to the output stream, not the tag or length of the data
    /// group.</summary>
    protected abstract void WriteContent(Stream outputStream);

    /// <summary>Returns a textual representation of this file.</summary>
    public override string ToString() => $"TaggedLDSFile [{GetTag():x} ({GetLength()})]";

    /// <summary>Returns the tag that identifies this LDS file. Not <c>sealed</c> because at least one
    /// concrete <c>nMRTD.Lds.Icao</c> subclass hides this with a hardcoded value (mirroring a JMRTD
    /// quirk, see <c>AdditionalDetailDataGroup</c>'s doc comment).</summary>
    public virtual int GetTag() => tag;

    /// <summary>The length of the value of the data group.</summary>
    public override int GetLength()
    {
        if (length < 0)
        {
            length = GetContent().Length;
        }
        return length;
    }

    /// <summary>Returns the value part of this LDS file.</summary>
    private byte[] GetContent()
    {
        using var outputStream = new MemoryStream();
        WriteContent(outputStream);
        outputStream.Flush();
        return outputStream.ToArray();
    }
}
