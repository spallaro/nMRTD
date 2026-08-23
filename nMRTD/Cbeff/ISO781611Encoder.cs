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

namespace nMRTD.Cbeff;

/// <summary>
/// Port of <c>org.jmrtd.cbeff.ISO781611Encoder</c>: ISO 7816-11 encoder for a BIR (biometric information
/// record).
/// </summary>
/// <typeparam name="B">the biometric data block type to use</typeparam>
/// <remarks>
/// Java's <c>ISO781611Encoder</c> implements the <c>ISO781611</c> constants interface so its methods can
/// reference the tag constants unqualified; here they are qualified as <c>ISO781611.SOME_TAG</c> instead
/// (see <see cref="ISO781611"/>'s own remarks on why it is a static class rather than an interface).
///
/// Java's public <c>encode(CBEFFInfo, OutputStream)</c> accepts the raw (ungenerified) <c>CBEFFInfo</c>
/// supertype and dispatches at runtime via <c>instanceof</c> between a bare <c>SimpleCBEFFInfo</c> (wrapped
/// into a one-element list) and a <c>ComplexCBEFFInfo</c> (whose sub-record list is used directly). The
/// only real caller in the whole JMRTD codebase, <c>CBEFFDataGroup.writeContent</c>, always constructs and
/// passes a <c>ComplexCBEFFInfo</c> (even when there is exactly one biometric record) -- so this port's
/// <see cref="Encode"/> takes a <see cref="ComplexCBEFFInfo{B}"/> directly and skips the runtime dispatch,
/// matching the API shape <c>nMRTD.Lds.CBEFFDataGroup</c> (an earlier wave) already pins down.
/// </remarks>
public class ISO781611Encoder<B> where B : BiometricDataBlock
{
    /// <summary>
    /// Minimal write-only <see cref="Stream"/> adapter over a <see cref="TlvOutputStream"/>'s currently
    /// open tag frame. Needed because <see cref="BiometricDataBlockEncoder{B}"/> is defined in terms of a
    /// plain <see cref="Stream"/> while this class does all of its own TLV framing via
    /// <see cref="TlvOutputStream"/>, which -- unlike Java's <c>TLVOutputStream</c> (an <c>OutputStream</c>
    /// subclass) -- is not itself a <see cref="Stream"/> (see <see cref="TlvOutputStream"/>'s own class
    /// remarks). Bytes written here land in whatever frame is currently open on the wrapped
    /// <see cref="TlvOutputStream"/> (the BDB value frame, in this class's usage) -- <c>Write</c> is
    /// forwarded straight to <c>TlvOutputStream.Write</c>, which appends to that open frame's buffer
    /// rather than emitting to the underlying stream immediately, exactly matching what a direct write to
    /// Java's <c>TLVOutputStream</c> (used as a plain <c>OutputStream</c>) would do. A BDB encoder that
    /// itself needs to emit nested TLV structure (as JMRTD's ISO-39794 BDB encoders do, by casting the
    /// <c>OutputStream</c> parameter back to <c>TLVOutputStream</c>) does so here by wrapping this adapter
    /// in its own <c>new TlvOutputStream(stream, leaveOpen: true)</c> -- the natural translation of that
    /// Java "same object, two interfaces" idiom now that the two responsibilities are split into separate
    /// types.
    /// </summary>
    private sealed class BdbValueStream(TlvOutputStream tlvOut) : Stream
    {
        public override bool CanRead => false;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count) => tlvOut.Write(buffer, offset, count);

        public override void Flush() => tlvOut.Flush();

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();
    }

    private readonly BiometricDataBlockEncoder<B> _bdbEncoder;

    private readonly BiometricEncodingType _encodingType;

    /// <summary>Constructs an ISO7816-11 encoder that uses the given BDB encoder.</summary>
    /// <param name="bdbEncoder">the BDB encoder to use</param>
    public ISO781611Encoder(BiometricDataBlockEncoder<B> bdbEncoder)
    {
        _bdbEncoder = bdbEncoder;
        _encodingType = bdbEncoder.GetEncodingType();
    }

    /// <summary>Writes a BIT group to an output stream.</summary>
    /// <param name="cbeffInfo">a CBEFF info containing the BIT group</param>
    /// <param name="outputStream">the output stream to write to</param>
    public void Encode(ComplexCBEFFInfo<B> cbeffInfo, Stream outputStream)
    {
        WriteBitGroup(cbeffInfo.GetSubRecords(), outputStream);
    }

    /// <summary>Writes a BIT group to a stream.</summary>
    /// <param name="records">the records of the BIT group</param>
    /// <param name="outputStream">the stream to write to</param>
    private void WriteBitGroup(List<CBEFFInfo<B>> records, Stream outputStream)
    {
        /* NOTE: Java checks "outputStream instanceof TLVOutputStream" to avoid double-wrapping an
         * already-TLV stream. Not applicable here: TlvOutputStream is never itself a Stream in this port
         * (see its own class remarks), so a caller can never hand us one via the Stream-typed parameter --
         * always wrap fresh. */
        using var tlvOut = new TlvOutputStream(outputStream, leaveOpen: true);
        tlvOut.WriteTag(ISO781611.BIOMETRIC_INFORMATION_GROUP_TEMPLATE_TAG); /* 7F61 */
        tlvOut.WriteTag(ISO781611.BIOMETRIC_INFO_COUNT_TAG); /* 0x02 */
        int count = records.Count;
        tlvOut.WriteValue([(byte)count]);

        for (int index = 0; index < count; index++)
        {
            var simpleCbeffInfo = (SimpleCBEFFInfo<B>)records[index];
            WriteBit(tlvOut, index, simpleCbeffInfo);
        }
        tlvOut.WriteValueEnd(); /* BIOMETRIC_INFORMATION_GROUP_TEMPLATE_TAG, i.e. 7F61 */
    }

    /// <summary>Writes a single BIT to a stream.</summary>
    /// <param name="tlvOutputStream">the stream to write to</param>
    /// <param name="index">the index of the BIT within the BIT group</param>
    /// <param name="cbeffInfo">the BIT</param>
    private void WriteBit(TlvOutputStream tlvOutputStream, int index, SimpleCBEFFInfo<B> cbeffInfo)
    {
        tlvOutputStream.WriteTag(ISO781611.BIOMETRIC_INFORMATION_TEMPLATE_TAG); /* 7F60 */
        WriteBht(tlvOutputStream, index, cbeffInfo);
        WriteBiometricDataBlock(tlvOutputStream, cbeffInfo.GetBiometricDataBlock());
        tlvOutputStream.WriteValueEnd(); /* BIOMETRIC_INFORMATION_TEMPLATE_TAG, i.e. 7F60 */
    }

    /// <summary>Writes a header for a single BIT to a stream.</summary>
    /// <param name="tlvOutputStream">the stream to write to</param>
    /// <param name="index">the index of the BIT within the BIT group</param>
    /// <param name="cbeffInfo">the BIT to write</param>
    private void WriteBht(TlvOutputStream tlvOutputStream, int index, SimpleCBEFFInfo<B> cbeffInfo)
    {
        /* NOTE: preserved Java quirk -- the Java source has "+ index" commented out here; the BHT tag is
         * always the plain base tag (0xA1), never BASE_TAG + index as ISO 7816-11's "A1, A2, ..." template
         * numbering might suggest. Ported as-is (the & 0xFF is a no-op given the constant's value, kept
         * for fidelity). */
        tlvOutputStream.WriteTag(ISO781611.BIOMETRIC_HEADER_TEMPLATE_BASE_TAG /* + index */ & 0xFF); /* A1 */

        B bdb = cbeffInfo.GetBiometricDataBlock();

        /* SBH */
        StandardBiometricHeader sbh = bdb.GetStandardBiometricHeader();
        SortedDictionary<int, byte[]> elements = sbh.GetElements();
        foreach (KeyValuePair<int, byte[]> entry in elements)
        {
            tlvOutputStream.WriteTag(entry.Key);
            tlvOutputStream.WriteValue(entry.Value);
        }
        tlvOutputStream.WriteValueEnd(); /* BIOMETRIC_HEADER_TEMPLATE_BASE_TAG, i.e. A1 */
    }

    /// <summary>Writes the contents of a single BIT to a stream.</summary>
    /// <param name="tlvOutputStream">the stream to write to</param>
    /// <param name="bdb">the contents to write</param>
    private void WriteBiometricDataBlock(TlvOutputStream tlvOutputStream, B bdb)
    {
        tlvOutputStream.WriteTag(BiometricEncodingTypeCodec.ToBDBTag(_encodingType)); /* 5F2E or 7F2E */

        _bdbEncoder.Encode(bdb, new BdbValueStream(tlvOutputStream));
        tlvOutputStream.WriteValueEnd(); /* BIOMETRIC_DATA_BLOCK_TAG, i.e. 5F2E or 7F2E */
    }
}
