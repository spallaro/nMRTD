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
/// Port of <c>org.jmrtd.cbeff.ISO781611Decoder</c>: ISO 7816-11 decoder for a BIR (biometric information
/// record).
/// </summary>
/// <typeparam name="B">the biometric data block type to use</typeparam>
/// <remarks>
/// Java's <c>ISO781611Decoder</c> implements the <c>ISO781611</c> constants interface so its methods can
/// reference the tag constants unqualified; here they are qualified as <c>ISO781611.SOME_TAG</c> instead
/// (see <see cref="ISO781611"/>'s own remarks on why it is a static class rather than an interface).
///
/// Unlike the encoder's <c>TlvOutputStream</c>/<see cref="Stream"/> split (see
/// <see cref="ISO781611Encoder{B}"/>'s remarks), the decoder side needs no adapter: <see cref="TlvInputStream"/>
/// never buffers ahead of what a caller explicitly requests, so after a <c>TlvInputStream</c> wrapping some
/// <see cref="Stream"/> reads a tag and length, that same underlying <see cref="Stream"/> is already
/// correctly positioned at the start of the value bytes and can be handed straight to a
/// <see cref="BiometricDataBlockDecoder{B}"/> (which expects a plain <see cref="Stream"/>), exactly as Java
/// hands the shared <c>InputStream</c>/<c>TLVInputStream</c> instance straight to <c>bdbDecoder.decode</c>.
/// </remarks>
public class ISO781611Decoder<B> where B : BiometricDataBlock
{
    private readonly IDictionary<int, BiometricDataBlockDecoder<B>> _bdbDecoders;

    private BiometricEncodingType _encodingType;

    /// <summary>Constructs an ISO7816-11 decoder that uses the given BDB decoder.</summary>
    /// <param name="bdbDecoder">the BDB decoder to use</param>
    public ISO781611Decoder(BiometricDataBlockDecoder<B> bdbDecoder)
        : this(ToMap(bdbDecoder))
    {
    }

    /// <summary>Constructs an ISO7816-11 decoder that dispatches per biometric data block tag.</summary>
    /// <param name="bdbDecoders">a map from biometric data block tag (<c>0x5F2E</c> or <c>0x7F2E</c>) to the BDB decoder to use for that tag</param>
    public ISO781611Decoder(IDictionary<int, BiometricDataBlockDecoder<B>> bdbDecoders)
    {
        _bdbDecoders = bdbDecoders;
    }

    /// <summary>Reads a BIT group from an input stream.</summary>
    /// <param name="inputStream">the input stream to read from</param>
    /// <returns>a complex CBEFF info representing the BIT group</returns>
    public ComplexCBEFFInfo<B> Decode(Stream inputStream) => ReadBitGroup(inputStream);

    public BiometricEncodingType GetEncodingType() => _encodingType;

    /// <summary>Reads a BIT group from an input stream.</summary>
    /// <param name="inputStream">the input stream to read from</param>
    /// <returns>a complex CBEFF info representing the BIT group</returns>
    private ComplexCBEFFInfo<B> ReadBitGroup(Stream inputStream)
    {
        using var tlvIn = new TlvInputStream(inputStream, leaveOpen: true);
        int tag = tlvIn.ReadTag();
        if (tag != ISO781611.BIOMETRIC_INFORMATION_GROUP_TEMPLATE_TAG)
        {
            throw new ArgumentException($"Expected tag {ISO781611.BIOMETRIC_INFORMATION_GROUP_TEMPLATE_TAG:x}, found {tag:x}");
        }

        int length = tlvIn.ReadLength();
        return ReadBitGroup(tag, length, inputStream);
    }

    /// <summary>Reads a BIT group value from an input stream.</summary>
    /// <param name="tag">the tag that was already read, which should be a BIT group tag (<c>7F61</c>)</param>
    /// <param name="length">the length that was already read</param>
    /// <param name="inputStream">the input stream from which to read the value</param>
    /// <returns>CBEFF info representing the BIT group that was read</returns>
    private ComplexCBEFFInfo<B> ReadBitGroup(int tag, int length, Stream inputStream)
    {
        using var tlvIn = new TlvInputStream(inputStream, leaveOpen: true);
        var result = new ComplexCBEFFInfo<B>();
        if (tag != ISO781611.BIOMETRIC_INFORMATION_GROUP_TEMPLATE_TAG) /* 7F61 */
        {
            throw new ArgumentException($"Expected tag {ISO781611.BIOMETRIC_INFORMATION_GROUP_TEMPLATE_TAG:x}, found {tag:x}");
        }

        int bitCountTag = tlvIn.ReadTag();
        if (bitCountTag != ISO781611.BIOMETRIC_INFO_COUNT_TAG) /* 02 */
        {
            throw new ArgumentException($"Expected tag BIOMETRIC_INFO_COUNT_TAG ({ISO781611.BIOMETRIC_INFO_COUNT_TAG:x}) in CBEFF structure, found {bitCountTag:x}");
        }

        int bitCountLength = tlvIn.ReadLength();
        if (bitCountLength != 1)
        {
            throw new ArgumentException($"BIOMETRIC_INFO_COUNT should have length 1, found length {bitCountLength}");
        }

        int bitCount = tlvIn.ReadValue()[0] & 0xFF;
        for (int i = 0; i < bitCount; i++)
        {
            /* NOTE: preserved Java quirk -- for a statically-protected BIT (see ReadBit's SMT_TAG branch),
             * ReadBit returns null, and Java unconditionally adds that null into the result's sub-records
             * list with no null check (Java: "result.add(readBIT(inputStream, i));"). So a decoded BIT
             * group containing a statically-protected BIT ends up with a literal null entry in its
             * sub-records list. JMRTD's own comment on readBIT ("FIXME: return type???") flags this as an
             * acknowledged rough edge, not an intentional design; preserved here rather than "fixed",
             * since CBEFFDataGroup.ReadContent (the sole real caller) would encounter the same failure
             * mode either way -- it throws on any non-SimpleCBEFFInfo record, null included. */
            result.Add(ReadBit(inputStream, i)!);
        }

        /* TODO: possibly more content, e.g. 0x53 tag with random as per ICAO 9303 Supplement R7-p1_v2_sIII_0057 */

        return result;
    }

    /// <summary>Reads a single BIT from the input stream.</summary>
    /// <param name="inputStream">the input stream to read from</param>
    /// <param name="index">index of this BIT within the BIT group</param>
    /// <returns>a CBEFF info representing the BIT</returns>
    private SimpleCBEFFInfo<B>? ReadBit(Stream inputStream, int index)
    {
        using var tlvIn = new TlvInputStream(inputStream, leaveOpen: true);
        int tag = tlvIn.ReadTag();
        int length = tlvIn.ReadLength();
        return ReadBit(tag, length, inputStream, index);
    }

    /// <summary>Reads a single BIT from the input stream.</summary>
    /// <param name="tag">the tag that was already read</param>
    /// <param name="length">the length that was already read (unused, kept for signature parity with the Java source)</param>
    /// <param name="inputStream">the stream to read the BIT value from</param>
    /// <param name="index">the index of the BIT within the BIT group</param>
    /// <returns>a CBEFF info representing the BIT, or <c>null</c> for a statically-protected BIT (see remarks on <see cref="ReadBitGroup(int, int, Stream)"/>)</returns>
    private SimpleCBEFFInfo<B>? ReadBit(int tag, int length, Stream inputStream, int index)
    {
        if (tag != ISO781611.BIOMETRIC_INFORMATION_TEMPLATE_TAG /* 7F60 */)
        {
            throw new ArgumentException($"Expected tag BIOMETRIC_INFORMATION_TEMPLATE_TAG ({ISO781611.BIOMETRIC_INFORMATION_TEMPLATE_TAG:x}), found {tag:x}, index is {index}");
        }

        using var tlvIn = new TlvInputStream(inputStream, leaveOpen: true);
        int bhtTag = tlvIn.ReadTag();
        int bhtLength = tlvIn.ReadLength();

        if (bhtTag == ISO781611.SMT_TAG)
        {
            /* The BIT is protected... */
            ReadStaticallyProtectedBIT(inputStream, bhtTag, bhtLength, index);
        }
        else if ((bhtTag & 0xA0) == 0xA0)
        {
            StandardBiometricHeader sbh = ReadBht(inputStream, bhtTag, bhtLength, index);
            B bdb = ReadBiometricDataBlock(inputStream, sbh, index);
            return new SimpleCBEFFInfo<B>(bdb);
        }
        else
        {
            throw new ArgumentException($"Unsupported template tag: {bhtTag:x}");
        }

        return null; // FIXME
    }

    /// <summary>
    /// Reads the biometric header template from an input stream. A1, A2, ... Will contain DOs as described
    /// in ISO 7816-11 Annex C.
    /// </summary>
    /// <param name="inputStream">the stream to read from</param>
    /// <param name="bhtTag">the tag of the biometric header</param>
    /// <param name="bhtLength">the length of the header</param>
    /// <param name="index">the index</param>
    /// <returns>the standard biometric header</returns>
    private static StandardBiometricHeader ReadBht(Stream inputStream, int bhtTag, int bhtLength, int index)
    {
        using var tlvIn = new TlvInputStream(inputStream, leaveOpen: true);
        int expectedBhtTag = ISO781611.BIOMETRIC_HEADER_TEMPLATE_BASE_TAG /* + index */ & 0xFF;
        if (bhtTag != expectedBhtTag)
        {
            // NOTE: Java logs a warning here; omitted per precedent.
        }

        var elements = new Dictionary<int, byte[]>();
        int bytesRead = 0;
        while (bytesRead < bhtLength)
        {
            int tag = tlvIn.ReadTag();
            bytesRead += TlvUtil.GetTagLength(tag);
            int length = tlvIn.ReadLength();
            bytesRead += TlvUtil.GetLengthLength(length);
            byte[] value = tlvIn.ReadValue();
            bytesRead += value.Length;
            elements[tag] = value;
        }

        return new StandardBiometricHeader(elements);
    }

    /// <summary>Reads a biometric information template protected with secure messaging. Described in ISO7816-11 Annex D.</summary>
    /// <param name="inputStream">source to read from</param>
    /// <param name="tag">should be <c>0x7D</c></param>
    /// <param name="length">the length of the BIT</param>
    /// <param name="index">index of the template</param>
    private void ReadStaticallyProtectedBIT(Stream inputStream, int tag, int length, int index)
    {
        /* NOTE: preserved Java quirk -- if decodeSMTValue returns null (the SMT_DO_CC/SMT_DO_DS/default
         * branches below), Java wraps it straight into "new ByteArrayInputStream(null)", which throws a
         * NullPointerException. The closest faithful C# equivalent is letting MemoryStream's constructor
         * throw ArgumentNullException on a null buffer -- not special-cased away, since a real decoder for
         * a statically-protected BIT with an unsupported/encrypted payload is expected to fail loudly here
         * in both languages, not silently produce a half-built result. */
        byte[]? bhtValue = DecodeSMTValue(inputStream);
        using var bhtStream = new MemoryStream(bhtValue!, writable: false);
        using var tlvBhtIn = new TlvInputStream(bhtStream, leaveOpen: true);
        int headerTemplateTag = tlvBhtIn.ReadTag();
        int headerTemplateLength = tlvBhtIn.ReadLength();
        StandardBiometricHeader sbh = ReadBht(bhtStream, headerTemplateTag, headerTemplateLength, index);

        byte[]? bdbValue = DecodeSMTValue(inputStream);
        using var biometricDataBlockIn = new MemoryStream(bdbValue!, writable: false);
        ReadBiometricDataBlock(biometricDataBlockIn, sbh, index);
    } /* FIXME: return type??? */

    /// <summary>Decodes a (protected) data object. Encrypted payloads are not currently supported.</summary>
    /// <param name="inputStream">the stream to read from</param>
    /// <returns>the decoded value</returns>
    private static byte[]? DecodeSMTValue(Stream inputStream)
    {
        using var tlvIn = new TlvInputStream(inputStream, leaveOpen: true);
        int doTag = tlvIn.ReadTag();
        int doLength = tlvIn.ReadLength();
        switch (doTag)
        {
            case ISO781611.SMT_DO_PV: /* 0x81 */
                /* NOTE: Plain value, just return whatever is in the payload */
                return tlvIn.ReadValue();
            case ISO781611.SMT_DO_CG: /* 0x85 */
                /* NOTE: content of payload is encrypted */
                throw new InvalidOperationException("Access denied. Biometric Information Template is statically protected.");
            case ISO781611.SMT_DO_CC: /* 0x8E */
            {
                /* NOTE: payload contains a MAC */
                // Not a loop around Skip, which looped forever on a truncated stream (JMRTD 0.8.10, a4b9e9e2).
                Io.InputStreams.SkipFully(tlvIn.Skip, doLength);
                return null;
            }

            case ISO781611.SMT_DO_DS: /* 0x9E */
            {
                /* NOTE: payload contains a signature */
                Io.InputStreams.SkipFully(tlvIn.Skip, doLength);
                return null;
            }

            default:
                // NOTE: Java logs an info message here; omitted per precedent.
                return null;
        }
    }

    /// <summary>Reads a biometric data block from an input stream.</summary>
    /// <param name="inputStream">the stream to read from</param>
    /// <param name="sbh">the biometric header that was already read</param>
    /// <param name="index">the index of the biometric data block within the BIT group</param>
    /// <returns>the biometric data block</returns>
    private B ReadBiometricDataBlock(Stream inputStream, StandardBiometricHeader sbh, int index)
    {
        using var tlvIn = new TlvInputStream(inputStream, leaveOpen: true);
        int bioDataBlockTag = tlvIn.ReadTag();
        if (bioDataBlockTag != ISO781611.BIOMETRIC_DATA_BLOCK_TAG /* 5F2E */
            && bioDataBlockTag != ISO781611.BIOMETRIC_DATA_BLOCK_CONSTRUCTED_TAG /* 7F2E */)
        {
            throw new ArgumentException(
                $"Expected tag BIOMETRIC_DATA_BLOCK_TAG ({ISO781611.BIOMETRIC_DATA_BLOCK_TAG:x}) or BIOMETRIC_DATA_BLOCK_CONSTRUCTED_ALT ({ISO781611.BIOMETRIC_DATA_BLOCK_CONSTRUCTED_TAG:x}), found {bioDataBlockTag:x}");
        }

        _encodingType = BiometricEncodingTypeCodec.FromBDBTag(bioDataBlockTag);
        int length = tlvIn.ReadLength();
        if (!_bdbDecoders.TryGetValue(bioDataBlockTag, out BiometricDataBlockDecoder<B>? bdbDecoder) || bdbDecoder == null)
        {
            throw new ArgumentException($"No decoder for biometric data block tag {bioDataBlockTag:x}");
        }

        return bdbDecoder.Decode(inputStream, sbh, index, length);
    }

    private static Dictionary<int, BiometricDataBlockDecoder<B>> ToMap(BiometricDataBlockDecoder<B> bdbDecoder)
    {
        return new Dictionary<int, BiometricDataBlockDecoder<B>>
        {
            [ISO781611.BIOMETRIC_DATA_BLOCK_TAG] = bdbDecoder, /* 5F2E */
            [ISO781611.BIOMETRIC_DATA_BLOCK_CONSTRUCTED_TAG] = bdbDecoder, /* 7F2E */
        };
    }
}
