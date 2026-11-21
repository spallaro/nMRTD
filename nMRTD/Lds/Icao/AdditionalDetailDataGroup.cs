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

using System.Text;
using nMRTD.Lds;
using nMRTD.SmartCards;

namespace nMRTD.Lds.Icao;

/// <summary>
/// Port of <c>org.jmrtd.lds.icao.AdditionalDetailDataGroup</c>: abstract superclass for DG11 and DG12.
///
/// NOTE on an upstream JMRTD quirk preserved here: the Java <c>AdditionalDetailDataGroup(int tag)</c>
/// constructor ignores its <c>tag</c> parameter and always passes <c>EF_DG11_TAG</c> to the super
/// constructor (<c>public AdditionalDetailDataGroup(int tag) { super(EF_DG11_TAG); }</c>), so a
/// <c>DG12File</c> built from data starts out with the DG11 tag in its <c>tag</c> field. This has no
/// effect on the encoding: <c>DG11File</c> and <c>DG12File</c> override <c>GetTag()</c>, and
/// <c>AbstractTaggedLDSFile.WriteObject</c> writes (and stores) <c>GetTag()</c>, so a DG12 is always
/// written with tag <c>0x6C</c>, as in JMRTD. The stream constructor
/// (<see cref="AdditionalDetailDataGroup(int, Stream)"/>) forwards <c>tag</c> correctly.
/// </summary>
public abstract class AdditionalDetailDataGroup : DataGroup
{
    public const int TAG_LIST_TAG = 0x5C;

    /// <summary>5F0F is always used inside A0 constructed object.</summary>
    public const int CONTENT_SPECIFIC_CONSTRUCTED_TAG = 0xA0;

    /// <summary>Used in A0 constructed object to indicate single byte count of simple objects.</summary>
    public const int COUNT_TAG = 0x02;

    protected AdditionalDetailDataGroup(int tag)
        : base(LDSFile.EF_DG11_TAG)
    {
    }

    /// <summary>Constructs a file from binary representation.</summary>
    protected AdditionalDetailDataGroup(int tag, Stream inputStream)
        : base(tag, inputStream)
    {
    }

    /// <summary>Returns the list of tags of fields actually present.</summary>
    public abstract List<int> GetTagPresenceList();

    protected abstract void ReadField(int expectedTag, TlvInputStream tlvInputStream);

    protected abstract void WriteField(int tag, TlvOutputStream tlvOut);

    protected override void ReadContent(Stream inputStream)
    {
        using var tlvInputStream = new TlvInputStream(inputStream, leaveOpen: true);
        List<int> tagList = ReadTagList(tlvInputStream);
        /* Now read the fields in order. */
        foreach (int t in tagList)
        {
            ReadField(t, tlvInputStream);
        }
    }

    protected override void WriteContent(Stream outputStream)
    {
        using var tlvOut = new TlvOutputStream(outputStream, leaveOpen: true);
        List<int> tagList = GetTagPresenceList();
        WriteTagList(tagList, tlvOut);
        foreach (int tag in tagList)
        {
            WriteField(tag, tlvOut);
        }
    }

    protected static List<int> ReadTagList(TlvInputStream tlvInputStream)
    {
        int tagListTag = tlvInputStream.ReadTag();
        if (tagListTag != TAG_LIST_TAG)
        {
            throw new ArgumentException("Expected tag list in DG11");
        }

        int tagListLength = tlvInputStream.ReadLength();
        int tagListBytesRead = 0;

        byte[] tagListBytes = tlvInputStream.ReadValue();
        using var tagListBytesInputStream = new MemoryStream(tagListBytes, writable: false);

        /* Find out which tags are present. */
        var tagList = new List<int>();
        while (tagListBytesRead < tagListLength)
        {
            /* We're using another TLV inputstream every time to read each tag.
             * This is required by SCUBA's state machine, which doesn't allow
             * calling readTag() repeatedly on a single TLVInputStream. */
            using var anotherTlvInputStream = new TlvInputStream(tagListBytesInputStream, leaveOpen: true);
            int tag = anotherTlvInputStream.ReadTag();
            tagListBytesRead += TlvUtil.GetTagLength(tag);
            tagList.Add(tag);
        }
        return tagList;
    }

    protected static void WriteTagList(List<int> tags, TlvOutputStream tlvOut)
    {
        tlvOut.WriteTag(TAG_LIST_TAG);
        using var byteArrayOutputStream = new MemoryStream();
        foreach (int tag in tags)
        {
            /* NOTE: JMRTD writes each tag via a throwaway TLVOutputStream's writeTag() with no matching
             * writeValue(), relying on Java's TLVOutputStream emitting raw tag bytes immediately. Our
             * TlvOutputStream instead buffers a tag's frame until WriteValue/WriteValueEnd closes it (see
             * its own doc comment) -- an unclosed frame is discarded on Dispose, not flushed. So the
             * "encode just the tag, no length, no value" step here is done directly via the same
             * algorithm TlvUtil.TlvEncode itself uses for the tag portion, matching what ReadTagList
             * expects to read back (bare concatenated tag encodings, no length/value bytes). */
            byte[] tagBytes = EncodeTagOnly(tag);
            byteArrayOutputStream.Write(tagBytes, 0, tagBytes.Length);
        }
        tlvOut.WriteValue(byteArrayOutputStream.ToArray());
    }

    /// <summary>Encodes just the BER-TLV tag number as bytes (no length, no value) -- mirrors
    /// <c>TlvUtil</c>'s private tag-encoding algorithm, duplicated here since it isn't exposed publicly
    /// and this is the one call site in the LDS layer that legitimately needs a bare tag encoding.</summary>
    private static byte[] EncodeTagOnly(int tag)
    {
        int tagLength = TlvUtil.GetTagLength(tag);
        byte[] result = new byte[tagLength];
        for (int i = tagLength - 1, shift = 0; i >= 0; i--, shift += 8)
        {
            result[i] = (byte)((tag >> shift) & 0xFF);
        }
        return result;
    }

    protected static byte[] ReadBytes(TlvInputStream tlvInputStream) => tlvInputStream.ReadValue();

    protected static void WriteBytes(int tag, byte[]? value, TlvOutputStream tlvOut)
    {
        tlvOut.WriteTag(tag);
        tlvOut.WriteValue(value ?? []);
    }

    protected static string ReadString(TlvInputStream tlvIn)
    {
        byte[] value = tlvIn.ReadValue();
        return Encoding.UTF8.GetString(value).Trim();
    }

    protected static void WriteString(int tag, string? value, TlvOutputStream tlvOut)
        => WriteBytes(tag, value == null ? null : Encoding.UTF8.GetBytes(value.Trim()), tlvOut);

    protected static string ReadFullDate(TlvInputStream tlvInputStream)
    {
        byte[] value = tlvInputStream.ReadValue();
        if (value.Length == 4)
        {
            /* Either France or Belgium uses this encoding for dates. */
            return Hex.BytesToHexString(value);
        }

        /* Assume length 8 yyyyMMdd as per spec, or whatever was put in. */
        return Encoding.UTF8.GetString(value);
    }

    protected static string ReadFullDateTime(TlvInputStream tlvInputStream)
    {
        byte[] value = tlvInputStream.ReadValue();
        if (value.Length == 7)
        {
            /* Bosnia apparently uses this encoding for dates. */
            return Hex.BytesToHexString(value);
        }

        /* Assume length 8 yyyyMMddHHmmss as per spec, or whatever was put in. */
        return Encoding.UTF8.GetString(value);
    }

    protected static List<string> ReadContentSpecificFieldsList(TlvInputStream tlvInputStream)
    {
        int countTag = tlvInputStream.ReadTag();
        if (countTag != COUNT_TAG)
        {
            throw new ArgumentException($"Expected {COUNT_TAG:X}, found {countTag:X}");
        }
        int countLength = tlvInputStream.ReadLength();
        if (countLength != 1)
        {
            throw new ArgumentException($"Expected length 1 count length, found {countLength}");
        }
        byte[] countValue = tlvInputStream.ReadValue();
        if (countValue.Length != 1)
        {
            throw new ArgumentException($"Number of content specific fields should be encoded in single byte, found {string.Join(",", countValue)}");
        }
        int count = countValue[0] & 0xFF;
        var list = new List<string>(count);
        for (int i = 0; i < count; i++)
        {
            tlvInputStream.ReadTag();
            tlvInputStream.ReadLength();
            list.Add(ReadString(tlvInputStream));
        }
        return list;
    }

    protected static void WriteContentSpecificFieldsList(int tag, List<string>? list, TlvOutputStream tlvOut)
    {
        list ??= [];
        tlvOut.WriteTag(CONTENT_SPECIFIC_CONSTRUCTED_TAG);
        tlvOut.WriteTag(COUNT_TAG);
        tlvOut.Write([(byte)list.Count]);
        tlvOut.WriteValueEnd(); /* COUNT_TAG */
        foreach (string otherName in list)
        {
            tlvOut.WriteTag(tag);
            tlvOut.WriteValue(Encoding.UTF8.GetBytes(otherName.Trim()));
        }
        tlvOut.WriteValueEnd(); /* CONTENT_SPECIFIC_CONSTRUCTED_TAG */
    }

    protected static List<string> ReadList(TlvInputStream tlvInputStream)
    {
        string field = ReadString(tlvInputStream);
        var list = new List<string>();
        foreach (string token in field.Split('<'))
        {
            list.Add(token.Trim());
        }
        return list;
    }

    protected static void WriteList(int tag, List<string>? list, TlvOutputStream tlvOut)
    {
        tlvOut.WriteTag(tag);
        if (list == null || list.Count == 0)
        {
            tlvOut.WriteValue([]);
        }
        else
        {
            var encodedString = new StringBuilder();
            bool isFirstOne = true;
            foreach (string? detail in list)
            {
                if (isFirstOne)
                {
                    isFirstOne = false;
                }
                else
                {
                    encodedString.Append('<');
                }
                encodedString.Append(detail == null ? "" : detail.Trim());
            }
            tlvOut.WriteValue(Encoding.UTF8.GetBytes(encodedString.ToString()));
        }
    }
}
