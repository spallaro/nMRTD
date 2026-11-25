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

using nMRTD.Cert;

namespace nMRTD.Lds;

// NOTE: PassportService.EF_CVCA (used below) is a forward reference to nMRTD.PassportService, a large
// not-yet-ported file outside the scope of this porting task. This mirrors the pattern already
// established by the committed DefaultFileSystem.cs, which forward-references
// PassportService.ExtendedMaxTransceiveLength/DefaultMaxBlocksize the same way.

/// <summary>
/// Port of <c>org.jmrtd.lds.CVCAFile</c>: file structure for the EF.CVCA file (on EAC protected
/// documents). Unlike the other LDS files, this is a fixed-length, non-BER-TLV structure: two
/// (optionally one) CAR-tagged (<c>0x42</c>) reference fields followed by <c>0x00</c> padding, in a
/// fixed 36-byte file.
/// </summary>
/// <remarks>
/// <c>CarTag</c> and <c>Length</c> are referenced by the already-committed <c>DefaultFileSystem.cs</c>
/// (<c>Lds.CVCAFile.CarTag</c>, <c>Lds.CVCAFile.Length</c>) so their names and public/static-const
/// visibility are load-bearing, not a free naming choice.
/// </remarks>
public class CVCAFile : AbstractLDSFile
{
    public const int CarTag = 0x42;

    public const int Length = 36;

    private short _fid;

    private string _caReference = null!;

    private string? _altCaReference;

    /// <summary>Constructs a CVCA file by reading from a stream, using the default EF.CVCA file identifier.</summary>
    public CVCAFile(Stream inputStream)
        : this(PassportService.EF_CVCA, inputStream)
    {
    }

    /// <summary>Constructs a new CVCA file from the data contained in an input stream.</summary>
    /// <param name="fid">file identifier</param>
    /// <param name="inputStream">stream with the data to be parsed</param>
    public CVCAFile(short fid, Stream inputStream)
    {
        _fid = fid;
        ReadObject(inputStream);
    }

    /// <summary>Constructs a new CVCA file with default file identifier.</summary>
    public CVCAFile(string caReference, string? altCaReference)
        : this(PassportService.EF_CVCA, caReference, altCaReference)
    {
    }

    /// <summary>Constructs a new CVCA file with the given certificate references.</summary>
    /// <param name="fid">file identifier</param>
    /// <param name="caReference">main CA certificate reference</param>
    /// <param name="altCaReference">second (alternative) CA certificate reference</param>
    public CVCAFile(short fid, string caReference, string? altCaReference)
    {
        ArgumentNullException.ThrowIfNull(caReference);
        if (caReference.Length > 16 || (altCaReference != null && altCaReference.Length > 16))
        {
            throw new ArgumentException("CA reference too long.");
        }
        _fid = fid;
        _caReference = caReference;
        _altCaReference = altCaReference;
    }

    /// <summary>Constructs a new CVCA file with the given certificate reference.</summary>
    /// <param name="fid">file identifier</param>
    /// <param name="caReference">main CA certificate reference</param>
    public CVCAFile(short fid, string caReference)
        : this(fid, caReference, null)
    {
    }

    /// <summary>Returns the file identifier of this CVCA file.</summary>
    public short GetFID() => _fid;

    /// <summary>Reads the length byte of a CA reference, at most 16. The end of the stream is an
    /// <see cref="EndOfStreamException"/>; it overflowed, as -1 (JMRTD 0.8.11, 251980fb).</summary>
    private static int ReadCaReferenceLength(Stream inputStream)
    {
        int length = inputStream.ReadByte();
        if (length < 0)
        {
            throw new EndOfStreamException("No length for CA reference");
        }
        if (length > 16)
        {
            throw new ArgumentException("Wrong length");
        }
        return length;
    }

    protected override void ReadObject(Stream inputStream)
    {
        int tag = inputStream.ReadByte();
        if (tag != CarTag)
        {
            throw new ArgumentException($"Wrong tag, expected {CarTag:X}, found {tag:X}");
        }
        int length = ReadCaReferenceLength(inputStream);
        byte[] data = ReadFully(inputStream, length);
        _caReference = Encoding.ASCII.GetString(data);
        tag = inputStream.ReadByte();
        if (tag != 0 && tag != -1)
        {
            if (tag != CarTag)
            {
                throw new ArgumentException("Wrong tag");
            }
            length = ReadCaReferenceLength(inputStream);
            data = ReadFully(inputStream, length);
            _altCaReference = Encoding.ASCII.GetString(data);
            tag = inputStream.ReadByte();
        }
        while (tag != -1)
        {
            if (tag != 0)
            {
                throw new ArgumentException("Bad file padding");
            }
            tag = inputStream.ReadByte();
        }
    }

    protected override void WriteObject(Stream outputStream)
    {
        byte[] result = new byte[Length];
        result[0] = CarTag;
        byte[] caReferenceBytes = Encoding.ASCII.GetBytes(_caReference);
        result[1] = (byte)caReferenceBytes.Length;
        Array.Copy(caReferenceBytes, 0, result, 2, result[1]);
        if (_altCaReference != null)
        {
            int index = result[1] + 2;
            result[index] = CarTag;
            byte[] altCaReferenceBytes = Encoding.ASCII.GetBytes(_altCaReference);
            result[index + 1] = (byte)altCaReferenceBytes.Length;
            Array.Copy(altCaReferenceBytes, 0, result, index + 2, result[index + 1]);
        }
        outputStream.Write(result, 0, result.Length);
    }

    /// <summary>Returns the CA Certificate identifier.</summary>
    public CVCPrincipal? GetCAReference() => _caReference == null ? null : new CVCPrincipal(_caReference);

    /// <summary>Returns the second (alternative) CA Certificate identifier, or <c>null</c> if none exists.</summary>
    public CVCPrincipal? GetAltCAReference() => _altCaReference == null ? null : new CVCPrincipal(_altCaReference);

    /// <summary>Returns a textual representation of this CVCAFile.</summary>
    public override string ToString() =>
        $"CA reference: \"{_caReference}\"{(_altCaReference != null ? $", Alternative CA reference: {_altCaReference}" : "")}";

    public override bool Equals(object? other)
    {
        if (other == null)
        {
            return false;
        }
        if (GetType() != other.GetType())
        {
            return false;
        }

        var otherCvcaFile = (CVCAFile)other;
        return _caReference == otherCvcaFile._caReference
            && ((_altCaReference == null && otherCvcaFile._altCaReference == null)
                || (_altCaReference != null && _altCaReference == otherCvcaFile._altCaReference));
    }

    public override int GetHashCode() =>
        (11 * _caReference.GetHashCode(StringComparison.Ordinal))
        + (_altCaReference != null ? 13 * _altCaReference.GetHashCode(StringComparison.Ordinal) : 0)
        + 5;

    /// <summary>Returns the length of the content of this CVCA file. This always returns <see cref="Length"/>.</summary>
    public override int GetLength() => Length;

    private static byte[] ReadFully(Stream stream, int count)
    {
        byte[] buffer = new byte[count];
        int totalRead = 0;
        while (totalRead < count)
        {
            int read = stream.Read(buffer, totalRead, count - totalRead);
            if (read <= 0)
            {
                throw new EndOfStreamException();
            }
            totalRead += read;
        }
        return buffer;
    }
}
