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

using System.Globalization;

using nMRTD.Io;
using nMRTD.SmartCards;

using FileInfo = nMRTD.SmartCards.FileInfo;

namespace nMRTD;

/// <summary>
/// Port of <c>org.jmrtd.DefaultFileSystem</c>: a file system for ICAO MRTDs (and similar file systems).
/// This translates abstract high level selection and read binary commands to concrete low level file
/// related APDUs which are sent to the ICC through the card service.
/// </summary>
/// <remarks>
/// Java's version logs via <c>java.util.logging.Logger</c> in a couple of non-essential warning
/// branches (empty read-ahead prefix, TLV-length parse failure, adding a fragment with no buffer). Per
/// porting-conventions.md, pulling in <c>Microsoft.Extensions.Logging.Abstractions</c> for these was
/// judged not worth it here; the conditions are simply not logged.
/// </remarks>
public class DefaultFileSystem : IFileSystemStructured
{
    /// <summary>Invalid short identifier.</summary>
    public const int NoSfi = -1;

    /// <summary>Number of bytes to read at start of file to determine file length.</summary>
    private const int ReadAheadLength = 8;

    private readonly object _lock = new();

    /// <summary>Indicates the file that is (or should be) selected.</summary>
    private short _selectedFid;

    private readonly bool _isSfiEnabled;

    private int _maxReadBinaryLength;

    /// <summary>A boolean indicating whether we actually already sent the SELECT command to select <c>_selectedFid</c>.</summary>
    private bool _isSelected;

    private readonly IApduLevelReadBinaryCapable _service;

    private readonly Dictionary<short, DefaultFileInfo> _fileInfos;

    private readonly IReadOnlyDictionary<short, byte> _fidToSfi;

    private IApduWrapper? _wrapper;

    /// <summary>Creates a file system.</summary>
    /// <param name="service">the card service supporting low-level SELECT and/or READ BINARY commands</param>
    /// <param name="isSfiEnabled">whether the file system should use short file identifiers in READ BINARY commands</param>
    public DefaultFileSystem(IApduLevelReadBinaryCapable service, bool isSfiEnabled)
        : this(service, isSfiEnabled, Lds.LDSFileUtil.FidToSfi)
    {
    }

    /// <summary>Creates a file system.</summary>
    /// <param name="service">the card service supporting low-level SELECT and/or READ BINARY commands</param>
    /// <param name="isSfiEnabled">whether the file system should use short file identifiers in READ BINARY commands</param>
    /// <param name="fidToSfi">maps file identifiers to short file identifiers</param>
    public DefaultFileSystem(IApduLevelReadBinaryCapable service, bool isSfiEnabled, IReadOnlyDictionary<short, byte> fidToSfi)
    {
        _service = service ?? throw new ArgumentNullException(nameof(service));
        _fileInfos = new Dictionary<short, DefaultFileInfo>();
        _selectedFid = 0;
        _isSelected = false;
        _isSfiEnabled = isSfiEnabled;
        _fidToSfi = fidToSfi ?? throw new ArgumentNullException(nameof(fidToSfi));
        _maxReadBinaryLength = PassportService.ExtendedMaxTransceiveLength;
    }

    /// <summary>Sets the current wrapper to the given APDU wrapper. Subsequent APDUs will be wrapped before sending to the ICC.</summary>
    /// <param name="wrapper">an APDU wrapper</param>
    public void SetWrapper(IApduWrapper? wrapper)
    {
        _wrapper = wrapper;
    }

    /// <summary>Returns the wrapper (secure messaging) currently in use.</summary>
    /// <returns>the wrapper</returns>
    public IApduWrapper? GetWrapper() => _wrapper;

    /// <summary>Returns the currently set maximum length to be requested in READ BINARY commands.</summary>
    /// <returns>the currently set maximum length to be requested in READ BINARY commands</returns>
    public int GetMaxReadBinaryLength() => _maxReadBinaryLength;

    /// <summary>Returns the selected path.</summary>
    /// <returns>the path components</returns>
    /// <exception cref="CardServiceException">on error</exception>
    public FileInfo[] GetSelectedPath()
    {
        lock (_lock)
        {
            DefaultFileInfo? fileInfo = GetFileInfo();
            return fileInfo is null ? null! : new FileInfo[] { fileInfo };
        }
    }

    // NOTE: This doesn't actually send a select file command. ReadBinary will do so if needed.
    /// <summary>Selects a file.</summary>
    /// <param name="fid">indicates the file to select</param>
    /// <exception cref="CardServiceException">on error communicating over the service</exception>
    public void SelectFile(short fid)
    {
        lock (_lock)
        {
            _fileInfos.TryGetValue(fid, out DefaultFileInfo? cachedFileInfo);
            if (_selectedFid == fid && cachedFileInfo is not null)
            {
                return;
            }

            _selectedFid = fid;
            _isSelected = false;
            DefaultFileInfo? fileInfo = GetFileInfo();
            if (fileInfo is null || fileInfo.GetBuffer() is null)
            {
                throw new CardServiceException("Could not select file");
            }
        }
    }

    /// <summary>Reads a block of bytes.</summary>
    /// <param name="offset">offset index in the selected file</param>
    /// <param name="length">the number of bytes to read</param>
    /// <returns>a copy of the bytes read</returns>
    /// <exception cref="CardServiceException">on error</exception>
    public byte[] ReadBinary(int offset, int length)
    {
        lock (_lock)
        {
            DefaultFileInfo? fileInfo = null;
            try
            {
                if (_selectedFid <= 0)
                {
                    throw new CardServiceException("No file selected");
                }

                // Check buffer to see if we already have some of the bytes.
                fileInfo = GetFileInfo();
                if (fileInfo is null)
                {
                    throw new CardServiceException("Could not get file info");
                }

                length = Math.Min(length, _maxReadBinaryLength);
                FragmentBuffer.Fragment fragment = fileInfo.GetSmallestUnbufferedFragment(offset, length);

                int responseLength = length;

                byte[]? bytes = null;
                if (fragment.Length > 0)
                {
                    if (_isSfiEnabled && offset < 256)
                    {
                        if (!_fidToSfi.TryGetValue(_selectedFid, out byte sfi))
                        {
                            throw new FormatException($"Unknown FID {(int)_selectedFid:x}");
                        }

                        bytes = SendReadBinary(0x80 | (sfi & 0xFF), fragment.Offset, fragment.Length, false);
                        _isSelected = true;
                    }
                    else
                    {
                        if (!_isSelected)
                        {
                            SendSelectFile(_selectedFid);
                            _isSelected = true;
                        }

                        bytes = SendReadBinary(fragment.Offset, fragment.Length, offset > 32767);
                    }

                    if (bytes is null)
                    {
                        throw new InvalidOperationException("Could not read bytes");
                    }

                    if (bytes.Length > 0)
                    {
                        // Update buffer with newly read bytes.
                        fileInfo.AddFragment(fragment.Offset, bytes);
                    }

                    // If we request a block of data, create the return buffer from the actual response length, not the
                    // requested Le. The latter causes issues when the returned block has a one byte padding (only 0x80)
                    // which ends up being removed but the length is not kept track of, leaving an unwanted 0-byte at the
                    // end of the data block, which now has a length of Le, but actually contained Le - 1 data bytes.
                    if (bytes.Length < fragment.Length)
                    {
                        responseLength = bytes.Length;
                    }
                }

                // Shrink wrap the bytes that are now buffered.
                byte[] buffer = fileInfo.GetBuffer()!;

                byte[] result = new byte[responseLength];
                Array.Copy(buffer, offset, result, 0, responseLength);

                return result;
            }
            catch (CardServiceException cse)
            {
                short sw = (short)cse.Sw;
                if ((sw & 0xFF00) == Iso7816.SwWrongLength && _maxReadBinaryLength > PassportService.DefaultMaxBlocksize)
                {
                    // The wrapper stays in step with the chip: SecureMessagingAPDUSender takes back a command answered
                    // with a plain 67xx, and a protected 67xx was unwrapped. Upstream JMRTD restored a copy of the
                    // wrapper made before the command (none with short file identifiers, so the next command went
                    // out unprotected; and a protected 6700 was rolled back too, out of step with the chip): JMRTD
                    // bug #92 (https://sourceforge.net/p/jmrtd/bugs/92/), fixed in JMRTD 0.8.11 (commit ab463f56).
                    _maxReadBinaryLength = PassportService.DefaultMaxBlocksize;
                    return Array.Empty<byte>();
                }

                throw new CardServiceException(
                    $"Read binary failed on file {(fileInfo is null ? ((int)_selectedFid).ToString("x", CultureInfo.InvariantCulture) : fileInfo.ToString())}",
                    cse);
            }
            catch (Exception e)
            {
                throw new CardServiceException(
                    $"Read binary failed on file {(fileInfo is null ? ((int)_selectedFid).ToString("x", CultureInfo.InvariantCulture) : fileInfo.ToString())}",
                    e);
            }
        }
    }

    /// <summary>
    /// Returns the file info object for the currently selected file. If this executes normally the
    /// result is non-null. If the file has not been read before this will send a READ BINARY to
    /// determine length.
    /// </summary>
    /// <returns>a non-null file info, or <c>null</c> if the read-ahead prefix could not be obtained</returns>
    /// <exception cref="CardServiceException">on error</exception>
    private DefaultFileInfo? GetFileInfo()
    {
        lock (_lock)
        {
            if (_selectedFid <= 0)
            {
                throw new CardServiceException("No file selected");
            }

            // If known file, use file info from cache.
            if (_fileInfos.TryGetValue(_selectedFid, out DefaultFileInfo? fileInfo))
            {
                return fileInfo;
            }

            // Not cached, actually read some bytes to determine file info.
            try
            {
                // Each passport file consists of a TLV structure, read ahead to determine length.
                // EF.CVCA is the exception and has a fixed length of CVCAFile.Length.
                byte[]? prefix;
                if (_isSfiEnabled)
                {
                    if (!_fidToSfi.TryGetValue(_selectedFid, out byte sfi))
                    {
                        throw new FormatException($"Unknown FID {(int)_selectedFid:x}");
                    }

                    prefix = SendReadBinary(0x80 | (sfi & 0xFF), 0, ReadAheadLength, false);
                    _isSelected = true;
                }
                else
                {
                    if (!_isSelected)
                    {
                        SendSelectFile(_selectedFid);
                        _isSelected = true;
                    }

                    prefix = SendReadBinary(0, ReadAheadLength, false);
                }

                if (prefix is null || prefix.Length == 0)
                {
                    return null;
                }

                int fileLength = GetFileLength(_selectedFid, ReadAheadLength, prefix);
                if (fileLength < prefix.Length)
                {
                    // We got more than the file's length. Ignore trailing bytes.
                    prefix = prefix[..fileLength];
                }

                fileInfo = new DefaultFileInfo(_selectedFid, fileLength);
                fileInfo.AddFragment(0, prefix);
                _fileInfos[_selectedFid] = fileInfo;
                return fileInfo;
            }
            catch (IOException ioe)
            {
                throw new CardServiceException($"Error getting file info for {(int)_selectedFid:x}", ioe);
            }
            catch (CardServiceException)
            {
                _fileInfos.Remove(_selectedFid);
                _isSelected = false;
                throw;
            }
        }
    }

    /// <summary>Determines the file length by inspecting a prefix of bytes read from the (TLV contents of a) file.</summary>
    /// <param name="fid">the file identifier</param>
    /// <param name="le">the requested length while requesting the prefix</param>
    /// <param name="prefix">the prefix read from the file</param>
    /// <returns>the file length</returns>
    private static int GetFileLength(short fid, int le, byte[] prefix)
    {
        if (prefix.Length < le)
        {
            // We got less than asked for, assume prefix is the complete file.
            return prefix.Length;
        }

        using MemoryStream byteArrayInputStream = new(prefix, writable: false);
        using TlvInputStream tlvInputStream = new(byteArrayInputStream, leaveOpen: true);
        try
        {
            int tag = tlvInputStream.ReadTag();
            if (tag == Lds.CVCAFile.CarTag)
            {
                return Lds.CVCAFile.Length;
            }

            // Determine length based on TLV.
            int valueLength = tlvInputStream.ReadLength();
            // NOTE: we're using a specific property of MemoryStream's Length - Position here, mirroring
            // Java's use of ByteArrayInputStream.available().
            int tlLength = prefix.Length - (int)(byteArrayInputStream.Length - byteArrayInputStream.Position);
            int fileLength = tlLength + valueLength;
            return fileLength;
        }
        catch (Exception)
        {
            return -1;
        }
    }

    /// <summary>Selects a file within the MRTD application.</summary>
    /// <param name="fid">a file identifier</param>
    /// <exception cref="CardServiceException">on error</exception>
    public void SendSelectFile(short fid)
    {
        lock (_lock)
        {
            _service.SendSelectFile(_wrapper, fid);
        }
    }

    /// <summary>Sends a READ BINARY command for the already selected file to the passport, using the wrapper when a secure channel has been set up.</summary>
    /// <param name="offset">offset into the file</param>
    /// <param name="le">the expected length of the file to read</param>
    /// <param name="isTlvEncodedOffsetNeeded">whether to encode the offset in a TLV object (typically for offset larger than 32767)</param>
    /// <returns>a byte array of length <paramref name="le"/> with (the specified part of) the contents of the currently selected file</returns>
    /// <exception cref="CardServiceException">on transceive error</exception>
    public byte[] SendReadBinary(int offset, int le, bool isTlvEncodedOffsetNeeded)
    {
        lock (_lock)
        {
            return _service.SendReadBinary(_wrapper, NoSfi, offset, le, false, isTlvEncodedOffsetNeeded);
        }
    }

    /// <summary>Sends a READ BINARY command using an explicit short file identifier to the passport, using the wrapper when a secure channel has been set up.</summary>
    /// <param name="sfi">the short file identifier byte as int value (between 0 and 255)</param>
    /// <param name="offset">offset into the file</param>
    /// <param name="le">the expected length of the file to read</param>
    /// <param name="isTlvEncodedOffsetNeeded">whether to encode the offset in a TLV object (typically for offset larger than 32767)</param>
    /// <returns>a byte array of length <paramref name="le"/> with (the specified part of) the contents of the currently selected file</returns>
    /// <exception cref="CardServiceException">on transceive error</exception>
    public byte[] SendReadBinary(int sfi, int offset, int le, bool isTlvEncodedOffsetNeeded)
    {
        lock (_lock)
        {
            return _service.SendReadBinary(_wrapper, sfi, offset, le, true, isTlvEncodedOffsetNeeded);
        }
    }

    /// <summary>A file info for the ICAO MRTD file system.</summary>
    private sealed class DefaultFileInfo : FileInfo
    {
        private readonly short _fid;
        private readonly FragmentBuffer? _buffer;

        /// <summary>Constructs a file info.</summary>
        /// <param name="fid">indicates which file</param>
        /// <param name="length">length of the contents of the file</param>
        public DefaultFileInfo(short fid, int length)
        {
            _fid = fid;
            if (length >= 0)
            {
                _buffer = new FragmentBuffer(length);
            }
        }

        /// <summary>Returns the buffer.</summary>
        /// <returns>the buffer, or <c>null</c></returns>
        public byte[]? GetBuffer() => _buffer?.GetBuffer();

        /// <summary>Returns the file identifier.</summary>
        public override short Fid => _fid;

        /// <summary>Returns the length of the file.</summary>
        public override int FileLength => _buffer?.GetLength() ?? -1;

        /// <summary>Returns a textual representation of this file info.</summary>
        public override string ToString() => ((int)_fid).ToString("x", CultureInfo.InvariantCulture);

        /// <summary>Returns the smallest unbuffered fragment included in <paramref name="offset"/> and <c>offset + length - 1</c>.</summary>
        /// <param name="offset">the offset</param>
        /// <param name="length">the length</param>
        /// <returns>a fragment smaller than or equal to the fragment indicated by <paramref name="offset"/> and <paramref name="length"/></returns>
        public FragmentBuffer.Fragment GetSmallestUnbufferedFragment(int offset, int length) =>
            _buffer is null ? null! : _buffer.GetSmallestUnbufferedFragment(offset, length);

        /// <summary>Adds a fragment of bytes at a specific offset to this file.</summary>
        /// <param name="offset">the offset</param>
        /// <param name="bytes">the bytes to be added</param>
        public void AddFragment(int offset, byte[] bytes)
        {
            _buffer?.AddFragment(offset, bytes);
        }
    }
}
