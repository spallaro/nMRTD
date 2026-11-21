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

namespace nMRTD;

/// <summary>
/// Port of <c>org.jmrtd.APDULevelReadBinaryCapable</c>: the low-level capability for reading files using
/// SELECT and READ BINARY (both SFI and non-SFI) commands. The actual file system on an ICAO compliant
/// chip supports this.
/// </summary>
public interface IApduLevelReadBinaryCapable
{
    /// <summary>Sends a SELECT APPLET command to the card.</summary>
    /// <param name="wrapper">the secure messaging wrapper to use</param>
    /// <param name="aid">the applet to select</param>
    /// <exception cref="CardServiceException">on transceive error</exception>
    void SendSelectApplet(IApduWrapper? wrapper, byte[] aid);

    /// <summary>Sends a SELECT MF command to the card.</summary>
    /// <exception cref="CardServiceException">on transceive error</exception>
    void SendSelectMf();

    /// <summary>Selects a file by file identifier.</summary>
    /// <param name="wrapper">the APDU wrapper to use</param>
    /// <param name="fid">the file identifier</param>
    /// <exception cref="CardServiceException">on error</exception>
    void SendSelectFile(IApduWrapper? wrapper, short fid);

    /// <summary>
    /// Sends a READ BINARY command to the passport. Secure messaging will be applied to the command and
    /// response APDU.
    /// </summary>
    /// <param name="wrapper">the secure messaging wrapper to use, or <c>null</c> for none</param>
    /// <param name="sfi">
    /// the short file identifier byte of the file to read as an int value (between 0 and 255) only if
    /// <paramref name="isSfiEnabled"/> is <c>true</c>, if not any value)
    /// </param>
    /// <param name="offset">
    /// offset into the file (either a value between 0 and 255 if <paramref name="isSfiEnabled"/> holds,
    /// or a value between 0 and 65535 if not)
    /// </param>
    /// <param name="le">the expected length of the file to read</param>
    /// <param name="isSfiEnabled">a boolean indicating whether short file identifiers are used</param>
    /// <param name="isTlvEncodedOffsetNeeded">a boolean indicating whether it should be a long (INS == 0xB1) read</param>
    /// <returns>a byte array of length at most <paramref name="le"/> with (the specified part of) the contents of the currently selected file</returns>
    /// <exception cref="CardServiceException">if the command was not successful</exception>
    byte[] SendReadBinary(IApduWrapper? wrapper, int sfi, int offset, int le, bool isSfiEnabled, bool isTlvEncodedOffsetNeeded);
}
