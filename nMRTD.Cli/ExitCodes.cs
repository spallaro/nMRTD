/*
 * nMRTD - A .Net API for accessing Machine Readable Travel Documents.
 *
 * Copyright (C) Sebastiano Pallaro.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * Distributed under the terms of GNU LGPL v3.
 * See LICENSE for more information.
 */

namespace nMRTD.Cli;

/// <summary>
/// The exit codes of the tool: 0 when the document was read and passed every check, a negative code for each
/// kind of problem. When several security checks fail, the code is the one of the first in this list; the
/// output lists them all.
/// </summary>
/// <remarks>
/// Windows passes the code as a signed 32-bit number. On Linux and macOS a process exit status is a byte, so
/// the shell sees 256 + code (for example -40 as 216).
/// </remarks>
public static class ExitCodes
{
    /// <summary>The document was read and passed every check (or the tool did what was asked).</summary>
    public const int Success = 0;

    // ---- Arguments ----

    /// <summary>Unknown option, missing value, or options that cannot be combined.</summary>
    public const int InvalidArguments = -1;

    /// <summary>Neither a CAN nor a complete MRZ access key (document number, dates of birth and expiry).</summary>
    public const int MissingAccessKey = -2;

    /// <summary>The <c>--csca</c> path does not exist or holds no readable certificate.</summary>
    public const int CscaNotLoaded = -3;

    // ---- Reader and card ----

    /// <summary>No PC/SC reader is available, or the reader named with <c>--reader</c> is not found.</summary>
    public const int ReaderNotFound = -10;

    /// <summary>The connection to the card could not be opened (no card on the reader, for example).</summary>
    public const int CardNotConnected = -11;

    // ---- Access control ----

    /// <summary>PACE is needed (<c>--pace</c>, or a CAN) but the document does not offer it.</summary>
    public const int PaceNotAvailable = -20;

    /// <summary>PACE failed: usually a wrong access key.</summary>
    public const int PaceFailed = -21;

    /// <summary>BAC failed: usually a wrong MRZ access key.</summary>
    public const int BacFailed = -22;

    // ---- Reading ----

    /// <summary>Communication with the card failed after access control (EF.SOD could not be read, for example).</summary>
    public const int CommunicationError = -30;

    /// <summary>Any other error, for example a malformed file.</summary>
    public const int UnexpectedError = -31;

    // ---- Security checks ----

    /// <summary>A data group's hash differs from the one signed in EF.SOD.</summary>
    public const int HashMismatch = -40;

    /// <summary>The EF.SOD signature is invalid, or its content does not match the signed digest.</summary>
    public const int SodSignatureInvalid = -41;

    /// <summary>The Document Signer certificate was not issued by a trusted CSCA (with <c>--csca</c>).</summary>
    public const int DocumentSignerNotTrusted = -42;

    /// <summary>Chip Authentication failed.</summary>
    public const int ChipAuthenticationFailed = -43;

    /// <summary>The Active Authentication signature does not verify.</summary>
    public const int ActiveAuthenticationFailed = -44;

    /// <summary>Chip or Active Authentication succeeded with a key not covered by a valid EF.SOD signature.</summary>
    public const int KeyNotAuthenticated = -45;
}

/// <summary>A problem that stops reading, with its exit code.</summary>
public sealed class ReadFailure(int exitCode, string message, Exception? cause = null) : Exception(message, cause)
{
    public int ExitCode { get; } = exitCode;
}
