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

/// <summary>What <see cref="DocumentReader"/> found on a document: the outcome of each step, for the JSON
/// output and for tests. The text output is written while reading.</summary>
public sealed class ReadReport
{
    /// <summary>"PACE" or "BAC", or <c>null</c> if no access protocol succeeded.</summary>
    public string? AccessProtocol { get; set; }

    /// <summary>The PACE protocol object identifier, if PACE was used.</summary>
    public string? PaceProtocol { get; set; }

    /// <summary>Whether PACE used explicit domain parameters from EF.CardAccess.</summary>
    public bool ExplicitPaceParameters { get; set; }

    /// <summary>The MRZ from DG1, if DG1 was read and parsed.</summary>
    public MrzSummary? Mrz { get; set; }

    public List<DataGroupResult> DataGroups { get; } = [];

    /// <summary>Files written to the output folder (images).</summary>
    public List<SavedFile> SavedFiles { get; } = [];

    public PassiveAuthenticationResult PassiveAuthentication { get; } = new();

    public ProtocolResult ChipAuthentication { get; } = new();

    public ProtocolResult ActiveAuthentication { get; } = new();

    /// <summary>Why reading stopped early, if it did.</summary>
    public string? Error { get; set; }
}

/// <summary>The fields of the machine readable zone.</summary>
public sealed record MrzSummary(
    string DocumentCode, string DocumentNumber, string PrimaryIdentifier, string SecondaryIdentifier,
    string Nationality, string IssuingState, string DateOfBirth, string DateOfExpiry, string Gender);

/// <summary>One data group: whether it is present, its size, and how its hash compares with EF.SOD.</summary>
public sealed class DataGroupResult(int number)
{
    public int Number { get; } = number;

    public bool Present { get; set; }

    public int Length { get; set; }

    /// <summary>"match", "mismatch", "not-in-sod", or <c>null</c> if not checked.</summary>
    public string? Hash { get; set; }
}

/// <summary>A file written to the output folder.</summary>
public sealed record SavedFile(string Path, string? MimeType, int Length);

/// <summary>The EF.SOD signature check and the Document Signer certificate check against trusted CSCAs.</summary>
public sealed class PassiveAuthenticationResult
{
    /// <summary>"valid", "invalid", "error" or "not-checked".</summary>
    public string Signature { get; set; } = "not-checked";

    public string? DigestAlgorithm { get; set; }

    public string? SignatureAlgorithm { get; set; }

    public string? Signer { get; set; }

    public string? Error { get; set; }

    /// <summary>"trusted", "untrusted", "no-certificate" or "not-checked" (no <c>--csca</c>).</summary>
    public string Csca { get; set; } = "not-checked";

    public string? CscaSubject { get; set; }

    public string? CscaDetail { get; set; }

    /// <summary>Whether the Document Signer certificate is within its validity period today; an expired
    /// document normally has an expired Document Signer certificate.</summary>
    public bool? SignerCertificateValidNow { get; set; }
}

/// <summary>The outcome of Chip Authentication or Active Authentication.</summary>
public sealed class ProtocolResult
{
    /// <summary>"succeeded", "failed", "not-available" or, for Active Authentication, "unverifiable".</summary>
    public string Status { get; set; } = "not-available";

    public string? Protocol { get; set; }

    public string? Error { get; set; }
}
