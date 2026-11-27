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

using System.Text.Json.Nodes;

namespace nMRTD.Cli;

/// <summary>What <see cref="DocumentReader"/> found on a document: the outcome of each step. It is rendered as
/// text, JSON or XML by <see cref="ReportOutput"/>.</summary>
public sealed class ReadReport
{
    /// <summary>Where the document was read: the nMRTD version, the operating system and the reader.</summary>
    public EnvironmentInfo Environment { get; } = new();

    /// <summary>The card's answer to reset, in hexadecimal, if available.</summary>
    public string? Atr { get; set; }

    /// <summary>What kind of document it is (DG1) and its LDS version (EF.COM).</summary>
    public DocumentInfo Document { get; } = new();

    /// <summary>"PACE" or "BAC", or <c>null</c> if no access protocol succeeded.</summary>
    public string? AccessProtocol { get; set; }

    /// <summary>The PACE protocol object identifier, if PACE was used.</summary>
    public string? PaceProtocol { get; set; }

    /// <summary>The PACE protocol name, for example "id-PACE-DH-GM-3DES-CBC-CBC".</summary>
    public string? PaceProtocolName { get; set; }

    /// <summary>The PACE standardized domain parameter id (0-31), or a proprietary one, if given.</summary>
    public int? PaceParameterId { get; set; }

    /// <summary>Whether PACE used explicit domain parameters from EF.CardAccess.</summary>
    public bool ExplicitPaceParameters { get; set; }

    public List<DataGroupResult> DataGroups { get; } = [];

    public PassiveAuthenticationResult PassiveAuthentication { get; } = new();

    public ProtocolResult ChipAuthentication { get; } = new();

    public ProtocolResult ActiveAuthentication { get; } = new();

    /// <summary>Why reading stopped early, if it did.</summary>
    public string? Error { get; set; }

    /// <summary>The exit code for a problem that stopped reading, if any.</summary>
    public int? FailureExitCode { get; set; }

    /// <summary>
    /// The security checks the document failed, with their exit codes, in the order of
    /// <see cref="ExitCodes"/>; empty when none failed. Counted: a data group whose hash differs from EF.SOD, an
    /// invalid EF.SOD signature, a Document Signer certificate not issued by a trusted CSCA (only when trusted
    /// CSCAs were given), a failed Chip Authentication, an Active Authentication signature that does not verify,
    /// and a Chip or Active Authentication that succeeded with a key not covered by a valid EF.SOD signature
    /// (unless Passive Authentication was skipped). Not counted, because they say nothing against the document:
    /// a protocol the document does not offer, an unverifiable Active Authentication, an Active Authentication
    /// that could not be completed, and a data group that EF.SOD has no hash for.
    /// </summary>
    public List<FailedCheck> FailedChecks()
    {
        var failed = new List<FailedCheck>();
        foreach (DataGroupResult dataGroup in DataGroups.Where(d => d.Hash == "mismatch"))
        {
            failed.Add(new(ExitCodes.HashMismatch, $"DG{dataGroup.Number} hash does not match EF.SOD"));
        }
        if (PassiveAuthentication.Signature == "invalid")
        {
            failed.Add(new(ExitCodes.SodSignatureInvalid, "EF.SOD signature is invalid"));
        }
        if (PassiveAuthentication.Csca is "untrusted" or "no-certificate")
        {
            failed.Add(new(ExitCodes.DocumentSignerNotTrusted, "Document Signer certificate is not issued by a trusted CSCA"));
        }
        if (PassiveAuthentication.Revocation == "revoked")
        {
            failed.Add(new(ExitCodes.DocumentSignerRevoked, "Document Signer certificate is revoked"));
        }
        if (ChipAuthentication.Status == "failed")
        {
            failed.Add(new(ExitCodes.ChipAuthenticationFailed, "Chip Authentication failed"));
        }
        if (ActiveAuthentication.Status == "failed")
        {
            failed.Add(new(ExitCodes.ActiveAuthenticationFailed, "Active Authentication signature does not verify"));
        }
        if (PassiveAuthentication.Signature != "skipped")
        {
            foreach ((string name, ProtocolResult result) in new[] { ("Chip", ChipAuthentication), ("Active", ActiveAuthentication) })
            {
                if (result.Status == "succeeded" && !result.KeyAuthenticated)
                {
                    failed.Add(new(ExitCodes.KeyNotAuthenticated, $"{name} Authentication used a key not covered by a valid EF.SOD signature"));
                }
            }
        }
        return failed;
    }

    /// <summary>The exit code: the code of the problem that stopped reading, or of the first failed check, or 0.</summary>
    public int ExitCode() => FailureExitCode ?? (FailedChecks() is [var first, ..] ? first.Code : ExitCodes.Success);
}

/// <summary>A failed security check and its exit code.</summary>
public sealed record FailedCheck(int Code, string Description);

/// <summary>One data group: whether it is present, its size, how its hash compares with EF.SOD, and its
/// contents.</summary>
public sealed class DataGroupResult(int number)
{
    public int Number { get; } = number;

    public bool Present { get; set; }

    public int Length { get; set; }

    /// <summary>"match", "mismatch", "not-in-sod", or <c>null</c> if not checked.</summary>
    public string? Hash { get; set; }

    /// <summary>The data group's bytes as read, or <c>null</c> if not present.</summary>
    public byte[]? Content { get; set; }

    /// <summary>The parsed information (<see cref="DataGroupFields"/>), or <c>null</c> without a parser.</summary>
    public JsonObject? Information { get; set; }

    /// <summary>Why the data group could not be parsed, if it could not.</summary>
    public string? InformationError { get; set; }
}

/// <summary>The EF.SOD signature check and the Document Signer certificate check against trusted CSCAs.</summary>
public sealed class PassiveAuthenticationResult
{
    /// <summary>"valid", "invalid", "error", "skipped" (<c>--skip-passive-authentication</c>) or "not-checked".</summary>
    public string Signature { get; set; } = "not-checked";

    public string? DigestAlgorithm { get; set; }

    public string? SignatureAlgorithm { get; set; }

    public string? Signer { get; set; }

    public string? Error { get; set; }

    /// <summary>"trusted", "untrusted", "no-certificate", "error", "skipped" or "not-checked" (no <c>--csca</c>).</summary>
    public string Csca { get; set; } = "not-checked";

    public string? CscaSubject { get; set; }

    public string? CscaDetail { get; set; }

    /// <summary>"not-revoked", "revoked", "no-crl", "crl-invalid" (see <see cref="CscaTrustStore.RevocationCheck"/>),
    /// or "not-checked" (no CRL given, or the Document Signer certificate is not trusted).</summary>
    public string Revocation { get; set; } = "not-checked";

    /// <summary>The CRL used, and the revocation date and reason when revoked.</summary>
    public string? RevocationDetail { get; set; }

    /// <summary>Whether the Document Signer certificate is within its validity period today; an expired
    /// document normally has an expired Document Signer certificate.</summary>
    public bool? SignerCertificateValidNow { get; set; }
}

/// <summary>The outcome of Chip Authentication or Active Authentication.</summary>
public sealed class ProtocolResult
{
    /// <summary>"succeeded"; "failed" (the chip did not prove it holds the key: for Active Authentication a
    /// wrong signature, the sign of a copied chip); "error" (the protocol could not be completed);
    /// "not-available"; or, for Active Authentication, "unverifiable".</summary>
    public string Status { get; set; } = "not-available";

    /// <summary>Whether the public key used (DG14 or DG15) is covered by a valid EF.SOD signature. A
    /// "succeeded" status shows that the chip is genuine only when this is true.</summary>
    public bool KeyAuthenticated { get; set; }

    /// <summary>The protocol object identifier (Chip Authentication) or the signature scheme (Active
    /// Authentication).</summary>
    public string? Protocol { get; set; }

    /// <summary>The Chip Authentication protocol name, for example "id-CA-DH-3DES-CBC-CBC".</summary>
    public string? ProtocolName { get; set; }

    /// <summary>The chip's public key algorithm and size (DG14 or DG15), for example "DH [2048 bit]".</summary>
    public string? PublicKey { get; set; }

    public string? Error { get; set; }
}

/// <summary>Where the document was read, to report a result.</summary>
public sealed class EnvironmentInfo
{
    /// <summary>The nMRTD library version.</summary>
    public string? NmrtdVersion { get; set; } = LibraryVersion();

    /// <summary>The operating system and the processor architecture.</summary>
    public string? OperatingSystem { get; set; } =
        $"{System.Runtime.InteropServices.RuntimeInformation.OSDescription} ({System.Runtime.InteropServices.RuntimeInformation.OSArchitecture})";

    /// <summary>The PC/SC reader name.</summary>
    public string? Reader { get; set; }

    /// <summary>The informational version of the library (for example "0.8.8-alpha"), without build metadata.</summary>
    private static string? LibraryVersion()
    {
        // Reading an attribute of a known type is safe with Native AOT and trimming.
        string? version = System.Reflection.CustomAttributeExtensions
            .GetCustomAttribute<System.Reflection.AssemblyInformationalVersionAttribute>(typeof(PassportService).Assembly)?.InformationalVersion;
        return version?.Split('+')[0];
    }
}

/// <summary>What kind of document it is: nothing here identifies the holder or the document.</summary>
public sealed class DocumentInfo
{
    /// <summary>The document code from the MRZ (DG1), for example "P" or "ID".</summary>
    public string? DocumentCode { get; set; }

    /// <summary>The issuing state from the MRZ (DG1), for example "ITA".</summary>
    public string? IssuingState { get; set; }

    /// <summary>The LDS version from EF.COM, for example "1.7".</summary>
    public string? LdsVersion { get; set; }

    /// <summary>The Unicode version from EF.COM, for example "4.0.0".</summary>
    public string? UnicodeVersion { get; set; }
}
