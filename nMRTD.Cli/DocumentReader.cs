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

using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.SmartCards;

using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace nMRTD.Cli;

/// <summary>Which access control protocol to use.</summary>
public enum AccessMode
{
    /// <summary>PACE when the document offers it, otherwise BAC (with the MRZ access key).</summary>
    Auto,

    /// <summary>PACE only (<c>--pace</c>).</summary>
    Pace,

    /// <summary>BAC only (<c>--bac</c>).</summary>
    Bac,
}

/// <summary>Which kind of access key was given.</summary>
public enum AccessKeyMode
{
    /// <summary>MRZ details (document number, date of birth, date of expiry): usable for PACE and BAC.</summary>
    Mrz,

    /// <summary>Card Access Number: usable for PACE only.</summary>
    Can,
}

/// <summary>The access key, together with which kind it is. Exactly one of <see cref="BacKey"/>/<see cref="Can"/>
/// is non-null, matching <see cref="Mode"/>.</summary>
public sealed record AccessCredentials(AccessKeyMode Mode, IBacKeySpec? BacKey, string? Can);

/// <summary>
/// Reads a document end to end through a <see cref="PassportService"/>: access control (PACE or BAC), every
/// standard data group except DG3/DG4, Passive Authentication against EF.SOD (optionally with trusted CSCAs),
/// Chip Authentication and Active Authentication. Fills a <see cref="ReadReport"/>; the progress is written to a
/// log (<c>--verbose</c>).
/// </summary>
public sealed class DocumentReader
{
    private readonly PassportService passportService;
    private readonly TextWriter _out;
    private readonly ReadReport report = new();

    /// <param name="passportService">the opened passport service</param>
    /// <param name="log">where the progress is written (<see cref="TextWriter.Null"/> without <c>--verbose</c>)</param>
    public DocumentReader(PassportService passportService, TextWriter log)
    {
        this.passportService = passportService;
        _out = log;
    }

    public ReadReport Report => report;

    /// <summary>Trusted CSCA certificates (<c>--csca</c>); without them the Document Signer certificate is not
    /// checked against a trust anchor.</summary>
    public CscaTrustStore? TrustStore { get; init; }

    /// <summary>
    /// Authenticates, reads the data groups, checks Passive Authentication (unless
    /// <paramref name="skipPassiveAuthentication"/>) and performs Chip and Active Authentication.
    /// </summary>
    /// <exception cref="ReadFailure">when access control fails or the card cannot be read; its exit code says why</exception>
    public void Read(AccessCredentials credentials, AccessMode mode, bool skipPassiveAuthentication)
    {
        try
        {
            report.Atr = Convert.ToHexString(passportService.GetAtr());
        }
        catch (CardServiceException e)
        {
            _out.WriteLine($"Could not read the ATR: {e.Message}");
        }

        Authenticate(credentials, mode);

        Dictionary<int, byte[]> dataGroupBytes = ReadDataGroups();

        if (skipPassiveAuthentication)
        {
            report.PassiveAuthentication.Signature = "skipped";
            report.PassiveAuthentication.Csca = "skipped";
            _out.WriteLine("Passive Authentication skipped (--skip-passive-authentication).");
        }
        else
        {
            byte[] sodBytes;
            try
            {
                sodBytes = ReadFileBytes(passportService, PassportService.EF_SOD);
            }
            catch (CardServiceException e)
            {
                throw new ReadFailure(ExitCodes.CommunicationError, $"EF.SOD could not be read: {e.Message}", e);
            }
            VerifyPassiveAuthentication(new SODFile(new MemoryStream(sodBytes)), dataGroupBytes);
        }

        try
        {
            PerformChipAuthentication(passportService, dataGroupBytes.GetValueOrDefault(14));
        }
        catch (Exception e) when (e is not CardServiceException)
        {
            // A malformed DG14: report it and go on.
            report.ChipAuthentication.Status = "error";
            report.ChipAuthentication.Error = e.Message;
            _out.WriteLine($"Chip Authentication could not be attempted: {e.Message}");
        }

        // Chip Authentication reads EF.COM as its proof; without it, EF.COM is read here for the LDS version.
        // Not after a failed Chip Authentication: the secure channel is then lost.
        if (report.ChipAuthentication.Status is "not-available" or "error")
        {
            try
            {
                DescribeCom(ReadFileBytes(passportService, PassportService.EF_COM));
            }
            catch (CardServiceException e)
            {
                _out.WriteLine($"EF.COM could not be read ({e.Message}).");
            }
        }

        // Last: under secure messaging a chip ends the session on an error status, so a failing Active
        // Authentication must not come before anything else.
        try
        {
            PerformActiveAuthentication(dataGroupBytes.GetValueOrDefault(15), dataGroupBytes.GetValueOrDefault(14));
        }
        catch (Exception e) when (e is not CardServiceException)
        {
            report.ActiveAuthentication.Status = "error";
            report.ActiveAuthentication.Error = e.Message;
            _out.WriteLine($"Active Authentication could not be attempted: {e.Message}");
        }

        // The chip proved it holds the private key for the DG14 or DG15 public key; that only says something
        // about the document if the key itself is the one the issuer signed in EF.SOD.
        report.ChipAuthentication.KeyAuthenticated = IsAuthenticatedBySod(14);
        report.ActiveAuthentication.KeyAuthenticated = IsAuthenticatedBySod(15);
    }

    /// <summary>Whether the data group's hash matches EF.SOD and the EF.SOD signature is valid.</summary>
    private bool IsAuthenticatedBySod(int dataGroup) =>
        report.PassiveAuthentication.Signature == "valid"
        && report.DataGroups.Any(d => d.Number == dataGroup && d.Hash == "match");

    /// <summary>PACE or BAC, as <paramref name="mode"/> and the document allow.</summary>
    private void Authenticate(AccessCredentials credentials, AccessMode mode)
    {
        if (mode == AccessMode.Bac)
        {
            PerformBac(credentials);
            return;
        }

        IAccessKeySpec paceKey = credentials.Mode == AccessKeyMode.Can
            ? PaceKeySpec.CreateCanKey(credentials.Can!)
            : PaceKeySpec.CreateMrzKey(credentials.BacKey!);
        if (TryPerformPace(paceKey))
        {
            return;
        }

        if (mode == AccessMode.Pace)
        {
            throw new ReadFailure(ExitCodes.PaceNotAvailable, "PACE was requested (--pace) but the document does not offer it.");
        }
        if (credentials.Mode == AccessKeyMode.Can)
        {
            // A CAN is only valid for PACE (BSI TR-03110): it cannot derive a BAC key.
            throw new ReadFailure(ExitCodes.PaceNotAvailable,
                "The document does not offer PACE, and a Card Access Number can only be used for PACE: use the MRZ access key.");
        }
        _out.WriteLine("PACE not available on this document: falling back to BAC.");
        PerformBac(credentials);
    }

    private void PerformBac(AccessCredentials credentials)
    {
        _out.WriteLine("Performing BAC...");
        try
        {
            passportService.SendSelectApplet(false);
            passportService.DoBAC(credentials.BacKey!);
        }
        catch (CardServiceException e)
        {
            throw new ReadFailure(ExitCodes.BacFailed, $"BAC failed (check the MRZ access key): {e.Message}", e);
        }
        report.AccessProtocol = "BAC";
        _out.WriteLine("BAC completed.");
    }

    /// <summary>Reads EF.CardAccess (if present) looking for a PACEInfo, and performs PACE if found.</summary>
    /// <param name="paceKey">the PACE access key to use (MRZ- or CAN-derived; see <see cref="PaceKeySpec"/>)</param>
    /// <returns><see langword="true"/> if PACE was performed, <see langword="false"/> if the document does not offer it.</returns>
    /// <exception cref="ReadFailure">if PACE was attempted and failed</exception>
    private bool TryPerformPace(IAccessKeySpec paceKey)
    {
        byte[] cardAccessBytes;
        try
        {
            cardAccessBytes = ReadFileBytes(passportService, PassportService.EF_CARD_ACCESS);
        }
        catch (CardServiceException)
        {
            return false;
        }

        var cardAccessFile = new CardAccessFile(new MemoryStream(cardAccessBytes));
        PACEInfo? paceInfo = cardAccessFile.GetSecurityInfos().OfType<PACEInfo>().FirstOrDefault();
        if (paceInfo == null)
        {
            return false;
        }

        // Standardized domain parameters (parameter id 0-31) or explicit ones from a PACEDomainParameterInfo
        // in EF.CardAccess (parameter id 32 and up, or no parameter id).
        Org.BouncyCastle.Math.BigInteger? parameterId = paceInfo.GetParameterId();
        object staticParameters;
        try
        {
            staticParameters = PaceParameters.Resolve(paceInfo, cardAccessFile.GetSecurityInfos());
        }
        catch (ArgumentException e)
        {
            _out.WriteLine($"PACE is advertised but its domain parameters cannot be resolved ({e.Message}).");
            return false;
        }

        if (parameterId == null || parameterId.IntValue > PaceParameters.MaxStandardizedParameterId)
        {
            report.ExplicitPaceParameters = true;
            _out.WriteLine("Using explicit PACE domain parameters from EF.CardAccess.");
        }

        _out.WriteLine($"Performing PACE (protocol {paceInfo.GetObjectIdentifier()})...");
        try
        {
            passportService.DoPace(paceKey, paceInfo.GetObjectIdentifier(), staticParameters, parameterId);
            passportService.SendSelectApplet(true);
        }
        catch (CardServiceException e)
        {
            throw new ReadFailure(ExitCodes.PaceFailed, $"PACE failed (check the access key): {e.Message}", e);
        }
        report.AccessProtocol = "PACE";
        report.PaceProtocol = paceInfo.GetObjectIdentifier();
        report.PaceProtocolName = paceInfo.GetProtocolOIDString();
        report.PaceParameterId = parameterId?.IntValue;
        _out.WriteLine("PACE completed; secure messaging established.");
        return true;
    }

    private static byte[] ReadFileBytes(PassportService passportService, short fid)
    {
        using Stream stream = passportService.GetInputStream(fid, PassportService.DefaultMaxBlocksize);
        using var buffer = new MemoryStream();
        stream.CopyTo(buffer);
        return buffer.ToArray();
    }

    /// <summary>
    /// The standard data groups, by number and file identifier. DG3 (fingerprints) and DG4 (iris) are left out:
    /// both need Terminal Authentication with an inspection system certificate, which this tool does not have.
    /// </summary>
    private static readonly (int Number, short Fid)[] StandardDataGroups =
    [
        (1, PassportService.EF_DG1),
        (2, PassportService.EF_DG2),
        (5, PassportService.EF_DG5),
        (6, PassportService.EF_DG6),
        (7, PassportService.EF_DG7),
        (8, PassportService.EF_DG8),
        (9, PassportService.EF_DG9),
        (10, PassportService.EF_DG10),
        (11, PassportService.EF_DG11),
        (12, PassportService.EF_DG12),
        (13, PassportService.EF_DG13),
        (14, PassportService.EF_DG14),
        (15, PassportService.EF_DG15),
        (16, PassportService.EF_DG16),
    ];

    /// <summary>Reads every standard data group the document has, and parses it where the library can. Returns
    /// the bytes of each data group read, by number, for the Passive Authentication hash check.</summary>
    private Dictionary<int, byte[]> ReadDataGroups()
    {
        var dataGroupBytes = new Dictionary<int, byte[]>();
        foreach ((int number, short fid) in StandardDataGroups)
        {
            var result = new DataGroupResult(number);
            report.DataGroups.Add(result);
            byte[] bytes;
            try
            {
                bytes = ReadFileBytes(passportService, fid);
            }
            catch (CardServiceException e)
            {
                _out.WriteLine($"DG{number}: not present ({e.Message}).");
                continue;
            }

            dataGroupBytes[number] = bytes;
            result.Present = true;
            result.Length = bytes.Length;
            result.Content = bytes;
            _out.WriteLine($"DG{number}: read ({bytes.Length} bytes).");
            try
            {
                result.Information = DataGroupFields.For(number, bytes);
                if (number == 1 && result.Information != null)
                {
                    report.Document.DocumentCode = (string?)result.Information["documentCode"];
                    report.Document.IssuingState = (string?)result.Information["issuingState"];
                }
            }
            catch (Exception e)
            {
                result.InformationError = e.Message;
                _out.WriteLine($"DG{number}: could not be parsed ({e.Message}).");
            }
        }
        return dataGroupBytes;
    }

    private void VerifyPassiveAuthentication(SODFile sodFile, IReadOnlyDictionary<int, byte[]> dataGroupBytes)
    {
        _out.WriteLine();
        _out.WriteLine("=== Passive Authentication ===");

        string? digestAlgorithm = sodFile.GetDigestAlgorithm();
        report.PassiveAuthentication.DigestAlgorithm = digestAlgorithm;
        if (digestAlgorithm == null)
        {
            _out.WriteLine("Could not determine the digest algorithm used in EF.SOD; skipping.");
            return;
        }

        SortedDictionary<int, byte[]> storedHashes = sodFile.GetDataGroupHashes();
        foreach ((int dgNumber, byte[] rawBytes) in dataGroupBytes)
        {
            DataGroupResult dataGroup = report.DataGroups.First(d => d.Number == dgNumber);
            if (!storedHashes.TryGetValue(dgNumber, out byte[]? expectedHash))
            {
                dataGroup.Hash = "not-in-sod";
                _out.WriteLine($"DG{dgNumber}: no hash present in EF.SOD -- cannot verify.");
                continue;
            }

            byte[] actualHash = ComputeDigest(digestAlgorithm, rawBytes);
            bool matches = actualHash.AsSpan().SequenceEqual(expectedHash);
            dataGroup.Hash = matches ? "match" : "mismatch";
            _out.WriteLine(matches
                ? $"DG{dgNumber}: hash matches EF.SOD ({digestAlgorithm})."
                : $"DG{dgNumber}: HASH MISMATCH -- this data group does not match what is certified in EF.SOD!");
        }

        // The content-hash-vs-messageDigest-attribute check (RFC 5652 5.4) happens as a side effect of
        // GetEContent() itself, which throws if the two don't agree -- see SignedDataUtil.GetEContent's remarks.
        byte[] eContent;
        try
        {
            eContent = sodFile.GetEContent();
        }
        catch (IOException e)
        {
            // The content does not match the message digest signed in EF.SOD: the signed content was changed.
            report.PassiveAuthentication.Signature = "invalid";
            report.PassiveAuthentication.Error = e.Message;
            _out.WriteLine($"EF.SOD content-digest check failed: {e.Message}");
            return;
        }

        byte[] encryptedDigest = sodFile.GetEncryptedDigest();
        string? digestEncryptionAlgorithm = sodFile.GetDigestEncryptionAlgorithm();
        var docSigningCertificate = sodFile.GetDocSigningCertificate();

        report.PassiveAuthentication.SignatureAlgorithm = digestEncryptionAlgorithm;
        report.PassiveAuthentication.Signer = docSigningCertificate?.SubjectDN.ToString();
        if (docSigningCertificate != null)
        {
            report.PassiveAuthentication.SignerCertificateValidNow = docSigningCertificate.IsValidNow;
        }
        else if (TrustStore != null)
        {
            report.PassiveAuthentication.Csca = "no-certificate";
        }

        if (digestEncryptionAlgorithm == null || docSigningCertificate == null)
        {
            report.PassiveAuthentication.Signature = "error";
            report.PassiveAuthentication.Error = "no signature algorithm or document signing certificate";
            _out.WriteLine("Could not determine the signature algorithm or document signing certificate; cannot verify the EF.SOD signature.");
            return;
        }

        try
        {
            AsymmetricKeyParameter publicKey = docSigningCertificate.GetPublicKey();
            (ISigner verifier, string algorithmDescription) = CreateSodSignatureVerifier(sodFile, digestEncryptionAlgorithm);
            verifier.Init(forSigning: false, publicKey);
            verifier.BlockUpdate(eContent, 0, eContent.Length);
            bool signatureValid = verifier.VerifySignature(encryptedDigest);
            report.PassiveAuthentication.Signature = signatureValid ? "valid" : "invalid";
            report.PassiveAuthentication.SignatureAlgorithm = algorithmDescription;

            _out.WriteLine(signatureValid
                ? $"EF.SOD signature is VALID ({algorithmDescription}, signed by: {docSigningCertificate.SubjectDN})."
                : "EF.SOD signature is INVALID -- the security object may have been tampered with!");
        }
        catch (Exception e)
        {
            report.PassiveAuthentication.Signature = "error";
            report.PassiveAuthentication.Error = e.Message;
            _out.WriteLine($"Could not verify the EF.SOD signature (algorithm '{digestEncryptionAlgorithm}' not supported by this CLI): {e.Message}");
        }

        if (TrustStore == null)
        {
            _out.WriteLine(
                "NOTE: this only proves EF.SOD and the data groups above are internally consistent and unmodified. "
                + "The document signing certificate itself was NOT validated against a trusted CSCA root (use --csca "
                + "to give trusted CSCA certificates), so this does NOT prove the document was issued by a legitimate authority.");
            return;
        }

        CscaTrustStore.Verification verification;
        try
        {
            verification = TrustStore.Verify(docSigningCertificate);
        }
        catch (Exception e)
        {
            report.PassiveAuthentication.Csca = "error";
            report.PassiveAuthentication.CscaDetail = e.Message;
            _out.WriteLine($"Could not check the Document Signer certificate against the trusted CSCAs: {e.Message}");
            return;
        }

        report.PassiveAuthentication.Csca = verification.Trusted ? "trusted" : "untrusted";
        report.PassiveAuthentication.CscaSubject = verification.Csca?.SubjectDN.ToString();
        report.PassiveAuthentication.CscaDetail = verification.Detail;
        if (verification.Trusted)
        {
            _out.WriteLine($"Document Signer certificate is issued by the trusted CSCA {verification.Csca!.SubjectDN} ({verification.Detail}).");
        }
        else
        {
            _out.WriteLine($"Document Signer certificate is NOT issued by a trusted CSCA: {verification.Detail}.");
        }
        _out.WriteLine(docSigningCertificate.IsValidNow
            ? $"Document Signer certificate valid until {docSigningCertificate.NotAfter:yyyy-MM-dd}."
            : $"Document Signer certificate expired on {docSigningCertificate.NotAfter:yyyy-MM-dd} (normal for an expired document).");
        _out.WriteLine("NOTE: revocation (CRLs) is not checked.");
    }

    /// <summary>
    /// Creates the verifier for the EF.SOD signature. For RSASSA-PSS, <see cref="SODFile.GetDigestEncryptionAlgorithm"/>
    /// only returns the generic name "SSAwithRSA/PSS" (as JMRTD does); the hash algorithm, the MGF1 hash and the
    /// salt length come from the algorithm parameters in the signer info.
    /// </summary>
    private (ISigner Verifier, string Description) CreateSodSignatureVerifier(SODFile sodFile, string digestEncryptionAlgorithm)
    {
        RsassaPssParameters? pssParameters = sodFile.GetDigestEncryptionAlgorithmParams();
        if (pssParameters == null)
        {
            return (SignerUtilities.GetSigner(digestEncryptionAlgorithm), digestEncryptionAlgorithm);
        }

        if (!PkcsObjectIdentifiers.IdMgf1.Equals(pssParameters.MaskGenAlgorithm.Algorithm))
        {
            throw new NotSupportedException($"Unsupported RSASSA-PSS mask generation function {pssParameters.MaskGenAlgorithm.Algorithm}");
        }
        if (!pssParameters.TrailerField.HasValue(1))
        {
            throw new NotSupportedException($"Unsupported RSASSA-PSS trailer field {pssParameters.TrailerField}");
        }

        IDigest contentDigest = DigestUtilities.GetDigest(pssParameters.HashAlgorithm.Algorithm);
        IDigest mgfDigest = DigestUtilities.GetDigest(AlgorithmIdentifier.GetInstance(pssParameters.MaskGenAlgorithm.Parameters).Algorithm);
        int saltLength = pssParameters.SaltLength.IntValueExact;
        var verifier = new PssSigner(new RsaBlindedEngine(), contentDigest, mgfDigest, saltLength, PssSigner.TrailerImplicit);
        return (verifier, $"RSASSA-PSS, {contentDigest.AlgorithmName}, MGF1 {mgfDigest.AlgorithmName}, salt {saltLength} bytes");
    }

    /// <summary>
    /// Performs EAC Chip Authentication (BSI TR-03110 / ICAO Doc 9303-11, 6.2) with the chip's key from DG14,
    /// then reads EF.COM, which has not been read before, over the restarted secure messaging channel: the
    /// read only succeeds if the chip holds the private key matching the DG14 public key. DG14's own
    /// integrity is covered by Passive Authentication, which runs first.
    /// </summary>
    private void PerformChipAuthentication(PassportService passportService, byte[]? dg14Bytes)
    {
        _out.WriteLine();
        _out.WriteLine("=== Chip Authentication ===");

        if (dg14Bytes == null)
        {
            _out.WriteLine("DG14 not present; Chip Authentication is not available on this document.");
            return;
        }

        IReadOnlyCollection<SecurityInfo> securityInfos = new DG14File(new MemoryStream(dg14Bytes)).GetSecurityInfos();
        List<ChipAuthenticationPublicKeyInfo> publicKeyInfos = securityInfos.OfType<ChipAuthenticationPublicKeyInfo>().ToList();
        List<ChipAuthenticationInfo> chipAuthenticationInfos = securityInfos.OfType<ChipAuthenticationInfo>().ToList();
        if (publicKeyInfos.Count == 0)
        {
            _out.WriteLine("DG14 has no ChipAuthenticationPublicKeyInfo; Chip Authentication is not available on this document.");
            return;
        }

        // Use the first public key, with the ChipAuthenticationInfo of the same key ID. With a single
        // ChipAuthenticationInfo and no key IDs, that one applies; without any, the protocol is inferred from
        // the public key's OID (as JMRTD does).
        ChipAuthenticationPublicKeyInfo publicKeyInfo = publicKeyInfos[0];
        ChipAuthenticationInfo? chipAuthenticationInfo =
            chipAuthenticationInfos.FirstOrDefault(info => Equals(info.GetKeyId(), publicKeyInfo.GetKeyId()))
            ?? (chipAuthenticationInfos.Count == 1 ? chipAuthenticationInfos[0] : null);

        string protocol = chipAuthenticationInfo?.GetProtocolOIDString() ?? "inferred from the public key";
        report.ChipAuthentication.Protocol = chipAuthenticationInfo?.GetObjectIdentifier() ?? publicKeyInfo.GetObjectIdentifier();
        report.ChipAuthentication.ProtocolName = chipAuthenticationInfo?.GetProtocolOIDString() ?? publicKeyInfo.GetProtocolOIDString();
        report.ChipAuthentication.PublicKey = KeyDescription.Of(publicKeyInfo.GetSubjectPublicKey());
        _out.WriteLine(
            $"Performing Chip Authentication (protocol {protocol}, chip key {report.ChipAuthentication.PublicKey}"
            + $"{(publicKeyInfo.GetKeyId() is { } keyId ? $", key ID {keyId}" : "")})...");

        try
        {
            passportService.DoEACCA(
                publicKeyInfo.GetKeyId(),
                chipAuthenticationInfo?.GetObjectIdentifier(),
                publicKeyInfo.GetObjectIdentifier(),
                publicKeyInfo.GetSubjectPublicKey());

            byte[] comBytes = ReadFileBytes(passportService, PassportService.EF_COM);
            report.ChipAuthentication.Status = "succeeded";
            _out.WriteLine(
                $"Chip Authentication succeeded: EF.COM ({comBytes.Length} bytes) was read with the new "
                + "session keys, so the chip holds the private key for the DG14 public key.");
            DescribeCom(comBytes);
        }
        catch (Exception e)
        {
            report.ChipAuthentication.Status = "failed";
            report.ChipAuthentication.Error = e.Message;
            _out.WriteLine($"Chip Authentication FAILED: {e.GetType().Name}: {e.Message}");
            for (Exception? inner = e.InnerException; inner != null; inner = inner.InnerException)
            {
                _out.WriteLine($"  caused by {inner.GetType().Name}: {inner.Message}");
            }
        }
    }

    /// <summary>
    /// Performs Active Authentication (ICAO Doc 9303-11, 6.1) with the DG15 key: sends a random challenge and
    /// verifies the chip's signature, which shows that the chip holds the private key matching DG15 (and so is
    /// not a copy). DG15's integrity is covered by Passive Authentication.
    /// </summary>
    private void PerformActiveAuthentication(byte[]? dg15Bytes, byte[]? dg14Bytes)
    {
        _out.WriteLine();
        _out.WriteLine("=== Active Authentication ===");

        AsymmetricKeyParameter? publicKey = dg15Bytes == null ? null : new DG15File(new MemoryStream(dg15Bytes)).GetPublicKey();
        if (publicKey == null)
        {
            _out.WriteLine(dg15Bytes == null
                ? "DG15 not present; Active Authentication is not available on this document."
                : "The DG15 public key could not be decoded; Active Authentication is not available.");
            return;
        }

        string? signatureAlgorithmOid = dg14Bytes == null ? null
            : new DG14File(new MemoryStream(dg14Bytes)).GetSecurityInfos().OfType<ActiveAuthenticationInfo>().FirstOrDefault()?.GetSignatureAlgorithmOID();
        byte[] challenge = new byte[8];
        System.Security.Cryptography.RandomNumberGenerator.Fill(challenge);
        report.ActiveAuthentication.PublicKey = KeyDescription.Of(publicKey);
        _out.WriteLine($"Performing Active Authentication (key {report.ActiveAuthentication.PublicKey})...");

        byte[] response;
        try
        {
            response = passportService.DoAA(publicKey, null, signatureAlgorithmOid ?? "", challenge).GetResponse() ?? [];
        }
        catch (Exception e)
        {
            // Not a wrong signature: the challenge got no usable answer (for example the secure channel was
            // already lost), which says nothing about whether the chip is a copy.
            report.ActiveAuthentication.Status = "error";
            report.ActiveAuthentication.Error = e.Message;
            _out.WriteLine($"Active Authentication could not be completed: the chip did not answer the challenge ({e.Message}).");
            return;
        }

        ActiveAuthenticationVerifier.Result result = ActiveAuthenticationVerifier.Verify(publicKey, signatureAlgorithmOid, challenge, response);
        report.ActiveAuthentication.Protocol = result.Algorithm;
        switch (result.Valid)
        {
            case true:
                report.ActiveAuthentication.Status = "succeeded";
                _out.WriteLine($"Active Authentication succeeded ({result.Algorithm}): the chip signed the challenge with the private key for the DG15 public key.");
                break;
            case false:
                report.ActiveAuthentication.Status = "failed";
                report.ActiveAuthentication.Error = "signature does not verify";
                _out.WriteLine($"Active Authentication FAILED ({result.Algorithm}): the signature does not verify with the DG15 public key -- the chip may be a copy!");
                break;
            default:
                report.ActiveAuthentication.Status = "unverifiable";
                _out.WriteLine($"Active Authentication response received but cannot be verified: {result.Algorithm}.");
                break;
        }
    }

    /// <summary>The LDS and Unicode versions from EF.COM; a malformed EF.COM is only logged.</summary>
    private void DescribeCom(byte[] comBytes)
    {
        try
        {
            var com = new COMFile(new MemoryStream(comBytes));
            report.Document.LdsVersion = com.GetLDSVersion();
            report.Document.UnicodeVersion = com.GetUnicodeVersion();
            _out.WriteLine($"EF.COM: LDS {report.Document.LdsVersion}, Unicode {report.Document.UnicodeVersion}.");
        }
        catch (Exception e)
        {
            _out.WriteLine($"EF.COM could not be parsed ({e.Message}).");
        }
    }

    private byte[] ComputeDigest(string digestAlgorithm, byte[] data)
    {
        IDigest digest = DigestUtilities.GetDigest(digestAlgorithm);
        digest.BlockUpdate(data, 0, data.Length);
        byte[] result = new byte[digest.GetDigestSize()];
        digest.DoFinal(result, 0);
        return result;
    }
}
