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

using System.Globalization;
using System.Text;

using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.Lds.Iso19794;
using nMRTD.SmartCards;

using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace nMRTD.Cli;

/// <summary>
/// Reads a document end to end through a <see cref="PassportService"/>: PACE (falling back to BAC), every
/// standard data group except DG3/DG4, Passive Authentication against EF.SOD and Chip Authentication. Writes
/// the human-readable output to a <see cref="TextWriter"/> and fills a <see cref="ReadReport"/>.
/// </summary>
public sealed class DocumentReader
{
    private readonly PassportService passportService;
    private readonly TextWriter _out;
    private readonly ReadReport report = new();

    public DocumentReader(PassportService passportService, TextWriter output)
    {
        this.passportService = passportService;
        _out = output;
    }

    public ReadReport Report => report;

    /// <summary>Trusted CSCA certificates (<c>--csca</c>); without them the Document Signer certificate is not
    /// checked against a trust anchor.</summary>
    public CscaTrustStore? TrustStore { get; init; }

    /// <summary>
    /// Authenticates (PACE, falling back to BAC unless <paramref name="forceBac"/>), reads the data groups,
    /// checks Passive Authentication and performs Chip Authentication.
    /// </summary>
    /// <returns><see langword="false"/> if the document cannot be accessed with a Card Access Number because
    /// it does not offer PACE; <see langword="true"/> otherwise.</returns>
    public bool Read(AccessCredentials credentials, bool forceBac, string outDir)
    {
        IAccessKeySpec paceKey = credentials.Mode == AccessKeyMode.Can
            ? PaceKeySpec.CreateCanKey(credentials.Can!)
            : PaceKeySpec.CreateMrzKey(credentials.BacKey!);

        bool usedPace = !forceBac && TryPerformPace(paceKey);
        if (forceBac)
        {
            _out.WriteLine("Skipping PACE (--bac): performing BAC.");
            PerformBac(credentials);
        }
        else if (!usedPace)
        {
            if (credentials.Mode == AccessKeyMode.Can)
            {
                return false;
            }

            _out.WriteLine("PACE not available (or not supported by this document) -- falling back to BAC.");
            PerformBac(credentials);
        }

        Dictionary<int, byte[]> dataGroupBytes = ReadAndPrintDataGroups(passportService, outDir);

        byte[] sodBytes = ReadFileBytes(passportService, PassportService.EF_SOD);
        var sodFile = new SODFile(new MemoryStream(sodBytes));
        VerifyPassiveAuthentication(sodFile, dataGroupBytes);

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
        foreach ((string name, ProtocolResult result) in new[] { ("Chip", report.ChipAuthentication), ("Active", report.ActiveAuthentication) })
        {
            if (result.Status == "succeeded" && !result.KeyAuthenticated)
            {
                _out.WriteLine($"WARNING: {name} Authentication succeeded, but its public key is not covered by a valid EF.SOD "
                    + "signature, so it does not show that the chip is genuine.");
            }
        }
        return true;
    }

    /// <summary>Whether the data group's hash matches EF.SOD and the EF.SOD signature is valid.</summary>
    private bool IsAuthenticatedBySod(int dataGroup) =>
        report.PassiveAuthentication.Signature == "valid"
        && report.DataGroups.Any(d => d.Number == dataGroup && d.Hash == "match");

    private void PerformBac(AccessCredentials credentials)
    {
        passportService.SendSelectApplet(false);
        passportService.DoBAC(credentials.BacKey!);
        report.AccessProtocol = "BAC";
        _out.WriteLine("BAC completed.");
    }

    /// <summary>Reads EF.CardAccess (if present) looking for a PACEInfo, and performs PACE if found.</summary>
    /// <param name="passportService">the opened passport service</param>
    /// <param name="paceKey">the PACE access key to use (MRZ- or CAN-derived; see <see cref="PaceKeySpec"/>)</param>
    /// <returns><see langword="true"/> if PACE was performed, <see langword="false"/> if the card has no EF.CardAccess (BAC-only document).</returns>
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
        PACEInfo? paceInfo = null;
        foreach (SecurityInfo securityInfo in cardAccessFile.GetSecurityInfos())
        {
            if (securityInfo is PACEInfo candidate)
            {
                paceInfo = candidate;
                break;
            }
        }

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
            _out.WriteLine($"PACE is advertised but its domain parameters cannot be resolved ({e.Message}) -- falling back to BAC.");
            return false;
        }

        if (parameterId == null || parameterId.IntValue > PaceParameters.MaxStandardizedParameterId)
        {
            report.ExplicitPaceParameters = true;
            _out.WriteLine("Using explicit PACE domain parameters from EF.CardAccess.");
        }

        _out.WriteLine($"Performing PACE (protocol {paceInfo.GetObjectIdentifier()})...");
        passportService.DoPace(paceKey, paceInfo.GetObjectIdentifier(), staticParameters, parameterId);
        passportService.SendSelectApplet(true);
        report.AccessProtocol = "PACE";
        report.PaceProtocol = paceInfo.GetObjectIdentifier();
        _out.WriteLine("PACE completed; secure messaging established.");

        return true;
    }

    private byte[] ReadFileBytes(PassportService passportService, short fid)
    {
        using Stream stream = passportService.GetInputStream(fid, PassportService.DefaultMaxBlocksize);
        using var buffer = new MemoryStream();
        stream.CopyTo(buffer);
        return buffer.ToArray();
    }

    /// <summary>
    /// Standard EF.DG file identifiers to iterate for the post-authentication summary in
    /// <see cref="ReadAndPrintDataGroups"/>, paired with their data group number. DG3 (fingerprints) and DG4
    /// (iris) are deliberately excluded: both require Extended Access Control (Chip/Terminal Authentication
    /// with an inspection-system certificate), which this CLI does not implement -- attempting to read them
    /// against a document that enforces EAC would just fail with a security-status-not-satisfied error, so
    /// they are skipped here rather than listed as "not present".
    /// </summary>
    private (int Number, short Fid)[] GetStandardDataGroupIds() =>
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

    /// <summary>
    /// Reads every standard data group listed in <see cref="GetStandardDataGroupIds"/>. For each one actually
    /// present on the document, prints a parsed summary (where this port has a parser for that DG -- see
    /// <see cref="PrintDataGroupContent"/>) or a raw-bytes-only notice, followed by a full hex dump; for each
    /// one absent, prints a clear "not present" line instead. Returns the raw bytes of every DG that was
    /// successfully read, keyed by DG number, for the Passive Authentication hash check that follows.
    /// </summary>
    private Dictionary<int, byte[]> ReadAndPrintDataGroups(PassportService passportService, string outDir)
    {
        _out.WriteLine();
        _out.WriteLine("=== Data Groups ===");

        var dataGroupBytes = new Dictionary<int, byte[]>();
        foreach ((int number, short fid) in GetStandardDataGroupIds())
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
                _out.WriteLine();
                _out.WriteLine($"--- DG{number} ---");
                _out.WriteLine($"Not present on this document ({e.Message}).");
                continue;
            }

            dataGroupBytes[number] = bytes;
            result.Present = true;
            result.Length = bytes.Length;
            result.Content = bytes;

            _out.WriteLine();
            _out.WriteLine($"--- DG{number} ({bytes.Length} bytes) ---");
            try
            {
                PrintDataGroupContent(number, bytes, outDir);
            }
            catch (Exception e)
            {
                _out.WriteLine($"(Could not parse DG{number} content: {e.Message})");
            }

            PrintHexDump(bytes);
        }

        return dataGroupBytes;
    }

    /// <summary>
    /// Prints a parsed, human-readable summary of one data group's content, dispatching on its number to the
    /// parser this port implements for it (if any). DGs this port has no dedicated parser for (8, 9, 10, 13,
    /// 16 -- all rarely used in practice) fall through to a plain notice; their raw bytes are still shown by
    /// the caller's subsequent <see cref="PrintHexDump"/> call.
    /// </summary>
    private void PrintDataGroupContent(int number, byte[] bytes, string outDir)
    {
        switch (number)
        {
            case 1:
                PrintMrzInfo(new DG1File(new MemoryStream(bytes)).GetMRZInfo());
                break;
            case 2:
                SaveFaceImage(new DG2File(new MemoryStream(bytes)), outDir);
                break;
            case 5:
                SaveDisplayedImages("DG5", new DG5File(new MemoryStream(bytes)).GetImages(), "dg5_portrait", outDir);
                break;
            case 6:
                SaveDisplayedImages("DG6", new DG6File(new MemoryStream(bytes)).GetImages(), "dg6_image", outDir);
                break;
            case 7:
                SaveDisplayedImages("DG7", new DG7File(new MemoryStream(bytes)).GetImages(), "dg7_signature", outDir);
                break;
            case 11:
                PrintDG11(new DG11File(new MemoryStream(bytes)));
                break;
            case 12:
                PrintDG12(new DG12File(new MemoryStream(bytes)));
                break;
            case 14:
                PrintDG14(new DG14File(new MemoryStream(bytes)));
                break;
            case 15:
                PrintDG15(new DG15File(new MemoryStream(bytes)));
                break;
            default:
                _out.WriteLine($"No structured parser for DG{number} in this port -- raw bytes only (see below).");
                break;
        }
    }

    /// <summary>Prints the given bytes as a hex dump (offset + <c>0xNN</c> tokens, 16 per line) -- shown for
    /// every data group read, regardless of whether this port has a structured parser for it.</summary>
    private void PrintHexDump(byte[] bytes)
    {
        _out.WriteLine("Raw bytes (hex):");
        if (bytes.Length == 0)
        {
            _out.WriteLine("  (empty)");
            return;
        }

        const int bytesPerLine = 16;
        var line = new StringBuilder();
        for (int offset = 0; offset < bytes.Length; offset += bytesPerLine)
        {
            line.Clear();
            line.Append("  ").Append(offset.ToString("X4", CultureInfo.InvariantCulture)).Append(": ");
            int count = Math.Min(bytesPerLine, bytes.Length - offset);
            for (int i = 0; i < count; i++)
            {
                line.Append("0x").Append(bytes[offset + i].ToString("X2", CultureInfo.InvariantCulture)).Append(' ');
            }

            _out.WriteLine(line.ToString().TrimEnd());
        }
    }

    /// <summary>Prints a summary of, and saves to <paramref name="outDir"/>, each image in a DG5/DG6/DG7
    /// displayed-image list (portrait for DG5, signature/mark for DG7, unspecified for DG6).</summary>
    private void SaveDisplayedImages(string label, List<DisplayedImageInfo> images, string fileNamePrefix, string outDir)
    {
        if (images.Count == 0)
        {
            _out.WriteLine($"{label}: no images present.");
            return;
        }

        Directory.CreateDirectory(outDir);
        int index = 0;
        foreach (DisplayedImageInfo image in images)
        {
            string extension = image.GetMimeType() switch
            {
                "image/jpeg" => "jpg",
                "image/jp2" => "jp2",
                _ => "bin",
            };
            string path = Path.Combine(outDir, $"{fileNamePrefix}_{index}.{extension}");
            using (Stream imageStream = image.GetImageInputStream())
            using (FileStream fileStream = File.Create(path))
            {
                imageStream.CopyTo(fileStream);
            }

            report.SavedFiles.Add(new SavedFile(path, image.GetMimeType(), image.GetImageLength()));
            _out.WriteLine($"{label}: saved image {index} ({image.GetMimeType()}, {image.GetImageLength()} bytes) to {path}");
            index++;
        }
    }

    /// <summary>Prints DG11 (additional personal details) as a list of the fields actually present.</summary>
    private void PrintDG11(DG11File dg11)
    {
        PrintFieldIfPresent("Name of holder", dg11.GetNameOfHolder());
        PrintListIfPresent("Other names", dg11.GetOtherNames());
        PrintFieldIfPresent("Personal number", dg11.GetPersonalNumber());
        PrintFieldIfPresent("Full date of birth", dg11.GetFullDateOfBirth());
        PrintListIfPresent("Place of birth", dg11.GetPlaceOfBirth());
        PrintListIfPresent("Permanent address", dg11.GetPermanentAddress());
        PrintFieldIfPresent("Telephone", dg11.GetTelephone());
        PrintFieldIfPresent("Profession", dg11.GetProfession());
        PrintFieldIfPresent("Title", dg11.GetTitle());
        PrintFieldIfPresent("Personal summary", dg11.GetPersonalSummary());
        byte[]? proofOfCitizenship = dg11.GetProofOfCitizenship();
        if (proofOfCitizenship != null)
        {
            _out.WriteLine($"Proof of citizenship: image ({proofOfCitizenship.Length} bytes)");
        }

        PrintListIfPresent("Other valid travel document numbers", dg11.GetOtherValidTDNumbers());
        PrintFieldIfPresent("Custody information", dg11.GetCustodyInformation());
        if (dg11.GetTagPresenceList().Count == 0)
        {
            _out.WriteLine("(No fields present.)");
        }
    }

    /// <summary>Prints DG12 (additional document details) as a list of the fields actually present.</summary>
    private void PrintDG12(DG12File dg12)
    {
        PrintFieldIfPresent("Issuing authority", dg12.GetIssuingAuthority());
        PrintFieldIfPresent("Date of issue", dg12.GetDateOfIssue());
        PrintListIfPresent("Names of other persons", dg12.GetNamesOfOtherPersons());
        PrintFieldIfPresent("Endorsements/observations", dg12.GetEndorsementsAndObservations());
        PrintFieldIfPresent("Tax or exit requirements", dg12.GetTaxOrExitRequirements());
        byte[]? imageOfFront = dg12.GetImageOfFront();
        if (imageOfFront != null)
        {
            _out.WriteLine($"Image of front: image ({imageOfFront.Length} bytes)");
        }

        byte[]? imageOfRear = dg12.GetImageOfRear();
        if (imageOfRear != null)
        {
            _out.WriteLine($"Image of rear: image ({imageOfRear.Length} bytes)");
        }

        PrintFieldIfPresent("Date/time of personalization", dg12.GetDateAndTimeOfPersonalization());
        PrintFieldIfPresent("Personalization system serial number", dg12.GetPersonalizationSystemSerialNumber());
        if (dg12.GetTagPresenceList().Count == 0)
        {
            _out.WriteLine("(No fields present.)");
        }
    }

    /// <summary>Prints DG14 (EAC/PACE SecurityInfos) as a count plus one line per SecurityInfo.</summary>
    private void PrintDG14(DG14File dg14)
    {
        IReadOnlyCollection<SecurityInfo> securityInfos = dg14.GetSecurityInfos();
        _out.WriteLine($"{securityInfos.Count} SecurityInfo(s):");
        foreach (SecurityInfo securityInfo in securityInfos)
        {
            _out.WriteLine($"  - {securityInfo.GetType().Name}: {securityInfo}");
        }
    }

    /// <summary>Prints DG15 (Active Authentication public key) as its algorithm/size.</summary>
    private void PrintDG15(DG15File dg15)
    {
        AsymmetricKeyParameter? publicKey = dg15.GetPublicKey();
        _out.WriteLine(publicKey == null
            ? "Could not decode the Active Authentication public key."
            : $"Active Authentication public key: {Util.GetDetailedPublicKeyAlgorithm(publicKey)}");
    }

    private void PrintFieldIfPresent(string label, string? value)
    {
        if (!string.IsNullOrEmpty(value))
        {
            _out.WriteLine($"{label}: {value}");
        }
    }

    private void PrintListIfPresent(string label, List<string>? values)
    {
        if (values != null && values.Count > 0)
        {
            _out.WriteLine($"{label}: {string.Join(", ", values)}");
        }
    }

    private void PrintMrzInfo(MRZInfo mrz)
    {
        report.Mrz = new MrzSummary(mrz.GetDocumentCode(), mrz.GetDocumentNumber(), mrz.GetPrimaryIdentifier(),
            mrz.GetSecondaryIdentifier(), mrz.GetNationality(), mrz.GetIssuingState(), mrz.GetDateOfBirth(),
            mrz.GetDateOfExpiry(), mrz.GetGenderCode().ToString());
        _out.WriteLine($"Document number: {mrz.GetDocumentNumber()}");
        _out.WriteLine($"Name:            {mrz.GetPrimaryIdentifier()} / {mrz.GetSecondaryIdentifier()}");
        _out.WriteLine($"Nationality:     {mrz.GetNationality()}");
        _out.WriteLine($"Issuing state:   {mrz.GetIssuingState()}");
        _out.WriteLine($"Date of birth:   {mrz.GetDateOfBirth()}");
        _out.WriteLine($"Date of expiry:  {mrz.GetDateOfExpiry()}");
        _out.WriteLine($"Gender:          {mrz.GetGenderCode()}");
    }

    /// <summary>Saves the face images of DG2, in the ISO/IEC 19794-5 format (<see cref="FaceInfo"/>) or the
    /// ISO/IEC 39794-5 format (<see cref="Lds.Iso39794.FaceImageDataBlock"/>).</summary>
    private void SaveFaceImage(DG2File dg2File, string outDir)
    {
        var images = new List<ImageInfo>();
        foreach (var record in dg2File.GetSubRecords())
        {
            switch (record)
            {
                case FaceInfo faceInfo:
                    images.AddRange(faceInfo.GetFaceImageInfos());
                    break;
                case Lds.Iso39794.FaceImageDataBlock dataBlock:
                    images.AddRange(dataBlock.GetRepresentationBlocks().Where(block => block.GetImageRepresentation2DBlock() != null));
                    break;
            }
        }

        if (images.Count == 0)
        {
            _out.WriteLine("No face image found in DG2.");
            return;
        }

        Directory.CreateDirectory(outDir);
        int index = 0;
        foreach (ImageInfo image in images)
        {
            string extension = image.GetMimeType() switch
            {
                "image/jp2" => "jp2",
                "image/jpeg" => "jpg",
                _ => "bin",
            };
            string path = Path.Combine(outDir, $"dg2_face_{index}.{extension}");
            using (Stream imageStream = image.GetImageInputStream())
            using (FileStream fileStream = File.Create(path))
            {
                imageStream.CopyTo(fileStream);
            }
            report.SavedFiles.Add(new SavedFile(path, image.GetMimeType(), image.GetImageLength()));
            _out.WriteLine($"Saved face image {index} ({image.GetMimeType()}, {image.GetImageLength()} bytes) to {path}");
            index++;
        }
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
        _out.WriteLine(
            $"Performing Chip Authentication (protocol {protocol}, chip key {Util.GetDetailedPublicKeyAlgorithm(publicKeyInfo.GetSubjectPublicKey())}"
            + $"{(publicKeyInfo.GetKeyId() is { } keyId ? $", key ID {keyId}" : "")})...");

        try
        {
            passportService.DoEACCA(
                publicKeyInfo.GetKeyId(),
                chipAuthenticationInfo?.GetObjectIdentifier(),
                publicKeyInfo.GetObjectIdentifier(),
                publicKeyInfo.GetSubjectPublicKey());

            byte[] comBytes = ReadFileBytes(passportService, PassportService.EF_COM);
            var com = new nMRTD.Lds.Icao.COMFile(new MemoryStream(comBytes));
            report.ChipAuthentication.Status = "succeeded";
            _out.WriteLine(
                $"Chip Authentication succeeded: EF.COM ({comBytes.Length} bytes, LDS {com.GetLDSVersion()}) was read with the new "
                + "session keys, so the chip holds the private key for the DG14 public key.");
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
        _out.WriteLine($"Performing Active Authentication (key {Util.GetDetailedPublicKeyAlgorithm(publicKey)})...");

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

    private byte[] ComputeDigest(string digestAlgorithm, byte[] data)
    {
        IDigest digest = DigestUtilities.GetDigest(digestAlgorithm);
        digest.BlockUpdate(data, 0, data.Length);
        byte[] result = new byte[digest.GetDigestSize()];
        digest.DoFinal(result, 0);
        return result;
    }
}
