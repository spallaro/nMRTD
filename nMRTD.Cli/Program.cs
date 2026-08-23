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

// nMRTD.Cli: a small end-to-end test tool for the nMRTD library. Not a port of any JMRTD Java source
// (JMRTD's own demo/test applications live outside src/main and were not part of this port) -- this is
// new application code assembling the already-ported library pieces into the flow described in Doc 9303:
// open a PC/SC reader, perform PACE (falling back to BAC when the card doesn't advertise PACE support),
// read and summarize every standard Data Group the document has (except DG3/DG4, which require Extended
// Access Control), and verify Passive Authentication against EF.SOD.

using System.Globalization;
using System.Text;

using nMRTD;
using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.Lds.Iso19794;
using nMRTD.Logging;
using nMRTD.SmartCards;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

return await RunAsync(args);

static async Task<int> RunAsync(string[] args)
{
    Dictionary<string, string> options;
    try
    {
        options = ParseArgs(args);
    }
    catch (ArgumentException e)
    {
        Console.Error.WriteLine($"Argument error: {e.Message}");
        PrintUsage();
        return 1;
    }

    if (options.ContainsKey("help"))
    {
        PrintUsage();
        return 0;
    }

    if (options.ContainsKey("list-readers"))
    {
        PrintReaderList();
        return 0;
    }

    string? readerName = options.GetValueOrDefault("reader");
    string? outDir = options.GetValueOrDefault("out", Directory.GetCurrentDirectory());

    AccessCredentials credentials;
    try
    {
        credentials = ResolveAccessCredentials(options);
    }
    catch (ArgumentException e)
    {
        Console.Error.WriteLine($"Cannot build access key: {e.Message}");
        PrintUsage();
        return 1;
    }

    PcscCardService cardService = new(readerName);
    PassportService passportService = new(
        cardService,
        PassportService.NormalMaxTranceiveLength,
        PassportService.DefaultMaxBlocksize,
        isSfiEnabled: true,
        shouldCheckMac: true);

    if (options.ContainsKey("verbose"))
    {
        passportService.AddLogListener(new DelegateLogListener(WriteLogEvent));
        Console.WriteLine("Verbose logging enabled -- APDU exchanges and protocol steps are printed to stderr.");
    }

    try
    {
        Console.WriteLine("Opening card service...");
        passportService.Open();

        IAccessKeySpec paceKey = credentials.Mode == AccessKeyMode.Can
            ? PaceKeySpec.CreateCanKey(credentials.Can!)
            : PaceKeySpec.CreateMrzKey(credentials.BacKey!);

        bool usedPace = await TryPerformPaceAsync(passportService, paceKey);
        if (!usedPace)
        {
            if (credentials.Mode == AccessKeyMode.Can)
            {
                // A CAN can only be used to perform PACE (BSI TR-03110): it is not valid BAC key material
                // (BAC is derived from the MRZ), so there is no fallback to offer here.
                Console.Error.WriteLine(
                    "PACE is not available on this document (no EF.CardAccess, or no PACEInfo in it), and "
                    + "a Card Access Number can only be used to perform PACE -- cannot fall back to BAC.");
                return 1;
            }

            Console.WriteLine("PACE not available (or not supported by this document) -- falling back to BAC.");
            passportService.SendSelectApplet(false);
            passportService.DoBAC(credentials.BacKey!);
            Console.WriteLine("BAC completed.");
        }

        Dictionary<int, byte[]> dataGroupBytes = ReadAndPrintDataGroups(passportService, outDir!);

        byte[] sodBytes = ReadFileBytes(passportService, PassportService.EF_SOD);
        var sodFile = new SODFile(new MemoryStream(sodBytes));
        VerifyPassiveAuthentication(sodFile, dataGroupBytes);

        return 0;
    }
    catch (CardServiceException e)
    {
        Console.Error.WriteLine($"Card communication error: {e.Message}");
        return 2;
    }
    finally
    {
        passportService.Close();
    }
}

/// <summary>Reads EF.CardAccess (if present) looking for a PACEInfo, and performs PACE if found.</summary>
/// <param name="passportService">the opened passport service</param>
/// <param name="paceKey">the PACE access key to use (MRZ- or CAN-derived; see <see cref="PaceKeySpec"/>)</param>
/// <returns><see langword="true"/> if PACE was performed, <see langword="false"/> if the card has no EF.CardAccess (BAC-only document).</returns>
static async Task<bool> TryPerformPaceAsync(PassportService passportService, IAccessKeySpec paceKey)
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

    Org.BouncyCastle.Math.BigInteger? parameterId = paceInfo.GetParameterId();
    if (parameterId == null)
    {
        // Custom (non-standardized) PACE domain parameters require a companion PACEDomainParameterInfo
        // in EF.CardAccess to resolve; this CLI only supports the common case of a standardized
        // parameter id (BSI TR-03110 Table 6).
        Console.WriteLine("PACE is advertised but uses non-standardized domain parameters, which this CLI does not resolve -- falling back to BAC.");
        return false;
    }

    object staticParameters = PACEInfo.ToParameterSpec(parameterId);

    Console.WriteLine($"Performing PACE (protocol {paceInfo.GetObjectIdentifier()})...");
    passportService.DoPace(paceKey, paceInfo.GetObjectIdentifier(), staticParameters, parameterId);
    passportService.SendSelectApplet(true);
    Console.WriteLine("PACE completed; secure messaging established.");

    await Task.CompletedTask;
    return true;
}

/// <summary>Short human-readable status line to print next to the raw status word hex in
/// <see cref="WriteLogEvent"/>. Covers a handful of well-known ISO 7816-4 / ICAO 9303 status words plus a
/// couple of range-based guesses (<c>61xx</c>/<c>63xx</c>); not exhaustive -- falls back to a generic
/// "Error" for anything else, or the empty string if <paramref name="sw"/> could not be parsed at all.</summary>
static string DescribeStatusWord(int sw) => sw switch
{
    0x9000 => "OK",
    0x6700 => "Wrong length",
    0x6982 => "Security status not satisfied",
    0x6985 => "Conditions of use not satisfied",
    0x6986 => "Command not allowed",
    0x6988 => "SM data objects incorrect",
    0x6A80 => "Incorrect parameters in data field",
    0x6A82 => "File not found",
    0x6A88 => "Referenced data not found",
    0x6D00 => "Instruction not supported",
    0x6E00 => "Class not supported",
    0x6F00 => "Unknown error",
    -1 => "",
    _ when (sw & 0xFF00) == 0x6100 => "More data available",
    _ when (sw & 0xFF00) == 0x6300 => "Verification failed",
    _ => "Error",
};

/// <summary>Extracts the 4 hex digits following <c>"SW="</c> in an APDU response trace message (see
/// <c>SecureMessagingAPDUSender.LogApduExchange</c>), or <c>-1</c> if not found/parseable.</summary>
static int ExtractStatusWord(string message)
{
    int index = message.IndexOf("SW=", StringComparison.Ordinal);
    if (index < 0 || index + 7 > message.Length)
    {
        return -1;
    }

    return int.TryParse(message.AsSpan(index + 3, 4), System.Globalization.NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int sw) ? sw : -1;
}

/// <summary>
/// Prints a <see cref="LogEvent"/> raised by the library (via <c>PassportService.AddLogListener</c>) to
/// stderr in real time, color-coded and formatted so a request is visually distinct from its response, and
/// both are visually distinct from a plain protocol-step message or an error. Used only when
/// <c>--verbose</c> is given -- see <see cref="RunAsync"/>. The two APDU cases rely on the fixed
/// <c>"--&gt; "</c>/<c>"&lt;-- "</c> markers that <c>SecureMessagingAPDUSender.LogApduExchange</c>
/// documents as part of its message format specifically so a listener like this one can tell them apart.
/// </summary>
static void WriteLogEvent(LogEvent logEvent)
{
    ConsoleColor previousColor = Console.ForegroundColor;
    string time = logEvent.Timestamp.ToString("HH:mm:ss.fff", CultureInfo.InvariantCulture);
    try
    {
        if (logEvent.Category == "APDU" && logEvent.Message.StartsWith("--> ", StringComparison.Ordinal))
        {
            Console.ForegroundColor = ConsoleColor.DarkCyan;
            Console.Error.WriteLine($"  {time}  → {logEvent.Message[4..]}"); // '→' = "->"
            return;
        }

        if (logEvent.Category == "APDU" && logEvent.Message.StartsWith("<-- ", StringComparison.Ordinal))
        {
            int sw = ExtractStatusWord(logEvent.Message);
            Console.ForegroundColor = sw == 0x9000 ? ConsoleColor.Green
                : (sw & 0xFF00) is 0x6100 or 0x6300 ? ConsoleColor.Yellow
                : ConsoleColor.Red;
            string description = DescribeStatusWord(sw);
            string suffix = description.Length == 0 ? string.Empty : $"  ({description})";
            Console.Error.WriteLine($"  {time}  ← {logEvent.Message[4..]}{suffix}"); // '←' = "<-"
            return;
        }

        switch (logEvent.Level)
        {
            case LogLevel.Error:
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Error.WriteLine($"  {time}  [{logEvent.Category}] ERROR: {logEvent.Message}");
                for (Exception? e = logEvent.Exception; e != null; e = e.InnerException)
                {
                    Console.Error.WriteLine($"  {time}      {(e == logEvent.Exception ? "->" : "caused by")} {e.GetType().Name}: {e.Message}");
                }
                break;
            case LogLevel.Warning:
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Error.WriteLine($"  {time}  [{logEvent.Category}] WARN: {logEvent.Message}");
                break;
            case LogLevel.Information:
                Console.ForegroundColor = ConsoleColor.White;
                Console.Error.WriteLine($"  {time}  [{logEvent.Category}] {logEvent.Message}");
                break;
            case LogLevel.Debug:
            default:
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Error.WriteLine($"  {time}  [{logEvent.Category}] {logEvent.Message}");
                break;
        }
    }
    finally
    {
        Console.ForegroundColor = previousColor;
    }
}

static byte[] ReadFileBytes(PassportService passportService, short fid)
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
static (int Number, short Fid)[] GetStandardDataGroupIds() =>
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
static Dictionary<int, byte[]> ReadAndPrintDataGroups(PassportService passportService, string outDir)
{
    Console.WriteLine();
    Console.WriteLine("=== Data Groups ===");

    var dataGroupBytes = new Dictionary<int, byte[]>();
    foreach ((int number, short fid) in GetStandardDataGroupIds())
    {
        byte[] bytes;
        try
        {
            bytes = ReadFileBytes(passportService, fid);
        }
        catch (CardServiceException e)
        {
            Console.WriteLine();
            Console.WriteLine($"--- DG{number} ---");
            Console.WriteLine($"Not present on this document ({e.Message}).");
            continue;
        }

        dataGroupBytes[number] = bytes;

        Console.WriteLine();
        Console.WriteLine($"--- DG{number} ({bytes.Length} bytes) ---");
        try
        {
            PrintDataGroupContent(number, bytes, outDir);
        }
        catch (Exception e)
        {
            Console.WriteLine($"(Could not parse DG{number} content: {e.Message})");
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
static void PrintDataGroupContent(int number, byte[] bytes, string outDir)
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
            Console.WriteLine($"No structured parser for DG{number} in this port -- raw bytes only (see below).");
            break;
    }
}

/// <summary>Prints the given bytes as a hex dump (offset + <c>0xNN</c> tokens, 16 per line) -- shown for
/// every data group read, regardless of whether this port has a structured parser for it.</summary>
static void PrintHexDump(byte[] bytes)
{
    Console.WriteLine("Raw bytes (hex):");
    if (bytes.Length == 0)
    {
        Console.WriteLine("  (empty)");
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

        Console.WriteLine(line.ToString().TrimEnd());
    }
}

/// <summary>Prints a summary of, and saves to <paramref name="outDir"/>, each image in a DG5/DG6/DG7
/// displayed-image list (portrait for DG5, signature/mark for DG7, unspecified for DG6).</summary>
static void SaveDisplayedImages(string label, List<DisplayedImageInfo> images, string fileNamePrefix, string outDir)
{
    if (images.Count == 0)
    {
        Console.WriteLine($"{label}: no images present.");
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

        Console.WriteLine($"{label}: saved image {index} ({image.GetMimeType()}, {image.GetImageLength()} bytes) to {path}");
        index++;
    }
}

/// <summary>Prints DG11 (additional personal details) as a list of the fields actually present.</summary>
static void PrintDG11(DG11File dg11)
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
        Console.WriteLine($"Proof of citizenship: image ({proofOfCitizenship.Length} bytes)");
    }

    PrintListIfPresent("Other valid travel document numbers", dg11.GetOtherValidTDNumbers());
    PrintFieldIfPresent("Custody information", dg11.GetCustodyInformation());
    if (dg11.GetTagPresenceList().Count == 0)
    {
        Console.WriteLine("(No fields present.)");
    }
}

/// <summary>Prints DG12 (additional document details) as a list of the fields actually present.</summary>
static void PrintDG12(DG12File dg12)
{
    PrintFieldIfPresent("Issuing authority", dg12.GetIssuingAuthority());
    PrintFieldIfPresent("Date of issue", dg12.GetDateOfIssue());
    PrintListIfPresent("Names of other persons", dg12.GetNamesOfOtherPersons());
    PrintFieldIfPresent("Endorsements/observations", dg12.GetEndorsementsAndObservations());
    PrintFieldIfPresent("Tax or exit requirements", dg12.GetTaxOrExitRequirements());
    byte[]? imageOfFront = dg12.GetImageOfFront();
    if (imageOfFront != null)
    {
        Console.WriteLine($"Image of front: image ({imageOfFront.Length} bytes)");
    }

    byte[]? imageOfRear = dg12.GetImageOfRear();
    if (imageOfRear != null)
    {
        Console.WriteLine($"Image of rear: image ({imageOfRear.Length} bytes)");
    }

    PrintFieldIfPresent("Date/time of personalization", dg12.GetDateAndTimeOfPersonalization());
    PrintFieldIfPresent("Personalization system serial number", dg12.GetPersonalizationSystemSerialNumber());
    if (dg12.GetTagPresenceList().Count == 0)
    {
        Console.WriteLine("(No fields present.)");
    }
}

/// <summary>Prints DG14 (EAC/PACE SecurityInfos) as a count plus one line per SecurityInfo.</summary>
static void PrintDG14(DG14File dg14)
{
    IReadOnlyCollection<SecurityInfo> securityInfos = dg14.GetSecurityInfos();
    Console.WriteLine($"{securityInfos.Count} SecurityInfo(s):");
    foreach (SecurityInfo securityInfo in securityInfos)
    {
        Console.WriteLine($"  - {securityInfo.GetType().Name}: {securityInfo}");
    }
}

/// <summary>Prints DG15 (Active Authentication public key) as its algorithm/size.</summary>
static void PrintDG15(DG15File dg15)
{
    AsymmetricKeyParameter? publicKey = dg15.GetPublicKey();
    Console.WriteLine(publicKey == null
        ? "Could not decode the Active Authentication public key."
        : $"Active Authentication public key: {Util.GetDetailedPublicKeyAlgorithm(publicKey)}");
}

static void PrintFieldIfPresent(string label, string? value)
{
    if (!string.IsNullOrEmpty(value))
    {
        Console.WriteLine($"{label}: {value}");
    }
}

static void PrintListIfPresent(string label, List<string>? values)
{
    if (values != null && values.Count > 0)
    {
        Console.WriteLine($"{label}: {string.Join(", ", values)}");
    }
}

static void PrintMrzInfo(MRZInfo mrz)
{
    Console.WriteLine($"Document number: {mrz.GetDocumentNumber()}");
    Console.WriteLine($"Name:            {mrz.GetPrimaryIdentifier()} / {mrz.GetSecondaryIdentifier()}");
    Console.WriteLine($"Nationality:     {mrz.GetNationality()}");
    Console.WriteLine($"Issuing state:   {mrz.GetIssuingState()}");
    Console.WriteLine($"Date of birth:   {mrz.GetDateOfBirth()}");
    Console.WriteLine($"Date of expiry:  {mrz.GetDateOfExpiry()}");
    Console.WriteLine($"Gender:          {mrz.GetGenderCode()}");
}

static void SaveFaceImage(DG2File dg2File, string outDir)
{
    FaceInfo? faceInfo = null;
    foreach (var record in dg2File.GetSubRecords())
    {
        if (record is FaceInfo candidate)
        {
            faceInfo = candidate;
            break;
        }
    }

    if (faceInfo == null)
    {
        Console.WriteLine("No face record found in DG2.");
        return;
    }

    List<FaceImageInfo> images = faceInfo.GetFaceImageInfos();
    if (images.Count == 0)
    {
        Console.WriteLine("Face record contains no images.");
        return;
    }

    Directory.CreateDirectory(outDir);
    int index = 0;
    foreach (FaceImageInfo image in images)
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
        Console.WriteLine($"Saved face image {index} ({image.GetMimeType()}, {image.GetImageLength()} bytes) to {path}");
        index++;
    }
}

static void VerifyPassiveAuthentication(SODFile sodFile, IReadOnlyDictionary<int, byte[]> dataGroupBytes)
{
    Console.WriteLine();
    Console.WriteLine("=== Passive Authentication ===");

    string? digestAlgorithm = sodFile.GetDigestAlgorithm();
    if (digestAlgorithm == null)
    {
        Console.WriteLine("Could not determine the digest algorithm used in EF.SOD; skipping.");
        return;
    }

    SortedDictionary<int, byte[]> storedHashes = sodFile.GetDataGroupHashes();
    foreach ((int dgNumber, byte[] rawBytes) in dataGroupBytes)
    {
        if (!storedHashes.TryGetValue(dgNumber, out byte[]? expectedHash))
        {
            Console.WriteLine($"DG{dgNumber}: no hash present in EF.SOD -- cannot verify.");
            continue;
        }

        byte[] actualHash = ComputeDigest(digestAlgorithm, rawBytes);
        bool matches = actualHash.AsSpan().SequenceEqual(expectedHash);
        Console.WriteLine(matches
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
        Console.WriteLine($"EF.SOD content-digest check failed: {e.Message}");
        return;
    }

    byte[] encryptedDigest = sodFile.GetEncryptedDigest();
    string? digestEncryptionAlgorithm = sodFile.GetDigestEncryptionAlgorithm();
    var docSigningCertificate = sodFile.GetDocSigningCertificate();

    if (digestEncryptionAlgorithm == null || docSigningCertificate == null)
    {
        Console.WriteLine("Could not determine the signature algorithm or document signing certificate; cannot verify the EF.SOD signature.");
        return;
    }

    try
    {
        AsymmetricKeyParameter publicKey = docSigningCertificate.GetPublicKey();
        ISigner verifier = SignerUtilities.GetSigner(digestEncryptionAlgorithm);
        verifier.Init(forSigning: false, publicKey);
        verifier.BlockUpdate(eContent, 0, eContent.Length);
        bool signatureValid = verifier.VerifySignature(encryptedDigest);

        Console.WriteLine(signatureValid
            ? $"EF.SOD signature is VALID ({digestEncryptionAlgorithm}, signed by: {docSigningCertificate.SubjectDN})."
            : "EF.SOD signature is INVALID -- the security object may have been tampered with!");
    }
    catch (Exception e)
    {
        Console.WriteLine($"Could not verify the EF.SOD signature (algorithm '{digestEncryptionAlgorithm}' not supported by this CLI): {e.Message}");
    }

    Console.WriteLine(
        "NOTE: this only proves EF.SOD and the data groups above are internally consistent and unmodified. "
        + "The document signing certificate itself was NOT validated against a trusted CSCA root (no trust "
        + "store is configured by this CLI), so this does NOT prove the document was issued by a legitimate authority.");
}

static byte[] ComputeDigest(string digestAlgorithm, byte[] data)
{
    IDigest digest = DigestUtilities.GetDigest(digestAlgorithm);
    digest.BlockUpdate(data, 0, data.Length);
    byte[] result = new byte[digest.GetDigestSize()];
    digest.DoFinal(result, 0);
    return result;
}

/// <summary>Resolves which access key to authenticate with: either MRZ details (document number, date of
/// birth, date of expiry -- usable for PACE, falling back to BAC) or a Card Access Number (usable for PACE
/// only). <c>--can</c> and the <c>--doc</c>/<c>--dob</c>/<c>--doe</c> triple are mutually exclusive; if
/// neither is given on the command line, the user is prompted to choose interactively.</summary>
static AccessCredentials ResolveAccessCredentials(Dictionary<string, string> options)
{
    string? can = options.GetValueOrDefault("can");
    string? documentNumber = options.GetValueOrDefault("doc");
    string? dateOfBirth = options.GetValueOrDefault("dob");
    string? dateOfExpiry = options.GetValueOrDefault("doe");

    bool hasCanArg = can != null;
    bool hasAnyMrzArg = documentNumber != null || dateOfBirth != null || dateOfExpiry != null;
    if (hasCanArg && hasAnyMrzArg)
    {
        throw new ArgumentException("--can cannot be combined with --doc/--dob/--doe -- a Card Access Number is an alternative to the MRZ details, not a supplement to them.");
    }

    AccessKeyMode mode = hasCanArg ? AccessKeyMode.Can : hasAnyMrzArg ? AccessKeyMode.Mrz : PromptAccessKeyMode();

    if (mode == AccessKeyMode.Can)
    {
        if (can == null)
        {
            Console.Write("Card Access Number (CAN): ");
            can = Console.ReadLine()?.Trim();
        }

        if (string.IsNullOrWhiteSpace(can))
        {
            throw new ArgumentException("A Card Access Number is required (use --can or answer the prompt).");
        }

        return new AccessCredentials(AccessKeyMode.Can, BacKey: null, Can: can);
    }

    if (documentNumber == null)
    {
        Console.Write("Document number: ");
        documentNumber = Console.ReadLine()?.Trim();
    }
    if (dateOfBirth == null)
    {
        Console.Write("Date of birth (yyMMdd): ");
        dateOfBirth = Console.ReadLine()?.Trim();
    }
    if (dateOfExpiry == null)
    {
        Console.Write("Date of expiry (yyMMdd): ");
        dateOfExpiry = Console.ReadLine()?.Trim();
    }

    if (string.IsNullOrWhiteSpace(documentNumber) || string.IsNullOrWhiteSpace(dateOfBirth) || string.IsNullOrWhiteSpace(dateOfExpiry))
    {
        throw new ArgumentException("Document number, date of birth, and date of expiry are all required (use --doc/--dob/--doe or answer the prompts).");
    }

    return new AccessCredentials(AccessKeyMode.Mrz, new BacKey(documentNumber, dateOfBirth, dateOfExpiry), Can: null);
}

/// <summary>Interactively asks the user whether to authenticate with MRZ details or a Card Access Number,
/// used only when neither <c>--can</c> nor any of <c>--doc</c>/<c>--dob</c>/<c>--doe</c> were given.</summary>
static AccessKeyMode PromptAccessKeyMode()
{
    Console.WriteLine("Choose the access key to authenticate with:");
    Console.WriteLine("  1) MRZ (document number + date of birth + date of expiry) -- PACE, falling back to BAC");
    Console.WriteLine("  2) CAN (Card Access Number) -- PACE only, no BAC fallback");
    while (true)
    {
        Console.Write("Select [1/2]: ");
        switch (Console.ReadLine()?.Trim())
        {
            case "1":
                return AccessKeyMode.Mrz;
            case "2":
                return AccessKeyMode.Can;
            default:
                Console.WriteLine("Please enter 1 or 2.");
                break;
        }
    }
}

static void PrintReaderList()
{
    string[] readers;
    try
    {
        readers = PcscCardService.GetReaderNames();
    }
    catch (CardServiceException e)
    {
        Console.Error.WriteLine($"Could not enumerate readers: {e.Message}");
        return;
    }

    if (readers.Length == 0)
    {
        Console.WriteLine("No PC/SC readers found.");
        return;
    }

    Console.WriteLine("Available PC/SC readers:");
    foreach (string reader in readers)
    {
        Console.WriteLine($"  {reader}");
    }
}

static Dictionary<string, string> ParseArgs(string[] args)
{
    var options = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    for (int i = 0; i < args.Length; i++)
    {
        string arg = args[i];
        switch (arg)
        {
            case "-h":
            case "--help":
                options["help"] = "true";
                break;
            case "--list-readers":
                options["list-readers"] = "true";
                break;
            case "--verbose":
                options["verbose"] = "true";
                break;
            case "--reader":
            case "--doc":
            case "--dob":
            case "--doe":
            case "--can":
            case "--out":
                if (i + 1 >= args.Length)
                {
                    throw new ArgumentException($"Missing value for {arg}");
                }
                options[arg.TrimStart('-')] = args[++i];
                break;
            default:
                throw new ArgumentException($"Unrecognized argument: {arg}");
        }
    }
    return options;
}

static void PrintUsage()
{
    Console.WriteLine("""
        nMRTD.Cli -- reads an eMRTD (BAC/PACE, all readable Data Groups, Passive Authentication) via a PC/SC reader.

        Usage:
          nMRTD.Cli [--reader <name>] --doc <documentNumber> --dob <yyMMdd> --doe <yyMMdd> [--out <dir>]
          nMRTD.Cli [--reader <name>] --can <CAN> [--out <dir>]
          nMRTD.Cli --list-readers

        Options:
          --reader <name>   PC/SC reader name to use (default: first reader found)
          --doc <value>     Document (passport) number, without check digit (MRZ access key)
          --dob <yyMMdd>    Date of birth (MRZ access key)
          --doe <yyMMdd>    Date of expiry (MRZ access key)
          --can <value>     Card Access Number (CAN access key; PACE only, see note below)
          --out <dir>       Directory to save extracted images (DG2/DG5/DG6/DG7) to (default: current directory)
          --verbose         Print APDU exchanges and protocol steps (BAC/PACE/...) to stderr as they happen
          --list-readers    List available PC/SC readers and exit
          -h, --help        Show this help

        --can and --doc/--dob/--doe are alternatives to each other, not to be combined. If
        neither is given, you will be prompted interactively to choose which one to use.

        A Card Access Number can only be used to perform PACE (BSI TR-03110): unlike the MRZ,
        it cannot derive a BAC key. If the document does not support PACE, --can authentication
        fails outright instead of falling back to BAC.

        After authentication, every standard Data Group is read and summarized, except DG3
        (fingerprints) and DG4 (iris), which require Extended Access Control and are always
        skipped. A DG the document does not have is reported as "not present"; each DG that is
        read is printed both as a parsed summary (where this port has a parser for it) and as a
        full raw hex dump.
        """);
}

/// <summary>Which kind of access key was resolved by <see cref="ResolveAccessCredentials"/>.</summary>
internal enum AccessKeyMode
{
    /// <summary>MRZ details (document number, date of birth, date of expiry): usable for PACE, falling back to BAC.</summary>
    Mrz,

    /// <summary>Card Access Number: usable for PACE only, no BAC fallback.</summary>
    Can,
}

/// <summary>The access key resolved from command-line options or interactive prompts, together with which
/// kind it is. Exactly one of <see cref="BacKey"/>/<see cref="Can"/> is non-null, matching <see cref="Mode"/>.</summary>
internal sealed record AccessCredentials(AccessKeyMode Mode, IBacKeySpec? BacKey, string? Can);
