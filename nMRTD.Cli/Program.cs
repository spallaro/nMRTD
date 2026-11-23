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

using nMRTD;
using nMRTD.Cli;
using nMRTD.Logging;
using nMRTD.SmartCards;

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
        await Console.Error.WriteLineAsync($"Argument error: {e.Message}");
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

    if (options.ContainsKey("bac") && options.ContainsKey("can"))
    {
        await Console.Error.WriteLineAsync("Argument error: --bac needs the MRZ access key (--doc/--dob/--doe); a CAN cannot be used for BAC.");
        PrintUsage();
        return 1;
    }

    AccessCredentials credentials;
    try
    {
        credentials = ResolveAccessCredentials(options);
    }
    catch (ArgumentException e)
    {
        await Console.Error.WriteLineAsync($"Cannot build access key: {e.Message}");
        PrintUsage();
        return 1;
    }

    PcscCardService cardService = new(readerName);
    PassportService passportService = new(
        cardService,
        PassportService.NormalMaxTransceiveLength,
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

        if (options.ContainsKey("bac") && credentials.Mode == AccessKeyMode.Can)
        {
            await Console.Error.WriteLineAsync("--bac needs the MRZ access key; a CAN cannot be used for BAC.");
            return 1;
        }

        var reader = new DocumentReader(passportService, Console.Out);
        if (!reader.Read(credentials, options.ContainsKey("bac"), outDir!))
        {
            // A CAN can only be used to perform PACE (BSI TR-03110): it is not valid BAC key material
            // (BAC is derived from the MRZ), so there is no fallback to offer here.
            await Console.Error.WriteLineAsync(
                "PACE is not available on this document (no EF.CardAccess, or no PACEInfo in it), and "
                + "a Card Access Number can only be used to perform PACE -- cannot fall back to BAC.");
            return 1;
        }

        return 0;
    }
    catch (CardServiceException e)
    {
        await Console.Error.WriteLineAsync($"Card communication error: {e.Message}");
        return 2;
    }
    finally
    {
        passportService.Close();
    }
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
            case "--bac":
                options["bac"] = "true";
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
        nMRTD.Cli -- reads an eMRTD (BAC/PACE, all readable Data Groups, Passive Authentication, Chip Authentication) via a PC/SC reader.

        Usage:
          nMRTD.Cli [--reader <name>] --doc <documentNumber> --dob <yyMMdd> --doe <yyMMdd> [--bac] [--out <dir>]
          nMRTD.Cli [--reader <name>] --can <CAN> [--out <dir>]
          nMRTD.Cli --list-readers

        Options:
          --reader <name>   PC/SC reader name to use (default: first reader found)
          --doc <value>     Document (passport) number, without check digit (MRZ access key)
          --dob <yyMMdd>    Date of birth (MRZ access key)
          --doe <yyMMdd>    Date of expiry (MRZ access key)
          --can <value>     Card Access Number (CAN access key; PACE only, see note below)
          --out <dir>       Directory to save extracted images (DG2/DG5/DG6/DG7) to (default: current directory)
          --bac             Skip PACE and use BAC (needs --doc/--dob/--doe), even if the document supports PACE
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
        full raw hex dump. If DG14 offers it, Chip Authentication is then performed and checked by
        reading EF.COM with the new session keys.
        """);
}

namespace nMRTD.Cli
{
    /// <summary>Which kind of access key was resolved by <c>ResolveAccessCredentials</c>.</summary>
    public enum AccessKeyMode
    {
        /// <summary>MRZ details (document number, date of birth, date of expiry): usable for PACE, falling back to BAC.</summary>
        Mrz,

        /// <summary>Card Access Number: usable for PACE only, no BAC fallback.</summary>
        Can,
    }

    /// <summary>The access key resolved from command-line options or interactive prompts, together with which
    /// kind it is. Exactly one of <see cref="BacKey"/>/<see cref="Can"/> is non-null, matching <see cref="Mode"/>.</summary>
    public sealed record AccessCredentials(AccessKeyMode Mode, IBacKeySpec? BacKey, string? Can);
}
