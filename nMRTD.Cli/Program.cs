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

// nMRTD.Cli: reads and checks an electronic travel document through a PC/SC reader with the nMRTD library.
// Not a port of any JMRTD Java source. See CLI.md for the documentation.

using System.Globalization;

using nMRTD;
using nMRTD.Cli;
using nMRTD.Logging;
using nMRTD.SmartCards;

return Run(args);

static int Run(string[] args)
{
    (CliOptions? options, CliOptions.Problem? problem) = CliOptions.Parse(args);
    if (problem != null)
    {
        Console.Error.WriteLine($"Error: {problem.Message}");
        Console.Error.WriteLine("Use --help for the options.");
        return problem.ExitCode;
    }
    if (options!.Help)
    {
        PrintUsage();
        return ExitCodes.Success;
    }
    if (options.ListReaders)
    {
        return PrintReaderList();
    }

    // The progress and the APDU trace go to stderr, and only with --verbose: stdout carries the result alone.
    TextWriter log = options.Verbose ? Console.Error : TextWriter.Null;

    CscaTrustStore? trustStore = null;
    if (options.CscaPath != null)
    {
        try
        {
            trustStore = CscaTrustStore.Load(options.CscaPath);
        }
        catch (FileNotFoundException e)
        {
            return Fail(options, ExitCodes.CscaNotLoaded, e.Message);
        }
        foreach (string warning in trustStore.Warnings)
        {
            log.WriteLine($"Skipped CSCA file {warning}");
        }
        if (trustStore.Certificates.Count == 0)
        {
            return Fail(options, ExitCodes.CscaNotLoaded, $"No CSCA certificate could be read from {options.CscaPath}.");
        }
        log.WriteLine($"Loaded {trustStore.Certificates.Count} trusted CSCA certificate(s) from {options.CscaPath}.");
    }

    // Find the reader first, to tell "no reader" from "no card".
    string[] readers;
    try
    {
        readers = PcscCardService.GetReaderNames();
    }
    catch (CardServiceException e)
    {
        return Fail(options, ExitCodes.ReaderNotFound, $"PC/SC readers could not be listed: {e.Message}");
    }
    if (readers.Length == 0)
    {
        return Fail(options, ExitCodes.ReaderNotFound, "No PC/SC reader found.");
    }
    if (options.Reader != null && !readers.Contains(options.Reader))
    {
        return Fail(options, ExitCodes.ReaderNotFound, $"Reader \"{options.Reader}\" not found (see --list-readers).");
    }

    var passportService = new PassportService(
        new PcscCardService(options.Reader),
        PassportService.NormalMaxTransceiveLength,
        PassportService.DefaultMaxBlocksize,
        isSfiEnabled: true,
        shouldCheckMac: true);
    if (options.Verbose)
    {
        passportService.AddLogListener(new DelegateLogListener(WriteLogEvent));
    }

    var reader = new DocumentReader(passportService, log) { TrustStore = trustStore };
    reader.Report.Environment.Reader = options.Reader ?? readers[0];
    try
    {
        log.WriteLine($"Opening the card on {options.Reader ?? readers[0]}...");
        try
        {
            passportService.Open();
        }
        catch (CardServiceException e)
        {
            throw new ReadFailure(ExitCodes.CardNotConnected, $"The card could not be connected (is it on the reader?): {e.Message}", e);
        }
        reader.Read(options.Credentials, options.AccessMode, options.SkipPassiveAuthentication);
    }
    catch (ReadFailure e)
    {
        reader.Report.FailureExitCode = e.ExitCode;
        reader.Report.Error = e.Message;
    }
    catch (CardServiceException e)
    {
        reader.Report.FailureExitCode = ExitCodes.CommunicationError;
        reader.Report.Error = $"Card communication error: {e.Message}";
    }
    catch (Exception e)
    {
        reader.Report.FailureExitCode = ExitCodes.UnexpectedError;
        reader.Report.Error = $"Unexpected error: {e.GetType().Name}: {e.Message}";
    }
    finally
    {
        passportService.Close();
    }

    WriteReport(reader.Report, options);
    return reader.Report.ExitCode();
}

/// <summary>A problem before the card is read: the report in the chosen format on stdout, with the message in its
/// error field (also on stderr with --verbose).</summary>
static int Fail(CliOptions options, int exitCode, string message)
{
    if (options.Verbose)
    {
        Console.Error.WriteLine($"Error: {message}");
    }
    var report = new ReadReport { FailureExitCode = exitCode, Error = message };
    WriteReport(report, options);
    return exitCode;
}

static void WriteReport(ReadReport report, CliOptions options)
{
    using Stream stdout = Console.OpenStandardOutput();
    ReportOutput.Write(report, options.Output, options.Format, stdout);
}

static int PrintReaderList()
{
    string[] readers;
    try
    {
        readers = PcscCardService.GetReaderNames();
    }
    catch (CardServiceException e)
    {
        Console.Error.WriteLine($"Error: PC/SC readers could not be listed: {e.Message}");
        return ExitCodes.ReaderNotFound;
    }

    if (readers.Length == 0)
    {
        Console.Error.WriteLine("Error: No PC/SC reader found.");
        return ExitCodes.ReaderNotFound;
    }

    foreach (string reader in readers)
    {
        Console.WriteLine(reader);
    }
    return ExitCodes.Success;
}

static void PrintUsage()
{
    Console.WriteLine("""
        nMRTD.Cli -- reads and checks an electronic travel document through a PC/SC reader.

        Usage:
          nMRTD.Cli --can <CAN> [options]
          nMRTD.Cli --doc <number> --dob <yyMMdd> --doe <yyMMdd> [options]
          nMRTD.Cli --list-readers

        Access:
          --can <CAN>                    Card Access Number (PACE only)
          --doc <number>                 Document number, without check digit (MRZ access key)
          --dob <yyMMdd>                 Date of birth (MRZ access key)
          --doe <yyMMdd>                 Date of expiry (MRZ access key)
          --pace                         Use PACE only (default: PACE, or BAC if the document has no PACE)
          --bac                          Use BAC only (needs the MRZ access key)
          --reader <name>                PC/SC reader to use (default: the first one found)
          --list-readers                 List the PC/SC readers and exit

        Checks:
          --csca <path>                  Trusted CSCA certificates (.cer/.crt/.der/.pem, ICAO master list .ml,
                                         or a folder of them): check the Document Signer certificate
          --skip-passive-authentication  Do not check the data group hashes and the EF.SOD signature

        Output (stdout):
          --output-json                  JSON (default: human readable text)
          --output-xml                   XML
          --include-information          Add the parsed data group information (images in Base64)
          --include-raw                  Add each data group's bytes in Base64
          --share                        Leave out everything that identifies the holder or the document,
                                         to share the result
          --verbose                      Print the progress and the APDU exchanges to stderr
          -h, --help                     Show this help

        Exit codes: 0 read and every check passed; negative for each problem:
          -1 invalid arguments, -2 missing access key, -3 CSCA certificates not loaded,
          -10 reader not found, -11 card not connected,
          -20 PACE not available, -21 PACE failed, -22 BAC failed,
          -30 communication error, -31 unexpected error,
          -40 data group hash mismatch, -41 invalid EF.SOD signature, -42 Document Signer not trusted,
          -43 Chip Authentication failed, -44 Active Authentication failed,
          -45 Chip/Active Authentication with a key not covered by EF.SOD.
        When several checks fail, the code is the first in this list. See CLI.md.
        """);
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
/// <c>--verbose</c> is given -- see <see cref="Run"/>. The two APDU cases rely on the fixed
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

