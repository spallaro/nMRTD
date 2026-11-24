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

/// <summary>The command-line options, parsed and checked by <see cref="Parse"/>.</summary>
public sealed class CliOptions
{
    public bool Help { get; private set; }

    public bool ListReaders { get; private set; }

    public bool Verbose { get; private set; }

    public OutputFormat Format { get; private set; } = OutputFormat.Text;

    public bool IncludeInformation { get; private set; }

    public bool IncludeRaw { get; private set; }

    public bool Share { get; private set; }

    public AccessMode AccessMode { get; private set; } = AccessMode.Auto;

    public string? Can { get; private set; }

    public string? DocumentNumber { get; private set; }

    public string? DateOfBirth { get; private set; }

    public string? DateOfExpiry { get; private set; }

    public string? Reader { get; private set; }

    public string? CscaPath { get; private set; }

    public bool SkipPassiveAuthentication { get; private set; }

    /// <summary>What the output contains.</summary>
    public OutputOptions Output => new(IncludeInformation, IncludeRaw, Share);

    /// <summary>The access key: the CAN, or the MRZ access key.</summary>
    public AccessCredentials Credentials => Can != null
        ? new AccessCredentials(AccessKeyMode.Can, null, Can)
        : new AccessCredentials(AccessKeyMode.Mrz, new BacKey(DocumentNumber!, DateOfBirth!, DateOfExpiry!), null);

    /// <summary>A problem with the arguments: its exit code and message.</summary>
    public sealed record Problem(int ExitCode, string Message);

    /// <summary>Parses and checks the arguments.</summary>
    /// <returns>the options, or the problem with the arguments</returns>
    public static (CliOptions? Options, Problem? Problem) Parse(string[] args)
    {
        var options = new CliOptions();
        bool outputJson = false;
        bool outputXml = false;
        bool pace = false;
        bool bac = false;
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            string Value()
            {
                if (i + 1 >= args.Length || args[i + 1].StartsWith("--", StringComparison.Ordinal))
                {
                    throw new ArgumentException($"Missing value for {arg}");
                }
                return args[++i];
            }

            try
            {
                switch (arg)
                {
                    case "-h":
                    case "--help":
                        options.Help = true;
                        break;
                    case "--list-readers":
                        options.ListReaders = true;
                        break;
                    case "--verbose":
                        options.Verbose = true;
                        break;
                    case "--output-json":
                        outputJson = true;
                        break;
                    case "--output-xml":
                        outputXml = true;
                        break;
                    case "--include-information":
                        options.IncludeInformation = true;
                        break;
                    case "--include-raw":
                        options.IncludeRaw = true;
                        break;
                    case "--share":
                        options.Share = true;
                        break;
                    case "--pace":
                        pace = true;
                        break;
                    case "--bac":
                        bac = true;
                        break;
                    case "--skip-passive-authentication":
                        options.SkipPassiveAuthentication = true;
                        break;
                    case "--can":
                        options.Can = Value();
                        break;
                    case "--doc":
                        options.DocumentNumber = Value();
                        break;
                    case "--dob":
                        options.DateOfBirth = Value();
                        break;
                    case "--doe":
                        options.DateOfExpiry = Value();
                        break;
                    case "--reader":
                        options.Reader = Value();
                        break;
                    case "--csca":
                        options.CscaPath = Value();
                        break;
                    default:
                        return (null, new Problem(ExitCodes.InvalidArguments, $"Unknown option: {arg}"));
                }
            }
            catch (ArgumentException e)
            {
                return (null, new Problem(ExitCodes.InvalidArguments, e.Message));
            }
        }

        if (options.Help || options.ListReaders)
        {
            return (options, null);
        }

        string? conflict = (outputJson, outputXml, pace, bac) switch
        {
            (true, true, _, _) => "--output-json and --output-xml cannot be combined.",
            (_, _, true, true) => "--pace and --bac cannot be combined.",
            _ when bac && options.Can != null => "--bac needs the MRZ access key (--doc, --dob, --doe): a CAN can only be used for PACE.",
            _ when options.Can != null && (options.DocumentNumber ?? options.DateOfBirth ?? options.DateOfExpiry) != null
                => "--can and the MRZ access key (--doc, --dob, --doe) are alternatives.",
            _ when options.Share && options.IncludeRaw => "--share leaves out the data group contents, so it cannot be combined with --include-raw.",
            _ when options.SkipPassiveAuthentication && options.CscaPath != null
                => "--csca checks the Document Signer, which is part of Passive Authentication: it cannot be combined with --skip-passive-authentication.",
            _ => null,
        };
        if (conflict != null)
        {
            return (null, new Problem(ExitCodes.InvalidArguments, conflict));
        }

        bool completeMrz = options.DocumentNumber != null && options.DateOfBirth != null && options.DateOfExpiry != null;
        if (options.Can == null && !completeMrz)
        {
            return (null, new Problem(ExitCodes.MissingAccessKey,
                "An access key is needed: --can <CAN>, or the MRZ access key --doc <number> --dob <yyMMdd> --doe <yyMMdd>."));
        }

        options.Format = outputJson ? OutputFormat.Json : outputXml ? OutputFormat.Xml : OutputFormat.Text;
        options.AccessMode = pace ? AccessMode.Pace : bac ? AccessMode.Bac : AccessMode.Auto;
        return (options, null);
    }
}
