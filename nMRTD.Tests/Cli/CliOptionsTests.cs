using nMRTD.Cli;

namespace nMRTD.Tests.Cli;

/// <summary>The command-line options and the exit code of each invalid combination.</summary>
public class CliOptionsTests
{
    private static readonly string[] Mrz = ["--doc", "L898902C3", "--dob", "740812", "--doe", "120415"];

    [Fact]
    public void DefaultsWithTheMrzAccessKey()
    {
        (CliOptions? options, CliOptions.Problem? problem) = CliOptions.Parse(Mrz);

        Assert.Null(problem);
        Assert.Equal(OutputFormat.Text, options!.Format);
        Assert.Equal(AccessMode.Auto, options.AccessMode);
        Assert.Equal(AccessKeyMode.Mrz, options.Credentials.Mode);
        Assert.False(options.Verbose || options.IncludeInformation || options.IncludeRaw || options.Share || options.SkipPassiveAuthentication);
    }

    [Fact]
    public void EveryOption()
    {
        (CliOptions? options, _) = CliOptions.Parse(["--can", "123456", "--pace", "--output-xml", "--include-information",
            "--share", "--verbose", "--reader", "My Reader", "--csca", "csca.pem"]);

        Assert.Equal(OutputFormat.Xml, options!.Format);
        Assert.Equal(AccessMode.Pace, options.AccessMode);
        Assert.Equal(AccessKeyMode.Can, options.Credentials.Mode);
        Assert.Equal("123456", options.Credentials.Can);
        Assert.Equal(new OutputOptions(IncludeInformation: true, IncludeRaw: false, Share: true), options.Output);
        Assert.True(options.Verbose);
        Assert.Equal("My Reader", options.Reader);
        Assert.Equal("csca.pem", options.CscaPath);
    }

    [Fact]
    public void JsonRawAndBac()
    {
        (CliOptions? options, _) = CliOptions.Parse([.. Mrz, "--bac", "--output-json", "--include-raw", "--skip-passive-authentication"]);

        Assert.Equal(OutputFormat.Json, options!.Format);
        Assert.Equal(AccessMode.Bac, options.AccessMode);
        Assert.True(options.IncludeRaw);
        Assert.True(options.SkipPassiveAuthentication);
    }

    [Theory]
    [InlineData("--help")]
    [InlineData("-h")]
    [InlineData("--list-readers")]
    public void HelpAndListReadersNeedNoAccessKey(string option)
    {
        (CliOptions? options, CliOptions.Problem? problem) = CliOptions.Parse([option]);

        Assert.Null(problem);
        Assert.True(options!.Help || options.ListReaders);
    }

    public static TheoryData<string[], int> Invalid => new()
    {
        { ["--unknown"], ExitCodes.InvalidArguments },
        { ["--can"], ExitCodes.InvalidArguments },
        { ["--can", "--pace"], ExitCodes.InvalidArguments },
        { ["--can", "1", "--output-json", "--output-xml"], ExitCodes.InvalidArguments },
        { [.. Mrz, "--pace", "--bac"], ExitCodes.InvalidArguments },
        { ["--can", "1", "--bac"], ExitCodes.InvalidArguments },
        { ["--can", "1", "--doc", "X"], ExitCodes.InvalidArguments },
        { ["--can", "1", "--share", "--include-raw"], ExitCodes.InvalidArguments },
        { ["--can", "1", "--skip-passive-authentication", "--csca", "x"], ExitCodes.InvalidArguments },
        { [], ExitCodes.MissingAccessKey },
        { ["--doc", "L898902C3", "--dob", "740812"], ExitCodes.MissingAccessKey },
        { ["--output-json"], ExitCodes.MissingAccessKey },
    };

    [Theory]
    [MemberData(nameof(Invalid))]
    public void InvalidArgumentsHaveTheirExitCode(string[] args, int exitCode)
    {
        (CliOptions? options, CliOptions.Problem? problem) = CliOptions.Parse(args);

        Assert.Null(options);
        Assert.Equal(exitCode, problem!.ExitCode);
    }

    [Fact]
    public void ExitCodesAreDistinctAndNegative()
    {
        int[] codes = typeof(ExitCodes).GetFields().Where(f => f.Name != nameof(ExitCodes.Success)).Select(f => (int)f.GetValue(null)!).ToArray();

        Assert.All(codes, code => Assert.True(code < 0));
        Assert.Equal(codes.Length, codes.Distinct().Count());
    }
}
