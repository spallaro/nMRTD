using nMRTD.Lds;
using nMRTD.Tests.Helpers;
using static nMRTD.Tests.EndToEnd.EndToEnd;

namespace nMRTD.Tests.EndToEnd;

/// <summary>READ BINARY block sizes: extended length APDUs, and the fallback when the chip refuses them.</summary>
public class TransportEndToEndTests
{
    private static (SimulatedChip, PassportService) Prepare(bool supportsExtendedLength, bool isSfiEnabled, bool usePace,
        bool protectedWrongLength = false)
    {
        var document = new SimulatedDocument { SupportsExtendedLength = supportsExtendedLength, ProtectedWrongLength = protectedWrongLength };
        document.Pace.Add(new SimulatedChip.PaceSupport(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, 13));
        SimulatedChip chip = document.Build();
        PassportService service = Open(chip, isSfiEnabled);
        if (usePace)
        {
            DoPace(service, PaceKeySpec.CreateCanKey(SimulatedDocument.Can));
        }
        else
        {
            DoBac(service);
        }
        return (chip, service);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void LargeBlocksUseExtendedLengthReadBinary(bool usePace)
    {
        (SimulatedChip chip, PassportService service) = Prepare(true, false, usePace);

        Assert.Equal(chip.ApplicationFiles[PassportService.EF_DG2], Read(service, PassportService.EF_DG2, 4096));

        Assert.Contains(chip.Reads, r => r.Fid == PassportService.EF_DG2 && r.Length > 256);
        Assert.Contains(chip.Commands, c => c.Ne > 256);
    }

    /// <summary>
    /// After a 6700 on a long READ BINARY, the file system falls back to short reads with the secure messaging
    /// wrapper saved before the failed command. The SFI rows are regression tests for the upstream JMRTD bug
    /// (DefaultFileSystem.java:421) where the SFI path did not save it, so the next READ BINARY went out
    /// without secure messaging.
    /// </summary>
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void ChipWithoutExtendedLengthFallsBackToShortReads(bool isSfiEnabled, bool usePace)
    {
        (SimulatedChip chip, PassportService service) = Prepare(false, isSfiEnabled, usePace);

        Assert.Equal(chip.ApplicationFiles[PassportService.EF_DG1], Read(service, PassportService.EF_DG1, 4096));
        Assert.Equal(chip.ApplicationFiles[PassportService.EF_DG2], Read(service, PassportService.EF_DG2, 4096));

        Assert.Contains(chip.Commands, c => c.Ne > 256); // refused with 6700
        Assert.All(chip.Reads, r => Assert.True(r.Length <= PassportService.DefaultMaxBlocksize));
    }

    /// <summary>
    /// A chip that answers the long READ BINARY with a protected 6700: it processed the command under secure
    /// messaging, so both send sequence counters moved on (Doc 9303-11, 9.8.3). The response must be unwrapped
    /// and the wrapper kept; rolling it back, as for a plain 6700, puts the terminal out of step with the chip.
    /// </summary>
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void ProtectedWrongLengthKeepsTheSecureMessagingInStep(bool isSfiEnabled, bool usePace)
    {
        (SimulatedChip chip, PassportService service) = Prepare(false, isSfiEnabled, usePace, protectedWrongLength: true);

        Assert.Equal(chip.ApplicationFiles[PassportService.EF_DG1], Read(service, PassportService.EF_DG1, 4096));
        Assert.Equal(chip.ApplicationFiles[PassportService.EF_DG2], Read(service, PassportService.EF_DG2, 4096));

        Assert.Contains(chip.Commands, c => c.Ne > 256); // answered with a protected 6700
        Assert.All(chip.Reads, r => Assert.True(r.Length <= PassportService.DefaultMaxBlocksize));
    }
}
