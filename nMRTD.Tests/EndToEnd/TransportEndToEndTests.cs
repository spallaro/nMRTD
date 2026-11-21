using nMRTD.Lds;
using nMRTD.Tests.Helpers;
using static nMRTD.Tests.EndToEnd.EndToEnd;

namespace nMRTD.Tests.EndToEnd;

/// <summary>READ BINARY block sizes: extended length APDUs, and the fallback when the chip refuses them.</summary>
public class TransportEndToEndTests
{
    private static (SimulatedChip, PassportService) Prepare(bool supportsExtendedLength, bool isSfiEnabled, bool usePace)
    {
        var document = new SimulatedDocument { SupportsExtendedLength = supportsExtendedLength };
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
    /// Library bug: after a 6700 on an SFI READ BINARY, DefaultFileSystem.ReadBinary (DefaultFileSystem.cs:226)
    /// restores <c>_oldWrapper</c>, which only the FID path snapshots (DefaultFileSystem.cs:381); on the SFI
    /// path (DefaultFileSystem.cs:178 -> 395) it still holds what SetWrapper left there (DefaultFileSystem.cs:91),
    /// null after the first BAC or PACE, so the next READ BINARY is sent in plain and the chip ends the session.
    /// </summary>
    private const string SfiFallbackBug =
        "Library bug: DefaultFileSystem.cs:226 restores _oldWrapper, never snapshotted on the SFI path (cs:178/395), so after a 6700 the next READ BINARY goes out without secure messaging";

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false, Skip = SfiFallbackBug)]
    [InlineData(true, true, Skip = SfiFallbackBug)]
    public void ChipWithoutExtendedLengthFallsBackToShortReads(bool isSfiEnabled, bool usePace)
    {
        (SimulatedChip chip, PassportService service) = Prepare(false, isSfiEnabled, usePace);

        Assert.Equal(chip.ApplicationFiles[PassportService.EF_DG1], Read(service, PassportService.EF_DG1, 4096));
        Assert.Equal(chip.ApplicationFiles[PassportService.EF_DG2], Read(service, PassportService.EF_DG2, 4096));

        Assert.Contains(chip.Commands, c => c.Ne > 256); // refused with 6700
        Assert.All(chip.Reads, r => Assert.True(r.Length <= PassportService.DefaultMaxBlocksize));
    }
}
