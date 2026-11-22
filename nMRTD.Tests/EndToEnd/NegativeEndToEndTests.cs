using nMRTD.Lds;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using static nMRTD.Tests.EndToEnd.EndToEnd;

namespace nMRTD.Tests.EndToEnd;

/// <summary>Wrong access keys and tampered secure messaging fail through <see cref="PassportService"/>.</summary>
public class NegativeEndToEndTests
{
    private static IEnumerable<int> StatusWords(Exception? e)
    {
        for (; e != null; e = e.InnerException)
        {
            if (e is CardServiceException cse)
            {
                yield return cse.Sw & 0xFFFF;
            }
        }
    }

    private static SimulatedChip PaceChip(string oid, int parameterId)
    {
        var document = new SimulatedDocument();
        document.Pace.Add(new SimulatedChip.PaceSupport(oid, parameterId));
        return document.Build();
    }

    [Fact]
    public void BacWithTheWrongMrzFails()
    {
        SimulatedChip chip = new SimulatedDocument().Build();
        PassportService service = Open(chip);
        service.SendSelectApplet(false);

        Assert.ThrowsAny<CardServiceException>(() => service.DoBAC(new BacKey(SimulatedDocument.DocumentNumber, SimulatedDocument.DateOfBirth, "301231")));

        Assert.Equal(0, chip.Session);
        Assert.Null(service.GetWrapper());
        Assert.ThrowsAny<CardServiceException>(() => Read(service, PassportService.EF_DG1));
    }

    [Theory]
    [InlineData(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, 13)]
    [InlineData(SecurityInfo.ID_PACE_DH_GM_3DES_CBC_CBC, 0)]
    [InlineData(SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_128, 13)]
    [InlineData(SecurityInfo.ID_PACE_ECDH_GM_3DES_CBC_CBC, 12)]
    public void PaceWithTheWrongCanFails(string oid, int parameterId)
    {
        SimulatedChip chip = PaceChip(oid, parameterId);
        PassportService service = Open(chip);

        Assert.ThrowsAny<CardServiceException>(() => DoPace(service, PaceKeySpec.CreateCanKey("654321")));

        Assert.Equal(0, chip.Session);
    }

    [Theory]
    [InlineData(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, 13)]
    [InlineData(SecurityInfo.ID_PACE_DH_GM_3DES_CBC_CBC, 0)]
    [InlineData(SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_256, 17)]
    public void PaceRejectsAChipWithAWrongAuthenticationToken(string oid, int parameterId)
    {
        SimulatedChip chip = PaceChip(oid, parameterId);
        chip.Fault = SimulatedChip.ChipFault.PaceToken;
        PassportService service = Open(chip);

        Assert.ThrowsAny<CardServiceException>(() => DoPace(service, PaceKeySpec.CreateCanKey(SimulatedDocument.Can)));

        Assert.Null(service.GetWrapper());
    }

    [Theory]
    [InlineData(nameof(SimulatedChip.ChipFault.PaceInvalidMappingKey), SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, 13, 2)]
    [InlineData(nameof(SimulatedChip.ChipFault.PaceInvalidMappingKey), SecurityInfo.ID_PACE_DH_GM_3DES_CBC_CBC, 0, 2)]
    [InlineData(nameof(SimulatedChip.ChipFault.PaceInvalidEphemeralKey), SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, 13, 3)]
    [InlineData(nameof(SimulatedChip.ChipFault.PaceInvalidEphemeralKey), SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_128, 13, 3)]
    [InlineData(nameof(SimulatedChip.ChipFault.PaceInvalidEphemeralKey), SecurityInfo.ID_PACE_DH_GM_3DES_CBC_CBC, 0, 3)]
    [InlineData(nameof(SimulatedChip.ChipFault.PaceEchoedEphemeralKey), SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, 13, 3)]
    [InlineData(nameof(SimulatedChip.ChipFault.PaceEchoedEphemeralKey), SecurityInfo.ID_PACE_DH_GM_3DES_CBC_CBC, 0, 3)]
    public void PaceRejectsAChipWithAnInvalidPublicKey(string fault, string oid, int parameterId, int step)
    {
        SimulatedChip chip = PaceChip(oid, parameterId);
        chip.Fault = Enum.Parse<SimulatedChip.ChipFault>(fault);
        PassportService service = Open(chip);

        var e = Assert.IsType<CardServiceProtocolException>(Assert.ThrowsAny<CardServiceException>(() => DoPace(service, PaceKeySpec.CreateCanKey(SimulatedDocument.Can))));

        Assert.Equal(step, e.Step);
        Assert.Equal(0, chip.Session);
        Assert.Null(service.GetWrapper());
    }

    [Fact]
    public void PaceWithParametersTheChipDoesNotSupportKeepsTheStatusWord()
    {
        SimulatedChip chip = PaceChip(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, 13);
        PassportService service = Open(chip);
        Org.BouncyCastle.Math.BigInteger otherParameterId = Org.BouncyCastle.Math.BigInteger.ValueOf(12);

        CardServiceException e = Assert.ThrowsAny<CardServiceException>(() => service.DoPace(
            PaceKeySpec.CreateCanKey(SimulatedDocument.Can), SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128,
            PACEInfo.ToParameterSpec(otherParameterId), otherParameterId));

        Assert.Contains(0x6A80, StatusWords(e));
        Assert.Null(service.GetWrapper());
    }

    [Theory]
    [InlineData(nameof(SimulatedChip.ChipFault.BacChecksum))]
    [InlineData(nameof(SimulatedChip.ChipFault.BacRandom))]
    public void BacRejectsAChipWithAWrongCryptogram(string fault)
    {
        SimulatedChip chip = new SimulatedDocument().Build();
        chip.Fault = Enum.Parse<SimulatedChip.ChipFault>(fault);
        PassportService service = Open(chip);

        Assert.ThrowsAny<CardServiceException>(() => DoBac(service));

        Assert.Null(service.GetWrapper());
    }

    [Fact]
    public void PaceWithTheWrongMrzFails()
    {
        SimulatedChip chip = PaceChip(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256, 17);
        PassportService service = Open(chip);

        Assert.ThrowsAny<CardServiceException>(() =>
            DoPace(service, PaceKeySpec.CreateMrzKey(new BacKey("TST123457", SimulatedDocument.DateOfBirth, SimulatedDocument.DateOfExpiry))));

        Assert.Equal(0, chip.Session);
    }

    [Fact]
    public void ApplicationFilesNeedAccessControl()
    {
        SimulatedChip chip = new SimulatedDocument().Build();
        PassportService service = Open(chip);
        service.SendSelectApplet(false);

        var e = Assert.ThrowsAny<CardServiceException>(() => Read(service, PassportService.EF_DG1));

        Assert.Contains(chip.Commands, c => c.Ins == 0xB0);
        Assert.Empty(chip.Reads);
        Assert.NotNull(e);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void TamperedResponseMacIsDetected(bool usePace)
    {
        var document = new SimulatedDocument();
        document.Pace.Add(new SimulatedChip.PaceSupport(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, 13));
        SimulatedChip chip = document.Build();
        PassportService service = Open(chip);
        if (usePace)
        {
            DoPace(service, PaceKeySpec.CreateCanKey(SimulatedDocument.Can));
        }
        else
        {
            DoBac(service);
        }

        chip.CorruptNextResponseMac = true;

        Assert.ThrowsAny<CardServiceException>(() => Read(service, PassportService.EF_DG1));
    }

    [Fact]
    public void TamperedResponseMacIsIgnoredWhenMacCheckingIsOff()
    {
        SimulatedChip chip = new SimulatedDocument().Build();
        PassportService service = Open(chip, shouldCheckMac: false);
        DoBac(service);

        chip.CorruptNextResponseMac = true;

        Assert.Equal(chip.ApplicationFiles[PassportService.EF_DG1], Read(service, PassportService.EF_DG1));
    }

    [Fact]
    public void TamperedCommandMacIsRejectedByTheChip()
    {
        SimulatedChip chip = new SimulatedDocument().Build();
        PassportService service = Open(chip);
        DoBac(service);

        chip.CorruptNextCommandMac = true;

        var e = Assert.ThrowsAny<CardServiceException>(() => Read(service, PassportService.EF_DG1));
        Assert.Contains(0x6988, StatusWords(e));
        // The chip has dropped the session: the terminal cannot carry on with its keys.
        Assert.ThrowsAny<CardServiceException>(() => Read(service, PassportService.EF_COM));
        Assert.Empty(chip.Reads);
    }
}
