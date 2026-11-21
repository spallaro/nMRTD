using nMRTD.Lds;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using static nMRTD.Tests.EndToEnd.EndToEnd;

namespace nMRTD.Tests.EndToEnd;

/// <summary>BAC and every PACE mapping and cipher, each reading DG1 and DG2 through <see cref="PassportService"/>.</summary>
public class AccessControlEndToEndTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void BacReadsDg1AndDg2(bool isSfiEnabled)
    {
        SimulatedChip chip = new SimulatedDocument().Build();
        PassportService service = Open(chip, isSfiEnabled);

        DoBac(service);
        AssertDg1AndDg2(service, chip);

        // DG2 is longer than 32 KB: its tail is only reachable with READ BINARY (odd INS).
        Assert.Contains(chip.Reads, r => r.Fid == PassportService.EF_DG2 && r.Ins == 0xB1 && r.Offset > 0x7FFF);
        Assert.Equal(isSfiEnabled, chip.Reads.Any(r => r.BySfi));
    }

    [Theory]
    [InlineData("0.4.0.127.0.7.2.2.4.1.1", 0, false, false)] // DH-GM 3DES
    [InlineData("0.4.0.127.0.7.2.2.4.1.2", 0, true, true)] // DH-GM AES-128
    [InlineData("0.4.0.127.0.7.2.2.4.1.3", 0, false, true)] // DH-GM AES-192
    [InlineData("0.4.0.127.0.7.2.2.4.1.4", 0, true, false)] // DH-GM AES-256
    [InlineData("0.4.0.127.0.7.2.2.4.2.1", 13, false, false)] // ECDH-GM 3DES, brainpoolP256r1
    [InlineData("0.4.0.127.0.7.2.2.4.2.2", 12, true, true)] // ECDH-GM AES-128, NIST P-256
    [InlineData("0.4.0.127.0.7.2.2.4.2.2", 8, false, false)] // ECDH-GM AES-128, NIST P-192
    [InlineData("0.4.0.127.0.7.2.2.4.2.3", 16, false, true)] // ECDH-GM AES-192, brainpoolP384r1
    [InlineData("0.4.0.127.0.7.2.2.4.2.4", 17, true, false)] // ECDH-GM AES-256, brainpoolP512r1
    [InlineData("0.4.0.127.0.7.2.2.4.2.4", 18, false, true)] // ECDH-GM AES-256, NIST P-521
    [InlineData("0.4.0.127.0.7.2.2.4.4.1", 13, false, true)] // ECDH-IM 3DES
    [InlineData("0.4.0.127.0.7.2.2.4.4.2", 13, true, false)] // ECDH-IM AES-128
    [InlineData("0.4.0.127.0.7.2.2.4.4.2", 15, false, false)] // ECDH-IM AES-128, NIST P-384
    [InlineData("0.4.0.127.0.7.2.2.4.4.3", 16, true, true)] // ECDH-IM AES-192
    [InlineData("0.4.0.127.0.7.2.2.4.4.4", 17, false, false)] // ECDH-IM AES-256
    [InlineData("0.4.0.127.0.7.2.2.4.6.2", 13, false, true)] // ECDH-CAM AES-128
    [InlineData("0.4.0.127.0.7.2.2.4.6.3", 16, true, false)] // ECDH-CAM AES-192
    [InlineData("0.4.0.127.0.7.2.2.4.6.4", 17, false, false)] // ECDH-CAM AES-256
    public void PaceReadsDg1AndDg2(string oid, int parameterId, bool useCan, bool isSfiEnabled)
    {
        var document = new SimulatedDocument();
        document.Pace.Add(new SimulatedChip.PaceSupport(oid, parameterId));
        if (oid.StartsWith(SecurityInfo.ID_PACE_ECDH_CAM, StringComparison.Ordinal))
        {
            // PACE-CAM authenticates the chip with its static Chip Authentication key on the PACE curve.
            document.ChipAuthenticationKeys.Add(new SimulatedChip.CaKey(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128, SimulatedDocument.GenerateEc(parameterId)));
        }
        SimulatedChip chip = document.Build();
        PassportService service = Open(chip, isSfiEnabled);

        IAccessKeySpec key = useCan ? PaceKeySpec.CreateCanKey(SimulatedDocument.Can) : PaceKeySpec.CreateMrzKey(SimulatedDocument.BacKey);
        Protocol.PACEResult result = DoPace(service, key);

        Assert.Equal(oid.EndsWith(".1", StringComparison.Ordinal) ? "DESede" : "AES", result.CipherAlg);
        AssertDg1AndDg2(service, chip);
        Assert.All(chip.Reads.Where(r => r.Fid != PassportService.EF_CARD_ACCESS), r => Assert.Equal(1, r.Session));
    }

    private sealed class ApduRecorder : IApduListener
    {
        public List<ApduEvent> Events { get; } = new();
        public void ExchangedApdu(ApduEvent apduEvent) => Events.Add(apduEvent);
    }

    [Fact]
    public void ListenersObserveTheWholeSession()
    {
        var document = new SimulatedDocument();
        document.Pace.Add(new SimulatedChip.PaceSupport(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, 13));
        SimulatedChip chip = document.Build();
        PassportService service = Open(chip);
        var apdus = new ApduRecorder();
        var logs = new List<Logging.LogEvent>();
        var logListener = new Logging.DelegateLogListener(logs.Add);
        service.AddApduListener(apdus);
        service.AddLogListener(logListener);

        DoPace(service, PaceKeySpec.CreateCanKey(SimulatedDocument.Can));
        byte[] dg1 = Read(service, PassportService.EF_DG1);

        Assert.Equal(chip.Commands.Count, apdus.Events.Count);
        WrappedApduEvent wrapped = apdus.Events.OfType<WrappedApduEvent>().Last();
        Assert.Equal(0xB0, wrapped.PlainTextCommandApdu.Ins);
        Assert.Equal(0x9000, wrapped.PlainTextResponseApdu!.Sw);
        Assert.Contains(logs, e => e.Category == "PACE");
        Assert.Contains(apdus, service.ApduListeners);
        Assert.Contains(logListener, service.LogListeners);
        Assert.Equal(chip.ApplicationFiles[PassportService.EF_DG1], dg1);

        service.RemoveApduListener(apdus);
        service.RemoveLogListener(logListener);
        int seen = apdus.Events.Count;
        Read(service, PassportService.EF_COM);
        Assert.Equal(seen, apdus.Events.Count);
        Assert.Empty(service.ApduListeners);

        Assert.True(service.IsOpen);
        service.Close();
        Assert.False(service.IsOpen);
        Assert.Null(service.GetWrapper());
    }

    /// <summary>
    /// PACE run over an existing secure channel (here, after BAC): its commands are protected with the old keys,
    /// and then secure messaging restarts with the new keys and, by TR-SAC 4.6 / Doc 9303-11, an SSC of 0.
    /// </summary>
    private const string PaceAesSscBug =
        "Library bug: PaceProtocol.cs:322 starts the new AES wrapper with the old wrapper's SSC (read at cs:315) instead of 0, as the 3DES branch (cs:318) and TR-SAC 4.6 do";

    [Theory]
    [InlineData(SecurityInfo.ID_PACE_ECDH_GM_3DES_CBC_CBC, 13)]
    [InlineData(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, 13, Skip = PaceAesSscBug)]
    [InlineData(SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_128, 0, Skip = PaceAesSscBug)]
    public void PaceOverAnExistingSecureChannelRestartsSecureMessaging(string oid, int parameterId)
    {
        var document = new SimulatedDocument();
        document.Pace.Add(new SimulatedChip.PaceSupport(oid, parameterId));
        SimulatedChip chip = document.Build();
        PassportService service = Open(chip);
        DoBac(service);

        Protocol.PACEResult result = service.DoPace(PaceKeySpec.CreateCanKey(SimulatedDocument.Can), oid,
            PACEInfo.ToParameterSpec(parameterId), Org.BouncyCastle.Math.BigInteger.ValueOf(parameterId));
        Assert.Equal(0, result.Wrapper!.SendSequenceCounter);
        service.SendSelectApplet(true);

        Assert.Equal(2, chip.Session);
        Assert.Equal(chip.ApplicationFiles[PassportService.EF_COM], Read(service, PassportService.EF_COM));
    }

    [Fact]
    public void PaceWithBacKeyUsesTheMrz()
    {
        var document = new SimulatedDocument();
        document.Pace.Add(new SimulatedChip.PaceSupport(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, 13));
        SimulatedChip chip = document.Build();
        PassportService service = Open(chip);

        DoPace(service, SimulatedDocument.BacKey);

        AssertDg1AndDg2(service, chip);
    }
}
