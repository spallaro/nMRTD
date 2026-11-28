using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.Protocol;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using static nMRTD.Tests.EndToEnd.EndToEnd;

namespace nMRTD.Tests.EndToEnd;

/// <summary>Chip Authentication (and PACE-CAM) end to end: secure messaging restarts with the keys agreed with the chip.</summary>
public class ChipAuthenticationEndToEndTests
{
    private const string CaDh3Des = "0.4.0.127.0.7.2.2.3.1.1";
    private const string CaEcdh3Des = "0.4.0.127.0.7.2.2.3.2.1";

    private static SimulatedChip.CaKey Key(string oid, int parameterId, int? keyId) => new(oid,
        parameterId == 0 ? SimulatedDocument.GenerateDh() : SimulatedDocument.GenerateEc(parameterId), keyId);

    private static (SimulatedChip Chip, PassportService Service) Authenticate(SimulatedChip.CaKey key, bool usePace, bool isSfiEnabled = false)
    {
        var document = new SimulatedDocument();
        document.ChipAuthenticationKeys.Add(key);
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
    [InlineData(CaDh3Des, 0, null, false)]
    [InlineData(CaEcdh3Des, 13, null, false)]
    [InlineData(CaEcdh3Des, 12, 7, true)]
    [InlineData(SecurityInfo.ID_CA_DH_AES_CBC_CMAC_128, 0, 1, false)]
    [InlineData(SecurityInfo.ID_CA_DH_AES_CBC_CMAC_256, 0, null, true)]
    [InlineData(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128, 13, 1, true)]
    [InlineData(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128, 13, null, false)]
    [InlineData(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_192, 16, 2, true)]
    [InlineData(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_256, 17, null, true)]
    public void ChipAuthenticationRestartsSecureMessagingAndEfComReadsWithTheNewKeys(string oid, int parameterId, int? keyId, bool usePace)
    {
        (SimulatedChip chip, PassportService service) = Authenticate(Key(oid, parameterId, keyId), usePace);
        int sessionBefore = chip.Session;

        EACCAResult result = DoChipAuthentication(service);

        Assert.Equal(sessionBefore + 1, chip.Session);
        Assert.Same(result.Wrapper, service.GetWrapper());
        Assert.Equal(0, result.Wrapper.SendSequenceCounter);
        Assert.Equal(oid == CaDh3Des || oid == CaEcdh3Des, result.Wrapper is DESedeSecureMessagingWrapper);

        // EF.COM was never read before Chip Authentication, so it cannot come from the file system cache.
        Assert.DoesNotContain(chip.Reads, r => r.Fid == PassportService.EF_COM);
        byte[] com = Read(service, PassportService.EF_COM);
        Assert.Equal(chip.ApplicationFiles[PassportService.EF_COM], com);
        Assert.Contains(LDSFileUtil.LookupTagByDataGroupNumber(14), new COMFile(new MemoryStream(com)).GetTagList());
        Assert.All(chip.Reads.Where(r => r.Fid == PassportService.EF_COM), r => Assert.Equal(chip.Session, r.Session));
        AssertDg1AndDg2(service, chip);
    }

    [Theory]
    [InlineData(CaEcdh3Des, 13)]
    [InlineData(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128, 13)]
    [InlineData(SecurityInfo.ID_CA_DH_AES_CBC_CMAC_128, 0)]
    public void ChipAuthenticationWithTheWrongChipKeyLosesTheSecureChannel(string oid, int parameterId)
    {
        (SimulatedChip chip, PassportService service) = Authenticate(Key(oid, parameterId, null), usePace: true);
        Org.BouncyCastle.Crypto.AsymmetricKeyParameter impostor = Key(oid, parameterId, null).KeyPair.Public;

        DoChipAuthentication(service, impostor);

        Assert.ThrowsAny<CardServiceException>(() => Read(service, PassportService.EF_COM));
        Assert.DoesNotContain(chip.Reads, r => r.Fid == PassportService.EF_COM);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PaceCamWithoutUsableChipAuthenticationDataStillEstablishesSecureMessaging(bool undecryptable)
    {
        var document = new SimulatedDocument();
        document.Pace.Add(new SimulatedChip.PaceSupport(SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_128, 13));
        document.ChipAuthenticationKeys.Add(Key(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128, 13, null));
        SimulatedChip chip = document.Build();
        chip.Fault = undecryptable
            ? SimulatedChip.ChipFault.PaceCamUndecryptableChipAuthenticationData
            : SimulatedChip.ChipFault.PaceCamNoChipAuthenticationData;
        PassportService service = Open(chip);

        // The chip is authenticated by the token; without (decryptable) CA_PICC the result has no Chip Authentication
        // data, and the terminal cannot check the static key (JMRTD 0.8.10, 42744048; before, this threw).
        var result = Assert.IsType<PACECAMResult>(DoPace(service, PaceKeySpec.CreateMrzKey(SimulatedDocument.BacKey)));

        Assert.Null(result.GetChipAuthenticationData());
        Assert.NotNull(service.GetWrapper());
        Assert.NotEmpty(Read(service, PassportService.EF_COM));
    }

    [Theory]
    [InlineData(SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_128, 13)]
    [InlineData(SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_192, 15)]
    [InlineData(SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_256, 17)]
    public void PaceCamChipAuthenticationDataProvesTheStaticKey(string oid, int parameterId)
    {
        var document = new SimulatedDocument();
        document.Pace.Add(new SimulatedChip.PaceSupport(oid, parameterId));
        document.ChipAuthenticationKeys.Add(Key(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128, parameterId, null));
        SimulatedChip chip = document.Build();
        PassportService service = Open(chip);

        var result = Assert.IsType<PACECAMResult>(DoPace(service, PaceKeySpec.CreateMrzKey(SimulatedDocument.BacKey)));

        // The library only decrypts CA_PICC; the terminal checks PK_Map,PICC = CA_PICC * PK_PICC itself.
        byte[] chipAuthenticationData = result.GetChipAuthenticationData()!;
        var staticKey = (ECPublicKeyParameters)ReadChipAuthenticationKey(service).Key.GetSubjectPublicKey();
        var mappingKey = (ECPublicKeyParameters)((PACEGMMappingResult)result.MappingResult!).PiccMappingPublicKey!;
        Assert.Equal(mappingKey.Q.Normalize(), staticKey.Q.Multiply(new BigInteger(1, chipAuthenticationData)).Normalize());

        var otherKey = (ECPublicKeyParameters)SimulatedDocument.GenerateEc(parameterId).Public;
        Assert.NotEqual(mappingKey.Q.Normalize(), otherKey.Q.Multiply(new BigInteger(1, chipAuthenticationData)).Normalize());
    }
}
