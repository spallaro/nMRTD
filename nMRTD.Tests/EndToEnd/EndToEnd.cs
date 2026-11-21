using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Security;
using static nMRTD.Tests.Helpers.TestData;

namespace nMRTD.Tests.EndToEnd;

/// <summary>Shared steps of the end-to-end tests: a <see cref="PassportService"/> over a <see cref="SimulatedChip"/>.</summary>
internal static class EndToEnd
{
    public static PassportService Open(SimulatedChip chip, bool isSfiEnabled = false, bool shouldCheckMac = true)
    {
        var service = new PassportService(chip, PassportService.NormalMaxTransceiveLength, PassportService.DefaultMaxBlocksize, isSfiEnabled, shouldCheckMac);
        service.Open();
        return service;
    }

    public static byte[] Read(PassportService service, short fid, int blockSize = PassportService.DefaultMaxBlocksize)
    {
        using Stream stream = service.GetInputStream(fid, blockSize);
        return ReadAll(stream);
    }

    public static void DoBac(PassportService service)
    {
        service.SendSelectApplet(false);
        service.DoBAC(SimulatedDocument.BacKey);
    }

    /// <summary>PACE as an inspection system does it: the protocol and parameters come from EF.CardAccess.</summary>
    public static Protocol.PACEResult DoPace(PassportService service, IAccessKeySpec key, string? oid = null)
    {
        var cardAccess = new CardAccessFile(new MemoryStream(Read(service, PassportService.EF_CARD_ACCESS)));
        PACEInfo info = cardAccess.GetSecurityInfos().OfType<PACEInfo>().First(i => oid == null || i.GetObjectIdentifier() == oid);
        Org.BouncyCastle.Math.BigInteger parameterId = info.GetParameterId()!;
        Protocol.PACEResult result = service.DoPace(key, info.GetObjectIdentifier(), PACEInfo.ToParameterSpec(parameterId), parameterId);
        service.SendSelectApplet(true);
        return result;
    }

    /// <summary>The first Chip Authentication public key of DG14, as read from the chip, with its protocol.</summary>
    public static (ChipAuthenticationPublicKeyInfo Key, ChipAuthenticationInfo? Info) ReadChipAuthenticationKey(PassportService service)
    {
        IReadOnlyCollection<SecurityInfo> infos = new DG14File(new MemoryStream(Read(service, PassportService.EF_DG14))).GetSecurityInfos();
        ChipAuthenticationPublicKeyInfo key = infos.OfType<ChipAuthenticationPublicKeyInfo>().First();
        ChipAuthenticationInfo? info = infos.OfType<ChipAuthenticationInfo>().FirstOrDefault(i => Equals(i.GetKeyId(), key.GetKeyId()));
        return (key, info);
    }

    /// <summary>Chip Authentication with the key and protocol of DG14, or with <paramref name="publicKey"/> instead of the chip's key.</summary>
    public static Protocol.EACCAResult DoChipAuthentication(PassportService service, Org.BouncyCastle.Crypto.AsymmetricKeyParameter? publicKey = null)
    {
        (ChipAuthenticationPublicKeyInfo key, ChipAuthenticationInfo? info) = ReadChipAuthenticationKey(service);
        return service.DoEACCA(key.GetKeyId(), info?.GetObjectIdentifier(), key.GetObjectIdentifier(), publicKey ?? key.GetSubjectPublicKey());
    }

    /// <summary>Reads DG1 and DG2 and checks them against the personalized document and EF.SOD.</summary>
    public static void AssertDg1AndDg2(PassportService service, SimulatedChip chip)
    {
        byte[] dg1 = Read(service, PassportService.EF_DG1);
        byte[] dg2 = Read(service, PassportService.EF_DG2);
        Assert.Equal(chip.ApplicationFiles[PassportService.EF_DG1], dg1);
        Assert.Equal(chip.ApplicationFiles[PassportService.EF_DG2], dg2);

        Assert.Equal(SimulatedDocument.Mrz, new DG1File(new MemoryStream(dg1)).GetMRZInfo());
        var face = new DG2File(new MemoryStream(dg2));
        var block = Assert.IsType<Lds.Iso39794.FaceImageDataBlock>(face.GetSubRecords()[0]);
        Assert.Equal(SimulatedDocument.FaceImage, ReadAll(block.GetRepresentationBlocks()[0].GetImageInputStream()));

        var sod = new SODFile(new MemoryStream(Read(service, PassportService.EF_SOD)));
        Assert.Equal(DigestUtilities.CalculateDigest("SHA-256", dg1), sod.GetDataGroupHashes()[1]);
        Assert.Equal(DigestUtilities.CalculateDigest("SHA-256", dg2), sod.GetDataGroupHashes()[2]);
    }
}
