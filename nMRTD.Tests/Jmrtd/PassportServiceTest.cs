using System.Reflection;
using nMRTD.Protocol;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Crypto.Parameters;

namespace nMRTD.Tests.Jmrtd;

/// <summary>Port of JMRTD's <c>org.jmrtd.PassportServiceTest</c>.</summary>
/// <remarks>
/// ADAPTATION: as in JMRTD, the private secure messaging state is set by reflection; nMRTD's private
/// fields are <c>_wrapper</c>, <c>_rootFileSystem</c> and <c>_appletFileSystem</c>.
/// </remarks>
public class PassportServiceTest
{
    [Fact]
    public void openIsIdempotentAndCloseClearsSecureMessagingState()
    {
        var service = new ScriptedCardService();
        PassportService passportService = CreatePassportService(service);
        SecureMessagingWrapper wrapper = CreateWrapper();
        SetSecureMessagingState(passportService, wrapper);

        passportService.Open();
        passportService.Open();

        Assert.True(passportService.IsOpen);
        Assert.Equal(1, service.GetOpenCount());
        Assert.Same(wrapper, passportService.GetWrapper());

        passportService.Close();

        Assert.False(passportService.IsOpen);
        Assert.Equal(1, service.GetCloseCount());
        Assert.Null(passportService.GetWrapper());
        Assert.Null(GetRootFileSystem(passportService).GetWrapper());
        Assert.Null(GetAppletFileSystem(passportService).GetWrapper());
    }

    [Fact]
    public void selectingMasterFileClearsSecureMessagingState()
    {
        var service = new ScriptedCardService(
            new ResponseApdu([(byte)(Iso7816.SwNoError >> 8), unchecked((byte)Iso7816.SwNoError)]));
        PassportService passportService = CreatePassportService(service);
        SetSecureMessagingState(passportService, CreateWrapper());

        passportService.SendSelectMf();

        Assert.Null(passportService.GetWrapper());
        Assert.Null(GetRootFileSystem(passportService).GetWrapper());
        Assert.Null(GetAppletFileSystem(passportService).GetWrapper());
    }

    private static PassportService CreatePassportService(ScriptedCardService service) =>
        new(service, PassportService.NormalMaxTransceiveLength, PassportService.DefaultMaxBlocksize, true, true);

    private static SecureMessagingWrapper CreateWrapper()
    {
        var encKey = new KeyParameter([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        var macKey = new KeyParameter([15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0]);
        return new DESedeSecureMessagingWrapper(encKey, macKey, 256, true, 42L);
    }

    private static void SetSecureMessagingState(PassportService passportService, SecureMessagingWrapper wrapper)
    {
        typeof(PassportService).GetField("_wrapper", BindingFlags.NonPublic | BindingFlags.Instance)!.SetValue(passportService, wrapper);
        GetRootFileSystem(passportService).SetWrapper(wrapper);
        GetAppletFileSystem(passportService).SetWrapper(wrapper);
    }

    private static DefaultFileSystem GetRootFileSystem(PassportService passportService) => GetFileSystem(passportService, "_rootFileSystem");

    private static DefaultFileSystem GetAppletFileSystem(PassportService passportService) => GetFileSystem(passportService, "_appletFileSystem");

    private static DefaultFileSystem GetFileSystem(PassportService passportService, string fieldName) =>
        (DefaultFileSystem)typeof(PassportService).GetField(fieldName, BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(passportService)!;
}
