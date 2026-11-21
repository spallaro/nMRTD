using System.Text;
using nMRTD.Cbeff;
using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.Lds.Iso19794;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;

namespace nMRTD.Tests.Jmrtd.Lds.Iso19794;

/// <summary>Port of JMRTD's <c>org.jmrtd.lds.iso19794.IrisBiometricSubtypeInfoTest</c>.</summary>
public class IrisBiometricSubtypeInfoTest
{

    [Fact]
    public void testCreate()
    {
        IrisBiometricSubtypeInfo irisSubtypeInfo = CreateTestObject();
        int subtypeId = irisSubtypeInfo.GetBiometricSubtype();
        Assert.True(subtypeId == IrisBiometricSubtypeInfo.EYE_LEFT
                || subtypeId == IrisBiometricSubtypeInfo.EYE_RIGHT
                || subtypeId == IrisBiometricSubtypeInfo.EYE_UNDEF);
        int imageFormat = irisSubtypeInfo.GetImageFormat();
        Assert.True(imageFormat >= 0);
    }

    [Fact]
    public void testToString()
    {
        IrisBiometricSubtypeInfo info = CreateTestObject();
        Assert.NotNull(info);
        string asString = info.ToString();
        Assert.NotNull(asString);
        Assert.StartsWith("IrisBiometricSubtypeInfo", asString);
    }

    public static IrisBiometricSubtypeInfo CreateTestObject()
    {
        IrisImageInfo irisImageInfo = IrisImageInfoTest.CreateTestObject();
        List<IrisImageInfo> irisImageInfos = new List<IrisImageInfo> { irisImageInfo };
        IrisBiometricSubtypeInfo irisSubtypeInfo = new IrisBiometricSubtypeInfo(IrisBiometricSubtypeInfo.EYE_LEFT, IrisInfo.IMAGEFORMAT_MONO_JPEG, irisImageInfos);
        return irisSubtypeInfo;
    }

}
