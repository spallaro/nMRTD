using System.Text;
using nMRTD.Cbeff;
using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.Lds.Iso39794;
using static nMRTD.Lds.Iso39794.PADDataBlock;

namespace nMRTD.Tests;

/// <summary>
/// Equal objects have equal hash codes, also when they hold equal byte arrays or lists that are different
/// instances (byte arrays hashed by identity in JMRTD; lists hashed per instance in the first .NET port).
/// </summary>
public class HashContractTests
{
    private static PADDataBlock PadData(string challenge) => new(
        PADDecisionCode.NoAttack, null, null, PADCaptureContextCode.Enrolment, PADSupervisionLevelCode.Unknown,
        1, PADCriteriaCategoryCode.Common, null, [Encoding.ASCII.GetBytes(challenge)], null);

    [Fact]
    public void PadDataBlocksWithEqualChallenges()
    {
        PADDataBlock first = PadData("challenge");
        PADDataBlock second = PadData("challenge");

        Assert.Equal(first, second);
        Assert.Equal(first.GetHashCode(), second.GetHashCode());
        Assert.Single(new HashSet<PADDataBlock> { first, second });
        Assert.NotEqual(first, PadData("other"));
    }

    [Fact]
    public void StandardBiometricHeadersWithEqualElements()
    {
        StandardBiometricHeader Header() => new(new SortedDictionary<int, byte[]>
        {
            [0x81] = [0x02],
            [0x87] = [0x01, 0x01],
            [0x88] = [0x00, 0x08],
        });

        StandardBiometricHeader first = Header();
        StandardBiometricHeader second = Header();

        Assert.Equal(first, second);
        Assert.Equal(first.GetHashCode(), second.GetHashCode());
        Assert.Single(new HashSet<StandardBiometricHeader> { first, second });
    }

    [Fact]
    public void DisplayedImageDataGroupsWithEqualImages()
    {
        DG5File Dg5() => new([new DisplayedImageInfo(ImageInfo.TYPE_PORTRAIT, [0xFF, 0xD8, 0xFF, 0xE0, 0x01])]);

        Assert.Equal(Dg5(), Dg5());
        Assert.Equal(Dg5().GetHashCode(), Dg5().GetHashCode());
        Assert.Single(new HashSet<DG5File> { Dg5(), Dg5() });
    }

    [Fact]
    public void FaceCaptureDeviceBlocksWithEqualCertifications()
    {
        FaceImageCaptureDeviceBlock Block() => new(new RegistryIdBlock(1, 1), [new RegistryIdBlock(2, 2), new RegistryIdBlock(3, 3)]);

        Assert.Equal(Block(), Block());
        Assert.Equal(Block().GetHashCode(), Block().GetHashCode());
    }
}
