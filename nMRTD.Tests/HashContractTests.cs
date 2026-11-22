using System.Text;
using nMRTD.Cbeff;
using nMRTD.Lds.Iso39794;
using static nMRTD.Lds.Iso39794.PADDataBlock;

namespace nMRTD.Tests;

/// <summary>
/// Equal objects have equal hash codes, also when they hold equal byte arrays that are different
/// instances (in JMRTD these hashed by array identity).
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
}
