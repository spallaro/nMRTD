using nMRTD.Cli;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Crypto.Parameters;

namespace nMRTD.Tests.Cli;

/// <summary>The key sizes in the command-line tool's result (<see cref="KeyDescription"/>).</summary>
public class KeyDescriptionTests
{
    private static readonly DHParameters Group = Util.RFC5114_2048_224; // as PACE standardized parameters

    [Fact]
    public void DhKeyWithTheSubgroupOrder() =>
        Assert.Equal("DH [2048 bit, q 224 bit]", KeyDescription.Of(new DHPublicKeyParameters(Group.G, Group)));

    [Fact]
    public void DhKeyWithoutTheSubgroupOrder()
    {
        var parameters = new DHParameters(Group.P, Group.G);

        Assert.Equal("DH [2048 bit]", KeyDescription.Of(new DHPublicKeyParameters(Group.G, parameters)));
    }

    [Fact]
    public void OtherKeysAreDescribedByTheLibrary()
    {
        Assert.Equal("RSA [1024 bit]", KeyDescription.Of(SimulatedDocument.RsaKey1024.Public));
        Assert.Equal("EC [brainpoolP256r1]", KeyDescription.Of(SimulatedDocument.GenerateEc(13).Public));
    }
}
