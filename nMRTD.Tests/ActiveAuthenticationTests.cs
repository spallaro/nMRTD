using nMRTD.Protocol;
using static nMRTD.Tests.Helpers.SecureMessagingFixtures;

namespace nMRTD.Tests;

public class ActiveAuthenticationTests
{
    [Fact]
    public void MaxShortResponseDataLengthDependsOnSecureMessaging()
    {
        Assert.Equal(231, AAAPDUSender.GetMaxShortResponseDataLength(NewWrapper(false)));
        Assert.Equal(223, AAAPDUSender.GetMaxShortResponseDataLength(NewWrapper(true)));
        Assert.Equal(231, AAAPDUSender.GetMaxShortResponseDataLength(null));
    }
}
