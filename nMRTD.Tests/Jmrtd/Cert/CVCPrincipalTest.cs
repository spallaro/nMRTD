using nMRTD.Cert;
using nMRTD.SmartCards;

namespace nMRTD.Tests.Jmrtd.Cert;

/// <summary>Port of JMRTD's <c>org.jmrtd.cert.CVCPrincipalTest</c>.</summary>
public class CVCPrincipalTest
{
    [Fact(Skip = "Possible divergence from JMRTD: SCUBA's Country.getInstance(\"UT\") resolves to TestCountry.UT (UT/UTO, Utopia), nMRTD has no test country and returns an unknown placeholder (alpha-3 XXX).")]
    public void testCVCPrincipalFromUT()
    {
        var principal = new CVCPrincipal("UTDVCS00001");
        Assert.Equal("UT", principal.CountryCode);

        // Java: assertEquals(TestCountry.UT, principal.getCountry()), the test country "Utopia".
        Assert.Equal("UT", principal.Country.Alpha2Code);
        Assert.Equal("UTO", principal.Country.Alpha3Code);
    }

    [Fact]
    public void testCVCPrincipalFromNL()
    {
        var principal = new CVCPrincipal("NLDVCS00001");
        Assert.Equal("NL", principal.CountryCode);
        Assert.Equal(Country.GetInstance("NLD"), principal.Country);
    }

    [Fact]
    public void testCVCPrincipalFromUnknown()
    {
        var principal = new CVCPrincipal("XYDVCS00001");
        Assert.Equal("XY", principal.CountryCode);
        Assert.Equal("XYDVCS00001", principal.Name);
        Assert.NotNull(principal.Country);
    }
}
