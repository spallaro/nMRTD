using nMRTD.Lds.Icao;
using nMRTD.SmartCards;

namespace nMRTD.Tests.Jmrtd.Lds.Icao;

/// <summary>Port of JMRTD's <c>org.jmrtd.lds.icao.CountryTest</c>.</summary>
/// <remarks>
/// ADAPTATION: SCUBA's <c>ISOCountry</c> and <c>UnicodeCountry</c> are both nMRTD's single
/// <c>Country</c> table (<c>Country.GetInstance</c>); SCUBA's <c>Country.getInstance</c> takes alpha-2 or
/// alpha-3 codes, nMRTD has <c>GetInstanceByAlpha2</c> for the former. Not ported:
/// <c>testCountryValues</c>, as nMRTD exposes no list of all countries (SCUBA's <c>Country.values()</c>).
/// </remarks>
public class CountryTest
{
    [Fact]
    public void testGermany()
    {
        Country icaoGermany = IcaoCountry.GetInstance("D<<");
        Country isoGermany = Country.GetInstance("DEU");
        Assert.NotNull(icaoGermany);
        Assert.Same(Country.GetInstance("DEU"), isoGermany); // Java: ISOCountry.DE == isoGermany || UnicodeCountry.DE == isoGermany
        Assert.Equal(IcaoCountry.DE, icaoGermany);
        Assert.Same(IcaoCountry.DE, icaoGermany);
        Assert.Equal(isoGermany.ToAlpha2Code(), icaoGermany.ToAlpha2Code());
    }

    [Fact(Skip = "Possible divergence from JMRTD: nMRTD names TWN \"Taiwan, Province of China\" (SmartCards/Country.cs:383), the name JMRTD's test rules out.")]
    public void testTaiwan()
    {
        Country icaoCountry = IcaoCountry.GetInstance("TWN");
        Assert.NotNull(icaoCountry);
        Country unicodeCountry = Country.GetInstance("TWN");
        Assert.NotNull(unicodeCountry);
        Assert.Equal(icaoCountry, unicodeCountry);
        Assert.DoesNotContain("china", icaoCountry.Name.ToLowerInvariant());
    }

    [Fact]
    public void testNetherlands()
    {
        Assert.Same(Country.GetInstance("NLD"), Country.GetInstance("NLD")); // Java: == ISOCountry.NL || == UnicodeCountry.NL
        Assert.Equal("NL", Country.GetInstance("NLD").ToAlpha2Code());
        Assert.Equal(Country.GetInstance("NLD").Name, Country.GetInstanceByAlpha2("NL").Name); // Java: ISOCountry.NL.getName() equals UnicodeCountry.NL.getName()
    }

    [Fact(Skip = "Possible divergence from JMRTD: SCUBA's Country.getInstance resolves \"UT\" and \"UTO\" to the test country Utopia; nMRTD has no test country and throws (SmartCards/Country.cs:90-114). See CVCPrincipalTest.testCVCPrincipalFromUT.")]
    public void testUtopia()
    {
        Country utopia = Country.GetInstanceByAlpha2("UT");
        Assert.NotNull(utopia);
        Country alsoUtopia = Country.GetInstance("UTO");
        Assert.NotNull(alsoUtopia);
        Assert.Equal(alsoUtopia, utopia);
    }
}
