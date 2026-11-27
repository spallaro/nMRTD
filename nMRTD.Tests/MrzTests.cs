using nMRTD.Lds.Icao;
using nMRTD.SmartCards;

namespace nMRTD.Tests;

public class MrzTests
{
    [Fact]
    public void Td2ShortDocumentNumberUsesCompositeCheckDigitOverPaddedField()
    {
        // JMRTD test vector.
        string mrz = "IDUTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<" + "DOC65483<1UTO9708147F4501310<<<<<<<0";
        var constructed = MRZInfo.CreateTD2MRZInfo("ID", "UTO", "ERIKSSON", "ANNA MARIA", "DOC65483", "UTO", "970814", Gender.Female, "450131", "");
        Assert.Equal(mrz, constructed.ToString().Replace("\n", ""));
        Assert.Equal(constructed, new MRZInfo(mrz));
    }

    [Fact]
    public void Td2NineCharacterDocumentNumber()
    {
        // JMRTD test vector.
        var c = MRZInfo.CreateTD2MRZInfo("I<", "UTO", "ERIKSSON", "ANNA MARIA", "D23145890", "UTO", "740812", Gender.Female, "120415", "");
        Assert.Equal("I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<D231458907UTO7408122F1204159<<<<<<<6", c.ToString().Replace("\n", ""));
    }

    [Theory]
    // ICAO Doc 9303 specimens: TD1 (3 lines of 30), TD2 (2 of 36), TD3 (2 of 44).
    [InlineData("I<UTOD231458907<<<<<<<<<<<<<<<", "7408122F1204159UTO<<<<<<<<<<<6", "ERIKSSON<<ANNA<MARIA<<<<<<<<<<")]
    [InlineData("I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<", "D231458907UTO7408122F1204159<<<<<<<6")]
    [InlineData("P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<", "L898902C36UTO7408122F1204159ZE184226B<<<<<10")]
    public void ToStringEndsEveryLineInANewline(params string[] lines)
    {
        var mrz = new MRZInfo(string.Concat(lines));
        Assert.Equal(string.Concat(lines.Select(line => line + "\n")), mrz.ToString());
    }
}
