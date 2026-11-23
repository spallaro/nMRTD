using nMRTD.Lds.Icao;
using nMRTD.SmartCards;

namespace nMRTD.Tests;

/// <summary>
/// <see cref="MRZInfo"/> against the ICAO Doc 9303 specimen MRZs (TD1, TD2, TD3, MRV-A, MRV-B): parsing,
/// re-encoding, check digits, the deprecated constructors and the rejection of malformed input.
/// </summary>
public class MrzSpecimenTests
{
    public const string Td1 = "I<UTOD231458907<<<<<<<<<<<<<<<7408122F1204159UTO<<<<<<<<<<<6ERIKSSON<<ANNA<MARIA<<<<<<<<<<";
    public const string Td2 = "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<D231458907UTO7408122F1204159<<<<<<<6";
    public const string Td3 = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10";
    public const string Mrva = "V<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L8988901C4XXX4009078F96121096ZE184226B<<<<<<";
    public const string Mrvb = "V<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<L8988901C4XXX4009078F9612109<<<<<<<<";

    [Theory]
    [InlineData(Td1, MRZInfo.DOC_TYPE_ID1, "D23145890")]
    [InlineData(Td2, MRZInfo.DOC_TYPE_ID2, "D23145890")]
    [InlineData(Td3, MRZInfo.DOC_TYPE_ID3, "L898902C3")]
    [InlineData(Mrva, 4, "L8988901C")]
    [InlineData(Mrvb, 5, "L8988901C")]
    public void SpecimenParsesAndReEncodesUnchanged(string mrz, int documentType, string documentNumber)
    {
        var info = new MRZInfo(mrz);

        Assert.Equal(mrz, info.ToString().Replace("\n", ""));
#pragma warning disable CS0618 // the deprecated numeric document type is still part of the API
        Assert.Equal(documentType, info.GetDocumentType());
#pragma warning restore CS0618
        Assert.Equal(documentNumber, info.GetDocumentNumber());
        Assert.Equal("ERIKSSON", info.GetPrimaryIdentifier());
        Assert.Equal(info, new MRZInfo(mrz));
        Assert.Equal(info.GetHashCode(), new MRZInfo(mrz).GetHashCode());
    }

    [Fact]
    public void Td3PersonalNumberAndCompositeCheckDigit()
    {
        var info = new MRZInfo(Td3);

        Assert.Equal("ZE184226B", info.GetPersonalNumber());
        Assert.Equal('0', Td3[^1]);
        // Doc 9303-4: document number, date of birth, date of expiry and optional data, each with its check digit.
        Assert.Equal('0', MRZInfo.CheckDigit("L898902C36" + "7408122" + "1204159" + "ZE184226B<<<<<1"));
    }

#pragma warning disable CS0618 // the deprecated constructors are what is tested here
    [Fact]
    public void DeprecatedTd3ConstructorMatchesTheFactory()
    {
        var deprecated = new MRZInfo("P", "UTO", "ERIKSSON", "ANNA MARIA", "L898902C3", "UTO", "740812", Gender.Female, "120415", "ZE184226B");
        MRZInfo factory = MRZInfo.CreateTD3MRZInfo("P", "UTO", "ERIKSSON", "ANNA MARIA", "L898902C3", "UTO", "740812", Gender.Female, "120415", "ZE184226B");

        Assert.Equal(factory, deprecated);
        Assert.Equal(Td3, deprecated.ToString().Replace("\n", ""));
    }

    [Fact]
    public void DeprecatedTd1ConstructorMatchesTheFactory()
    {
        var deprecated = new MRZInfo("I", "UTO", "D23145890", "", "740812", Gender.Female, "120415", "UTO", "", "ERIKSSON", "ANNA MARIA");
        MRZInfo factory = MRZInfo.CreateTD1MRZInfo("I", "UTO", "D23145890", "", "740812", Gender.Female, "120415", "UTO", "", "ERIKSSON", "ANNA MARIA");

        Assert.Equal(factory, deprecated);
        Assert.Equal(Td1, deprecated.ToString().Replace("\n", ""));
    }

    [Theory]
    [InlineData("A")]
    [InlineData("C")]
    [InlineData("I")]
    public void DeprecatedTd1ConstructorAcceptsTheTd1DocumentCodes(string documentCode) =>
        Assert.Equal(MRZInfo.DOC_TYPE_ID1, new MRZInfo(documentCode, "UTO", "D23145890", "", "740812", Gender.Female, "120415", "UTO", "", "ERIKSSON", "ANNA").GetDocumentType());

    [Fact]
    public void DeprecatedConstructorsRejectADocumentCodeOfAnotherType()
    {
        Assert.ThrowsAny<ArgumentException>(() => new MRZInfo("P", "UTO", "D23145890", "", "740812", Gender.Female, "120415", "UTO", "", "ERIKSSON", "ANNA"));
        Assert.ThrowsAny<ArgumentException>(() => new MRZInfo("X", "UTO", "ERIKSSON", "ANNA", "L898902C3", "UTO", "740812", Gender.Female, "120415", null));
    }
#pragma warning restore CS0618

    [Fact]
    public void FactoriesRejectInconsistentDocumentCodesAndOptionalData()
    {
        Assert.ThrowsAny<ArgumentException>(() => MRZInfo.CreateTD3MRZInfo("V", "UTO", "ERIKSSON", "ANNA", "L898902C3", "UTO", "740812", Gender.Female, "120415", null));
        Assert.ThrowsAny<ArgumentException>(() => MRZInfo.CreateMRVAMRZInfo("P", "UTO", "ERIKSSON", "ANNA", "L8988901C", "XXX", "400907", Gender.Female, "961210", null));
        Assert.ThrowsAny<ArgumentException>(() => MRZInfo.CreateTD2MRZInfo("IXX", "UTO", "ERIKSSON", "ANNA", "D23145890", "UTO", "740812", Gender.Female, "120415", null));
        Assert.ThrowsAny<ArgumentException>(() => MRZInfo.CreateTD2MRZInfo("I", "UTO", "ERIKSSON", "ANNA", "D23145890", "UTO", "740812", Gender.Female, "120415", "TOOLONGDATA"));
        Assert.ThrowsAny<ArgumentException>(() => MRZInfo.CreateTD3MRZInfo("P", "UTO", "ERIKSSON", "ANNA", "L898902C3", "UTO", "740812", Gender.Female, "120415", "PERSONALNUMBER123"));
    }

    [Theory]
    [InlineData("<", '0')]
    [InlineData("0", '0')]
    [InlineData("A", '0')]
    [InlineData("z", '5')]
    [InlineData("520727", '3')] // Doc 9303-3 example: date of birth 27 July 1952
    [InlineData("AB2134<<<", '5')] // Doc 9303-3 example document number
    public void CheckDigitFollowsTheSevenThreeOneRule(string field, char checkDigit) =>
        Assert.Equal(checkDigit, MRZInfo.CheckDigit(field));

    [Theory]
    [InlineData("L898902C#")]
    [InlineData("L898902C ")]
    public void CheckDigitRejectsCharactersOutsideTheMrzAlphabet(string field) =>
        Assert.Throws<FormatException>(() => MRZInfo.CheckDigit(field));

    [Fact]
    public void DifferentDocumentsAreNotEqual()
    {
        var td3 = new MRZInfo(Td3);

        Assert.NotEqual(td3, new MRZInfo(Td1));
        Assert.NotEqual(td3, new MRZInfo(Td3.Replace("ANNA<MARIA", "ANNA<MARIE")));
        Assert.False(td3.Equals(null));
        Assert.False(td3.Equals(Td3));
    }

    [Fact]
    public void TruncatedEncodingIsRejected()
    {
        byte[] encoded = System.Text.Encoding.ASCII.GetBytes(Td3);

        Assert.ThrowsAny<ArgumentException>(() => new MRZInfo(new MemoryStream(encoded, 0, 40), encoded.Length));
    }
}
