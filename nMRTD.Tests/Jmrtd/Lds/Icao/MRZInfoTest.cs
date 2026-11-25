using System.Globalization;
using System.Text;
using nMRTD.Lds.Icao;
using nMRTD.SmartCards;

namespace nMRTD.Tests.Jmrtd.Lds.Icao;

/// <summary>Port of JMRTD's <c>org.jmrtd.lds.icao.MRZInfoTest</c>.</summary>
/// <remarks>
/// ADAPTATION: JUnit catch blocks that swallow exceptions are restricted so they do not swallow xUnit's
/// assertion exceptions (Java's <c>AssertionError</c> is not an <c>Exception</c>); SCUBA's
/// <c>ISOCountry.NL</c> is <c>Country.GetInstance("NLD")</c>.
/// </remarks>
public class MRZInfoTest
{

    /* ID 1 samples. */

    private const string MRZ_SUSANNA_SAMPLE_3LINE_ID1 =
            "IRGBRZU12345673<<<<<<<<<<<<<<<"
                    + "6608198F0808088COU<<<<<<<<<<<6"
                    + "SAMPLE<<SUSANNA<<<<<<<<<<<<<<<";

    /*
      * NOTE: line length = 28, not 30?
      */
    private const string MRZ_MICHAEL_VAN_PASSEL_3LINE_ID1 =
            "I<BEL0000000000<<<<<<<<<<<<<"
                    + "5001013F0806017BEL<<<<<<<<<<"
                    + "VAN<PASSEL<<MICHAEL<<<<<<<<<";

    /*
      * NOTE: 3?
      */
    private const string MRZ_PETER_STEVENSON_3LINE_ID1 =
            "CIUT0D231458907A123X5328434D23"
                    + "3407127M9507122UTO<<<<<<<<<<<6"
                    + "STEVENSON<<PETER<<<<<<<<<<<<<<";

    private const string MRZ_CARVALHO_FERNANDA_SILVA_3LINE_ID1 =
            "IDUTO00000000032<<<<<<<<<<<<<<"
                    + "7507123F1510212UTO<<<<<<<<<<<2"
                    + "SILVA<<CARVALHO<FERNANDA<<<<<<";

    /*
      * NOTE: optional data 2, right aligned.
      */
    private const string MRZ_MARIA_SILVA_OLIVEIRA_3LINE_ID1 =
            "IDBRA123456789712345R00F456912"
                    + "7006012F0212311UTO<<<HDFDTR091"
                    + "OLIVEIRA<<MARIA<SILVA<<<<<<<<<";

    private const string MRZ_ANNA_KOWALSKA_3LINE_ID1 =
            "I<POLABA3000004<<<<<<<<<<<<<<<"
                    + "7203305F1208227POL<<<<<<<<<<<2"
                    + "KOWALSKA<<ANNA<<<<<<<<<<<<<<<<";

    /* ID 3 samples. */

    private const string MRZ_ANNA_ERIKSSON_2LINE_ID3 =
            "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<"
                    + "L898902C<3UTO6908061F9406236ZE184226B<<<<<14";

    private const string MRZ_LOES_MEULENDIJK_2LINE_ID3_ZERO_CHECKDIGIT =
            "P<NLDMEULENDIJK<<LOES<ALBERTINE<<<<<<<<<<<<<"
                    + "XX00000000NLD7110195F1108280123456782<<<<<02";


    private const string MRZ_LOES_MEULENDIJK_2LINE_ID3_FILLER_CHECKDIGIT =
            "P<NLDMEULENDIJK<<LOES<ALBERTINE<<<<<<<<<<<<<"
                    + "XX00000000NLD7110195F1108280123456782<<<<<<2";

    private const string MRZ_GERARD_ROBBERT_MARTINUS_SEBASTIAAN_VAN_NIEUWENHUIZEN_2LINE_ID3 =
            "P<NLDVAN<NIEUWENHUIZEN<<GERARD<ROBBERT<MARTI"
                    + "XN01BC0150NLD7112247M1108268123456782<<<<<02";

    private const string MRZ_ERIKA_MUSTERMAN_2LINE_ID3 =
            "P<D<<MUSTERMANN<<ERIKA<<<<<<<<<<<<<<<<<<<<<<"
                    + "C11T002JM4D<<9608122F1310317<<<<<<<<<<<<<<<6";

    private const string MRZ_CHRISTIAN_MUSTERMAN_2LINE_ID3 =
            "P<D<<MUSTERMAN<<CHRISTIAN<<<<<<<<<<<<<<<<<<<"
                    + "0000000000D<<8601067M1111156<<<<<<<<<<<<<<<2";

    private const string MRZ_VZOR_SPECIMEN_2LINE_ID3 =
            "P<CZESPECIMEN<<VZOR<<<<<<<<<<<<<<<<<<<<<<<<<"
                    + "99009054<4CZE6906229F16072996956220612<<<<74";

    private const string MRZ_HAPPY_TRAVELER_2LINE_ID3 =
            "P<USATRAVELER<<HAPPY<<<<<<<<<<<<<<<<<<<<<<<<"
                    + "1500000035USA5609165M0811150<<<<<<<<<<<<<<08";

    private const string MRZ_FRANK_AMOSS_2LINE_ID3 =
            "P<USAAMOSS<<FRANK<<<<<<<<<<<<<<<<<<<<<<<<<<<"
                    + "0000780043USA5001013M1511169100000000<381564";

    private const string MRZ_LORENA_FERNANDEZ_2LINE_ID3 =
            "P<ARGFERNANDEZ<<LORENA<<<<<<<<<<<<<<<<<<<<<<"
                    + "00000000A0ARG7903122F081210212300004<<<<<<86";

    private const string MRZ_KWOK_SUM_CHNCHUNG_2LINE_ID3 =
            "P<CHNCHUNG<<KWOK<SUM<<<<<<<<<<<<<<<<<<<<<<<<"
                    + "K123455994CHN8008080F1702057HK8888888<<<<<36";

    private static readonly string[] MRZ_SAMPLES = { MRZ_ANNA_ERIKSSON_2LINE_ID3,
            MRZ_LOES_MEULENDIJK_2LINE_ID3_ZERO_CHECKDIGIT,
            MRZ_LOES_MEULENDIJK_2LINE_ID3_FILLER_CHECKDIGIT,
            MRZ_GERARD_ROBBERT_MARTINUS_SEBASTIAAN_VAN_NIEUWENHUIZEN_2LINE_ID3,
            MRZ_ERIKA_MUSTERMAN_2LINE_ID3, MRZ_CHRISTIAN_MUSTERMAN_2LINE_ID3,
            MRZ_VZOR_SPECIMEN_2LINE_ID3, MRZ_HAPPY_TRAVELER_2LINE_ID3,
            MRZ_FRANK_AMOSS_2LINE_ID3, MRZ_SUSANNA_SAMPLE_3LINE_ID1,
            MRZ_CARVALHO_FERNANDA_SILVA_3LINE_ID1,
            MRZ_LORENA_FERNANDEZ_2LINE_ID3,
            MRZ_ANNA_KOWALSKA_3LINE_ID1,
            MRZ_KWOK_SUM_CHNCHUNG_2LINE_ID3 };

    [Fact]
    public void testVanPassel()
    {
        Assert.ThrowsAny<ArgumentException>(() => new MRZInfo(MRZ_MICHAEL_VAN_PASSEL_3LINE_ID1));
    }

    [Fact]
    public void testOliveira()
    {
        CheckLength(new MRZInfo(MRZ_MARIA_SILVA_OLIVEIRA_3LINE_ID1));
        CheckToString(new MRZInfo(MRZ_MARIA_SILVA_OLIVEIRA_3LINE_ID1), MRZ_MARIA_SILVA_OLIVEIRA_3LINE_ID1);
    }

    [Fact]
    public void testToStringLoes()
    {
        MRZInfo mrzInfo = CreateTestObject();
        string expectedResult = "P<NLDMEULENDIJK<<LOES<ALBERTINE<<<<<<<<<<<<<\nXX00000000NLD7110195F1108280123456782<<<<<02\n";
        CheckToString(mrzInfo, expectedResult);
    }

    [Fact]
    public void testToStringHappy()
    {
        string mrz = "P<USATRAVELER<<HAPPY<<<<<<<<<<<<<<<<<<<<<<<<\n"
                + "1500000035USA5609165M0811150<<<<<<<<<<<<<<08\n";
        CheckToString(new MRZInfo(mrz), mrz);
    }

    [Fact]
    public void testToStringSamples()
    {
        foreach (string str in MRZ_SAMPLES)
        {
            CheckToString(new MRZInfo(str), str);
        }
    }

    private static void CheckToString(MRZInfo mrzInfo, string expectedResult)
    {
        Assert.Equal(GetMRZString(mrzInfo), GetMRZString(expectedResult));
    }

    [Fact]
    public void testLength()
    {
        MRZInfo mrzInfo = CreateTestObject();
        CheckLength(mrzInfo);

        foreach (string str in MRZ_SAMPLES)
        {
            CheckLength(new MRZInfo(str));
        }
    }

    private static void CheckLength(MRZInfo mrzInfo)
    {
        string str = GetMRZString(mrzInfo);
        Assert.NotNull(str);
        string documentCode = mrzInfo.GetDocumentCode();
        if (documentCode.StartsWith("P") || documentCode.StartsWith("V"))
        {
            Assert.Equal(88, str.Length);
        }
        else if (documentCode.StartsWith("C") || documentCode.StartsWith("I") || documentCode.StartsWith("A"))
        {
            Assert.Equal(90, str.Length);
        }
        else
        {
            Assert.Fail("Unsupported document code: " + documentCode);
        }
    }

    [Fact]
    public void testEncodeToString()
    {
        MRZInfo mrzInfo = CreateTestObject();
        CheckEncodeToString(mrzInfo);

        foreach (string str in MRZ_SAMPLES)
        {
            CheckEncodeToString(new MRZInfo(str));
        }
    }

    private static void CheckEncodeToString(MRZInfo mrzInfo)
    {
        string str = mrzInfo.ToString();
        Assert.NotNull(str);
        byte[] bytes = mrzInfo.GetEncoded()!;
        Assert.NotNull(bytes);
        string strEncoded = Encoding.UTF8.GetString(bytes);
        Assert.Equal(strEncoded, GetMRZString(str));
    }

    [Fact]
    public void testEncodeDecode()
    {
        MRZInfo mrzInfo = CreateTestObject();
        byte[] encoded = mrzInfo.GetEncoded()!;
        MemoryStream input = new MemoryStream(encoded);
        MRZInfo copy = new MRZInfo(input, encoded.Length);

        Assert.Equal(mrzInfo.GetDocumentCode(), copy.GetDocumentCode());

        Assert.Equal(mrzInfo, copy);
        Assert.True(Enumerable.SequenceEqual(encoded, copy.GetEncoded()!));
    }

    [Fact]
    public void testDecodeEncode()
    {
        try
        {
            CheckDecodeEncode(MRZ_LOES_MEULENDIJK_2LINE_ID3_ZERO_CHECKDIGIT, "P", "NLD", "MEULENDIJK", new string[] { "LOES", "ALBERTINE" }, "XX0000000", "711019", Gender.Female, "110828", "NLD");
            CheckDecodeEncode(MRZ_ANNA_ERIKSSON_2LINE_ID3, "P", "UTO", "ERIKSSON", new string[] { "ANNA", "MARIA" }, "L898902C", "690806", Gender.Female, "940623", "UTO");
            CheckDecodeEncode(MRZ_CHRISTIAN_MUSTERMAN_2LINE_ID3, "P", "D<<", "MUSTERMAN", new string[] { "CHRISTIAN" }, "000000000", "860106", Gender.Male, "111115", "D<<");
            CheckDecodeEncode(MRZ_CHRISTIAN_MUSTERMAN_2LINE_ID3, "P", "D", "MUSTERMAN", new string[] { "CHRISTIAN" }, "000000000", "860106", Gender.Male, "111115", "D");
            CheckDecodeEncode(MRZ_VZOR_SPECIMEN_2LINE_ID3, "P", "CZE", "SPECIMEN", new string[] { "VZOR" }, "99009054", "690622", Gender.Female, "160729", "CZE");
            CheckDecodeEncode(MRZ_FRANK_AMOSS_2LINE_ID3, "P", "USA", "AMOSS", new string[] { "FRANK" }, "000078004", "500101", Gender.Male, "151116", "USA");
            CheckDecodeEncode(MRZ_SUSANNA_SAMPLE_3LINE_ID1, "IR", "COU", "SAMPLE", new string[] { "SUSANNA" }, "ZU1234567", "660819", Gender.Female, "080808", "GBR");
        }
        catch (Exception e) when (e is not Xunit.Sdk.XunitException) { Assert.Fail(e.Message); }
    }

    [Fact]
    public void testBelgianMRZ()
    {
        try
        {
            string specimenSampleMRZ = "IDBEL590330101085020100200<<<<" +
                    "8502016F0901015BEL<<<<<<<<<<<8" +
                    "VAN<DER<VELDEN<<GREET<HILDE<<<";

            Assert.NotNull(specimenSampleMRZ);
            Assert.Equal(30 * 3, GetMRZString(specimenSampleMRZ).Length);

            MRZInfo mrzInfo = new MRZInfo(specimenSampleMRZ);

            string reencoded = mrzInfo.ToString();

            Assert.Equal(GetMRZString(specimenSampleMRZ), GetMRZString(reencoded));
        }
        catch (Exception e) when (e is not Xunit.Sdk.XunitException) { Assert.Fail(e.Message); }
    }

    [Fact]
    public void testStringConstructor()
    {
        MRZInfo mrzInfo = new MRZInfo(MRZ_ERIKA_MUSTERMAN_2LINE_ID3);
        MRZInfo mrzInfo1 = MRZInfo.CreateTD3MRZInfo(
                "P<", "D<<", "MUSTERMANN", "ERIKA",
                "C11T002JM", "D<<", "960812", Gender.Female, "131031", "");
        Assert.Equal(mrzInfo, mrzInfo1);
        CheckDecodeEncode(MRZ_ERIKA_MUSTERMAN_2LINE_ID3, mrzInfo.GetDocumentCode(), mrzInfo.GetNationality(), mrzInfo.GetPrimaryIdentifier(), mrzInfo.GetSecondaryIdentifierComponents(), mrzInfo.GetDocumentNumber(), mrzInfo.GetDateOfBirth(), mrzInfo.GetGenderCode(), mrzInfo.GetDateOfExpiry(), mrzInfo.GetIssuingState());
    }

    private static void CheckDecodeEncode(string mrz, string documentCode, string nationality, string lastName, string[] firstNames, string documentNumber, string dateOfBirth, Gender gender, string dateOfExpiry, string issuingState)
    {
        try
        {
            MRZInfo mrzInfo = new MRZInfo(mrz);
            Assert.Equal(mrzInfo.GetDocumentCode(), documentCode);
            Assert.True(MRZInfo.EqualsModuloFillerChars(nationality, mrzInfo.GetNationality()));
            Assert.Equal(mrzInfo.GetPrimaryIdentifier(), lastName);
            Assert.True(Enumerable.SequenceEqual(mrzInfo.GetSecondaryIdentifierComponents(), firstNames));
            Assert.Equal(mrzInfo.GetDocumentNumber(), documentNumber);
            Assert.True(MRZInfo.EqualsModuloFillerChars(issuingState, mrzInfo.GetIssuingState()));
            Assert.Equal(mrzInfo.GetDateOfBirth(), dateOfBirth);
            Assert.Equal(mrzInfo.GetGenderCode(), gender);
            Assert.Equal(mrzInfo.GetDateOfExpiry(), dateOfExpiry);
        }
        catch (Exception e) when (e is not Xunit.Sdk.XunitException) { Assert.Fail(e.Message); }
    }

    /**
      * Document number should have length 9 (for example for BAC key derivation),
      * but MRZInfo trims following '<' chars.
      */
    [Fact]
    public void testShortDocumentNumber()
    {
        MRZInfo mrzInfo1 = new MRZInfo(MRZ_ANNA_ERIKSSON_2LINE_ID3);

        byte[] encoded = mrzInfo1.GetEncoded()!;
        Assert.NotNull(encoded);
        MRZInfo mrzInfo2 = new MRZInfo(new MemoryStream(encoded), encoded.Length);

        MRZInfo mrzInfo3 = MRZInfo.CreateTD3MRZInfo(mrzInfo1.GetDocumentCode(), mrzInfo1.GetIssuingState(), mrzInfo1.GetPrimaryIdentifier(), mrzInfo1.GetSecondaryIdentifier(), mrzInfo1.GetDocumentNumber(), mrzInfo1.GetNationality(), mrzInfo1.GetDateOfBirth(), mrzInfo1.GetGenderCode(), mrzInfo1.GetDateOfExpiry(), mrzInfo1.GetPersonalNumber());

        string documentNumber1 = mrzInfo1.GetDocumentNumber();
        Assert.NotNull(documentNumber1);

        string documentNumber2 = mrzInfo2.GetDocumentNumber();
        Assert.NotNull(documentNumber2);

        string documentNumber3 = mrzInfo3.GetDocumentNumber();
        Assert.NotNull(documentNumber3);

        Assert.Equal(documentNumber1, documentNumber2);
        Assert.Equal(documentNumber2, documentNumber3);
        Assert.Equal(documentNumber3, documentNumber1);

        Assert.True(documentNumber1.Length <= 9);
        Assert.True(documentNumber1.IndexOf('<') < 0);
    }

    [Fact]
    public void testFillerZeroCheckDigit()
    {
        MRZInfo mrzInfo1 = new MRZInfo(MRZ_LOES_MEULENDIJK_2LINE_ID3_FILLER_CHECKDIGIT);
        MRZInfo mrzInfo2 = new MRZInfo(MRZ_LOES_MEULENDIJK_2LINE_ID3_ZERO_CHECKDIGIT);

        // Assert.Equal(mrzInfo1, mrzInfo2);
        Assert.Equal(mrzInfo1.GetPersonalNumber(), mrzInfo2.GetPersonalNumber());
    }

    [Fact]
    public void testEqualsId3()
    {
        CheckEquals(MRZ_LOES_MEULENDIJK_2LINE_ID3_FILLER_CHECKDIGIT);
        CheckEquals(MRZ_LOES_MEULENDIJK_2LINE_ID3_ZERO_CHECKDIGIT);
        CheckEquals(MRZ_ANNA_ERIKSSON_2LINE_ID3);
        CheckEquals(MRZ_VZOR_SPECIMEN_2LINE_ID3);
        CheckEquals(MRZ_HAPPY_TRAVELER_2LINE_ID3);
    }

    [Fact]
    public void testEqualsId1()
    {
        CheckEquals(MRZ_SUSANNA_SAMPLE_3LINE_ID1);
        CheckEquals(MRZ_PETER_STEVENSON_3LINE_ID1);
    }

    private static void CheckEquals(string mrz)
    {
        try
        {
            MRZInfo original = new MRZInfo(mrz);
            MRZInfo copy = Reconstruct(original);
            Assert.Equal(original, copy);
        }
        catch (Exception e) when (e is not Xunit.Sdk.XunitException) { Assert.Fail(e.Message); }
    }

    [Fact]
    public void testNationality()
    {
        //    CheckNationality(MRZ_LOES_MEULENDIJK_2LINE_ID3_ZERO_CHECKDIGIT, Country.GetInstance("NL"));
        //    CheckNationality(MRZ_HAPPY_TRAVELER_2LINE_ID3, Country.GetInstance("US"));
        CheckNationality(MRZ_CHRISTIAN_MUSTERMAN_2LINE_ID3, IcaoCountry.DE);
        //    CheckNationality(MRZ_ANNA_ERIKSSON_2LINE_ID3, TestCountry.UT);
    }

    private static void CheckNationality(string mrz, Country expectedCountry)
    {
        try
        {
            MRZInfo mrzInfo = new MRZInfo(mrz);
            string code = mrzInfo.GetNationality();
            Country country = IcaoCountry.GetInstance(code);
            Assert.Equal(country, expectedCountry);
        }
        catch (Exception e) when (e is not Xunit.Sdk.XunitException) { Assert.Fail(e.Message); }
    }

    [Fact]
    public void testArnjlotMalaysia()
    {
        string anonymizedSample =
                "P<MYSABC<DEFG<HIJKLMNOP<QRS<TUV<XYZABCDEFGHI"
                        + "A984726053MYS8709125M2204134880811055050<<52";

        MRZInfo mrzInfo = new MRZInfo(anonymizedSample);
        Assert.Equal("ABC DEFG HIJKLMNOP QRS TUV XYZABCDEFGHI", mrzInfo.GetPrimaryIdentifier());
        Assert.Equal("", mrzInfo.GetSecondaryIdentifier());
    }

    [Fact]
    public void testArnjlotLongPrimaryIdenfitier()
    {
        string sampleWithLongPrimaryIdentifier =
                "P<MYSMEGAN<ELLA<RUTH<BIN<ISMAELAR<EZZAHUDDIN"
                        + "A001122338MYS0911267M2010153<<<<<<<<<<<<<<<8";

        try
        {
            MRZInfo mrzInfo = new MRZInfo(sampleWithLongPrimaryIdentifier);

            Assert.Equal("MEGAN ELLA RUTH BIN ISMAELAR EZZAHUDDIN", mrzInfo.GetPrimaryIdentifier());
            Assert.Equal("", mrzInfo.GetSecondaryIdentifier());

            string mrzAsString = GetMRZString(mrzInfo);
            Assert.Equal(sampleWithLongPrimaryIdentifier, mrzAsString);
        }
        catch (Exception e) when (e is not Xunit.Sdk.XunitException) { Assert.Fail(e.Message); }
    }

    /*
      * Document number check digit indicates extension in optional data,
      * but optional data is empty.
      */
    [Fact]
    public void testMRZWithEmptyExtendedDocumentNumber()
    {
        string mrz = GetMRZString("I<UTOD23145890<<<<<<<<<<<<<<<<" +
                "7408122F1204159UTO<<<<<<<<<<<6" +
                "ERIKSSON<<ANNA<MARIA<<<<<<<<<<");

        Assert.Equal(90, mrz.Length);

        MRZInfo mrzInfo = new MRZInfo(mrz);
        Assert.Equal("740812", mrzInfo.GetDateOfBirth());
    }

    [Fact]
    public void testTD2EncodeDecode()
    {
        try
        {
            string mrz = "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<"
                    + "D231458907UTO7408122F1204159<<<<<<<6";
            MRZInfo mrzInfo = new MRZInfo(mrz);
            Assert.Equal("I", mrzInfo.GetDocumentCode());
            Assert.Equal("UTO", mrzInfo.GetIssuingState());
            Assert.Equal("ERIKSSON", mrzInfo.GetPrimaryIdentifier());
            Assert.Equal("ANNA MARIA", mrzInfo.GetSecondaryIdentifier());
            Assert.Equal("D23145890", mrzInfo.GetDocumentNumber());
            Assert.Equal("UTO", mrzInfo.GetNationality());
            Assert.Equal("740812", mrzInfo.GetDateOfBirth());
            Assert.Equal(Gender.Female, mrzInfo.GetGenderCode());
            Assert.Equal("120415", mrzInfo.GetDateOfExpiry());
            Assert.Equal("", mrzInfo.GetOptionalData1());

            byte[] encoded = mrzInfo.GetEncoded()!;
            MRZInfo decodedMRZInfo = new MRZInfo(new MemoryStream(encoded), GetMRZString(mrz).Length);
            Assert.Equal(mrzInfo, decodedMRZInfo);
            Assert.Equal("I", decodedMRZInfo.GetDocumentCode());
            Assert.Equal("UTO", decodedMRZInfo.GetIssuingState());
            Assert.Equal("ERIKSSON", decodedMRZInfo.GetPrimaryIdentifier());
            Assert.Equal("ANNA MARIA", decodedMRZInfo.GetSecondaryIdentifier());
            Assert.Equal("D23145890", decodedMRZInfo.GetDocumentNumber());
            Assert.Equal("UTO", decodedMRZInfo.GetNationality());
            Assert.Equal("740812", decodedMRZInfo.GetDateOfBirth());
            Assert.Equal(Gender.Female, decodedMRZInfo.GetGenderCode());
            Assert.Equal("120415", decodedMRZInfo.GetDateOfExpiry());
            Assert.Equal("", decodedMRZInfo.GetOptionalData1());

            MRZInfo constructedMRZInfo = MRZInfo.CreateTD2MRZInfo("I<", "UTO", "ERIKSSON", "ANNA MARIA", "D23145890", "UTO", "740812", Gender.Female, "120415", "");
            Assert.Equal(mrzInfo, constructedMRZInfo);
            Assert.Equal(GetMRZString(mrz), GetMRZString(constructedMRZInfo));
        }
        catch (Exception e) when (e is not Xunit.Sdk.XunitException)
        {
        }
    }

    [Fact]
    public void testTD2ExtendedDocumentNumber()
    {
        try
        {
            MRZInfo mrzInfo = MRZInfo.CreateTD2MRZInfo("I<", "UTO", "ERIKSSON", "ANNA MARIA", "12345678910", "UTO", "740812", Gender.Female, "120415", null);
            Assert.Equal("12345678910", mrzInfo.GetDocumentNumber());
            Assert.Equal("", mrzInfo.GetOptionalData1());
            string mrzString =  GetMRZString(mrzInfo);
            Assert.Equal("I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<123456789<UTO7408122F1204159104<<<<8",
                    mrzString);

            MRZInfo reconstructedMRZInfo = new MRZInfo(mrzString);

            Assert.Equal("12345678910", reconstructedMRZInfo.GetDocumentNumber());
            Assert.Equal("", reconstructedMRZInfo.GetOptionalData1());

            Assert.Equal("I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<123456789<UTO7408122F1204159104<<<<8",
                    GetMRZString(reconstructedMRZInfo));
        }
        catch (Exception e) when (e is not Xunit.Sdk.XunitException)
        {
        }
    }

    /*
      * A document number shorter than 9 characters is padded with fillers,
      * and the composite check digit is computed over the padded field (as printed).
      */
    [Fact]
    public void testTD2ShortDocumentNumberCompositeCheckDigit()
    {
        string mrz = "IDUTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<"
                + "DOC65483<1UTO9708147F4501310<<<<<<<0";

        MRZInfo constructedMRZInfo = MRZInfo.CreateTD2MRZInfo("ID", "UTO", "ERIKSSON", "ANNA MARIA", "DOC65483", "UTO", "970814", Gender.Female, "450131", "");
        Assert.Equal("DOC65483", constructedMRZInfo.GetDocumentNumber());
        Assert.Equal(GetMRZString(mrz), GetMRZString(constructedMRZInfo));

        MRZInfo parsedMRZInfo = new MRZInfo(mrz);
        Assert.Equal(constructedMRZInfo, parsedMRZInfo);
    }

    [Fact]
    public void testMRVA()
    {
        try
        {
            MRZInfo constructedMRZInfo = MRZInfo.CreateMRVAMRZInfo("V<", "UTO", "ERIKSSON", "ANNA MARIA", "L8988901C",
                    "XXX", "400907", Gender.Female, "961210", "6ZE184226B");

            Assert.Equal("V", constructedMRZInfo.GetDocumentCode());
            Assert.Equal("UTO", constructedMRZInfo.GetIssuingState());
            Assert.Equal("ERIKSSON", constructedMRZInfo.GetPrimaryIdentifier());
            Assert.Equal("ANNA MARIA", constructedMRZInfo.GetSecondaryIdentifier());
            Assert.Equal("L8988901C", constructedMRZInfo.GetDocumentNumber());
            Assert.Equal("XXX", constructedMRZInfo.GetNationality());
            Assert.Equal("400907", constructedMRZInfo.GetDateOfBirth());
            Assert.Equal(Gender.Female, constructedMRZInfo.GetGenderCode());
            Assert.Equal("961210", constructedMRZInfo.GetDateOfExpiry());
            Assert.Equal("6ZE184226B", constructedMRZInfo.GetOptionalData1());
        }
        catch (Exception e) when (e is not Xunit.Sdk.XunitException) { Assert.Fail(e.Message); }
    }

    [Fact]
    public void testMRVB()
    {
        try
        {
            string mrz = GetMRZString("V<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<"
                    + "L8988901C4XXX4009078F9612109<<<<<<<<");
            MRZInfo mrzInfo = new MRZInfo(mrz);
            Assert.Equal("V", mrzInfo.GetDocumentCode());
            Assert.Equal("UTO", mrzInfo.GetIssuingState());
            Assert.Equal("ERIKSSON", mrzInfo.GetPrimaryIdentifier());
            Assert.Equal("ANNA MARIA", mrzInfo.GetSecondaryIdentifier());
            Assert.Equal("L8988901C", mrzInfo.GetDocumentNumber());
            Assert.Equal("XXX", mrzInfo.GetNationality());
            Assert.Equal("400907", mrzInfo.GetDateOfBirth());
            Assert.Equal(Gender.Female, mrzInfo.GetGenderCode());
            Assert.Equal("961210", mrzInfo.GetDateOfExpiry());
            Assert.Equal("", mrzInfo.GetOptionalData1());

            MRZInfo constructedMRZInfo = MRZInfo.CreateMRVBMRZInfo("V<", "UTO", "ERIKSSON", "ANNA MARIA", "L8988901C",
                    "XXX", "400907", Gender.Female, "961210", "");
            Assert.Equal(mrzInfo, constructedMRZInfo);

            Assert.Equal("V", constructedMRZInfo.GetDocumentCode());
            Assert.Equal("UTO", constructedMRZInfo.GetIssuingState());
            Assert.Equal("ERIKSSON", constructedMRZInfo.GetPrimaryIdentifier());
            Assert.Equal("ANNA MARIA", constructedMRZInfo.GetSecondaryIdentifier());
            Assert.Equal("L8988901C", constructedMRZInfo.GetDocumentNumber());
            Assert.Equal("XXX", constructedMRZInfo.GetNationality());
            Assert.Equal("400907", constructedMRZInfo.GetDateOfBirth());
            Assert.Equal(Gender.Female, constructedMRZInfo.GetGenderCode());
            Assert.Equal("961210", constructedMRZInfo.GetDateOfExpiry());
            Assert.Equal("", constructedMRZInfo.GetOptionalData1());

            Assert.Equal(GetMRZString(mrzInfo), GetMRZString(constructedMRZInfo));

            MRZInfo reconstructedMRZInfo = new MRZInfo(GetMRZString(constructedMRZInfo));
            Assert.Equal(mrzInfo, reconstructedMRZInfo);

            Assert.Equal("V", reconstructedMRZInfo.GetDocumentCode());
            Assert.Equal("UTO", reconstructedMRZInfo.GetIssuingState());
            Assert.Equal("ERIKSSON", reconstructedMRZInfo.GetPrimaryIdentifier());
            Assert.Equal("ANNA MARIA", reconstructedMRZInfo.GetSecondaryIdentifier());
            Assert.Equal("L8988901C", reconstructedMRZInfo.GetDocumentNumber());
            Assert.Equal("XXX", reconstructedMRZInfo.GetNationality());
            Assert.Equal("400907", reconstructedMRZInfo.GetDateOfBirth());
            Assert.Equal(Gender.Female, reconstructedMRZInfo.GetGenderCode());
            Assert.Equal("961210", reconstructedMRZInfo.GetDateOfExpiry());
            Assert.Equal("", constructedMRZInfo.GetOptionalData1());

            Assert.Equal(GetMRZString(mrzInfo), GetMRZString(reconstructedMRZInfo));
        }
        catch (Exception e) when (e is not Xunit.Sdk.XunitException) { Assert.Fail(e.Message); }
    }

    /* https://sourceforge.net/p/jmrtd/bugs/63/ */
    [Fact]
    public void testBug63()
    {
        string mrzString = GetMRZString("IDBRA123456789712345R00F4569<<"
                + "7006012F0212311UTO<<<HDFDTR091"
                + "OLIVEIRA<<MARIA<SILVA<<<<<<<<<");
        MRZInfo mrzInfo = new MRZInfo(mrzString);
        Assert.Equal(mrzString, GetMRZString(mrzInfo));
    }

    /**
      * Check digit worked example from ICAO Doc 9303 Part 3, Appendix A.
      * MRZ_information = documentNumber + cd + dateOfBirth + cd + dateOfExpiry + cd
      * = "L898902C3" + "6" + "690806" + "1" + "940623" + "6".
      */
    [Fact]
    public void testCheckDigitICAOWorkedExample()
    {
        Assert.Equal('6', MRZInfo.CheckDigit("L898902C3"));
        Assert.Equal('1', MRZInfo.CheckDigit("690806"));
        Assert.Equal('6', MRZInfo.CheckDigit("940623"));
    }

    [Fact]
    public void testCheckDigitEdgeCases()
    {
        /* All filler characters map to value 0, so the check digit is 0. */
        Assert.Equal('0', MRZInfo.CheckDigit("<<<<<<<<<"));

        /* Empty string: sum is 0, so the check digit is 0. */
        Assert.Equal('0', MRZInfo.CheckDigit(""));

        /* Single digit, weight 7: 9 * 7 = 63, mod 10 = 3. */
        Assert.Equal('3', MRZInfo.CheckDigit("9"));
    }

    [Fact]
    public void testPRTFromPrado()
    {
        string documentCode = "I";
        string issuingState = "PRT";
        string documentNumber = "000024759ZZ7"; // 2
        string optionalData1 = "<<<<<<<<<<<";
        string optionalData2 = "<<<<<<<<<<<";
        string dateOfBirth = "801010"; // 0
        Gender gender = Gender.Female;
        string dateOfExpiry = "200601"; // 7
        string nationality = "PRT";
        string mrzSurname ="CARLOS<MONTEIRO";
        string mrzgivennames= "AMELIA<VANESS";
        MRZInfo mrzInfo = MRZInfo.CreateTD1MRZInfo(documentCode, issuingState, documentNumber, optionalData1,
                dateOfBirth, gender, dateOfExpiry, nationality, optionalData2, mrzSurname, mrzgivennames);

        Assert.Equal("I<PRT000024759<ZZ70<<<<<<<<<<<"
                + "8010100F2006017PRT<<<<<<<<<<<2"
                + "CARLOS<MONTEIRO<<AMELIA<VANESS",
                GetMRZString(mrzInfo));

        Assert.Equal("000024759ZZ7", mrzInfo.GetDocumentNumber());

        Assert.Equal('2', MRZInfo.CheckDigit("000024759<ZZ70<<<<<<<<<<<80101002006017<<<<<<<<<<<"));
        Assert.Equal('8', MRZInfo.CheckDigit("000024759<ZZ72<<<<<<<<<<<80101002006017<<<<<<<<<<<"));
    }

    [Fact]
    public void testBug65()
    {
        string documentCode = "I";
        string issuingState = "PRT";
        string nationality = "PRT";
        string documentNumber = "119000652ZX4";
        string optionalData1 = "";
        string optionalData2 = "";
        string dateOfBirth = "810923";
        Gender gender = Gender.Male;
        string dateOfExpiry = "290612";
        string mrzSurname ="MENDES<ESTEVES<NOGUEIRA";
        string mrzgivennames= "RUI<G";
        MRZInfo mrzInfo = MRZInfo.CreateTD1MRZInfo(documentCode, issuingState, documentNumber, optionalData1, dateOfBirth, gender, dateOfExpiry, nationality, optionalData2, mrzSurname, mrzgivennames);

        Assert.Equal("I<PRT119000652<ZX46<<<<<<<<<<<"
                + "8109231M2906128PRT<<<<<<<<<<<2"
                + "MENDES<ESTEVES<NOGUEIRA<<RUI<G",
                GetMRZString(mrzInfo));

        Assert.Equal("119000652ZX4", mrzInfo.GetDocumentNumber());
        Assert.Equal("", mrzInfo.GetOptionalData1());
        Assert.Equal("", mrzInfo.GetOptionalData2());

        string mrzString = GetMRZString(mrzInfo);
        Assert.Contains("119000652<ZX46", mrzString);
        Assert.Contains("8109231", mrzString);
        Assert.Contains("2906128", mrzString);

        Assert.Equal('2', MRZInfo.CheckDigit("119000652<ZX46<<<<<<<<<<<81092312906128<<<<<<<<<<<"));
    }

    /*
      * TD1 MRZ with non-empty optional data 1 and
      * empty optional data 2.
      */
    [Fact]
    public void testLVATD1EmptyOptionalData2()
    {
        string mrzString =
                GetMRZString("I<LVAPA99220658324951<45849<<<"
                        + "8212122F2911113LVA<<<<<<<<<<<4"
                        + "PARAUDZINA<<MARA<<<<<<<<<<<<<<");
        MRZInfo mrzInfo = new MRZInfo(mrzString);
        Assert.Equal(mrzString, GetMRZString(mrzInfo));

        Assert.Equal("324951<45849", mrzInfo.GetOptionalData1());
        Assert.Equal("", mrzInfo.GetOptionalData2());

        MRZInfo mrzInfoContructedWithFillers = MRZInfo.CreateTD1MRZInfo(
                "I<", "LVA", "PA9922065", "324951<45849<<<",
                "821212", Gender.Female, "291111", "LVA", "<<<<<<<<<<<",
                "PARAUDZINA", "MARA<<<<<<<<<<<<<<");

        string? optionalData2 = mrzInfo.GetOptionalData2();
        Assert.NotNull(optionalData2);
        Assert.True(optionalData2.Length == 0);

        Assert.Equal(mrzInfo, mrzInfoContructedWithFillers);

        Assert.Equal(mrzInfo.GetOptionalData1(), mrzInfoContructedWithFillers.GetOptionalData1());

        string? optionalData2ContructedWithFillers = mrzInfoContructedWithFillers.GetOptionalData2();
        Assert.NotNull(optionalData2ContructedWithFillers);
        Assert.True(optionalData2ContructedWithFillers.Length == 0);
        Assert.Equal(optionalData2, optionalData2ContructedWithFillers);

        MRZInfo mrzInfoContructedWithNoFillers = MRZInfo.CreateTD1MRZInfo(
                "I", "LVA", "PA9922065", "324951<45849",
                "821212", Gender.Female, "291111", "LVA", "",
                "PARAUDZINA", "MARA");

        string? optionalData2ContructedWithNoFillers = mrzInfoContructedWithNoFillers.GetOptionalData2();
        Assert.NotNull(optionalData2ContructedWithNoFillers);
        Assert.True(optionalData2ContructedWithNoFillers.Length == 0);
        Assert.Equal(optionalData2, optionalData2ContructedWithNoFillers);
    }

    [Fact]
    public void testNLDTD3Old()
    {
        string mrzString = GetMRZString("P<NLDDE<BRUIJN<<WILLEKE<LISELOTTE<<<<<<<<<<<"
                + "SPECI20142NLD6503101F2403096999999990<<<<<84");
        Assert.Equal(88, mrzString.Length);

        MRZInfo mrzInfo = new MRZInfo(mrzString);
        Assert.Equal(mrzString, GetMRZString(mrzInfo));

        MRZInfo mrzInfoConstructedWithNoFillers = MRZInfo.CreateTD3MRZInfo(
                "P", "NLD", "DE BRUIJN", "WILLEKE LISELOTTE",
                "SPECI2014", "NLD", "650310", Gender.Female, "240309", "999999990");

        Assert.Equal(mrzInfo.GetOptionalData1(), mrzInfoConstructedWithNoFillers.GetOptionalData1());
        Assert.Equal(mrzInfo.GetOptionalData2(), mrzInfoConstructedWithNoFillers.GetOptionalData2());

        Assert.Equal(mrzInfo.GetDocumentCode(), mrzInfoConstructedWithNoFillers.GetDocumentCode());
        Assert.Equal(mrzInfo.GetIssuingState(), mrzInfoConstructedWithNoFillers.GetIssuingState());
        Assert.Equal(mrzInfo.GetPrimaryIdentifier(), mrzInfoConstructedWithNoFillers.GetPrimaryIdentifier());
        Assert.Equal(mrzInfo.GetSecondaryIdentifier(), mrzInfoConstructedWithNoFillers.GetSecondaryIdentifier());
        Assert.Equal(mrzInfo.GetNationality(), mrzInfoConstructedWithNoFillers.GetNationality());
        Assert.Equal(mrzInfo.GetDocumentNumber(), mrzInfoConstructedWithNoFillers.GetDocumentNumber());
        Assert.Equal(mrzInfo.GetDateOfBirth(), mrzInfoConstructedWithNoFillers.GetDateOfBirth());
        Assert.Equal(mrzInfo.GetGenderCode(), mrzInfoConstructedWithNoFillers.GetGenderCode());
        Assert.Equal(mrzInfo.GetDateOfExpiry(), mrzInfoConstructedWithNoFillers.GetDateOfExpiry());
        Assert.Equal(mrzInfo, mrzInfoConstructedWithNoFillers);
    }

    [Fact]
    public void testVietnam()
    {
        MRZInfo mrzInfo = MRZInfo.CreateTD3MRZInfo(
                "P", "VNM", "DE BRUIJN", "WILLEKE LISELOTTE",
                "SPECIMEN", "VNM", "980101", Gender.Female, "250505", "");
        Assert.Equal(88, GetMRZString(mrzInfo).Length);
    }

    [Fact]
    public void testNLDTD3New()
    {
        string mrzString = GetMRZString("P<NLDDE<BRUIJN<<WILLEKE<LISELOTTE<<<<<<<<<<<"
                + "SPECI20212NLD6503101F3108309<<<<<<<<<<<<<<<0");
        Assert.Equal(88, GetMRZString(mrzString).Length);

        MRZInfo mrzInfo = new MRZInfo(mrzString);
        Assert.Equal(mrzString, GetMRZString(mrzInfo));

        MRZInfo mrzInfoConstructedWithNoFillers = MRZInfo.CreateTD3MRZInfo(
                "P", "NLD", "DE BRUIJN", "WILLEKE LISELOTTE",
                "SPECI2021", "NLD", "650310", Gender.Female, "310830", "");

        Assert.Equal(mrzInfo.GetOptionalData1(), mrzInfoConstructedWithNoFillers.GetOptionalData1());
        Assert.Equal(mrzInfo.GetOptionalData2(), mrzInfoConstructedWithNoFillers.GetOptionalData2());

        Assert.Equal(mrzInfo.GetDocumentCode(), mrzInfoConstructedWithNoFillers.GetDocumentCode());
        Assert.Equal(mrzInfo.GetIssuingState(), mrzInfoConstructedWithNoFillers.GetIssuingState());
        Assert.Equal(mrzInfo.GetPrimaryIdentifier(), mrzInfoConstructedWithNoFillers.GetPrimaryIdentifier());
        Assert.Equal(mrzInfo.GetSecondaryIdentifier(), mrzInfoConstructedWithNoFillers.GetSecondaryIdentifier());
        Assert.Equal(mrzInfo.GetNationality(), mrzInfoConstructedWithNoFillers.GetNationality());
        Assert.Equal(mrzInfo.GetDocumentNumber(), mrzInfoConstructedWithNoFillers.GetDocumentNumber());
        Assert.Equal(mrzInfo.GetDateOfBirth(), mrzInfoConstructedWithNoFillers.GetDateOfBirth());
        Assert.Equal(mrzInfo.GetGenderCode(), mrzInfoConstructedWithNoFillers.GetGenderCode());
        Assert.Equal(mrzInfo.GetDateOfExpiry(), mrzInfoConstructedWithNoFillers.GetDateOfExpiry());
        Assert.Equal(mrzInfo, mrzInfoConstructedWithNoFillers);

        MRZInfo mrzInfoConstructedWithFillers = MRZInfo.CreateTD3MRZInfo(
                "P<", "NLD", "DE<BRUIJN", "WILLEKE<LISELOTTE",
                "SPECI2021", "NLD", "650310", Gender.Female, "310830", "<<<<<<<<<<<<<<");
        Assert.Equal(mrzInfo, mrzInfoConstructedWithFillers);
    }

    /*
      * TD3 MRZ, empty optional data. Country codes have trailing fillers.
      */
    [Fact]
    public void testDEUTD3()
    {
        string mrzString = GetMRZString("P<D<<MUSTERMANN<<ERIKA<<<<<<<<<<<<<<<<<<<<<<"
                + "C01XGY7661D<<6408125F2707196<<<<<<<<<<<<<<<2");
        Assert.Equal(88, mrzString.Length);

        MRZInfo mrzInfo = new MRZInfo(mrzString);
        Assert.Equal(mrzString, GetMRZString(mrzInfo));

        Assert.True(MRZInfo.EqualsModuloFillerChars("D", mrzInfo.GetIssuingState()));
        Assert.True(MRZInfo.EqualsModuloFillerChars("D", mrzInfo.GetNationality()));

        MRZInfo mrzInfoConstructedWithNoFillers = MRZInfo.CreateTD3MRZInfo(
                "P", "D", "MUSTERMANN", "ERIKA",
                "C01XGY766", "D", "640812", Gender.Female, "270719", "");

        Assert.Equal(mrzInfo.GetOptionalData1(), mrzInfoConstructedWithNoFillers.GetOptionalData1());
        Assert.Equal(mrzInfo.GetOptionalData2(), mrzInfoConstructedWithNoFillers.GetOptionalData2());

        Assert.Equal(mrzInfo.GetDocumentCode(), mrzInfoConstructedWithNoFillers.GetDocumentCode());
        Assert.Equal(mrzInfo.GetIssuingState(), mrzInfoConstructedWithNoFillers.GetIssuingState());
        Assert.Equal(mrzInfo.GetPrimaryIdentifier(), mrzInfoConstructedWithNoFillers.GetPrimaryIdentifier());
        Assert.Equal(mrzInfo.GetSecondaryIdentifier(), mrzInfoConstructedWithNoFillers.GetSecondaryIdentifier());
        Assert.Equal(mrzInfo.GetNationality(), mrzInfoConstructedWithNoFillers.GetNationality());
        Assert.Equal(mrzInfo.GetDocumentNumber(), mrzInfoConstructedWithNoFillers.GetDocumentNumber());
        Assert.Equal(mrzInfo.GetDateOfBirth(), mrzInfoConstructedWithNoFillers.GetDateOfBirth());
        Assert.Equal(mrzInfo.GetGenderCode(), mrzInfoConstructedWithNoFillers.GetGenderCode());
        Assert.Equal(mrzInfo.GetDateOfExpiry(), mrzInfoConstructedWithNoFillers.GetDateOfExpiry());
        Assert.Equal(mrzInfo, mrzInfoConstructedWithNoFillers);

        MRZInfo mrzInfoConstructedWithFillers = MRZInfo.CreateTD3MRZInfo(
                "P<", "D<<", "MUSTERMANN", "ERIKA<<<<<<<<<<<<<<<<<<<<<<",
                "C01XGY766", "D<<", "640812", Gender.Female, "270719", "<<<<<<<<<<<<<<");

        Assert.Equal(mrzInfo.GetDocumentCode(), mrzInfoConstructedWithFillers.GetDocumentCode());
        Assert.Equal(mrzInfo.GetIssuingState(), mrzInfoConstructedWithFillers.GetIssuingState());
        Assert.Equal(mrzInfo.GetPrimaryIdentifier(), mrzInfoConstructedWithFillers.GetPrimaryIdentifier());
        Assert.Equal(mrzInfo.GetSecondaryIdentifier(), mrzInfoConstructedWithFillers.GetSecondaryIdentifier());
        Assert.Equal(mrzInfo.GetNationality(), mrzInfoConstructedWithFillers.GetNationality());
        Assert.Equal(mrzInfo.GetDocumentNumber(), mrzInfoConstructedWithFillers.GetDocumentNumber());
        Assert.Equal(mrzInfo.GetDateOfBirth(), mrzInfoConstructedWithFillers.GetDateOfBirth());
        Assert.Equal(mrzInfo.GetGenderCode(), mrzInfoConstructedWithFillers.GetGenderCode());
        Assert.Equal(mrzInfo.GetDateOfExpiry(), mrzInfoConstructedWithFillers.GetDateOfExpiry());
        Assert.Equal(mrzInfo, mrzInfoConstructedWithFillers);

        Assert.Equal(mrzInfo, mrzInfoConstructedWithFillers);
    }

    [Fact]
    public void testGBRTD3()
    {
        string mrzString = GetMRZString("P<GBRUK<SPECIMEN<<ANGELA<ZOE<<<<<<<<<<<<<<<<"
                + "9992307632GBR9501016F2911272<<<<<<<<<<<<<<02");
        Assert.Equal(88, mrzString.Length);

        MRZInfo mrzInfo = new MRZInfo(mrzString);
        Assert.Equal(mrzString, GetMRZString(mrzInfo));

        MRZInfo mrzInfoConstructedWithNoFillers = MRZInfo.CreateTD3MRZInfo(
                "P", "GBR", "UK SPECIMEN", "ANGELA ZOE",
                "999230763", "GBR", "950101", Gender.Female, "291127", "");

        Assert.Equal(mrzInfo.GetOptionalData1(), mrzInfoConstructedWithNoFillers.GetOptionalData1());
        Assert.Equal(mrzInfo.GetOptionalData2(), mrzInfoConstructedWithNoFillers.GetOptionalData2());

        Assert.Equal(mrzInfo.GetDocumentCode(), mrzInfoConstructedWithNoFillers.GetDocumentCode());
        Assert.Equal(mrzInfo.GetIssuingState(), mrzInfoConstructedWithNoFillers.GetIssuingState());
        Assert.Equal(mrzInfo.GetPrimaryIdentifier(), mrzInfoConstructedWithNoFillers.GetPrimaryIdentifier());
        Assert.Equal(mrzInfo.GetSecondaryIdentifier(), mrzInfoConstructedWithNoFillers.GetSecondaryIdentifier());
        Assert.Equal(mrzInfo.GetNationality(), mrzInfoConstructedWithNoFillers.GetNationality());
        Assert.Equal(mrzInfo.GetDocumentNumber(), mrzInfoConstructedWithNoFillers.GetDocumentNumber());
        Assert.Equal(mrzInfo.GetDateOfBirth(), mrzInfoConstructedWithNoFillers.GetDateOfBirth());
        Assert.Equal(mrzInfo.GetGenderCode(), mrzInfoConstructedWithNoFillers.GetGenderCode());
        Assert.Equal(mrzInfo.GetDateOfExpiry(), mrzInfoConstructedWithNoFillers.GetDateOfExpiry());
        Assert.Equal(mrzInfo, mrzInfoConstructedWithNoFillers);
    }

    /*
      * TD3 with non-empty optional data.
      */
    [Fact]
    public void testNORTD3()
    {
        string mrzString = GetMRZString("PUNORSPECIMEN<<PLACEBO<<<<<<<<<<<<<<<<<<<<<<"
                + "00000000<0UTO0508104F19110135200508102468906");
        Assert.Equal(88, mrzString.Length);
        MRZInfo mrzInfo = new MRZInfo(mrzString);

        Assert.Equal(mrzString, GetMRZString(mrzInfo));
        MRZInfo.EqualsModuloFillerChars(null, mrzInfo.GetOptionalData1());
        MRZInfo.EqualsModuloFillerChars(null, mrzInfo.GetOptionalData2());
        Assert.Equal("52005081024689", mrzInfo.GetOptionalData1());
        Assert.Null(mrzInfo.GetOptionalData2());
        Assert.Equal("SPECIMEN", mrzInfo.GetPrimaryIdentifier());
        Assert.Equal("PLACEBO", mrzInfo.GetSecondaryIdentifier());

        MRZInfo mrzInfoConstructedWithNoFillers = MRZInfo.CreateTD3MRZInfo(
                "PU", "NOR", "SPECIMEN", "PLACEBO",
                "00000000", "UTO", "050810", Gender.Female, "191101", "52005081024689");

        Assert.Equal(mrzInfo.GetOptionalData1(), mrzInfoConstructedWithNoFillers.GetOptionalData1());
        Assert.Equal(mrzInfo.GetOptionalData2(), mrzInfoConstructedWithNoFillers.GetOptionalData2());

        Assert.Equal(mrzInfo.GetDocumentCode(), mrzInfoConstructedWithNoFillers.GetDocumentCode());
        Assert.Equal(mrzInfo.GetIssuingState(), mrzInfoConstructedWithNoFillers.GetIssuingState());
        Assert.Equal(mrzInfo.GetPrimaryIdentifier(), mrzInfoConstructedWithNoFillers.GetPrimaryIdentifier());
        Assert.Equal(mrzInfo.GetSecondaryIdentifier(), mrzInfoConstructedWithNoFillers.GetSecondaryIdentifier());
        Assert.Equal(mrzInfo.GetNationality(), mrzInfoConstructedWithNoFillers.GetNationality());
        Assert.Equal(mrzInfo.GetDocumentNumber(), mrzInfoConstructedWithNoFillers.GetDocumentNumber());
        Assert.Equal(mrzInfo.GetDateOfBirth(), mrzInfoConstructedWithNoFillers.GetDateOfBirth());
        Assert.Equal(mrzInfo.GetGenderCode(), mrzInfoConstructedWithNoFillers.GetGenderCode());
        Assert.Equal(mrzInfo.GetDateOfExpiry(), mrzInfoConstructedWithNoFillers.GetDateOfExpiry());
        Assert.Equal(mrzInfo, mrzInfoConstructedWithNoFillers);
    }

    /*
      * TD3 MRZ with empty optional data (1) and 0 optional data check digit.
      */
    [Fact]
    public void testNZLTD3OptionalData()
    {
        string mrzString = GetMRZString("P<NZLWATA<<AROHA<MERE<TERESA<<<<<<<<<<<<<<<<"
                + "LF100358<5NZL9010015F2512152<<<<<<<<<<<<<<02");

        MRZInfo mrzInfo = new MRZInfo(mrzString);
        Assert.Equal(mrzString, GetMRZString(mrzInfo));

        Assert.NotNull(mrzInfo.GetOptionalData1());
        Assert.Equal("", mrzInfo.GetOptionalData1());
        Assert.Null(mrzInfo.GetOptionalData2());

        MRZInfo mrzInfoConstructedWithNoFillers = MRZInfo.CreateTD3MRZInfo(
                "P", "NZL", "WATA", "AROHA MERE TERESA",
                "LF100358", "NZL", "901001", Gender.Female, "251215", "");
        Assert.Equal("", mrzInfoConstructedWithNoFillers.GetOptionalData1());
        Assert.Equal(mrzInfo, mrzInfoConstructedWithNoFillers);

        MRZInfo mrzInfoConstructedWithFillers = MRZInfo.CreateTD3MRZInfo(
                "P<", "NZL", "WATA", "AROHA<MERE<TERESA",
                "LF100358<", "NZL", "901001", Gender.Female, "251215", "<<<<<<<<<<<<<<");
        Assert.Equal("", mrzInfoConstructedWithFillers.GetOptionalData1());
        Assert.Equal(mrzInfoConstructedWithFillers, mrzInfo);
        Assert.Equal(mrzInfo, mrzInfoConstructedWithFillers);
    }

    /*
      * TD1 MRZ with empty optional data 1 and long
      * document number (overflowing) and
      * non-empty optional data 2.
      */
    [Fact]
    public void testBELID()
    {
        string mrzString = GetMRZString("IDBEL000000387<2899<<<<<<<<<<<"
                + "9502286F3001064BEL950228998741"
                + "SPECIMEN<<SPECIMEN<<<<<<<<<<<<");

        MRZInfo mrzInfo = new MRZInfo(mrzString);
        Assert.Equal(mrzString, GetMRZString(mrzInfo));

        Assert.Equal("", mrzInfo.GetOptionalData1());
        Assert.Equal("95022899874", mrzInfo.GetOptionalData2());

        MRZInfo mrzInfoConstructedWithFillers = MRZInfo.CreateTD1MRZInfo(
                "ID", "BEL", "000000387289", "<<<<<<<<<<<",
                "950228", Gender.Female, "300106", "BEL", "95022899874",
                "SPECIMEN", "SPECIMEN<<<<<<<<<<<<");

        Assert.Equal("95022899874", mrzInfoConstructedWithFillers.GetOptionalData2());

        Assert.True(MRZInfo.EqualsModuloFillerChars(null, mrzInfoConstructedWithFillers.GetOptionalData1()));
        Assert.True(MRZInfo.EqualsModuloFillerChars("95022899874", mrzInfoConstructedWithFillers.GetOptionalData2()));
        Assert.Equal(mrzInfo, mrzInfoConstructedWithFillers);

        Assert.Equal("ID", mrzInfoConstructedWithFillers.GetDocumentCode());
        Assert.Equal("BEL", mrzInfoConstructedWithFillers.GetIssuingState());
        Assert.Equal("000000387289", mrzInfoConstructedWithFillers.GetDocumentNumber());
        Assert.Equal("", mrzInfoConstructedWithFillers.GetOptionalData1());
        Assert.Equal("", mrzInfoConstructedWithFillers.GetPersonalNumber());
        Assert.Equal("950228", mrzInfoConstructedWithFillers.GetDateOfBirth());
        Assert.Equal(Gender.Female, mrzInfoConstructedWithFillers.GetGenderCode());
        Assert.Equal("300106", mrzInfoConstructedWithFillers.GetDateOfExpiry());
        Assert.Equal("BEL", mrzInfoConstructedWithFillers.GetNationality());
        Assert.Equal("95022899874", mrzInfoConstructedWithFillers.GetOptionalData2());
        Assert.Equal("SPECIMEN", mrzInfoConstructedWithFillers.GetPrimaryIdentifier());
        Assert.Equal("SPECIMEN", mrzInfoConstructedWithFillers.GetSecondaryIdentifier());

        MRZInfo mrzInfoConstructedWithNoFillers = MRZInfo.CreateTD1MRZInfo(
                "ID", "BEL", "000000387289", "",
                "950228", Gender.Female, "300106", "BEL", "95022899874",
                "SPECIMEN", "SPECIMEN");
        Assert.Equal(mrzInfo, mrzInfoConstructedWithNoFillers);
    }

    /*
      * TD1 MRZ with empty optional data 1 and empty optional data 2.
      */
    [Fact]
    public void testNLDTD1EmptyOptionalData1()
    {
        string mrzString = GetMRZString("I<NLDSPECI20212<<<<<<<<<<<<<<<"
                + "6503101F3108022NLD<<<<<<<<<<<8"
                + "DE<BRUIJN<<WILLEKE<LISELOTTE<<");

        MRZInfo mrzInfo = new MRZInfo(mrzString);
        Assert.Equal(mrzString, GetMRZString(mrzInfo));
        MRZInfo.EqualsModuloFillerChars(null, mrzInfo.GetOptionalData1());
        MRZInfo.EqualsModuloFillerChars(null, mrzInfo.GetOptionalData2());
        Assert.Equal("", mrzInfo.GetOptionalData1());
        Assert.Equal("", mrzInfo.GetOptionalData2());
        Assert.Equal("DE BRUIJN", mrzInfo.GetPrimaryIdentifier());
        Assert.Equal("WILLEKE LISELOTTE", mrzInfo.GetSecondaryIdentifier());

        MRZInfo mrzInfoConstructedWithFillers = MRZInfo.CreateTD1MRZInfo(
                "I<", "NLD", "SPECI2021", "<<<<<<<<<<<<<<<",
                "650310", Gender.Female, "310802", "NLD", "<<<<<<<<<<<",
                "DE<BRUIJN", "WILLEKE<LISELOTTE<<");
        Assert.True(MRZInfo.EqualsModuloFillerChars(null, mrzInfoConstructedWithFillers.GetOptionalData1()));
        Assert.True(MRZInfo.EqualsModuloFillerChars(null, mrzInfoConstructedWithFillers.GetOptionalData2()));
        Assert.Equal("DE BRUIJN", mrzInfoConstructedWithFillers.GetPrimaryIdentifier());
        Assert.Equal("WILLEKE LISELOTTE", mrzInfoConstructedWithFillers.GetSecondaryIdentifier());
        Assert.Equal(mrzInfo, mrzInfoConstructedWithFillers);

        MRZInfo mrzInfoConstructedWithNoFillers = MRZInfo.CreateTD1MRZInfo(
                "I", "NLD", "SPECI2021", "",
                "650310", Gender.Female, "310802", "NLD", "",
                "DE BRUIJN", "WILLEKE LISELOTTE");
        Assert.True(MRZInfo.EqualsModuloFillerChars(null, mrzInfoConstructedWithNoFillers.GetOptionalData1()));
        Assert.True(MRZInfo.EqualsModuloFillerChars(null, mrzInfoConstructedWithNoFillers.GetOptionalData2()));
        Assert.Equal(mrzInfo, mrzInfoConstructedWithNoFillers);
    }

    [Fact]
    public void testTD1LongDocumentNumberAndAlsoOptionalData1()
    {
        MRZInfo mrzInfo = new MRZInfo(
                "I<NLD123456789<010<OHDA1<<<<<<\n"
                        + "6503101F3108022NLDOPT<DATA2<<5\n"
                        + "DE<BRUIJN<<WILLEKE<LISELOTTE<<");

        Assert.Equal("12345678901", mrzInfo.GetDocumentNumber());
        Assert.Equal("OHDA1", mrzInfo.GetOptionalData1());

        MRZInfo reconstructedMRZInfo = Reconstruct(mrzInfo);

        Assert.Equal("OHDA1", reconstructedMRZInfo.GetOptionalData1());
        Assert.Equal("12345678901", reconstructedMRZInfo.GetDocumentNumber());

        Assert.Equal(GetMRZString(mrzInfo), GetMRZString(reconstructedMRZInfo));
    }

    [Fact]
    public void testTD1ConstructedLongDocumentNumberAndAlsoOptionalData1()
    {
        MRZInfo mrzInfo = MRZInfo.CreateTD1MRZInfo(
                "I<", "NLD", "12345678901", "OHDA1",
                "650310", Gender.Female, "310802", "NLD", "OPT<DATA2",
                "DE<BRUIJN", "WILLEKE<LISELOTTE");

        string expectedMRZString =
                GetMRZString("I<NLD123456789<010<OHDA1<<<<<<\n"
                        + "6503101F3108022NLDOPT<DATA2<<5\n"
                        + "DE<BRUIJN<<WILLEKE<LISELOTTE<<");

        Assert.Equal("12345678901", mrzInfo.GetDocumentNumber());
        Assert.Equal("OHDA1", mrzInfo.GetOptionalData1());

        MRZInfo reconstructedMRZInfo = Reconstruct(mrzInfo);
        Assert.Equal("12345678901", reconstructedMRZInfo.GetDocumentNumber());
        Assert.Equal("OHDA1", reconstructedMRZInfo.GetOptionalData1());

        Assert.Equal(expectedMRZString, GetMRZString(mrzInfo));
        Assert.Equal(GetMRZString(mrzInfo), GetMRZString(reconstructedMRZInfo));
        Assert.Equal(expectedMRZString, GetMRZString(reconstructedMRZInfo));

        MRZInfo reconstructedResconstructedMRZInfo = new MRZInfo(GetMRZString(reconstructedMRZInfo));
        Assert.Equal("12345678901", reconstructedResconstructedMRZInfo.GetDocumentNumber());
        Assert.Equal("OHDA1", reconstructedResconstructedMRZInfo.GetOptionalData1());
    }

    [Fact]
    public void testTD1ConstructedLongDocumentNumberAndAlsoMaxOptionalData1()
    {
        MRZInfo mrzInfo = MRZInfo.CreateTD1MRZInfo(
                "I<", "NLD", "1234567890", "OHDA1234567X",
                "650310", Gender.Female, "310802", "NLD", "OPT<DATA2",
                "DE<BRUIJN", "WILLEKE<LISELOTTE");

        string expectedMRZString =
                GetMRZString("I<NLD123456789<07<OHDA1234567X"
                        + "6503101F3108022NLDOPT<DATA2<<1"
                        + "DE<BRUIJN<<WILLEKE<LISELOTTE<<");

        Assert.Equal("1234567890", mrzInfo.GetDocumentNumber());
        Assert.Equal("OHDA1234567X", mrzInfo.GetOptionalData1());

        MRZInfo reconstructedMRZInfo = Reconstruct(mrzInfo);
        Assert.Equal("1234567890", reconstructedMRZInfo.GetDocumentNumber());
        Assert.Equal("OHDA1234567X", reconstructedMRZInfo.GetOptionalData1());

        Assert.Equal(expectedMRZString, GetMRZString(mrzInfo));
        Assert.Equal(GetMRZString(mrzInfo), GetMRZString(reconstructedMRZInfo));
        Assert.Equal(expectedMRZString, GetMRZString(reconstructedMRZInfo));

        MRZInfo reconstructedResconstructedMRZInfo = new MRZInfo(GetMRZString(reconstructedMRZInfo));
        Assert.Equal("1234567890", reconstructedResconstructedMRZInfo.GetDocumentNumber());
        Assert.Equal("OHDA1234567X", reconstructedResconstructedMRZInfo.GetOptionalData1());
    }

    [Fact]
    public void testTD1ConstructedLongMaxDocumentNumberAndAlsoOptionalData1()
    {
        MRZInfo mrzInfo = MRZInfo.CreateTD1MRZInfo(
                "I<", "NLD", "123456789012345678801", "X",
                "650310", Gender.Female, "310802", "NLD", "OPT<DATA2",
                "DE<BRUIJN", "WILLEKE<LISELOTTE");

        string expectedMRZString =
                GetMRZString("I<NLD123456789<0123456788018<X"
                        + "6503101F3108022NLDOPT<DATA2<<5"
                        + "DE<BRUIJN<<WILLEKE<LISELOTTE<<");

        Assert.Equal(expectedMRZString, GetMRZString(mrzInfo));

        Assert.Equal("123456789012345678801", mrzInfo.GetDocumentNumber());
        Assert.Equal("X", mrzInfo.GetOptionalData1());

        MRZInfo reconstructedMRZInfo = Reconstruct(mrzInfo);
        Assert.Equal("123456789012345678801", reconstructedMRZInfo.GetDocumentNumber());
        Assert.Equal("X", reconstructedMRZInfo.GetOptionalData1());

        Assert.Equal(GetMRZString(mrzInfo), GetMRZString(reconstructedMRZInfo));
        Assert.Equal(expectedMRZString, GetMRZString(reconstructedMRZInfo));

        MRZInfo reconstructedResconstructedMRZInfo = new MRZInfo(GetMRZString(reconstructedMRZInfo));
        Assert.Equal("123456789012345678801", reconstructedResconstructedMRZInfo.GetDocumentNumber());
        Assert.Equal("X", reconstructedResconstructedMRZInfo.GetOptionalData1());
    }

    [Fact]
    public void testTD1ConstructedMaxDocumentNumberAndNoOptionalData1()
    {
        MRZInfo mrzInfo = MRZInfo.CreateTD1MRZInfo(
                "I<", "NLD", "1234567890123456788012", "",
                "650310", Gender.Female, "310802", "NLD", "OPT<DATA2",
                "DE<BRUIJN", "WILLEKE<LISELOTTE");

        string expectedMRZString =
                GetMRZString("I<NLD123456789<01234567880122<"
                        + "6503101F3108022NLDOPT<DATA2<<8"
                        + "DE<BRUIJN<<WILLEKE<LISELOTTE<<");

        Assert.Equal(expectedMRZString, GetMRZString(mrzInfo));

        Assert.Equal("1234567890123456788012", mrzInfo.GetDocumentNumber());
        Assert.Equal("", mrzInfo.GetOptionalData1());

        MRZInfo reconstructedMRZInfo = Reconstruct(mrzInfo);
        Assert.Equal("1234567890123456788012", reconstructedMRZInfo.GetDocumentNumber());
        Assert.Equal("", reconstructedMRZInfo.GetOptionalData1());

        Assert.Equal(GetMRZString(mrzInfo), GetMRZString(reconstructedMRZInfo));
        Assert.Equal(expectedMRZString, GetMRZString(reconstructedMRZInfo));

        MRZInfo reconstructedResconstructedMRZInfo = new MRZInfo(GetMRZString(reconstructedMRZInfo));
        Assert.Equal("1234567890123456788012", reconstructedResconstructedMRZInfo.GetDocumentNumber());
        Assert.Equal("", reconstructedResconstructedMRZInfo.GetOptionalData1());
    }

    [Fact]
    public void testTD1AUTDocumentNumberAndOptionalData1()
    {
        MRZInfo mrzInfo = MRZInfo.CreateTD1MRZInfo(
                "ID", "AUT", "PA1234567", "",
                "811231", Gender.Female, "310801", "AUT", "",
                "MUSTERFRAU", "MARIA");

        Assert.Equal("IDAUTPA12345673<<<<<<<<<<<<<<<"
                + "8112314F3108011AUT<<<<<<<<<<<6"
                + "MUSTERFRAU<<MARIA<<<<<<<<<<<<<", GetMRZString(mrzInfo));

        Assert.Equal(mrzInfo, new MRZInfo(mrzInfo.ToString()));
        Assert.Equal(mrzInfo, Reconstruct(mrzInfo));
    }

    [Fact]
    public void testTD1BELDocumentNumberAndOptionalData1()
    {
        MRZInfo mrzInfo = MRZInfo.CreateTD1MRZInfo(
                "ID", "BEL", "600001131775", "",
                "130101", Gender.Female, "231120", "UTO", "13010112359",
                "SPECIMEN", "SPECIMEN");

        Assert.Equal("IDBEL600001131<7755<<<<<<<<<<<"
                + "1301014F2311207UTO130101123596"
                + "SPECIMEN<<SPECIMEN<<<<<<<<<<<<", GetMRZString(mrzInfo));

        Assert.Equal(mrzInfo, new MRZInfo(mrzInfo.ToString()));
        Assert.Equal(mrzInfo, Reconstruct(mrzInfo));
    }

    [Fact]
    public void testTD1ESPDocumentNumberAndOptionalData1()
    {
        MRZInfo mrzInfo = MRZInfo.CreateTD1MRZInfo(
                "ID", "ESP", "CAA000000", "99999999R",
                "800101", Gender.Female, "310602", "ESP", "",
                "ESPANOLA ESPANOLA", "CARMEN");

        Assert.Equal("IDESPCAA000000499999999R<<<<<<"
                + "8001014F3106028ESP<<<<<<<<<<<1"
                + "ESPANOLA<ESPANOLA<<CARMEN<<<<<", GetMRZString(mrzInfo));

        Assert.Equal("CAA000000", mrzInfo.GetDocumentNumber());
        Assert.Equal("99999999R", mrzInfo.GetOptionalData1());
        Assert.Equal(mrzInfo, new MRZInfo(mrzInfo.ToString()));
        Assert.Equal(mrzInfo, Reconstruct(mrzInfo));
    }

    [Fact]
    public void testTD1ESTDocumentNumberAndOptionalData1()
    {
        MRZInfo mrzInfo = MRZInfo.CreateTD1MRZInfo(
                "ID", "EST", "AS0002262", "38001085718",
                "800108", Gender.Male, "260628", "EST", "",
                "JOEORG", "JAAK KRISTJAN");

        Assert.Equal("IDESTAS0002262038001085718<<<<"
                + "8001081M2606288EST<<<<<<<<<<<9"
                + "JOEORG<<JAAK<KRISTJAN<<<<<<<<<", GetMRZString(mrzInfo));

        Assert.Equal("AS0002262", mrzInfo.GetDocumentNumber());
        Assert.Equal("38001085718", mrzInfo.GetOptionalData1());
        Assert.Equal(mrzInfo, new MRZInfo(mrzInfo.ToString()));
        Assert.Equal(mrzInfo, Reconstruct(mrzInfo));
    }

    [Fact]
    public void testTD1LongDocumentNumberNoOptionalData1()
    {
        string optionalData1 = "";
        MRZInfo mrzInfo = MRZInfo.CreateTD1MRZInfo(
                "I", "NLD", "12345678901", optionalData1,
                "650310", Gender.Female, "310802", "NLD", "OPT<DATA2",
                "DE BRUIJN", "WILLEKE LISELOTTE");
        Assert.Equal("", mrzInfo.GetOptionalData1());
    }

    [Fact]
    public void testOptionalData1TD1()
    {
        // Old style NIK (Dutch Id card)
        string bsn = "299496892";
        string optionalData1 = bsn + "<<<<<" + MRZInfo.CheckDigit(bsn).ToString();
        MRZInfo mrzInfo = MRZInfo.CreateTD1MRZInfo(
                "I", "NLD", "SPECIMEN1", optionalData1,
                "650310", Gender.Female, "310802", "NLD", "OPT<DATA2",
                "DE BRUIJN", "WILLEKE LISELOTTE");

        Assert.StartsWith(mrzInfo.GetPersonalNumber(), optionalData1);

        Assert.Equal(optionalData1, mrzInfo.GetOptionalData1());
        Assert.Equal("OPT<DATA2", mrzInfo.GetOptionalData2());

        Assert.Equal("I<NLDSPECIMEN13299496892<<<<<6"
                + "6503101F3108022NLDOPT<DATA2<<2"
                + "DE<BRUIJN<<WILLEKE<LISELOTTE<<",
                GetMRZString(mrzInfo));

        // New style NIK (Dutch Id card) no BSN
        MRZInfo mrzInfoNew = MRZInfo.CreateTD1MRZInfo(
                "I", "NLD", "SPECIMEN2", "",
                "650310", Gender.Female, "310802", "NLD", "OPT<DATA3",
                "DE BRUIJN", "WILLEKE LISELOTTE");

        Assert.Equal("", mrzInfoNew.GetOptionalData1());
        Assert.Equal("OPT<DATA3", mrzInfoNew.GetOptionalData2());
    }

    [Fact]
    public void testCompositeCheckDigitTD3()
    {
        MRZInfo mrzInfo = MRZInfo.CreateTD3MRZInfo(
                "P", "GBR",
                "OTHER FORTYFOUR", "ANNA NICHOLA",
                "CCC014356", "GBR", "600101", Gender.Female, "270801", "OPTIONAL<DATA1");

        Assert.Equal("P<GBROTHER<FORTYFOUR<<ANNA<NICHOLA<<<<<<<<<<"
                + "CCC0143561GBR6001010F2708012OPTIONAL<DATA198",
                GetMRZString(mrzInfo));
    }

    [Fact]
    public void testOptionalData1TD3()
    {
        MRZInfo mrzInfo = MRZInfo.CreateTD3MRZInfo(
                "P", "GBR",
                "OTHER FORTYFOUR", "ANNA NICHOLA",
                "CCC014356", "GBR", "600101", Gender.Female, "270801", "OPTIONAL<DATAA");

        Assert.Equal("OPTIONAL<DATAA", mrzInfo.GetOptionalData1());
        Assert.Null(mrzInfo.GetOptionalData2());

        Assert.Equal("P<GBROTHER<FORTYFOUR<<ANNA<NICHOLA<<<<<<<<<<"
                + "CCC0143561GBR6001010F2708012OPTIONAL<DATAA62",
                GetMRZString(mrzInfo));

        MRZInfo mrzInfoSomeOptionalData = MRZInfo.CreateTD3MRZInfo(
                "P", "GBR",
                "OTHER FORTYFOUR", "ANNA NICHOLA",
                "CCC014356", "GBR", "600101", Gender.Female, "270801", "OPTIONAL DATA");

        Assert.Equal("OPTIONAL<DATA", mrzInfoSomeOptionalData.GetOptionalData1());
        Assert.Null(mrzInfoSomeOptionalData.GetOptionalData2());

        MRZInfo mrzInfoNoOptionalData = MRZInfo.CreateTD3MRZInfo(
                "P", "GBR",
                "OTHER FORTYFOUR", "ANNA NICHOLA",
                "CCC014356", "GBR", "600101", Gender.Female, "270801", null);

        Assert.Equal("", mrzInfoNoOptionalData.GetOptionalData1());
        Assert.Null(mrzInfoNoOptionalData.GetOptionalData2());
    }

    /*
      * Regression test for https://sourceforge.net/p/jmrtd/bugs/85/ :
      * '<' is only used in place of a calculated '0' personal number check digit when the personal
      * number field itself is empty (ICAO Doc 9303 Part 4), not whenever the 7-3-1 weighted sum
      * happens to come out to 0. Personal number "123456782" below is deliberately chosen because
      * its 7-3-1 check digit is 0: padded to 14 chars with 5 fillers, weighted sum 140, 140 mod 10 == 0.
      */
    [Fact]
    public void testPersonalNumberCheckDigitZeroIsNotReplacedByFillerWhenPersonalNumberIsNonEmpty()
    {
        MRZInfo mrzInfoNonEmptyPersonalNumber = MRZInfo.CreateTD3MRZInfo(
                "P", "GBR",
                "OTHER FORTYFOUR", "ANNA NICHOLA",
                "CCC014356", "GBR", "600101", Gender.Female, "270801", "123456782");

        Assert.Equal("P<GBROTHER<FORTYFOUR<<ANNA<NICHOLA<<<<<<<<<<"
                + "CCC0143561GBR6001010F2708012123456782<<<<<00",
                GetMRZString(mrzInfoNonEmptyPersonalNumber));

        /* Empty personal number should still yield '<' for a check digit that happens to be 0. */
        MRZInfo mrzInfoEmptyPersonalNumber = MRZInfo.CreateTD3MRZInfo(
                "P", "GBR",
                "OTHER FORTYFOUR", "ANNA NICHOLA",
                "CCC014356", "GBR", "600101", Gender.Female, "270801", "");

        Assert.Equal("P<GBROTHER<FORTYFOUR<<ANNA<NICHOLA<<<<<<<<<<"
                + "CCC0143561GBR6001010F2708012<<<<<<<<<<<<<<<0",
                GetMRZString(mrzInfoEmptyPersonalNumber));
    }

    [Fact]
    public void testOptionalData1TD2()
    {
        MRZInfo mrzInfo = MRZInfo.CreateTD2MRZInfo(
                "A", "UTO",
                "OTHER FORTYFOUR", "ANNA NICHOLA",
                "CCC014356", "GBR", "600101",
                Gender.Female, "270801", "OPT<DAT");

        Assert.Equal("OPT<DAT", mrzInfo.GetOptionalData1());

        Assert.Equal("A<UTOOTHER<FORTYFOUR<<ANNA<NICHOLA<<"
                + "CCC0143561GBR6001010F2708012OPT<DAT4",
                GetMRZString(mrzInfo));
    }

    [Fact]
    public void testOptionalData1MRVA()
    {
        MRZInfo mrzInfo = MRZInfo.CreateMRVAMRZInfo(
                "V", "GBR",
                "OTHER FORTYFOUR", "ANNA NICHOLA",
                "CCC014356", "GBR", "600101", Gender.Female, "270801", "OPTIONAL<DATAAAA");

        string mrzString = GetMRZString(mrzInfo);
        Assert.Equal(2 * 44, mrzString.Length);
        Assert.Equal("V<GBROTHER<FORTYFOUR<<ANNA<NICHOLA<<<<<<<<<<"
                + "CCC0143561GBR6001010F2708012OPTIONAL<DATAAAA",
                mrzString);

        Assert.Equal("OPTIONAL<DATAAAA", mrzInfo.GetOptionalData1());

        MRZInfo reconstructedMRZInfo = new MRZInfo(GetMRZString(mrzInfo));
        Assert.Equal("OPTIONAL<DATAAAA", reconstructedMRZInfo.GetOptionalData1());
        Assert.Null(reconstructedMRZInfo.GetOptionalData2());
    }

    [Fact]
    public void testOptionalDataMRVB()
    {
        MRZInfo mrzInfo = MRZInfo.CreateMRVBMRZInfo(
                "V", "UTO",
                "OTHER FORTYFOUR", "ANNA NICHOLA",
                "CCC014356", "GBR", "600101",
                Gender.Female, "270801", "OPT<DAT");

        string mrzString = GetMRZString(mrzInfo);
        Assert.Equal(2 * 36, mrzString.Length);
        Assert.Equal("V<UTOOTHER<FORTYFOUR<<ANNA<NICHOLA<<"
                + "CCC0143561GBR6001010F2708012OPT<DAT<",
                mrzString);

        Assert.Equal("OPT<DAT", mrzInfo.GetOptionalData1());

        MRZInfo mrzInfo1 = MRZInfo.CreateMRVBMRZInfo(
                "V", "UTO",
                "OTHER FORTYFOUR", "ANNA NICHOLA",
                "CCC014356", "GBR", "600101",
                Gender.Female, "270801", "OPT<DATA");

        Assert.Equal("OPT<DATA", mrzInfo1.GetOptionalData1());

        Assert.Equal("V<UTOOTHER<FORTYFOUR<<ANNA<NICHOLA<<"
                + "CCC0143561GBR6001010F2708012OPT<DATA",
                GetMRZString(mrzInfo1));

        // Optional data length > 8 not allowed.
        try
        {
            MRZInfo.CreateMRVBMRZInfo(
                    "V", "UTO",
                    "OTHER FORTYFOUR", "ANNA NICHOLA",
                    "CCC014356", "GBR", "600101",
                    Gender.Female, "270801", "123456789");
        }
        catch (ArgumentException)
        {
        }
    }

    [Fact]
    public void testMRVBMRZFormatFields()
    {
        MRZInfo mrzInfo = MRZInfo.CreateMRVBMRZInfo(
                "V", "UTO",
                "OTHER FORTYFOUR", "ANNA NICHOLA",
                "CCC014356", "GBR", "600101",
                Gender.Female, "270801", "OPT DAT");

        MRZInfo mrzInfo2 = MRZInfo.CreateMRVBMRZInfo(
                "V", "UTO",
                "OTHER<FORTYFOUR", "ANNA<NICHOLA",
                "CCC014356", "GBR", "600101",
                Gender.Female, "270801", "OPT<DAT");

        Assert.Equal(mrzInfo, mrzInfo2);

        Assert.True(MRZInfo.EqualsModuloFillerChars(mrzInfo.GetOptionalData1(), mrzInfo2.GetOptionalData1()));

        Assert.Equal(mrzInfo.GetPrimaryIdentifier(), mrzInfo2.GetPrimaryIdentifier());

        string mrzString = GetMRZString(mrzInfo);
        Assert.Equal(2 * 36, mrzString.Length);
        Assert.Equal("V<UTOOTHER<FORTYFOUR<<ANNA<NICHOLA<<"
                + "CCC0143561GBR6001010F2708012OPT<DAT<",
                mrzString);
        Assert.Equal(mrzString, GetMRZString(mrzInfo2));
    }

    [Fact]
    public void testTD3MRVAOptionalDataCompositeCheckDigit()
    {
        MRZInfo mrzInfoTD3 =  new MRZInfo("P<GBROTHER<FORTYFOUR<<ANNA<NICHOLA<<<<<<<<<<CCC0143561GBR6001010F27080121234567890123450");
        MRZInfo mrzInfoMRVA = new MRZInfo("V<GBROTHER<FORTYFOUR<<ANNA<NICHOLA<<<<<<<<<<CCC0143561GBR6001010F27080121234567890123450");
        Assert.Equal(14, mrzInfoTD3.GetOptionalData1().Length);
        Assert.Equal(16, mrzInfoMRVA.GetOptionalData1().Length);
    }

    [Fact]
    public void testTD2MRVBOptionalDataCompositeCheckDigit()
    {
        MRZInfo mrzInfoTD2 = new MRZInfo("I<UTOOTHER<FORTYFOUR<<ANNA<NICHOLA<<CCC0143561GBR6001010F270801234567892");
        MRZInfo mrzInfoMRVB = new MRZInfo("V<UTOOTHER<FORTYFOUR<<ANNA<NICHOLA<<CCC0143561GBR6001010F270801234567892");
        Assert.Equal(7, mrzInfoTD2.GetOptionalData1().Length);
        Assert.Equal(8, mrzInfoMRVB.GetOptionalData1().Length);
    }

    [Fact]
    public void testTD1OptionalData1OptionalData2()
    {
        string optionalData1 = "OPT DATA1     1"; // Length 15
        string optionalData2 = "OPT DATA  2"; // Length 11

        MRZInfo mrzInfo = MRZInfo.CreateTD1MRZInfo(
                "I", "NLD", "SPECI2021", optionalData1,
                "650310", Gender.Female, "310802", "NLD", optionalData2,
                "DE BRUIJN", "WILLEKE LISELOTTE");

        Assert.Equal(GetMRZString("I<NLDSPECI20212OPT<DATA1<<<<<1\n"
                + "6503101F3108022NLDOPT<DATA<<22\n"
                + "DE<BRUIJN<<WILLEKE<LISELOTTE<<"), GetMRZString(mrzInfo));

        // When constructing from fields, we get the original fields that were set.
        Assert.Equal(optionalData1, mrzInfo.GetOptionalData1());
        Assert.Equal(optionalData2, mrzInfo.GetOptionalData2());

        // When parsing from MRZ string, we get fields with fillers, but trailing fillers are stripped.
        MRZInfo reparsedMRZInfo = new MRZInfo(GetMRZString(mrzInfo));

        string expectedOptionalData1 = "OPT<DATA1<<<<<1"; // length 15
        string expectedOptionalData2 = "OPT<DATA<<2"; // length 11

        Assert.Equal(expectedOptionalData1, reparsedMRZInfo.GetOptionalData1());
        Assert.Equal(expectedOptionalData2, reparsedMRZInfo.GetOptionalData2());
    }

    [Fact]
    public void testGBRNoPrimary()
    {
        MRZInfo mrzInfo = new MRZInfo("IRGBRZU12345673<<<<<<<<<<<<<<<"
                + "6608198F0808088COU<<<<<<<<<<<6"
                + "A<BBBBBBBB<CCCCC<DDDDD<<<<<<<<");

        Assert.Equal("A BBBBBBBB CCCCC DDDDD", mrzInfo.GetPrimaryIdentifier());
        Assert.Equal("", mrzInfo.GetSecondaryIdentifier());
    }

    [Fact]
    public void testGetNameOfHolder()
    {
        CheckGetNameOfHolder("OTHER<FORTYFOUR<<ANNA<NICHOLA", new MRZInfo("P<GBROTHER<FORTYFOUR<<ANNA<NICHOLA<<<<<<<<<<"
                + "CCC0143561GBR6001010F27080121234567890123450"));
        CheckGetNameOfHolder("OTHER<FORTYFOUR<<ANNA<NICHOLA", new MRZInfo("V<GBROTHER<FORTYFOUR<<ANNA<NICHOLA<<<<<<<<<<"
                + "CCC0143561GBR6001010F27080121234567890123450"));
        CheckGetNameOfHolder("OTHER<FORTYFOUR<<ANNA<NICHOLA", new MRZInfo("I<UTOOTHER<FORTYFOUR<<ANNA<NICHOLA<<"
                + "CCC0143561GBR6001010F270801234567892"));
        CheckGetNameOfHolder("OTHER<FORTYFOUR<<ANNA<NICHOLA", new MRZInfo("V<UTOOTHER<FORTYFOUR<<ANNA<NICHOLA<<"
                + "CCC0143561GBR6001010F270801234567892"));
        CheckGetNameOfHolder("OTHER<FORTYFOUR<<ANNA<NICHOLA", new MRZInfo("IRGBRZU12345673<<<<<<<<<<<<<<<"
                + "6608198F0808088COU<<<<<<<<<<<6"
                + "OTHER<FORTYFOUR<<ANNA<NICHOLA<"));

        CheckGetNameOfHolder("OTHER<FORTYSEVEN<<ANN<NICHOLA<MARGARETH", new MRZInfo("P<GBROTHER<FORTYSEVEN<<ANN<NICHOLA<MARGARETH"
                + "CCC0143561GBR6001010F27080121234567890123450"));

        CheckGetNameOfHolder("OTHER<FORTYFOUR<ANNA<NICHOLA", new MRZInfo("P<GBROTHER<FORTYFOUR<ANNA<NICHOLA<<<<<<<<<<<"
                + "CCC0143561GBR6001010F27080121234567890123450"));
        CheckGetNameOfHolder("A<BBBBBBBB<CCCCC<DDDDD", new MRZInfo("IRGBRZU12345673<<<<<<<<<<<<<<<"
                + "6608198F0808088COU<<<<<<<<<<<6"
                + "A<BBBBBBBB<CCCCC<DDDDD<<<<<<<<"));

        CheckGetNameOfHolder("OTHER<FORTYSEVEN<ANNA<NICHOLA<MARGARETH", new MRZInfo("P<GBROTHER<FORTYSEVEN<ANNA<NICHOLA<MARGARETH"
                + "CCC0143561GBR6001010F27080121234567890123450"));

        CheckGetNameOfHolder("<<HER<FORTYSEVEN<ANNA<NICHOLA<MARGARETH", new MRZInfo("P<GBR<<HER<FORTYSEVEN<ANNA<NICHOLA<MARGARETH"
                + "CCC0143561GBR6001010F27080121234567890123450"));
    }

    private static void CheckGetNameOfHolder(string expectedNameOfHolder, MRZInfo mrzInfo)
    {
        Assert.Equal(expectedNameOfHolder, mrzInfo.GetNameOfHolder());
        Assert.Equal(expectedNameOfHolder, Reconstruct(mrzInfo).GetNameOfHolder());
        Assert.Equal(expectedNameOfHolder, new MRZInfo(GetMRZString(mrzInfo)).GetNameOfHolder());

        string primaryIdentifier = mrzInfo.GetPrimaryIdentifier();
        Assert.Contains(primaryIdentifier.Replace(" ", "<"), expectedNameOfHolder);

        string secondaryIdentifier = mrzInfo.GetSecondaryIdentifier();
        Assert.Contains(secondaryIdentifier.Replace(" ", "<"), expectedNameOfHolder);
    }

    [Fact]
    public void testConstructTD1()
    {
        try
        {

            MRZInfo mrzInfo = MRZInfo.CreateTD1MRZInfo(
                    "I",
                    "UTO",
                    "999999999",
                    "<<<<<<<<<<<<<<",
                    "800101",
                    "M",
                    "301231",
                    "UTO",
                    null,
                    "LAST<NAME",
                    "FIRST<NAME");

            MRZInfo mrzInfoFromString = new MRZInfo(
                    "I<UTO9999999997<<<<<<<<<<<<<<<"
                            + "8001014M3012316UTO<<<<<<<<<<<0"
                            + "LAST<NAME<<FIRST<NAME<<<<<<<<<");
            Assert.Equal(mrzInfoFromString, mrzInfo);


            DG1File dg1File = new DG1File(mrzInfo);
            DG1File reconstructedDG1File = new DG1File(new MemoryStream(dg1File.GetEncoded()!));
            Assert.Equal(mrzInfo, reconstructedDG1File.GetMRZInfo());

            Assert.Equal(mrzInfo, Reconstruct(mrzInfo));
        }
        catch (Exception e) when (e is not Xunit.Sdk.XunitException) { Assert.Fail(e.Message); }
    }

    /* HELPERS BELOW. */

    internal static MRZInfo CreateTestObject()
    {
        string documentCode = "P<";
        Country issuingState = Country.GetInstance("NLD");
        string primaryIdentifier = "MEULENDIJK";
        string secondaryIdentifier = "LOES" + "<" + "ALBERTINE";
        string documentNumber = "XX0000000";
        Country nationality = Country.GetInstance("NLD");
        string dateOfBirth = new DateTime(1971, 10, 19).ToString("yyMMdd", CultureInfo.InvariantCulture);
        Gender gender = Gender.Female;
        string dateOfExpiry = new DateTime(2011, 8, 28).ToString("yyMMdd", CultureInfo.InvariantCulture);
        string personalNumber = "123456782";
        return MRZInfo.CreateTD3MRZInfo(documentCode, issuingState.ToAlpha3Code(),
                primaryIdentifier, secondaryIdentifier, documentNumber, nationality.ToAlpha3Code(),
                dateOfBirth, gender, dateOfExpiry, personalNumber);
    }

    private static MRZInfo Reconstruct(MRZInfo mrzInfo)
    {
        string mrzString = GetMRZString(mrzInfo);
        int mrzLength = mrzString.Length;
        string documentCode = mrzInfo.GetDocumentCode();
        if (mrzLength == 2 * 44 && documentCode.StartsWith("P"))
        {
            string issuingState = mrzInfo.GetIssuingState();
            string primaryIdentifier = mrzInfo.GetPrimaryIdentifier();
            string secondaryIdentifier = mrzInfo.GetSecondaryIdentifier();
            string documentNumber = mrzInfo.GetDocumentNumber();
            string nationality = mrzInfo.GetNationality();
            string dateOfBirth = mrzInfo.GetDateOfBirth();
            Gender gender = mrzInfo.GetGenderCode();
            string dateOfExpiry = mrzInfo.GetDateOfExpiry();
            string? personalNumber = mrzInfo.GetPersonalNumber();
            return MRZInfo.CreateTD3MRZInfo(documentCode, issuingState, primaryIdentifier, secondaryIdentifier, documentNumber,
                    nationality, dateOfBirth, gender, dateOfExpiry, personalNumber);
        }
        else if (mrzLength == 2 * 44 && documentCode.StartsWith("V"))
        {
            string issuingState = mrzInfo.GetIssuingState();
            string primaryIdentifier = mrzInfo.GetPrimaryIdentifier();
            string secondaryIdentifier = mrzInfo.GetSecondaryIdentifier();
            string documentNumber = mrzInfo.GetDocumentNumber();
            string nationality = mrzInfo.GetNationality();
            string dateOfBirth = mrzInfo.GetDateOfBirth();
            Gender gender = mrzInfo.GetGenderCode();
            string dateOfExpiry = mrzInfo.GetDateOfExpiry();
            string? personalNumber = mrzInfo.GetPersonalNumber();
            return MRZInfo.CreateMRVAMRZInfo(documentCode, issuingState, primaryIdentifier, secondaryIdentifier, documentNumber,
                    nationality, dateOfBirth, gender, dateOfExpiry, personalNumber);
        }
        else if ( mrzLength == 2 * 36 && documentCode.StartsWith("V"))
        {
            string issuingState = mrzInfo.GetIssuingState();
            string primaryIdentifier = mrzInfo.GetPrimaryIdentifier();
            string secondaryIdentifier = mrzInfo.GetSecondaryIdentifier();
            string documentNumber = mrzInfo.GetDocumentNumber();
            string nationality = mrzInfo.GetNationality();
            string dateOfBirth = mrzInfo.GetDateOfBirth();
            Gender gender = mrzInfo.GetGenderCode();
            string dateOfExpiry = mrzInfo.GetDateOfExpiry();
            string optionalData = mrzInfo.GetOptionalData1();
            return MRZInfo.CreateMRVBMRZInfo(documentCode, issuingState, primaryIdentifier, secondaryIdentifier, documentNumber,
                    nationality, dateOfBirth, gender, dateOfExpiry, optionalData);
        }
        else if (mrzLength == 2 * 36 && (documentCode.StartsWith("C") || documentCode.StartsWith("I") || documentCode.StartsWith("A")))
        {
            string issuingState = mrzInfo.GetIssuingState();
            string primaryIdentifier = mrzInfo.GetPrimaryIdentifier();
            string secondaryIdentifier = mrzInfo.GetSecondaryIdentifier();
            string documentNumber = mrzInfo.GetDocumentNumber();
            string nationality = mrzInfo.GetNationality();
            string dateOfBirth = mrzInfo.GetDateOfBirth();
            Gender gender = mrzInfo.GetGenderCode();
            string dateOfExpiry = mrzInfo.GetDateOfExpiry();
            string optionalData = mrzInfo.GetOptionalData1();
            return MRZInfo.CreateTD2MRZInfo(documentCode,issuingState, primaryIdentifier, secondaryIdentifier, documentNumber,
                    nationality, dateOfBirth, gender, dateOfExpiry, optionalData);
        }
        else if (mrzLength == 3 * 30 && (documentCode.StartsWith("C") || documentCode.StartsWith("I") || documentCode.StartsWith("A")))
        {
            string issuingState = mrzInfo.GetIssuingState();
            string primaryIdentifier = mrzInfo.GetPrimaryIdentifier();
            string secondaryIdentifier = mrzInfo.GetSecondaryIdentifier();
            string documentNumber = mrzInfo.GetDocumentNumber();
            string nationality = mrzInfo.GetNationality();
            string dateOfBirth = mrzInfo.GetDateOfBirth();
            Gender gender = mrzInfo.GetGenderCode();
            string dateOfExpiry = mrzInfo.GetDateOfExpiry();
            string optionalData1 = mrzInfo.GetOptionalData1();
            string? optionalData2 = mrzInfo.GetOptionalData2();
            return MRZInfo.CreateTD1MRZInfo(documentCode, issuingState, documentNumber, optionalData1, dateOfBirth, gender,
                    dateOfExpiry, nationality, optionalData2, primaryIdentifier, secondaryIdentifier);
        }
        else
        {
            throw new ArgumentException("Unsupported document code: " + documentCode + " and/or length: " + mrzLength);
        }
    }

    private static string GetMRZString(MRZInfo mrzInfo) => GetMRZString(mrzInfo.ToString());

    private static string GetMRZString(string mrzString) => mrzString.Replace("\n", "").Trim();

    /*
      * In a Turkish locale "ita".toUpperCase() is "İTA" (dotted capital I), which is not an MRZ character.
      */
    [Fact]
    public void testMRZFormatInTurkishLocale()
    {
        CultureInfo defaultCulture = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = new CultureInfo("tr-TR");
            MRZInfo mrzInfo = MRZInfo.CreateTD3MRZInfo(
                    "P<", "ita", "MUSTERMANN", "ERIKA",
                    "C11T002JM", "ita", "960812", Gender.Female, "131031", "");
            Assert.Equal("ITA", mrzInfo.GetIssuingState());
            Assert.Equal("ITA", mrzInfo.GetNationality());
        }
        finally
        {
            CultureInfo.CurrentCulture = defaultCulture;
        }
    }

    /// <summary>Document number check digit indicates extension in optional data, but optional data starts with a
    /// filler. Used to throw an ArgumentOutOfRangeException (JMRTD 0.8.10, cf340d7d).</summary>
    [Fact]
    public void testMRZWithExtendedDocumentNumberStartingWithFiller()
    {
        string mrz = GetMRZString("I<UTOD23145890<<ABC<<<<<<<<<<<" +
            "7408122F1204159UTO<<<<<<<<<<<6" +
            "ERIKSSON<<ANNA<MARIA<<<<<<<<<<");

        Assert.Equal(90, mrz.Length);

        var mrzInfo = new MRZInfo(mrz);
        Assert.Equal("D23145890", mrzInfo.GetDocumentNumber());
        Assert.Equal("<ABC", mrzInfo.GetOptionalData1());
        Assert.Equal(mrz, GetMRZString(mrzInfo.ToString()));
    }
}
