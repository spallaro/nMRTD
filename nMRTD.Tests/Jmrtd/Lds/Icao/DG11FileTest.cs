using System.Text;
using nMRTD.Cbeff;
using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.Lds.Iso19794;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using nMRTD.Tests.Jmrtd.Lds.Iso19794;

namespace nMRTD.Tests.Jmrtd.Lds.Icao;

/// <summary>Port of JMRTD's <c>org.jmrtd.lds.icao.DG11FileTest</c>.</summary>
public class DG11FileTest
{

    [Fact]
    public void testToString()
    {
        DG11File dg11File = CreateTestObject();
        string expectedResult = "DG11File [, [], , 19711019, [], [], , , , , , [], ]";
        Assert.Equal(dg11File.ToString(), expectedResult);
    }

    [Fact]
    public void testDecodeEncode()
    {
        byte[] simpleDG11 = new byte[] {
                0x6B, 0x34, 0x5C, 0x10, 0x5F, 0x0E, 0x5F, 0x10,
                0x5F, 0x2B, 0x5F, 0x12, 0x5F, 0x13, 0x5F, 0x14,
                0x5F, 0x15, 0x5F, 0x18, 0x5F, 0x0E, 0x02, 0x3C,
                0x3C, 0x5F, 0x10, 0x00, 0x5F, 0x2B, 0x08, 0x31,
                0x39, 0x37, 0x31, 0x31, 0x30, 0x31, 0x39, 0x5F,
                0x12, 0x00, 0x5F, 0x13, 0x00, 0x5F, 0x14, 0x00,
                0x5F, 0x15, 0x00, 0x5F, 0x18, 0x00
        };

        try
        {
            DG11File dg11File = new DG11File(new MemoryStream(simpleDG11));
            byte[] encoded = dg11File.GetEncoded()!;
            Assert.Equal(Hex.BytesToHexString(simpleDG11), Hex.BytesToHexString(encoded));
        }
        catch (IOException e)
        {
            Assert.Fail(e.Message);
        }
    }

    [Fact]
    public void testReflexive()
    {
        CheckReflexive(CreateTestObject());
        CheckReflexive(CreateComplexTestObject());
    }

    internal static void CheckReflexive(DG11File dg11File)
    {
        Assert.NotNull(dg11File);

        byte[] encoded = dg11File.GetEncoded()!;
        Assert.NotNull(encoded);

        MemoryStream input = new MemoryStream(encoded);
        DG11File copy = new DG11File(input);

        Assert.NotNull(copy);

        List<string>? otherNames = dg11File.GetOtherNames();
        if (otherNames !=  null)
        {
            Assert.NotNull(copy.GetOtherNames());
            Assert.Equal(otherNames.Count, copy.GetOtherNames()!.Count);
            Assert.Equal(otherNames, copy.GetOtherNames());
        }

        List<string>? otherValidTDNumbers = dg11File.GetOtherValidTDNumbers();
        if (otherValidTDNumbers != null)
        {
            Assert.NotNull(copy.GetOtherValidTDNumbers());
            Assert.Equal(otherValidTDNumbers.Count, copy.GetOtherValidTDNumbers()!.Count);
        }

        List<string>? placeOfBirth = dg11File.GetPlaceOfBirth();
        if (placeOfBirth != null)
        {
            Assert.NotNull(copy.GetPlaceOfBirth());
            Assert.Equal(placeOfBirth.Count, copy.GetPlaceOfBirth()!.Count);
        }

        List<string>? permanentAddress = dg11File.GetPermanentAddress();
        if (permanentAddress != null)
        {
            Assert.NotNull(copy.GetPermanentAddress());
            Assert.Equal(permanentAddress.Count, copy.GetPermanentAddress()!.Count);
        }

        Assert.Equal(dg11File, copy);

        byte[] encodedCopy = copy.GetEncoded()!;
        Assert.NotNull(encodedCopy);

        Assert.Equal(Hex.BytesToHexString(encoded), Hex.BytesToHexString(copy.GetEncoded()!));

        Assert.Equal(dg11File, DecodeEncode(dg11File));
        Assert.Equal(dg11File, Reconstruct(dg11File));

    }

    /**
      * Ronny is a fictional character.
      * Any resemblance to living persons is pure coincidence.
      */
    [Fact]
    public void testRonny()
    {
        byte[] bytes = {
                0x6B, 0x2F, 0x5C, 0x02, 0x5F, 0x0E, 0x5F, 0x0E,
                0x28, 0x57, 0x49, 0x43, 0x48, 0x45, 0x52, 0x53,
                0x3C, 0x53, 0x43, 0x48, 0x52, 0x45, 0x55, 0x52,
                0x3C, 0x3C, 0x52, 0x4F, 0x4E, 0x41, 0x4C, 0x44,
                0x55, 0x53, 0x3C, 0x4A, 0x4F, 0x48, 0x41, 0x4E,
                0x4E, 0x45, 0x53, 0x3C, 0x4D, 0x41, 0x52, 0x49,
                0x41
        };

        MemoryStream input = new MemoryStream(bytes);
        DG11File file = new DG11File(input);
        string primary = "WICHERS" + "<" + "SCHREUR";
        string secondary = "RONALDUS" + "<" + "JOHANNES" + "<" + "MARIA";
        Assert.Equal(file.GetNameOfHolder(), primary + "<<" + secondary);
    }

    [Fact]
    public void testSpecSample()
    {
        byte[] bytes = {
                0x6B, /* L */ 0x63,
                0x5C, /* L = 10, i.e. 5 tags */ 0x0A,
                0x5F, 0x0E,
                0x5F, 0x11,
                0x5F, 0x42,
                0x5F, 0x12,
                0x5F, 0x13,
                0x5F, 0x0E, /* L */ 0x0D,
                (byte)'S', (byte)'M', (byte)'I', (byte)'T', (byte)'H', (byte)'<', (byte)'<', (byte)'J', (byte)'O', (byte)'H', (byte)'N', (byte)'<', (byte)'J',
                0x5F, 0x11, /* L */ 0x0A,
                (byte)'A', (byte)'N', (byte)'Y', (byte)'T', (byte)'O', (byte)'W', (byte)'N', (byte)'<', (byte)'M', (byte)'N',
                0x5F, 0x42, /* L */ 0x17,
                (byte)'1', (byte)'2', (byte)'3', (byte)' ', (byte)'M', (byte)'A', (byte)'P', (byte)'L', (byte)'E', (byte)' ', (byte)'R', (byte)'D', (byte)'<', (byte)'A', (byte)'N', (byte)'Y', (byte)'T', (byte)'O', (byte)'W', (byte)'N', (byte)'<', (byte)'M', (byte)'N',
                0x5F, 0x12, /* L */ 0x0E,
                (byte)'1', (byte)'-', (byte)'6', (byte)'1', (byte)'2', (byte)'-', (byte)'5', (byte)'5', (byte)'5', (byte)'-', (byte)'1', (byte)'2', (byte)'1', (byte)'2',
                0x5F, 0x13, /* L */ 0x0C,
                (byte)'T', (byte)'R', (byte)'A', (byte)'V', (byte)'E', (byte)'L', (byte)'<', (byte)'A', (byte)'G', (byte)'E', (byte)'N', (byte)'T'
        };

        MemoryStream input = new MemoryStream(bytes);
        DG11File file = new DG11File(input);
        string primary = "SMITH";
        string secondary = "JOHN" + "<" + "J";
        Assert.Equal(file.GetNameOfHolder(), primary + "<<" + secondary);
        //				Assert.Equal("SMITH", file.GetFullNamePrimaryIdentifier());
        //				Assert.Equal(2, file.GetFullNameSecondaryIdentifiers().Count);
        //				Assert.Equal("JOHN", file.GetFullNameSecondaryIdentifiers()[0]);
        //				Assert.Equal("J", file.GetFullNameSecondaryIdentifiers()[1]);
        Assert.Equal(2, file.GetPlaceOfBirth()!.Count);
        Assert.Equal("ANYTOWN", file.GetPlaceOfBirth()![0]);
        Assert.Equal("MN", file.GetPlaceOfBirth()![1]);
        Assert.Equal(3, file.GetPermanentAddress()!.Count);
        Assert.Equal("123 MAPLE RD", file.GetPermanentAddress()![0]);
        Assert.Equal("ANYTOWN", file.GetPermanentAddress()![1]);
        Assert.Equal("MN", file.GetPermanentAddress()![2]);
        Assert.Equal("1-612-555-1212", file.GetTelephone());
        Assert.Equal("TRAVEL<AGENT", file.GetProfession());
    }

    [Fact]
    public void testComplex()
    {
        DG11File dg11 = CreateComplexTestObject();
        byte[] encoded = dg11.GetEncoded()!;
        DG11File copy = new DG11File(new MemoryStream(encoded));
        byte[] copyEncoded = copy.GetEncoded()!;
        Assert.Equal(encoded, copyEncoded); // Java: a plain assert
    }

    [Fact]
    public void testHappyAllFieldsNonEmpty()
    {
        DG11File dg11 = new DG11File(
                "NAME OF HOLDER", // name of holder
                new List<string> { "OTHER", "NAMES" }, // other names
                "123456789", // personal number
                DateTime.Now, // full date of birth
                new List<string> { "PLACE", "OF BIRTH" }, // place of birth
                new List<string> { "PERMANENT", "ADDRESS" }, // permanent address
                "555 2368", // telephone
                "PROFESSION", // profession
                "TITLE", // title
                "PERSONAL SUMMARY", // personal summary
                new byte[] { 0x00, 0x00 }, // proof of citizenship,
                new List<string> { "OTHER", "VALID", "TD", "NUMBERS" }, // otherValidTDNumbers,
                "CUSTODY INFORMATION"); // custodyInformation)

        Assert.Equal(dg11, Reconstruct(dg11));

        DG11File reencoded = DecodeEncode(dg11);

        Assert.Equal(dg11.GetTagPresenceList(), reencoded.GetTagPresenceList());

        Assert.Equal(dg11.GetNameOfHolder(), reencoded.GetNameOfHolder());
        Assert.Equal(dg11.GetOtherNames(), reencoded.GetOtherNames());
        Assert.Equal(dg11.GetPersonalNumber(), reencoded.GetPersonalNumber());
        Assert.Equal(dg11.GetFullDateOfBirth(), reencoded.GetFullDateOfBirth());
        Assert.Equal(dg11.GetPlaceOfBirth(), reencoded.GetPlaceOfBirth());
        Assert.Equal(dg11.GetPermanentAddress(), reencoded.GetPermanentAddress());
        Assert.Equal(dg11.GetTelephone(), reencoded.GetTelephone());
        Assert.Equal(dg11.GetProfession(), reencoded.GetProfession());
        Assert.Equal(dg11.GetTitle(), reencoded.GetTitle());
        Assert.Equal(dg11.GetPersonalSummary(), reencoded.GetPersonalSummary());
        Assert.Equal(dg11.GetProofOfCitizenship(), reencoded.GetProofOfCitizenship());
        Assert.Equal(dg11.GetOtherValidTDNumbers(), reencoded.GetOtherValidTDNumbers());
        Assert.Equal(dg11.GetCustodyInformation(), reencoded.GetCustodyInformation());

        Assert.Equal(dg11, reencoded);

        Assert.Equal(dg11, reencoded);
    }

    /**
      * https://sourceforge.net/p/jmrtd/bugs/65/
      */
    [Fact]
    public void testNullDate()
    {
        string nameOfHolder = "SOME<MRZ_FORMATTED<NAME";
        DG11File dg11 = new DG11File(nameOfHolder, null, null, (DateTime?)null, null, null, null, null, null, null, null, null, null);
        Assert.Equal(nameOfHolder, dg11.GetNameOfHolder());
        Assert.Null(dg11.GetFullDateOfBirth());
        Assert.Equal(dg11, Reconstruct(dg11));

        CheckReflexive(dg11);
    }

    [Fact]
    public void testEmpty()
    {
        DG11File dg11 = new DG11File(
                "", // name of holder
                new List<string> { "OTHER", "NAMES" }, // other names
                "123456789", // personal number
                DateTime.Now, // full date of birth
                new List<string> { "A", "B" }, // place of birth
                new List<string> { "A", "B" }, // permanent address
                "", // telephone
                "", // profession
                "", // title
                "", // personal summary
                new byte[] { }, // proof of citizenship,
                new List<string> { "A", "" }, // otherValidTDNumbers,
                ""); // custodyInformation)

        Assert.Equal(dg11, Reconstruct(dg11));

        DG11File reencoded = DecodeEncode(dg11);

        Assert.Equal(dg11.GetTagPresenceList(), reencoded.GetTagPresenceList());

        Assert.Equal(dg11.GetNameOfHolder(), reencoded.GetNameOfHolder());
        Assert.Equal(dg11.GetOtherNames(), reencoded.GetOtherNames());
        Assert.Equal(dg11.GetPersonalNumber(), reencoded.GetPersonalNumber());
        Assert.Equal(dg11.GetFullDateOfBirth(), reencoded.GetFullDateOfBirth());
        Assert.Equal(dg11.GetPlaceOfBirth(), reencoded.GetPlaceOfBirth());
        Assert.Equal(dg11.GetPermanentAddress(), reencoded.GetPermanentAddress());
        Assert.Equal(dg11.GetTelephone(), reencoded.GetTelephone());
        Assert.Equal(dg11.GetProfession(), reencoded.GetProfession());
        Assert.Equal(dg11.GetTitle(), reencoded.GetTitle());
        Assert.Equal(dg11.GetPersonalSummary(), reencoded.GetPersonalSummary());
        Assert.Equal(dg11.GetProofOfCitizenship(), reencoded.GetProofOfCitizenship());
        Assert.Equal(dg11.GetOtherValidTDNumbers(), reencoded.GetOtherValidTDNumbers());
        Assert.Equal(dg11.GetCustodyInformation(), reencoded.GetCustodyInformation());

        Assert.Equal(dg11, reencoded);

        Assert.Equal(dg11, DecodeEncode(dg11));
    }

    [Fact]
    public void testSingletonStringLists()
    {
        List<string> placeOfBirth = new List<string> { "" };
        List<string> permanentAddress = new List<string> { "" };
        List<string> otherValidTDNumbers = new List<string> { "" };

        DG11File dg11 = new DG11File(
                "NAME OF HOLDER", // name of holder
                null, // other names
                "123456789", // personal number
                DateTime.Now, // full date of birth
                placeOfBirth, // place of birth
                permanentAddress, // permanent address
                "555 2368", // telephone
                "PROFESSION", // profession
                "TITLE", // title
                "PERSONAL SUMMARY", // personal summary
                new byte[] { 0x00, 0x00 }, // proof of citizenship,
                otherValidTDNumbers, // otherValidTDNumbers,
                "CUSTODY INFORMATION"); // custodyInformation)

        CheckReflexive(dg11);
    }

    [Fact]
    public void testEmptyStringLists()
    {
        List<string> placeOfBirth = new List<string>();
        List<string> permanentAddress = new List<string>();
        List<string> otherValidTDNumbers = new List<string>();

        DG11File dg11 = new DG11File(
                "NAME OF HOLDER", // name of holder
                null, // other names
                "123456789", // personal number
                DateTime.Now, // full date of birth
                placeOfBirth, // place of birth
                permanentAddress, // permanent address
                "555 2368", // telephone
                "PROFESSION", // profession
                "TITLE", // title
                "PERSONAL SUMMARY", // personal summary
                new byte[] { 0x00, 0x00 }, // proof of citizenship,
                otherValidTDNumbers, // otherValidTDNumbers,
                "CUSTODY INFORMATION"); // custodyInformation)

        CheckReflexive(dg11);

        /* NOTE: Replaces empty list with singleton with empty string. !!! */
        Assert.NotEqual(placeOfBirth.Count, dg11.GetPlaceOfBirth()!.Count);
        Assert.NotEqual(permanentAddress.Count, dg11.GetPermanentAddress()!.Count);
        Assert.NotEqual(otherValidTDNumbers.Count, dg11.GetOtherValidTDNumbers()!.Count);

    }

    /* HELPERS */

    public static DG11File CreateComplexTestObject()
    {
        string fullNamePrimaryIdentifier = "TEST";
        string fullNameSecondaryIdentifiers = "FIRST" + "<" + "SECOND";
        List<string> otherNames = new List<string> { "FIRST OTHER", "SECOND OTHER", "THIRD OTHER" };
        string nameOfHolder = fullNamePrimaryIdentifier + "<<" + fullNameSecondaryIdentifiers;
        string personalNumber = "123456789";
        DateTime fullDateOfBirth = new DateTime(1971, 10, 19);
        List<string> placeOfBirth = new List<string>();
        List<string> permanentAddress = new List<string>();
        string telephone = "";
        string profession = "";
        string title = "";
        string personalSummary = "";
        byte[]? proofOfCitizenship = null;
        List<string> otherValidTDNumbers = new List<string>();
        string custodyInformation = "";
        return new DG11File(nameOfHolder, otherNames, personalNumber,
                fullDateOfBirth, placeOfBirth, permanentAddress,
                telephone, profession, title,
                personalSummary, proofOfCitizenship,
                otherValidTDNumbers, custodyInformation);
    }

    public static DG11File CreateTestObject()
    {
        string nameOfHolder = "";
        List<string> otherNames = new List<string>();
        string personalNumber = "";
        DateTime fullDateOfBirth = new DateTime(1971, 10, 19);
        string telephone = "";
        string profession = "";
        string title = "";
        string personalSummary = "";
        byte[]? proofOfCitizenship = null;
        string custodyInformation = "";
        List<string> placeOfBirth = new List<string> { "" }; // new List<string>();
        List<string> permanentAddress = new List<string> { "" }; // new List<string>();
        List<string> otherValidTDNumbers = new List<string> { "" }; // new List<string>();

        return new DG11File(nameOfHolder, otherNames, personalNumber,
                fullDateOfBirth, placeOfBirth, permanentAddress,
                telephone, profession, title,
                personalSummary, proofOfCitizenship,
                otherValidTDNumbers, custodyInformation);
    }

    private static DG11File DecodeEncode(DG11File dg11)
    {
        MemoryStream byteArrayOutputStream = new MemoryStream();
        try
        {
            byteArrayOutputStream.Write(dg11.GetEncoded()!);
        }
        finally
        {
            byteArrayOutputStream.Close();
        }
        byte[] encoded = byteArrayOutputStream.ToArray();
        MemoryStream byteArrayInputStream = new MemoryStream(encoded);
        try
        {
            return new DG11File(byteArrayInputStream);
        }
        finally
        {
            byteArrayInputStream.Close();
        }
    }

    private static DG11File Reconstruct(DG11File dg11)
    {
        return new DG11File(
                dg11.GetNameOfHolder(),
                dg11.GetOtherNames(),
                dg11.GetPersonalNumber(),
                dg11.GetFullDateOfBirth(),
                dg11.GetPlaceOfBirth(),
                dg11.GetPermanentAddress(),
                dg11.GetTelephone(),
                dg11.GetProfession(),
                dg11.GetTitle(),
                dg11.GetPersonalSummary(),
                dg11.GetProofOfCitizenship(),
                dg11.GetOtherValidTDNumbers(),
                dg11.GetCustodyInformation());
    }
}
