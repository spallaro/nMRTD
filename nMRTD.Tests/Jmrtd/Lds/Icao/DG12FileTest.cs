using System.Text;
using nMRTD.Cbeff;
using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.Lds.Iso19794;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using nMRTD.Tests.Jmrtd.Lds.Iso19794;

namespace nMRTD.Tests.Jmrtd.Lds.Icao;

/// <summary>Port of JMRTD's <c>org.jmrtd.lds.icao.DG12FileTest</c>.</summary>
public class DG12FileTest
{

    [Fact]
    public void testToString()
    {
        DG12File dg12File = CreateTestObject();
        string expectedPrefix = "DG12File [, 19711019, [], , , , , 19711019";
        Assert.StartsWith(expectedPrefix, dg12File.ToString());
    }

    [Fact]
    public void testReflexive()
    {
        CheckReflexive(CreateTestObject());
    }

    internal static void CheckReflexive(DG12File dg12File)
    {
        if (dg12File == null)
        {
            Assert.Fail("Input file is null");
        }

        byte[] encoded = dg12File.GetEncoded()!;
        Assert.NotNull(encoded);

        MemoryStream input = new MemoryStream(encoded);
        DG12File copy = new DG12File(input);

        Assert.NotNull(copy);
        Assert.Equal(dg12File, copy);

        byte[] encodedCopy = copy.GetEncoded()!;
        Assert.NotNull(encodedCopy);

        Assert.Equal(Hex.BytesToHexString(encoded), Hex.BytesToHexString(copy.GetEncoded()!));

    }

    [Fact]
    public void testEarlySpecSample()
    {
        byte[] bytes = {

                0x6C, /* L */ 0x40,
                0x5C, /* L = 6, i.e. 3 tags */ 0x06,
                0x5F, 0x19, 0x5F, 0x26, 0x5F, 0x1A,
                0x5F, 0x19, /* L */ 0x18,
                (byte)'U', (byte)'N', (byte)'I', (byte)'T', (byte)'E', (byte)'D', (byte)' ', (byte)'S', (byte)'T', (byte)'A', (byte)'T', (byte)'E', (byte)'S', (byte)' ', (byte)'O', (byte)'F', (byte)' ', (byte)'A', (byte)'M', (byte)'E', (byte)'R', (byte)'I', (byte)'C', (byte)'A',
                0x5F, 0x26, /* L */ 0x08,
                (byte)'2', (byte)'0', (byte)'0', (byte)'2', (byte)'0', (byte)'5', (byte)'3', (byte)'1', /* NOTE: see R7-p1_v2_sIII_0058 */
                0x5F, 0x1A, /* L */ 0x0F,
                (byte)'S', (byte)'M', (byte)'I', (byte)'T', (byte)'H', (byte)'<', (byte)'<', (byte)'B', (byte)'R', (byte)'E', (byte)'N', (byte)'D', (byte)'A', (byte)'<', (byte)'P'
        };

        MemoryStream input = new MemoryStream(bytes);
        DG12File file = new DG12File(input);
        Assert.Equal("UNITED STATES OF AMERICA", file.GetIssuingAuthority());
        Assert.StartsWith("20020531", file.GetDateOfIssue());
        Assert.Equal(file.GetNamesOfOtherPersons(), new List<string> { "SMITH<<BRENDA<P" });
    }

    [Fact]
    public void testNewSpecSample()
    {
        byte[] bytes = {

                0x6C, /* L */ 0x45,
                0x5C, /* L = 6, i.e. 3 tags */ 0x06,
                0x5F, 0x19, 0x5F, 0x26, 0x5F, 0x1A,
                0x5F, 0x19, /* L */ 0x18,
                (byte)'U', (byte)'N', (byte)'I', (byte)'T', (byte)'E', (byte)'D', (byte)' ', (byte)'S', (byte)'T', (byte)'A', (byte)'T', (byte)'E', (byte)'S', (byte)' ', (byte)'O', (byte)'F', (byte)' ', (byte)'A', (byte)'M', (byte)'E', (byte)'R', (byte)'I', (byte)'C', (byte)'A',
                0x5F, 0x26, /* L */ 0x08,
                (byte)'2', (byte)'0', (byte)'0', (byte)'2', (byte)'0', (byte)'5', (byte)'3', (byte)'1', /* NOTE: see R7-p1_v2_sIII_0058 */
                (byte)0xA0, /* L */ 0x15,
                0x02, 0x01, 0x01,
                0x5F, 0x1A, /* L */ 0x0F,
                (byte)'S', (byte)'M', (byte)'I', (byte)'T', (byte)'H', (byte)'<', (byte)'<', (byte)'B', (byte)'R', (byte)'E', (byte)'N', (byte)'D', (byte)'A', (byte)'<', (byte)'P'
        };

        MemoryStream input = new MemoryStream(bytes);
        DG12File file = new DG12File(input);
        Assert.Equal("UNITED STATES OF AMERICA", file.GetIssuingAuthority());
        Assert.StartsWith("20020531", file.GetDateOfIssue());
        Assert.Equal(file.GetNamesOfOtherPersons(), new List<string> { "SMITH<<BRENDA<P" });
    }

    [Fact]
    public void testComplex()
    {
        DG12File dg12 = CreateComplexTestObject();
        Assert.Equal("UTOPIA", dg12.GetIssuingAuthority());
        Assert.Equal("19711019", dg12.GetDateOfIssue());
        Assert.NotNull(dg12.GetNamesOfOtherPersons());
        Assert.True(dg12.GetNamesOfOtherPersons()!.Count > 0); // Java: a plain assert

        byte[] encoded = dg12.GetEncoded()!;
        DG12File copy = new DG12File(new MemoryStream(encoded));
        Assert.Equal("UTOPIA", copy.GetIssuingAuthority());
        Assert.Equal("19711019", copy.GetDateOfIssue());
        Assert.NotNull(copy.GetNamesOfOtherPersons());
        Assert.True(dg12.GetNamesOfOtherPersons()!.Count > 0); // Java: a plain assert

        Assert.Equal(dg12, copy);
        Assert.True(Enumerable.SequenceEqual(dg12.GetEncoded()!, copy.GetEncoded()!)); // Java: a plain assert
    }

    /*
      * The date and time of personalization uses the 24 hour clock (it used 'hh', so 15:30 became 03:30 and 00:05 became 12:05).
      */
    [Fact]
    public void testDateAndTimeOfPersonalizationUses24HourClock()
    {
        DateTime cal = new DateTime(1971, 10, 19, 15, 30, 45);
        DG12File afternoon = new DG12File("UTOPIA", cal, null, "", "", null, null, cal, "");
        Assert.Equal("19711019153045", afternoon.GetDateAndTimeOfPersonalization());
        Assert.Equal("19711019153045", new DG12File(new MemoryStream(afternoon.GetEncoded()!)).GetDateAndTimeOfPersonalization());

        cal = new DateTime(1971, 10, 19, 0, 5, 0);
        DG12File afterMidnight = new DG12File("UTOPIA", cal, null, "", "", null, null, cal, "");
        Assert.Equal("19711019000500", afterMidnight.GetDateAndTimeOfPersonalization());
        Assert.Equal("19711019000500", new DG12File(new MemoryStream(afterMidnight.GetEncoded()!)).GetDateAndTimeOfPersonalization());
    }

    public static DG12File CreateComplexTestObject()
    {
        string issuingAuthority = "UTOPIA";
        DateTime cal = new DateTime(1971, 10, 19); // 1971/10/19
        DateTime dateOfIssue = cal;
        List<string> namesOfOtherPersons = new List<string> { "OTHER PERSON 1", "OTHER PERSON 2" };
        string endorseMentsAndObservations = "";
        string taxOrExitRequirements = "";
        byte[]? imageOfFront = null;
        byte[]? imageOfRear = null;
        DateTime dateAndTimeOfPersonalization = cal;
        string personalizationSystemSerialNumber = "";

        return new DG12File(issuingAuthority, dateOfIssue, namesOfOtherPersons,
                endorseMentsAndObservations, taxOrExitRequirements, imageOfFront,
                imageOfRear, dateAndTimeOfPersonalization,
                personalizationSystemSerialNumber);
    }

    public static DG12File CreateTestObject()
    {
        string issuingAuthority = "";
        DateTime cal = new DateTime(1971, 10, 19);
        DateTime dateOfIssue = cal;
        List<string>? namesOfOtherPersons = null;
        string endorseMentsAndObservations = "";
        string taxOrExitRequirements = "";
        byte[]? imageOfFront = null;
        byte[]? imageOfRear = null;
        DateTime dateAndTimeOfPersonalization = cal;
        string personalizationSystemSerialNumber = "";

        return new DG12File(issuingAuthority, dateOfIssue, namesOfOtherPersons,
                endorseMentsAndObservations, taxOrExitRequirements, imageOfFront,
                imageOfRear, dateAndTimeOfPersonalization,
                personalizationSystemSerialNumber);
    }

    internal static void CheckFile(Stream input)
    {
        try
        {
            CheckReflexive(new DG12File(input));
        }
        catch (IOException ioe)
        {
            Assert.Fail(ioe.ToString());
        }
    }
}
