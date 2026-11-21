using System.Text;
using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.SmartCards;

namespace nMRTD.Tests.Jmrtd.Lds.Icao;

/// <summary>Port of JMRTD's <c>org.jmrtd.lds.icao.DG1FileTest</c>.</summary>
public class DG1FileTest
{

    [Fact]
    public void testToString()
    {
        DG1File dg1File = CreateTestObject();
        string expectedResult = "DG1File P<NLDMEULENDIJK<<LOES<ALBERTINE<<<<<<<<<<<<<XX00000000NLD7110195F1108280123456782<<<<<02";
        Assert.Equal(dg1File.ToString(), expectedResult);
    }

    [Fact]
    public void testReflexive()
    {
        CheckReflexive(CreateTestObject());
    }

    private static void CheckReflexive(DG1File dg1File)
    {
        byte[] encoded = dg1File.GetEncoded()!;
        MemoryStream input = new MemoryStream(encoded);
        DG1File copy = new DG1File(input);
        Assert.Equal(dg1File, copy);
        Assert.Equal(Hex.BytesToHexString(encoded), Hex.BytesToHexString(copy.GetEncoded()!));
    }

    private const string SMITH_SAMPLE = "P<ATASMITH<<JOHN<T<<<<<<<<<<<<<<<<<<<<<<<<<<123456789<HMD7406222M10123130121<<<<<<<<<<54";
    private const string LOES_SAMPLE = "P<NLDMEULENDIJK<<LOES<ALBERTINE<<<<<<<<<<<<<XA00277324NLD7110195F0610010123456782<<<<<08";

    [Fact]
    public void testSpecSample()
    {
        DG1File file = GetSpecSampleObject(SMITH_SAMPLE)!;
        Assert.Equal(SMITH_SAMPLE, file.GetMRZInfo().ToString().Replace("\n", "").Trim());

        file = GetSpecSampleObject(LOES_SAMPLE)!;
        Assert.Equal(LOES_SAMPLE, file.GetMRZInfo().ToString().Replace("\n", "").Trim());
    }

    /* Doc 9303 - Part 5. */
    [Fact]
    public void testTD1()
    {
        DG1File dg1File = new DG1File(MRZInfo.CreateTD1MRZInfo(
                "I", "UTO", "123456789", "",
                "850101", Gender.Female, "321123", "UTO", "",
                "ERIKSSON", "ANNA MARIA"));
        byte[] dg1Encoded = dg1File.GetEncoded()!;
        DG1File reencodedDG1File = new DG1File(new MemoryStream(dg1Encoded));
        Assert.True(Enumerable.SequenceEqual(dg1Encoded, reencodedDG1File.GetEncoded()!));
        Assert.Equal(MRZInfo.DOC_TYPE_ID1, reencodedDG1File.GetMRZInfo().GetDocumentType());
    }

    /* Doc 9303 - part 6. */
    [Fact]
    public void testTD2()
    {
        DG1File dg1File = new DG1File(MRZInfo.CreateTD2MRZInfo(
                "A", "UTO", "ERIKSSON", "ANNA MARIA",
                "123456789", "UTO", "740812", Gender.Female, "321123", ""));
        byte[] dg1Encoded = dg1File.GetEncoded()!;
        DG1File reencodedDG1File = new DG1File(new MemoryStream(dg1Encoded));
        Assert.True(Enumerable.SequenceEqual(dg1Encoded, reencodedDG1File.GetEncoded()!));
        Assert.Equal(MRZInfo.DOC_TYPE_ID2, reencodedDG1File.GetMRZInfo().GetDocumentType());
    }

    /* Doc 9303 - Part 4. */
    [Fact]
    public void testTD3()
    {
        DG1File dg1File = new DG1File(MRZInfo.CreateTD3MRZInfo(
                "P", "UTO", "VILARCHO FERNANDEZ", "JOSE RAMON",
                "123456789", "UTO", "850101", Gender.Male, "321123", ""));
        byte[] dg1Encoded = dg1File.GetEncoded()!;
        DG1File reencodedDG1File = new DG1File(new MemoryStream(dg1Encoded));
        Assert.True(Enumerable.SequenceEqual(dg1Encoded, reencodedDG1File.GetEncoded()!));
        Assert.Equal(MRZInfo.DOC_TYPE_ID3, reencodedDG1File.GetMRZInfo().GetDocumentType());
    }

    [Fact]
    public void testLength()
    {
        List<DG1File?> dg1s = GetTestObjects();
        foreach (DG1File? dg1 in dg1s)
        {
            CheckLength(dg1!);
        }
    }

    private static void CheckLength(DG1File dg1)
    {
        byte[] encoded = dg1.GetEncoded()!;
        Assert.NotNull(encoded);

        int length = dg1.GetLength();
        if (length <= 0)
        {
        }
        Assert.True(length > 0);

        Assert.True(length <= encoded.Length);
    }

    private static List<DG1File?> GetTestObjects()
    {
        List<DG1File?> testObjects = new List<DG1File?>();
        try
        {
            testObjects.Add(CreateTestObject());
        }
        catch (Exception)
        {
        }
        try
        {
            testObjects.Add(GetSpecSampleObject(SMITH_SAMPLE));
        }
        catch (Exception)
        {
        }
        try
        {
            testObjects.Add(GetSpecSampleObject(LOES_SAMPLE));
        }
        catch (Exception)
        {
        }
        return testObjects;
    }

    private static DG1File? GetSpecSampleObject(string str)
    {
        byte[] header = [0x61, 0x5B, 0x5F, 0x1F, 0x58];
        try
        {
            MemoryStream output = new MemoryStream();
            output.Write(header);
            output.Write(Encoding.UTF8.GetBytes(str));
            output.Flush();
            byte[] bytes = output.ToArray();
            MemoryStream input = new MemoryStream(bytes);
            return new DG1File(input);
        }
        catch (Exception)
        {
        }

        return null;
    }

    internal static DG1File CreateTestObject()
    {
        MRZInfo mrzInfo = MRZInfoTest.CreateTestObject();
        return new DG1File(mrzInfo);
    }

    private static void CheckFile(Stream input)
    {
        CheckReflexive(new DG1File(input));
    }
}
