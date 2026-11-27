using System.Text;
using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.SmartCards;

namespace nMRTD.Tests.Jmrtd.Lds.Icao;

/// <summary>Port of JMRTD's <c>org.jmrtd.lds.icao.COMFileTest</c>.</summary>
public class COMFileTest
{

    [Fact]
    public void testToString()
    {
        COMFile dg1File = CreateTestObject();
        string expectedResult = "COMFile LDS 01.07, Unicode 04.00.00, [DG1, DG2, DG15]";
        Assert.Equal(dg1File.ToString(), expectedResult);
    }

    [Fact]
    public void testReflexive()
    {
        CheckReflexive(CreateTestObject());
    }

    private static void CheckReflexive(COMFile comFile)
    {
        byte[] encoded = comFile.GetEncoded()!;
        Assert.NotNull(encoded);
        MemoryStream input = new MemoryStream(encoded);
        COMFile copy = new COMFile(input);
        Assert.Equal(comFile, copy);
        byte[] encodedCopy = copy.GetEncoded()!;
        Assert.NotNull(encodedCopy);
        Assert.Equal(encoded.Length, encodedCopy.Length);
        Assert.True(Enumerable.SequenceEqual(encoded, encodedCopy));
    }

    [Fact]
    public void testSpecSample()
    {
        byte[] bytes = [ 0x60, /* L */ 0x16,
                0x5F, 0x01, /* L */ 0x04,
                (byte)'0', (byte)'1', (byte)'0', (byte)'7',
                0x5F, 0x36, /* L */ 0x06,
                (byte)'0', (byte)'4', (byte)'0', (byte)'0', (byte)'0', (byte)'0',
                0x5C, /* L */ 0x04,
                0x61, 0x75, 0x76, 0x6C ];

        MemoryStream input = new MemoryStream(bytes);
        COMFile comFile = new COMFile(input);
        Assert.Equal("1.7", comFile.GetLDSVersion());
        Assert.Equal("4.0.0", comFile.GetUnicodeVersion());

        int[] tagList = comFile.GetTagList();
        Assert.NotNull(tagList);
        Assert.Equal(4, tagList.Length);
        Assert.Equal(LDSFileTags.EF_DG1_TAG, tagList[0]);
        Assert.Equal(LDSFileTags.EF_DG2_TAG, tagList[1]);
        Assert.Equal(LDSFileTags.EF_DG4_TAG, tagList[2]);
        Assert.Equal(LDSFileTags.EF_DG12_TAG, tagList[3]);
    }

    [Fact]
    public void testAlternativeConstructor()
    {
        int[] tagList1 = new int[2];
        tagList1[0] = LDSFileTags.EF_DG1_TAG;
        tagList1[1] = LDSFileTags.EF_DG2_TAG;
        int[] tagList2 = new int[tagList1.Length];
        Array.Copy(tagList1, 0, tagList2, 0, tagList1.Length);
        Assert.NotNull(tagList1);
        Assert.NotNull(tagList2);
        Assert.True(Enumerable.SequenceEqual(tagList1, tagList2));
        COMFile comFile1 = new COMFile("01", "07", "04", "00", "00", tagList1);
        COMFile comFile2 = new COMFile("1.7", "4.0.0", tagList2);
        Assert.Equal(comFile1, comFile2);
        Assert.Equal("1.7", comFile2.GetLDSVersion());
        Assert.Equal("4.0.0", comFile2.GetUnicodeVersion());

        Assert.Equal(new COMFile("01.7", "4.00.0", tagList1), new COMFile("1.07", "04.0.00", tagList2));
    }

    internal static COMFile CreateTestObject()
    {
        int[] tagList = new int[3];
        tagList[0] = LDSFileTags.EF_DG1_TAG;
        tagList[1] = LDSFileTags.EF_DG2_TAG;
        tagList[2] = LDSFileTags.EF_DG15_TAG;
        return new COMFile("01", "07", "04", "00", "00", tagList);
    }

    private static void CheckFile(Stream input)
    {
        CheckReflexive(new COMFile(input));
    }
}
