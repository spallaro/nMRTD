using System.Text;
using nMRTD.Cbeff;
using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.Lds.Iso19794;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using nMRTD.Tests.Jmrtd.Lds.Iso19794;

namespace nMRTD.Tests.Jmrtd.Lds.Icao;

/// <summary>Port of JMRTD's <c>org.jmrtd.lds.icao.DG3FileTest</c>.</summary>
[Collection(nMRTD.Tests.Helpers.CbeffDataGroupCollection.Name)]
public class DG3FileTest
{

    private const string TEST_FILE = "/lds/bsi2008/Datagroup3.bin";

    [Fact]
    public void testConstruct()
    {
        DG3File dg3 = new DG3File(new List<FingerInfo> { });
        Assert.NotNull(dg3.GetFingerInfos());
        Assert.True(dg3.GetFingerInfos().Count == 0);
    }

    [Fact]
    public void testFile()
    {
        DG3File dg3 = GetTestObjectFromResource();
        List<FingerInfo> recordInfos = dg3.GetFingerInfos();
        int recordCount = recordInfos.Count;
        int recordNumber = 1;
//      LOGGER.info("DEBUG: Number of finger records = " + recordCount);
        foreach (FingerInfo record in recordInfos)
        {
            List<FingerImageInfo> imageInfos = record.GetFingerImageInfos();
            int imageInfoCount = imageInfos.Count;
//        LOGGER.info("DEBUG: Number of images in record " + recordNumber + " is " + imageInfoCount);
            foreach (FingerImageInfo imageInfo in imageInfos)
            {
                int length = imageInfo.GetImageLength();
                byte[] bytes = new byte[length];
                Stream dataIn = (imageInfo.GetImageInputStream());
                dataIn.ReadFully(bytes);
            }
            recordNumber ++;
        }
    }

    [Fact]
    public void testDecodeEncode()
    {
        CheckDecodeEncode(Fixtures.GetInputStream(TEST_FILE));
    }

    internal static void CheckDecodeEncode(Stream input)
    {
        try
        {
            DG3File dg3 = new DG3File(input);

            byte[] encoded = dg3.GetEncoded()!;

            //			File outputDir = new File("tmp");
            //			if (!outputDir.exists()) {
            //				if (!outputDir.mkdirs()) {
            //					Assert.Fail("Could not make output dir \"" + outputDir.GetAbsolutePath() + "\"");
            //				}
            //			}
            //			if (!outputDir.IsDirectory()) {
            //				Assert.Fail("Could not make output dir \"" + outputDir.GetAbsolutePath() + "\"");
            //			}
            //			FileOutputStream origOut = new FileOutputStream(new File(outputDir, "dg3orig.bin"));
            //			origOut.Write(encoded);
            //			origOut.Flush();
            //			origOut.Close();

            Assert.NotNull(encoded);

            DG3File copy = new DG3File(new MemoryStream(encoded));

            byte[] encodedCopy = copy.GetEncoded()!;

            //			FileOutputStream copyOut = new FileOutputStream(new File(outputDir, "dg3copy.bin"));
            //			copyOut.Write(encodedCopy);
            //			copyOut.Flush();
            //			copyOut.Close();


            Assert.NotNull(encodedCopy);
            List<FingerInfo> fingerInfos = dg3.GetFingerInfos();
            int fingerInfoCount = fingerInfos.Count;

            List<FingerInfo> fingerInfos1 = copy.GetFingerInfos();
            int fingerInfoCount1 = fingerInfos1.Count;

            Assert.Equal(fingerInfoCount, fingerInfoCount1);

            int fingerInfoIndex = 0;
            foreach (FingerInfo fingerInfo in fingerInfos)
            {
                List<FingerImageInfo> fingerImageInfos = fingerInfo.GetFingerImageInfos();
                int fingerImageInfoCount = fingerImageInfos.Count;
                FingerInfo fingerInfo1 = fingerInfos1[fingerInfoIndex];
                List<FingerImageInfo> fingerImageInfos1 = fingerInfo1.GetFingerImageInfos();
                int fingerImageInfoCount1 = fingerImageInfos1.Count;
                Assert.Equal(fingerImageInfoCount, fingerImageInfoCount1);
                int fingerImageInfoIndex = 0;
                foreach (FingerImageInfo fingerImageInfo in fingerImageInfos)
                {
                    FingerImageInfo fingerImageInfo1 = fingerImageInfos1[fingerImageInfoIndex];
                    fingerImageInfoIndex ++;
                }
                fingerInfoIndex ++;
            }
        }
        catch(Exception e)
        {
            Assert.Fail(e.Message);
        }
    }

    [Fact]
    public void testElements()
    {
        CheckElements(GetTestObjectFromResource());
    }

    internal static void CheckElements(DG3File dg3File)
    {
        List<FingerInfo> records = dg3File.GetFingerInfos();
        foreach (FingerInfo fingerInfo in records)
        {
            FingerInfoTest.CheckEncodeDecode(fingerInfo);
            FingerInfoTest.CheckFieldsReasonable(fingerInfo);
            FingerInfoTest.CheckFieldsSameAfterReconstruct(fingerInfo);
            FingerInfoTest.CheckReflexiveReconstruct(fingerInfo);
            FingerInfoTest.CheckMandatorySBHFields(fingerInfo);
            FingerInfoTest.CheckOptionalSBHFields(fingerInfo);
            FingerInfoTest.CheckBiometricSubType(fingerInfo);
            FingerInfoTest.CheckElements(fingerInfo);
        }
    }

    internal static void CheckFile(Stream input)
    {
        CheckDecodeEncode(input);
    }

    [Fact]
    public void testImageBytes()
    {
        DG3File dg3 = GetTestObjectFromResource();
        FingerImageInfo i1 = dg3.GetFingerInfos()[0].GetFingerImageInfos()[0];
        int l1 = i1.GetImageLength();
        byte[] b1 = new byte[l1];
        (i1.GetImageInputStream()).ReadFully(b1);
        FingerImageInfo i2 = dg3.GetFingerInfos()[1].GetFingerImageInfos()[0];
        int l2 = i2.GetImageLength();
        byte[] b2 = new byte[l2];
        (i2.GetImageInputStream()).ReadFully(b2);
    }

    [Fact]
    public void testImageBytes0()
    {
        Stream inputStream = Fixtures.GetInputStream(TEST_FILE);
        DG3File dg3 = new DG3File(inputStream);
        List<FingerInfo> fingerInfos = dg3.GetFingerInfos();
        foreach (FingerInfo fingerInfo in fingerInfos)
        {
            List<FingerImageInfo> fingerImageInfos = fingerInfo.GetFingerImageInfos();
            foreach (FingerImageInfo fingerImageInfo in fingerImageInfos)
            {
                Stream dataInputStream = (fingerImageInfo.GetImageInputStream());
                byte[] imageBytes = new byte[64]; // FIXME: first check 64 < fingerImageInfo.GetImageLength()
                dataInputStream.ReadFully(imageBytes);
                // LOGGER.info("DEBUG:\n" + Hex.bytesToPrettyString(imageBytes));
            }
        }
    }

    [Fact]
    public void testImageBytes2()
    {
        /* Test with byte array input stream as carrier. */

        DG3File dg3 = new DG3File(Fixtures.GetInputStream(TEST_FILE));

        List<FingerInfo> recordInfos = dg3.GetFingerInfos();
        Assert.Equal(2, recordInfos.Count);
        FingerInfo record = recordInfos[1];
        List<FingerImageInfo> imageInfos = record.GetFingerImageInfos();
        Assert.Single(imageInfos);
        FingerImageInfo imageInfo = imageInfos[0];
        int imgLength = imageInfo.GetImageLength();
        Assert.Equal(15931, imgLength);

        byte[] imgBytes = new byte[imgLength];

        Stream imgDataIn = (imageInfo.GetImageInputStream());
        imgDataIn.ReadFully(imgBytes);
        Assert.Equal("FFA0FFA4003A0907000932D3263C000AE0F31A84010A41EFF1BC010B8E27653F000BE179A4DD00092EFF55D3010AF933D1B6010BF2871F37000A2677DA0CFFA5", Convert.ToHexString(imgBytes, 0, 64));

    }

    [Fact]
    public void testDecodeSecondImage()
    {
        DG3File dg3 = new DG3File(Fixtures.GetInputStream(TEST_FILE));

        int img1Length = dg3.GetFingerInfos()[0].GetFingerImageInfos()[0].GetImageLength();
        Stream img1In = (dg3.GetFingerInfos()[0].GetFingerImageInfos()[0].GetImageInputStream());
        byte[] img1Bytes = new byte[img1Length];
        img1In.ReadFully(img1Bytes);

        int img2Length = dg3.GetFingerInfos()[1].GetFingerImageInfos()[0].GetImageLength();
        Stream img2In = (dg3.GetFingerInfos()[1].GetFingerImageInfos()[0].GetImageInputStream());
        byte[] img2Bytes = new byte[img2Length];
        img2In.ReadFully(img2Bytes);

        // LOGGER.info("DEBUG: img1 (" + img1Bytes.Length + ")\n" + Convert.ToHexString(img1Bytes, 0, 256));
        // LOGGER.info("DEBUG: img2 (" + img2Bytes.Length + ")\n" + Convert.ToHexString(img2Bytes, 0, 256));

        Assert.Equal("FFA0FFA4003A0907000932D3263C000AE0F31A84010A41EFF1BC010B8E27653F", Convert.ToHexString(img2Bytes, 0, 32));
    }

    [Fact]
    public void testEncodeDecode1()
    {
        /* Fetch the contents of the binary file. */
        byte[] bytes = Fixtures.GetBytes(TEST_FILE);
        Stream dataIn = (Fixtures.GetInputStream(TEST_FILE));
        dataIn.ReadFully(bytes);
        dataIn.Close();

        /* Test with byte array input stream as carrier. */

        DG3File dg3 = new DG3File(new MemoryStream(bytes));
        int img1Length = dg3.GetFingerInfos()[0].GetFingerImageInfos()[0].GetImageLength();
        Stream img1In = (dg3.GetFingerInfos()[0].GetFingerImageInfos()[0].GetImageInputStream());
        byte[] img1Bytes = new byte[img1Length];
        img1In.ReadFully(img1Bytes);
//      LOGGER.info("DEBUG: img1\n" + Convert.ToHexString(img1Bytes, 0, 32));

        int img2Length = dg3.GetFingerInfos()[1].GetFingerImageInfos()[0].GetImageLength();
        Stream img2In = (dg3.GetFingerInfos()[1].GetFingerImageInfos()[0].GetImageInputStream());
        byte[] img2Bytes = new byte[img2Length];
        img2In.ReadFully(img2Bytes);

//      LOGGER.info("DEBUG: img2\n" + Convert.ToHexString(img2Bytes, 0, 32));

        byte[] encodedFromByteArrayStream = dg3.GetEncoded()!;

        Assert.Equal(bytes.Length, encodedFromByteArrayStream.Length);

        for (int i = 0; i < encodedFromByteArrayStream.Length; i++)
        {
            if (bytes[i] != encodedFromByteArrayStream[i])
            {
                break;
            }
        }

        //			FileOutputStream out1 = new FileOutputStream("bytes.bin");
        //			out1.Write(bytes);
        //			out1.Flush();
        //			out1.Close();
        //
        //			FileOutputStream out2 = new FileOutputStream("encodedFromByteArrayStream.bin");
        //			out2.Write(encodedFromByteArrayStream);
        //			out2.Flush();
        //			out2.Close();

        Assert.True(Enumerable.SequenceEqual(bytes, encodedFromByteArrayStream));

        /* Same but using file input stream */

        Stream inputStream = Fixtures.GetInputStream(TEST_FILE);
        DG3File dg3FromFileStream = new DG3File(inputStream);
        byte[] encodedFromFileStream = dg3FromFileStream.GetEncoded()!;
        Assert.Equal(bytes.Length, encodedFromFileStream.Length);
        for (int i = 0; i < encodedFromByteArrayStream.Length; i++)
        {
            if (bytes[i] != encodedFromFileStream[i])
            {
                break;
            }
        }
        Assert.True(Enumerable.SequenceEqual(bytes, encodedFromFileStream));

    }

    [Fact]
    public void testEncodeDecode2()
    {
        /* Fetch the contents of the binary file. */
        byte[] bytes = Fixtures.GetBytes(TEST_FILE);
        Stream dataIn = (Fixtures.GetInputStream(TEST_FILE));
        dataIn.ReadFully(bytes);
        dataIn.Close();

        /* Test with byte array input stream as carrier. */

        DG3File dg3 = new DG3File(new MemoryStream(bytes));
        byte[] encodedFromByteArrayStream = dg3.GetEncoded()!;

        DG3File dg3Other = new DG3File(new MemoryStream(encodedFromByteArrayStream));
        byte[] encodedFromByteArrayStreamOther = dg3Other.GetEncoded()!;

        Assert.Equal(dg3, dg3Other);

        Assert.Equal(encodedFromByteArrayStream.Length, encodedFromByteArrayStreamOther.Length);
        Assert.True(Enumerable.SequenceEqual(encodedFromByteArrayStream, encodedFromByteArrayStreamOther));

    }

    [Fact]
    public void testEncodeDecode()
    {
        DG3File dg3 = GetTestObjectFromResource();
        byte[] dg3Bytes = dg3.GetEncoded()!;
        Assert.NotNull(dg3Bytes);

        DG3File copy = new DG3File(new MemoryStream(dg3Bytes));
        byte[] copyBytes = copy.GetEncoded()!;
        Assert.NotNull(copyBytes);

        //			FileOutputStream output = new FileOutputStream("dg3Bytes.out");
        //			output.Write(dg3Bytes);
        //			output.Flush();
        //			output.Flush();
        //			output.Close();
        //
        //			output = new FileOutputStream("copyBytes.out");
        //			output.Write(copyBytes);
        //			output.Flush();
        //			output.Flush();
        //			output.Close();

        Assert.Equal(dg3Bytes.Length, copyBytes.Length);

        for (int i = 0; i < dg3Bytes.Length; i++)
        {
            if (dg3Bytes[i] != copyBytes[i])
            {
                break;
            }
        }

        Assert.True(Enumerable.SequenceEqual(dg3Bytes, copyBytes));
    }

    [Fact]
    public void testZeroInstanceTestObjectNotEquals()
    {
        DG3File dg3 = new DG3File(new List<FingerInfo>());
        byte[] dg3Bytes = dg3.GetEncoded()!;
        Assert.NotNull(dg3Bytes);

        DG3File anotherDG3 = new DG3File(new List<FingerInfo>());
        byte[] anotherDG3Bytes = anotherDG3.GetEncoded()!;
        Assert.NotNull(anotherDG3Bytes);

        Assert.False(Enumerable.SequenceEqual(dg3Bytes, anotherDG3Bytes));

        DG3File copy = new DG3File(new MemoryStream(dg3Bytes));
        byte[] copyBytes = copy.GetEncoded()!;
        Assert.NotNull(copyBytes);

        Assert.False(Enumerable.SequenceEqual(dg3Bytes, copyBytes));
    }

    [Fact]
    public void testCreate()
    {
        DG3File dg3 = CreateTestObject();
        byte[] header = new byte[256];
        Array.Copy(dg3.GetEncoded()!, 0, header, 0, header.Length);
//    LOGGER.info(Hex.bytesToPrettyString(header));
    }

    [Fact]
    public void testFromBin()
    {
        Stream inputStream = Fixtures.GetInputStream(TEST_FILE);
        DG3File dg3 = new DG3File(inputStream);
    }

    public static DG3File CreateTestObject()
    {
        try
        {
            FingerInfo fingerInfo1 = FingerInfoTest.CreateSingleRightIndexFingerTestObject();
            //			FingerInfo fingerInfo2 = FingerInfoTest.CreateTestObject();
            List<FingerInfo> fingerInfos = new List<FingerInfo> { fingerInfo1, /* fingerInfo2 */ };
            DG3File dg3 = new DG3File(fingerInfos);
            return dg3;
        }
        catch (Exception e)
        {
            Assert.Fail(e.Message);

            return null;
        }
    }

    public static DG3File GetTestObjectFromResource()
    {
        try
        {
            Stream input = Fixtures.GetInputStream(TEST_FILE);
            DG3File dg3 = new DG3File(input);
            return dg3;
        }
        catch (Exception)
        {
            return null!;
        }
    }
}
