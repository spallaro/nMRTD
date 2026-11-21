using System.Text;
using nMRTD.Cbeff;
using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.Lds.Iso19794;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using nMRTD.Tests.Jmrtd.Lds.Icao;
using nMRTD.Lds.Iso39794;
using static nMRTD.Lds.Iso39794.FaceImageCaptureDevice2DBlock;
using static nMRTD.Lds.Iso39794.FaceImageIdentityMetadataBlock;
using static nMRTD.Lds.Iso39794.FaceImageLandmarkKind;
using static nMRTD.Lds.Iso39794.FaceImagePoseAngleBlock;
using static nMRTD.Lds.Iso39794.PADDataBlock;
using static nMRTD.Lds.Iso39794.FaceImageInformation2DBlock;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;

namespace nMRTD.Tests.Jmrtd.Lds.Icao;

/// <summary>Port of JMRTD's <c>org.jmrtd.lds.icao.ISO39794DG2FileTest</c>.</summary>





[Collection(nMRTD.Tests.Helpers.CbeffDataGroupCollection.Name)]
public class ISO39794DG2FileTest
{




    [Fact]
    public void testReconstructSilverMandatoryDataset()
    {
        VersionBlock versionBlock = new VersionBlock(3, 2019);

        BigInteger representationId = BigInteger.Zero;

        byte[] representationData2DBytes = ReadResource("/dg2/silver.jp2");

        ImageSizeBlock? imageSizeBlock = null;

        ImageDataFormatCode imageDataFormat = ImageDataFormatCode.Jpeg2000Lossy;
        FaceImageInformation2DBlock imageInformation2DBlock = new FaceImageInformation2DBlock(imageDataFormat,
                null, null, null, null, null, null, imageSizeBlock, null, null, null);
        FaceImageCaptureDevice2DBlock? captureDevice2DBlock = null;
        FaceImageRepresentation2DBlock imageRepresentation2DBlock = new FaceImageRepresentation2DBlock(representationData2DBytes, imageInformation2DBlock, captureDevice2DBlock);

        DateTimeBlock? captureDateTimeBlock = null;
        List<QualityBlock>? qualityBlocks = null;
        List<PADDataBlock>? padDataBlocks = null;
        BigInteger? faceImageRepresenationBlockSessionId = null;
        BigInteger? derivedFrom = null;
        FaceImageCaptureDeviceBlock? captureDeviceBlock = null;
        FaceImageIdentityMetadataBlock? identityMetadataBlock = null;
        List<FaceImageLandmarkBlock>? landmarkBlocks = null;

        FaceImageRepresentationBlock faceImageRepresentationBlock = new FaceImageRepresentationBlock(representationId,
                imageRepresentation2DBlock, captureDateTimeBlock,
                qualityBlocks, padDataBlocks, faceImageRepresenationBlockSessionId, derivedFrom,
                captureDeviceBlock, identityMetadataBlock, landmarkBlocks);

        List<FaceImageRepresentationBlock> representationBlocks = [faceImageRepresentationBlock];

        Dictionary<int, byte[]> sbhMap = new Dictionary<int, byte[]>();
        sbhMap.Add(0x87, new byte[] { 0x01, 0x01 });
        sbhMap.Add(0x88, new byte[] { 0x00, 0x2A });
        StandardBiometricHeader sbh = new StandardBiometricHeader(sbhMap);
        FaceImageDataBlock faceImageDataBlock = new FaceImageDataBlock(versionBlock, representationBlocks, sbh);

        DG2File dg2File = DG2File.CreateISO39794DG2File([faceImageDataBlock],
                ISO39794EncodingProfile.Icao39794_5EmrtdV1);
        Assert.NotNull(dg2File);
        Assert.Equal(ReadResource("/lds/dg2/dg2_silver_mandatory_fields.bin"), dg2File.GetEncoded()!);

        DG2File reEncodedDG2File = LDSFileUtil.GetDG2File(new MemoryStream(dg2File.GetEncoded()!));
        Assert.NotNull(reEncodedDG2File);

        FaceImageDataBlock a = (FaceImageDataBlock)dg2File.GetSubRecords()[0];
        FaceImageDataBlock b = (FaceImageDataBlock)reEncodedDG2File.GetSubRecords()[0];

        // FileOutputStream fOut = new FileOutputStream("silver_mandatory.bin");
        // fOut.Write(dg2File.GetEncoded()!);
        // fOut.Flush();
        // fOut.Close();
        // Thread.Sleep(500);
    }

    [Fact]
    public void testReconstructSilverAllDataset()
    {
        VersionBlock versionBlock = new VersionBlock(3, 2019);

        BigInteger representationId = BigInteger.Zero;

        byte[] representationData2DBytes = ReadResource("/dg2/silver.jp2");

        ImageSizeBlock imageSizeBlock = new ImageSizeBlock(572, 731);

        ImageDataFormatCode imageDataFormat = ImageDataFormatCode.Jpeg2000Lossy;

        FaceImageKind2DCode faceImageKind2DCode = FaceImageKind2DCode.Mrtd;

        FaceImagePostAcquisitionProcessingBlock postAcquisitionProcessingBlock = new FaceImagePostAcquisitionProcessingBlock(
                false, false, false, false, false, false, false, false, false, false, false, false);
        LossyTransformationAttemptsCode lossyTransformationAttemptsCode = LossyTransformationAttemptsCode.Zero;
        int cameraToSubjectDistance = 3000;
        int sensorDiagonal = 43;
        int lensFocalLength = 55;
        ImageFaceMeasurementsBlock imageFaceMeasurementsBlock = new ImageFaceMeasurementsBlock(
                BigInteger.ValueOf(300), BigInteger.ValueOf(150), BigInteger.ValueOf(180), BigInteger.ValueOf(500));
        ImageColourSpaceCode imageColourSpaceCode = ImageColourSpaceCode.Rgb24Bit;

        FaceImageReferenceColourMappingBlock referenceColourMappingBlock = new FaceImageReferenceColourMappingBlock(
                Encoding.UTF8.GetBytes("Reference Colour Schema Example"),
                [new FaceImageReferenceColourMappingBlock.ReferenceColourDefinitionAndValueBlock(
                        Encoding.UTF8.GetBytes("Reference Colour Definition Example"),
                        Encoding.UTF8.GetBytes("Reference Colour Value Example"))]);
        FaceImageInformation2DBlock imageInformation2DBlock = new FaceImageInformation2DBlock(imageDataFormat, faceImageKind2DCode,
                postAcquisitionProcessingBlock, lossyTransformationAttemptsCode, cameraToSubjectDistance, sensorDiagonal, lensFocalLength,
                imageSizeBlock, imageFaceMeasurementsBlock, imageColourSpaceCode, referenceColourMappingBlock);

        FaceImageCaptureDevice2DBlock captureDevice2DBlock = new FaceImageCaptureDevice2DBlock(
                new FaceImageCaptureDeviceSpectral2DBlock(false, false, false),
                CaptureDeviceTechnologyId2DCode.StaticPhotographFromDigitalStillImageCamera);
        FaceImageRepresentation2DBlock imageRepresentation2DBlock = new FaceImageRepresentation2DBlock(representationData2DBytes, imageInformation2DBlock, captureDevice2DBlock);

        DateTimeBlock captureDateTimeBlock = new DateTimeBlock(2024, 1, 20, 13, 23, 9, 908);
        QualityBlock qualityBlock = new QualityBlock(new RegistryIdBlock(1, 1), 99);
        PADDataBlock padDataBlock = new PADDataBlock(
                PADDecisionCode.NoAttack,
                [new PADScoreBlock(new RegistryIdBlock(1, 1), 99)],
                [new ExtendedDataBlock(new RegistryIdBlock(1, 1), Encoding.UTF8.GetBytes("ExtendedDataBlock data"))],
                PADCaptureContextCode.Enrolment,
                PADSupervisionLevelCode.Unknown,
                5,
                PADCriteriaCategoryCode.Common,
                Encoding.UTF8.GetBytes("PAD Parameter"),
                [Encoding.UTF8.GetBytes("Challenge1")],
                new DateTimeBlock(2024, 1, 22, 15, 16, 17, 18));
        BigInteger faceImageRepresenationBlockSessionId = BigInteger.ValueOf(9);
        BigInteger derivedFrom = BigInteger.ValueOf(0);
        FaceImageCaptureDeviceBlock captureDeviceBlock = new FaceImageCaptureDeviceBlock(new RegistryIdBlock(1,  1), [new RegistryIdBlock(2, 2)]);
        FaceImageIdentityMetadataBlock identityMetadataBlock = new FaceImageIdentityMetadataBlock(GenderCode.Female, EyeColourCode.Blue, HairColourCode.Brown, 1786,
                new FaceImagePropertiesBlock(false, false, false, false, false, false, false, false, false, false, false),
                new FaceImageExpressionBlock(true, false, false, false, false, false),
                new FaceImagePoseAngleBlock(new AngleDataBlock(2, 1), new AngleDataBlock(3, 1), new AngleDataBlock(1, 2)));
        FaceImageLandmarkBlock landmarkBlock = new FaceImageLandmarkBlock(
                new FaceImageLandmarkKind(FaceImageLandmarkKind.MPEGFeaturePointCode.Mpeg4PointCode_02_11), // Java: the enum constant itself
                new CoordinateCartesian2DUnsignedShortBlock(90, 22));

        FaceImageRepresentationBlock faceImageRepresentationBlock = new FaceImageRepresentationBlock(representationId,
                imageRepresentation2DBlock, captureDateTimeBlock,
                [qualityBlock], [padDataBlock], faceImageRepresenationBlockSessionId, derivedFrom,
                captureDeviceBlock, identityMetadataBlock, [landmarkBlock]);

        List<FaceImageRepresentationBlock> representationBlocks = [faceImageRepresentationBlock];

        Dictionary<int, byte[]> sbhMap = new Dictionary<int, byte[]>();
        sbhMap.Add(0x80, new byte[] { 0x01, 0x01 });
        sbhMap.Add(0x81, new byte[] { 0x02 });
        sbhMap.Add(0x82, new byte[] { 0x00 });
        sbhMap.Add(0x83, new byte[] { 0x21, 0x24, 0x01, 0x05, 0x11, 0x23, 0x45 });
        sbhMap.Add(0x85, new byte[] { 0x21, 0x24, 0x01, 0x05, 0x21, 0x29, 0x01, 0x05 });
        sbhMap.Add(0x86, new byte[] { 0x01, 0x03, 0x00, 0x01 });
        sbhMap.Add(0x87, new byte[] { 0x01, 0x01 });
        sbhMap.Add(0x88, new byte[] { 0x00, 0x2A });
        StandardBiometricHeader sbh = new StandardBiometricHeader(sbhMap);
        FaceImageDataBlock faceImageDataBlock = new FaceImageDataBlock(versionBlock, representationBlocks, sbh);

        DG2File dg2File = DG2File.CreateISO39794DG2File([faceImageDataBlock],
                ISO39794EncodingProfile.Icao39794_5EmrtdV1);
        Assert.NotNull(dg2File);
        Assert.Equal(ReadResource("/lds/dg2/dg2_silver_all_fields.bin"), dg2File.GetEncoded()!);
//    FileOutputStream fOut = new FileOutputStream("silver_all.bin");
//    fOut.Write(dg2File.GetEncoded()!);
//    fOut.Flush();
//    fOut.Close();
//    Thread.Sleep(500);

        DG2File reEncodedDG2File = LDSFileUtil.GetDG2File(new MemoryStream(dg2File.GetEncoded()!));
        Assert.NotNull(reEncodedDG2File);

        Assert.Equal(dg2File, reEncodedDG2File);
    }

    [Fact]
    public void testCreateDG2()
    {
        FaceImageRepresentationBlock faceImageRepresentationBlock = new FaceImageRepresentationBlock(null!, null, null, null, null, null, null, null, null, null);
        FaceImageDataBlock faceImageDataBlock = new FaceImageDataBlock(new VersionBlock(3, 2019), [faceImageRepresentationBlock], null);
        StandardBiometricHeader sbh = faceImageDataBlock.GetStandardBiometricHeader();
        Assert.NotNull(sbh);

        //    DG2File dg2File = DG2File.CreateISO39794DG2File([faceImageDataBlock]);
    }

    [Fact]
    public void testISOSampleFaceImageDataBlock()
    {
        CheckFaceImageDataBlock("/lds/dg2/iso39794/sample-39794-5-ed-1-v1.der");
    }

    private static FaceImageDataBlock CreateSampleFaceImageDataBlock(ImageDataFormatCode formatCode, byte[] representationData2DBytes)
    {
        VersionBlock versionBlock = new VersionBlock(1, 2019);
        FaceImageRepresentationBlock faceImageRepresentationBlock = CreateSampleFaceImageRepresentationBlock(formatCode, representationData2DBytes);
        FaceImageDataBlock fidb = new FaceImageDataBlock(versionBlock, [faceImageRepresentationBlock], null);
        return fidb;
    }

    private static FaceImageRepresentationBlock CreateSampleFaceImageRepresentationBlock(ImageDataFormatCode formatCode, byte[] representationData2DBytes)
    {
        BigInteger representationId = BigInteger.One;
        FaceImageRepresentation2DBlock imageRepresentation2DBlock = CreateSampleFaceImageRepresentation2DBlock(formatCode, representationData2DBytes);
        DateTimeBlock? captureDateTimeBlock = null;
        List<QualityBlock>? qualityBlocks = null;
        List<PADDataBlock>? padDataBlocks = null;
        BigInteger? sessionId = null;
        BigInteger? derivedFrom = null;
        FaceImageCaptureDeviceBlock? captureDeviceBlock = null;
        FaceImageIdentityMetadataBlock? identityMetadataBlock = null;
        List<FaceImageLandmarkBlock>? landmarkBlocks = null;
        return new FaceImageRepresentationBlock(representationId,
                imageRepresentation2DBlock,
                captureDateTimeBlock, qualityBlocks, padDataBlocks, sessionId, derivedFrom, captureDeviceBlock,
                identityMetadataBlock, landmarkBlocks);
    }

    private static FaceImageRepresentation2DBlock CreateSampleFaceImageRepresentation2DBlock(ImageDataFormatCode formatCode, byte[] representationData2DBytes)
    {
        FaceImageInformation2DBlock imageInformation2DBlock =  CreateSampleFaceImageInformation2DBlock(formatCode);
        FaceImageCaptureDevice2DBlock? captureDevice2DBlock = null;
        return new FaceImageRepresentation2DBlock(representationData2DBytes, imageInformation2DBlock, captureDevice2DBlock);
    }

    private static FaceImageInformation2DBlock CreateSampleFaceImageInformation2DBlock(ImageDataFormatCode imageDataFormatCode)
    {
        ImageSizeBlock? imageSizeBlock = null;
        FaceImageKind2DCode? faceImageKind2DCode = null;
        FaceImagePostAcquisitionProcessingBlock? postAcquisitionProcessingBlock = null;
        LossyTransformationAttemptsCode? lossyTransformationAttemptsCode = null;
        int? cameraToSubjectDistance = null;
        int? sensorDiagonal = null;
        int? lensFocalLength = null;
        ImageFaceMeasurementsBlock? imageFaceMeasurementsBlock = null;
        ImageColourSpaceCode? imageColourSpaceCode = null;
        FaceImageReferenceColourMappingBlock? referenceColourMappingBlock = null;
        return new FaceImageInformation2DBlock(imageDataFormatCode, faceImageKind2DCode,
                postAcquisitionProcessingBlock, lossyTransformationAttemptsCode,
                cameraToSubjectDistance, sensorDiagonal, lensFocalLength, imageSizeBlock, imageFaceMeasurementsBlock,
                imageColourSpaceCode, referenceColourMappingBlock);
    }

    [Fact]
    public void testDG2File()
    {
        CheckDG2File("/lds/dg2/dg2_silver_all_fields.bin", 1);
        //    CheckDG2File("/lds/dg2/dg2_silver_mandatory_fields.bin", 1);
    }

    [Fact]
    public void testSilverMandatoryRoundTrip()
    {
        byte[] originalBytes = ReadResource("/lds/dg2/dg2_silver_mandatory_fields.bin");
        DG2File dg2File = new DG2File(new MemoryStream(originalBytes));
        Assert.NotNull(dg2File);
        List<FaceImageDataBlock> subRecords = dg2File.GetSubRecords().Cast<FaceImageDataBlock>().ToList();
        DG2File roundTripDG2File = DG2File.CreateISO39794DG2File(subRecords, ISO39794EncodingProfile.Icao39794_5EmrtdV1);

        byte[] reEncodedBytes = roundTripDG2File.GetEncoded()!;
        Assert.Equal(originalBytes, reEncodedBytes);
    }

    [Fact]
    public void testSilverAllRoundTrip()
    {
        byte[] originalBytes = ReadResource("/lds/dg2/dg2_silver_all_fields.bin");
        DG2File dg2File = new DG2File(new MemoryStream(originalBytes));
        Assert.NotNull(dg2File);
        List<FaceImageDataBlock> subRecords = dg2File.GetSubRecords().Cast<FaceImageDataBlock>().ToList();
        DG2File roundTripDG2File = DG2File.CreateISO39794DG2File(subRecords, ISO39794EncodingProfile.Icao39794_5EmrtdV1);

        byte[] reEncodedBytes = roundTripDG2File.GetEncoded()!;
        Assert.Equal(originalBytes, reEncodedBytes);
    }

    internal static void CheckFaceImageDataBlock(string resource)
    {
        Stream inputStream = Fixtures.GetInputStream(resource);
        Assert.NotNull(inputStream);
        FaceImageDataBlock dataBlock = new FaceImageDataBlock(inputStream);
        CheckDecodeEncode(dataBlock, resource);
    }

    internal static void CheckDG2File(string resource, int expectedBDBCount)
    {
        Stream inputStream = Fixtures.GetInputStream(resource);
        Assert.NotNull(inputStream);
        DG2File dg2File = new DG2File(inputStream);
        Assert.Equal(BiometricEncodingType.Iso39794, dg2File.GetEncodingType());

        List<FaceInfo> faceInfos = dg2File.GetFaceInfos();
        Assert.NotNull(faceInfos);
        Assert.Empty(faceInfos);

        List<BiometricDataBlock> records = dg2File.GetSubRecords();
        Assert.NotNull(records);
        Assert.Equal(expectedBDBCount, records.Count);
        foreach (BiometricDataBlock record in records)
        {
            Assert.NotNull(record);
            Assert.IsAssignableFrom<FaceImageDataBlock>(record);
            FaceImageDataBlock faceImageDataBlock = (FaceImageDataBlock)record;

            // [80 => 0101, 81 => 02, 82 => 00, 83 => 21240105112345, 85 => 2124010521290105, 86 => 01030001, 87 => 0101, 88 => 002A]
            // [87 => 0101, 88 => 002A]
            // [81 => 02, 82 => 00, 87 => 0101, 88 => 002A]
            // [81 => 02, 82 => 00, 87 => 0101, 88 => 002A]

            CheckDecodeEncode(faceImageDataBlock, resource);

            List<FaceImageRepresentationBlock> imageRepresentationBlocks = faceImageDataBlock.GetRepresentationBlocks();
            FaceImageRepresentation2DBlock? imageRepresentation2DBlock = imageRepresentationBlocks[0].GetImageRepresentation2DBlock();
            Assert.Equal("image/jp2", imageRepresentation2DBlock!.GetRepresentationData2DInputMimeType());

            long imageLength = imageRepresentation2DBlock.GetRepresentationData2DInputLength();
            Assert.True(imageLength > 0);

            Stream imageInputStream = imageRepresentation2DBlock.GetRepresentationData2DInputStream();
            byte[] imageBytes = ReadInputStream(imageInputStream);
            Assert.Equal(imageLength, imageBytes.Length);

            FaceImageInformation2DBlock imageInformation2DBlock = imageRepresentation2DBlock.GetImageInformation2DBlock();

            ImageSizeBlock? imageSizeBlock = imageInformation2DBlock.GetImageSizeBlock();

            if (imageSizeBlock != null)
            {
                int imageWidth = imageSizeBlock.GetWidth();
                Assert.Equal(572, imageWidth);

                int imageHeight = imageSizeBlock.GetHeight();
                Assert.Equal(731, imageHeight);
            }
        }

        //      byte[] reEncodedDG2Bytes = dg2File.GetEncoded()!;
        //
        //      DG2File decodedDGFile = new DG2File(new MemoryStream(reEncodedDG2Bytes));


    }

    internal static void CheckDecodeEncode(FaceImageDataBlock faceImageDataBlock, string resource)
    {
        byte[] encoded = faceImageDataBlock.GetEncoded()!;

        FaceImageDataBlock reconstructed = new FaceImageDataBlock(faceImageDataBlock.GetStandardBiometricHeader(), new MemoryStream(encoded));

        Assert.Equal(faceImageDataBlock, reconstructed);

        byte[] reEncoded = reconstructed.GetEncoded()!;

        Assert.Equal(encoded.Length, reEncoded.Length);
        Assert.Equal(encoded, reEncoded);

    }

    private static byte[] ReadInputStream(Stream inputStream)
    {
        MemoryStream buffer = new MemoryStream();
        int nRead;
        byte[] data = new byte[16384];
        while ((nRead = inputStream.Read(data, 0, data.Length)) > 0) // Java: != -1
        {
            buffer.Write(data, 0, nRead);
        }
        return buffer.ToArray();
    }

    private static byte[] ReadResource(string resource)
    {
        Stream inputStream = Fixtures.GetInputStream(resource);
        Assert.NotNull(inputStream);
        return ReadInputStream(inputStream);
    }

    private static byte[] CreateTrivialJPEGBytes(int width, int height)
    {
        return TestImages.TrivialJpeg; // Java: a blank image of the given size, encoded with ImageIO
    }
}
