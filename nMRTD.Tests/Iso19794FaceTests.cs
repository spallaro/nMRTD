using nMRTD.Lds.Icao;
using nMRTD.Lds.Iso19794;
using nMRTD.SmartCards;
using static nMRTD.Lds.Iso19794.FaceImageInfo;

namespace nMRTD.Tests;

/// <summary>
/// ISO/IEC 19794-5 face images with the optional parts the fixtures lack: feature points, a full feature
/// mask, pose angle uncertainties, every hair colour, expression and source type. Each record must
/// survive an encode and decode round trip through DG2 and print its values.
/// </summary>
public class Iso19794FaceTests
{
    private const int AllFeatures = 0x07FF; // "features are specified" plus the ten feature flags

    private static readonly byte[] Jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46];

    private static FaceImageInfo Face(
        int featureMask = AllFeatures, int hairColor = HAIR_COLOR_BROWN, int expression = EXPRESSION_NEUTRAL,
        int sourceType = SOURCE_TYPE_STATIC_PHOTO_DIGITAL_CAM, FeaturePoint[]? featurePoints = null, int quality = 0) =>
        new(Gender.Female, EyeColor.Blue, featureMask, hairColor, expression,
            [10, 20, 30], [1, 2, 3],
            FACE_IMAGE_TYPE_FULL_FRONTAL, IMAGE_COLOR_SPACE_RGB24, sourceType, 0x0102, quality,
            featurePoints ?? [new FeaturePoint(1, 12, 1, 100, 120), new FeaturePoint(1, 12, 2, 180, 121)],
            640, 480, new MemoryStream(Jpeg), Jpeg.Length, IMAGE_DATA_TYPE_JPEG);

    private static FaceImageInfo RoundTrip(FaceImageInfo face)
    {
        var dg2 = new DG2File([new FaceInfo([face])]);
        var copy = new DG2File(new MemoryStream(dg2.GetEncoded()!));
        return Assert.Single(Assert.Single(copy.GetFaceInfos()).GetFaceImageInfos());
    }

    [Fact]
    public void RecordWithFeaturePointsAndAllFeaturesRoundTrips()
    {
        FaceImageInfo face = Face();

        FaceImageInfo copy = RoundTrip(face);

        Assert.Equal(face, copy);
        Assert.Equal(face.GetHashCode(), copy.GetHashCode());
        Assert.Equal(AllFeatures, copy.GetFeatureMask());
        Assert.Equal([10, 20, 30], copy.GetPoseAngle());
        Assert.Equal([1, 2, 3], copy.GetPoseAngleUncertainty());
        Assert.Equal(0x0102, copy.GetDeviceType());
        Assert.Equal(2, copy.GetFeaturePoints().Length);
        FeaturePoint point = copy.GetFeaturePoints()[1];
        Assert.Equal((1, 12, 2, 180, 121), (point.GetPointType(), point.GetMajorCode(), point.GetMinorCode(), point.GetX(), point.GetY()));
    }

    [Fact]
    public void TextListsFeaturesPoseAndFeaturePoints()
    {
        string text = Face().ToString();

        foreach (string feature in new[] { "glasses", "moustache", "beard", "teeth visible", "blink", "mouth open",
                     "left eye patch", "right eye patch", "dark glasses", "distorting medical condition" })
        {
            Assert.Contains(feature, text);
        }
        Assert.Contains("(y: 10 (1), p:20 (2), r: 30 (3))", text);
        Assert.Contains("full frontal", text);
        Assert.Contains("FeaturePoints [", text);
        Assert.DoesNotContain("glasses", Face(featureMask: 0x0002).ToString()); // flags without "specified" are not listed
    }

    [Theory]
    [InlineData(HAIR_COLOR_UNSPECIFIED, "unspecified")]
    [InlineData(HAIR_COLOR_BALD, "bald")]
    [InlineData(HAIR_COLOR_BLACK, "black")]
    [InlineData(HAIR_COLOR_BLONDE, "blonde")]
    [InlineData(HAIR_COLOR_BROWN, "brown")]
    [InlineData(HAIR_COLOR_GRAY, "gray")]
    [InlineData(HAIR_COLOR_WHITE, "white")]
    [InlineData(HAIR_COLOR_RED, "red")]
    [InlineData(HAIR_COLOR_GREEN, "green")]
    [InlineData(HAIR_COLOR_BLUE, "blue")]
    [InlineData(HAIR_COLOR_UNKNOWN, "unknown")]
    public void HairColoursRoundTripAndPrint(int hairColor, string name)
    {
        FaceImageInfo copy = RoundTrip(Face(hairColor: hairColor));

        Assert.Equal(hairColor, copy.GetHairColor());
        Assert.Contains(name, copy.ToString());
    }

    [Theory]
    [InlineData(EXPRESSION_UNSPECIFIED, "unspecified")]
    [InlineData(EXPRESSION_NEUTRAL, "neutral")]
    [InlineData(EXPRESSION_SMILE_CLOSED, "closed jaw")]
    [InlineData(EXPRESSION_SMILE_OPEN, "teeth is exposed")]
    [InlineData(EXPRESSION_RAISED_EYEBROWS, "raised eyebrows")]
    [InlineData(EXPRESSION_EYES_LOOKING_AWAY, "looking away")]
    [InlineData(EXPRESSION_SQUINTING, "squinting")]
    [InlineData(EXPRESSION_FROWNING, "frowning")]
    [InlineData(0x0042, "unknown")]
    public void ExpressionsRoundTripAndPrint(int expression, string name)
    {
        FaceImageInfo copy = RoundTrip(Face(expression: expression));

        Assert.Equal(expression, copy.GetExpression());
        Assert.Contains(name, copy.ToString());
    }

    [Theory]
    [InlineData(SOURCE_TYPE_UNSPECIFIED, "unspecified")]
    [InlineData(SOURCE_TYPE_STATIC_PHOTO_UNKNOWN_SOURCE, "static photograph from an unknown source")]
    [InlineData(SOURCE_TYPE_STATIC_PHOTO_DIGITAL_CAM, "digital still-image camera")]
    [InlineData(SOURCE_TYPE_STATIC_PHOTO_SCANNER, "scanner")]
    [InlineData(SOURCE_TYPE_VIDEO_FRAME_UNKNOWN_SOURCE, "video frame from an unknown source")]
    [InlineData(SOURCE_TYPE_VIDEO_FRAME_ANALOG_CAM, "analogue camera")]
    [InlineData(SOURCE_TYPE_VIDEO_FRAME_DIGITAL_CAM, "video frame from a digital camera")]
    [InlineData(SOURCE_TYPE_UNKNOWN, "unknown")]
    public void SourceTypesRoundTripAndPrint(int sourceType, string name)
    {
        FaceImageInfo copy = RoundTrip(Face(sourceType: sourceType));

        Assert.Equal(sourceType, copy.GetSourceType());
        Assert.Contains(name, copy.ToString());
    }

    [Fact]
    public void DifferentFieldsAreNotEqual()
    {
        FaceImageInfo face = Face();

        Assert.NotEqual(face, Face(hairColor: HAIR_COLOR_BLACK));
        Assert.NotEqual(face, Face(expression: EXPRESSION_FROWNING));
        Assert.NotEqual(face, Face(featureMask: 0x0001));
        Assert.NotEqual(face, Face(quality: 1));
        Assert.NotEqual(face, Face(featurePoints: [new FeaturePoint(1, 12, 1, 100, 120)]));
        Assert.False(face.Equals(null));
        Assert.False(face.Equals("face"));
    }
}
