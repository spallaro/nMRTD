using nMRTD.Cbeff;
using nMRTD.Lds;
using nMRTD.Lds.Iso19794;
using static nMRTD.Lds.Iso19794.FingerImageInfo;

namespace nMRTD.Tests;

/// <summary>
/// ISO/IEC 19794-4 finger images: every finger and palm position maps to the CBEFF biometric subtype of
/// its hand and finger, prints its name, and survives an encode and decode round trip.
/// </summary>
public class Iso19794FingerTests
{
    private const int Right = CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_RIGHT;
    private const int Left = CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_LEFT;
    private const int Thumb = CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_THUMB;
    private const int Index = CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_POINTER_FINGER;
    private const int Middle = CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_MIDDLE_FINGER;
    private const int Ring = CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_RING_FINGER;
    private const int Little = CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_MASK_LITTLE_FINGER;
    private const int None = CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_NONE;

    private static readonly byte[] Image = [0xFF, 0xA0, 0xFF, 0xA8, 0x00, 0x01, 0x02, 0x03];

    private static FingerImageInfo Finger(int position, int impressionType = IMPRESSION_TYPE_LIVE_SCAN_PLAIN) =>
        new(position, 1, 1, 80, impressionType, 400, 500, new MemoryStream(Image), Image.Length, FingerInfo.COMPRESSION_WSQ);

    [Theory]
    [InlineData(POSITION_UNKNOWN_FINGER, None, "Unknown finger")]
    [InlineData(POSITION_RIGHT_THUMB, Right | Thumb, "Right thumb")]
    [InlineData(POSITION_RIGHT_INDEX_FINGER, Right | Index, "Right index finger")]
    [InlineData(POSITION_RIGHT_MIDDLE_FINGER, Right | Middle, "Right middle finger")]
    [InlineData(POSITION_RIGHT_RING_FINGER, Right | Ring, "Right ring finger")]
    [InlineData(POSITION_RIGHT_LITTLE_FINGER, Right | Little, "Right little finger")]
    [InlineData(POSITION_LEFT_THUMB, Left | Thumb, "Left thumb")]
    [InlineData(POSITION_LEFT_INDEX_FINGER, Left | Index, "Left index finger")]
    [InlineData(POSITION_LEFT_MIDDLE_FINGER, Left | Middle, "Left middle finger")]
    [InlineData(POSITION_LEFT_RING_FINGER, Left | Ring, "Left ring finger")]
    [InlineData(POSITION_LEFT_LITTLE_FINGER, Left | Little, "Left little finger")]
    [InlineData(POSITION_PLAIN_RIGHT_FOUR_FINGERS, Right, "Right four fingers")]
    [InlineData(POSITION_PLAIN_LEFT_FOUR_FINGERS, Left, "Left four fingers")]
    [InlineData(POSITION_PLAIN_THUMBS, Thumb, "Plain thumbs")]
    [InlineData(POSITION_UNKNOWN_PALM, None, "Unknown palm")]
    [InlineData(POSITION_RIGHT_FULL_PALM, Right, "Right full palm")]
    [InlineData(POSITION_RIGHT_WRITER_S_PALM, Right, "Right writer's palm")]
    [InlineData(POSITION_LEFT_FULL_PALM, Left, "Left full palm")]
    [InlineData(POSITION_LEFT_WRITER_S_PALM, Left, "Left writer's palm")]
    [InlineData(POSITION_RIGHT_LOWER_PALM, Right, "Right lower palm")]
    [InlineData(POSITION_RIGHT_UPPER_PALM, Right, "Right upper palm")]
    [InlineData(POSITION_LEFT_LOWER_PALM, Left, "Left lower palm")]
    [InlineData(POSITION_LEFT_UPPER_PALM, Left, "Left upper palm")]
    [InlineData(POSITION_RIGHT_OTHER, Right, "Right other")]
    [InlineData(POSITION_LEFT_OTHER, Left, "Left other")]
    [InlineData(POSITION_RIGHT_INTERDIGITAL, Right, "Right interdigital")]
    [InlineData(POSITION_RIGHT_THENAR, Right, "Right thenar")]
    [InlineData(POSITION_RIGHT_HYPOTHENAR, Right, "Right hypothenar")]
    [InlineData(POSITION_LEFT_INTERDIGITAL, Left, "Left interdigital")]
    [InlineData(POSITION_LEFT_THENAR, Left, "Left thenar")]
    [InlineData(POSITION_LEFT_HYPOTHENAR, Left, "Left hypothenar")]
    public void PositionMapsToItsHandAndFinger(int position, int subtype, string name)
    {
        FingerImageInfo finger = Finger(position);

        Assert.Equal(subtype, finger.GetBiometricSubtype());
        Assert.Contains("position: " + name + ",", finger.ToString());

        var decoded = new FingerInfo(new MemoryStream(new FingerInfo(
            0, 31, FingerInfo.SCALE_UNITS_PPI, 500, 500, 500, 500, 8, FingerInfo.COMPRESSION_WSQ, [finger]).GetEncoded()!));
        FingerImageInfo copy = Assert.Single(decoded.GetFingerImageInfos());
        Assert.Equal(finger, copy);
        Assert.Equal(finger.GetHashCode(), copy.GetHashCode());
        Assert.Equal(position, copy.GetPosition());
    }

    [Fact]
    public void UnknownPositionHasNoSubtypeAndPrintsNull()
    {
        FingerImageInfo finger = Finger(99);

        Assert.Equal(None, finger.GetBiometricSubtype());
        Assert.Contains("position: null,", finger.ToString());
    }

    [Theory]
    [InlineData(IMPRESSION_TYPE_LIVE_SCAN_PLAIN, "Live scan plain")]
    [InlineData(IMPRESSION_TYPE_LIVE_SCAN_ROLLED, "Live scan rolled")]
    [InlineData(IMPRESSION_TYPE_NON_LIVE_SCAN_PLAIN, "Non-live scan plain")]
    [InlineData(IMPRESSION_TYPE_NON_LIVE_SCAN_ROLLED, "Non-live scan rolled")]
    [InlineData(IMPRESSION_TYPE_LATENT, "Latent")]
    [InlineData(IMPRESSION_TYPE_SWIPE, "Swipe")]
    [InlineData(IMPRESSION_TYPE_LIVE_SCAN_CONTACTLESS, "Live scan contactless")]
    [InlineData(5, "null")]
    public void ImpressionTypesPrintTheirName(int impressionType, string name) =>
        Assert.Contains("impression type: " + name + ",", Finger(POSITION_RIGHT_THUMB, impressionType).ToString());

    [Fact]
    public void QualityOutsideZeroToHundredIsRejected()
    {
        Assert.Throws<ArgumentException>(() => new FingerImageInfo(POSITION_RIGHT_THUMB, 1, 1, 101, 0, 1, 1, new MemoryStream(Image), Image.Length, FingerInfo.COMPRESSION_WSQ));
        Assert.Throws<ArgumentException>(() => new FingerImageInfo(POSITION_RIGHT_THUMB, 1, 1, -1, 0, 1, 1, new MemoryStream(Image), Image.Length, FingerInfo.COMPRESSION_WSQ));
    }

    [Fact]
    public void DifferentFieldsAreNotEqual()
    {
        FingerImageInfo finger = Finger(POSITION_RIGHT_THUMB);

        Assert.NotEqual(finger, Finger(POSITION_LEFT_THUMB));
        Assert.NotEqual(finger, Finger(POSITION_RIGHT_THUMB, IMPRESSION_TYPE_LIVE_SCAN_ROLLED));
        Assert.NotEqual(finger, new FingerImageInfo(POSITION_RIGHT_THUMB, 1, 1, 79, 0, 400, 500, new MemoryStream(Image), Image.Length, FingerInfo.COMPRESSION_WSQ));
        Assert.NotEqual(finger, new FingerImageInfo(POSITION_RIGHT_THUMB, 2, 1, 80, 0, 400, 500, new MemoryStream(Image), Image.Length, FingerInfo.COMPRESSION_WSQ));
        Assert.NotEqual(finger, new FingerImageInfo(POSITION_RIGHT_THUMB, 1, 2, 80, 0, 400, 500, new MemoryStream(Image), Image.Length, FingerInfo.COMPRESSION_WSQ));
        Assert.False(finger.Equals(null));
        Assert.False(finger.Equals("finger"));
    }
}
