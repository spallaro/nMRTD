/*
 * nMRTD - A .Net API for accessing Machine Readable Travel Documents.
 *
 * Copyright (C) Sebastiano Pallaro.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * This is a porting from jMRTD, Copyright (C) The jMRTD Team (https://jmrtd.org/).
 *
 * Distributed under the terms of GNU LGPL v3.
 * See LICENSE for more information.
 */

using nMRTD.Lds;
using nMRTD.SmartCards;

namespace nMRTD.Lds.Iso19794;

/// <summary>
/// Port of <c>org.jmrtd.lds.iso19794.FaceImageInfo</c>: data structure for storing facial image data.
/// This represents a facial record data block as specified in Section 5.5, 5.6, and 5.7 of ISO/IEC FCD
/// 19794-5 (2004-03-22, AKA Annex D). A facial record data block contains a single facial image.
/// </summary>
public class FaceImageInfo : AbstractImageInfo
{
    /// <summary>Eye color code based on Section 5.5.4 of ISO 19794-5.</summary>
    public enum EyeColor
    {
        Unspecified = EYE_COLOR_UNSPECIFIED,
        Black = EYE_COLOR_BLACK,
        Blue = EYE_COLOR_BLUE,
        Brown = EYE_COLOR_BROWN,
        Gray = EYE_COLOR_GRAY,
        Green = EYE_COLOR_GREEN,
        MultiColored = EYE_COLOR_MULTI_COLORED,
        Pink = EYE_COLOR_PINK,
        Unknown = EYE_COLOR_UNKNOWN,
    }

    /* These correspond to values in Table 4 in 5.5.4 in ISO/IEC 19794-5:2005(E). */
    public const int EYE_COLOR_UNSPECIFIED = 0x00;
    public const int EYE_COLOR_BLACK = 0x01;
    public const int EYE_COLOR_BLUE = 0x02;
    public const int EYE_COLOR_BROWN = 0x03;
    public const int EYE_COLOR_GRAY = 0x04;
    public const int EYE_COLOR_GREEN = 0x05;
    public const int EYE_COLOR_MULTI_COLORED = 0x06;
    public const int EYE_COLOR_PINK = 0x07;
    public const int EYE_COLOR_UNKNOWN = 0xFF;

    /// <summary>
    /// Hair color code based on Section 5.5.5 of ISO 19794-5. Ported for API parity with the Java source:
    /// like upstream, this enum type is declared but never actually used as a field type in this class --
    /// <see cref="GetHairColor"/> returns the raw <c>int</c> code (see <see cref="HAIR_COLOR_UNSPECIFIED"/>
    /// and friends), not this enum. Kept nested here only because callers may want the symbolic names.
    /// </summary>
    public enum HairColor
    {
        Unspecified = HAIR_COLOR_UNSPECIFIED,
        Bald = HAIR_COLOR_BALD,
        Black = HAIR_COLOR_BLACK,
        Blonde = HAIR_COLOR_BLONDE,
        Brown = HAIR_COLOR_BROWN,
        Gray = HAIR_COLOR_GRAY,
        White = HAIR_COLOR_WHITE,
        Red = HAIR_COLOR_RED,
        Green = HAIR_COLOR_GREEN,
        Blue = HAIR_COLOR_BLUE,
        Unknown = HAIR_COLOR_UNKNOWN,
    }

    public const int HAIR_COLOR_UNSPECIFIED = 0x00;
    public const int HAIR_COLOR_BALD = 0x01;
    public const int HAIR_COLOR_BLACK = 0x02;
    public const int HAIR_COLOR_BLONDE = 0x03;
    public const int HAIR_COLOR_BROWN = 0x04;
    public const int HAIR_COLOR_GRAY = 0x05;
    public const int HAIR_COLOR_WHITE = 0x06;
    public const int HAIR_COLOR_RED = 0x07;
    public const int HAIR_COLOR_GREEN = 0x08;
    public const int HAIR_COLOR_BLUE = 0x09;
    public const int HAIR_COLOR_UNKNOWN = 0xFF;

    /// <summary>
    /// Feature flags meaning based on Section 5.5.6 of ISO 19794-5. Like the Java source, declared but
    /// unused elsewhere in this class -- the feature mask itself is manipulated as a raw <c>int</c> bitmask
    /// via the <c>FEATURE_*_FLAG</c> constants below (see <see cref="GetFeatureMask"/>).
    /// </summary>
    public enum Features
    {
        FeaturesAreSpecified,
        Glasses,
        Moustache,
        Beard,
        TeethVisible,
        Blink,
        MouthOpen,
        LeftEyePatch,
        RightEyePatch,
        DarkGlasses,
        DistortingMedicalCondition,
    }

    private const int FEATURE_FEATURES_ARE_SPECIFIED_FLAG = 0x000001;
    private const int FEATURE_GLASSES_FLAG = 0x000002;
    private const int FEATURE_MOUSTACHE_FLAG = 0x000004;
    private const int FEATURE_BEARD_FLAG = 0x000008;
    private const int FEATURE_TEETH_VISIBLE_FLAG = 0x000010;
    private const int FEATURE_BLINK_FLAG = 0x000020;
    private const int FEATURE_MOUTH_OPEN_FLAG = 0x000040;
    private const int FEATURE_LEFT_EYE_PATCH_FLAG = 0x000080;
    private const int FEATURE_RIGHT_EYE_PATCH = 0x000100;
    private const int FEATURE_DARK_GLASSES = 0x000200;
    private const int FEATURE_DISTORTING_MEDICAL_CONDITION = 0x000400;

    /// <summary>
    /// Expression code based on Section 5.5.7 of ISO 19794-5. Like <see cref="HairColor"/>, declared but
    /// unused as a field type in this class -- <see cref="GetExpression"/> returns the raw <c>int</c> code.
    /// </summary>
    public enum Expression
    {
        Unspecified = EXPRESSION_UNSPECIFIED,
        Neutral = EXPRESSION_NEUTRAL,
        SmileClosed = EXPRESSION_SMILE_CLOSED,
        SmileOpen = EXPRESSION_SMILE_OPEN,
        RaisedEyebrows = EXPRESSION_RAISED_EYEBROWS,
        EyesLookingAway = EXPRESSION_EYES_LOOKING_AWAY,
        Squinting = EXPRESSION_SQUINTING,
        Frowning = EXPRESSION_FROWNING,
    }

    public const short EXPRESSION_UNSPECIFIED = 0x0000;
    public const short EXPRESSION_NEUTRAL = 0x0001;
    public const short EXPRESSION_SMILE_CLOSED = 0x0002;
    public const short EXPRESSION_SMILE_OPEN = 0x0003;
    public const short EXPRESSION_RAISED_EYEBROWS = 0x0004;
    public const short EXPRESSION_EYES_LOOKING_AWAY = 0x0005;
    public const short EXPRESSION_SQUINTING = 0x0006;
    public const short EXPRESSION_FROWNING = 0x0007;

    /// <summary>Face image type code based on Section 5.7.1 of ISO 19794-5. See the <see cref="HairColor"/> remark.</summary>
    public enum FaceImageType
    {
        Basic = FACE_IMAGE_TYPE_BASIC,
        FullFrontal = FACE_IMAGE_TYPE_FULL_FRONTAL,
        TokenFrontal = FACE_IMAGE_TYPE_TOKEN_FRONTAL,
    }

    public const int FACE_IMAGE_TYPE_BASIC = 0x00;
    public const int FACE_IMAGE_TYPE_FULL_FRONTAL = 0x01;
    public const int FACE_IMAGE_TYPE_TOKEN_FRONTAL = 0x02;

    /// <summary>Image data type code based on Section 5.7.2 of ISO 19794-5. See the <see cref="HairColor"/> remark.</summary>
    public enum ImageDataType
    {
        TypeJpeg = IMAGE_DATA_TYPE_JPEG,
        TypeJpeg2000 = IMAGE_DATA_TYPE_JPEG2000,
    }

    public const int IMAGE_DATA_TYPE_JPEG = 0x00;
    public const int IMAGE_DATA_TYPE_JPEG2000 = 0x01;

    /// <summary>Color space code based on Section 5.7.4 of ISO 19794-5. See the <see cref="HairColor"/> remark.</summary>
    public enum ImageColorSpace
    {
        Unspecified = IMAGE_COLOR_SPACE_UNSPECIFIED,
        Rgb24 = IMAGE_COLOR_SPACE_RGB24,
        Yuv422 = IMAGE_COLOR_SPACE_YUV422,
        Gray8 = IMAGE_COLOR_SPACE_GRAY8,
        Other = IMAGE_COLOR_SPACE_OTHER,
    }

    public const int IMAGE_COLOR_SPACE_UNSPECIFIED = 0x00;
    public const int IMAGE_COLOR_SPACE_RGB24 = 0x01;
    public const int IMAGE_COLOR_SPACE_YUV422 = 0x02;
    public const int IMAGE_COLOR_SPACE_GRAY8 = 0x03;
    public const int IMAGE_COLOR_SPACE_OTHER = 0x04;

    /// <summary>Source type based on Section 5.7.6 of ISO 19794-5. See the <see cref="HairColor"/> remark.</summary>
    public enum SourceType
    {
        Unspecified = SOURCE_TYPE_UNSPECIFIED,
        StaticPhotoUnknownSource = SOURCE_TYPE_STATIC_PHOTO_UNKNOWN_SOURCE,
        StaticPhotoDigitalCam = SOURCE_TYPE_STATIC_PHOTO_DIGITAL_CAM,
        StaticPhotoScanner = SOURCE_TYPE_STATIC_PHOTO_SCANNER,
        VideoFrameUnknownSource = SOURCE_TYPE_VIDEO_FRAME_UNKNOWN_SOURCE,
        VideoFrameAnalogCam = SOURCE_TYPE_VIDEO_FRAME_ANALOG_CAM,
        VideoFrameDigitalCam = SOURCE_TYPE_VIDEO_FRAME_DIGITAL_CAM,
        Unknown = SOURCE_TYPE_UNKNOWN,
    }

    public const int SOURCE_TYPE_UNSPECIFIED = 0x00;
    public const int SOURCE_TYPE_STATIC_PHOTO_UNKNOWN_SOURCE = 0x01;
    public const int SOURCE_TYPE_STATIC_PHOTO_DIGITAL_CAM = 0x02;
    public const int SOURCE_TYPE_STATIC_PHOTO_SCANNER = 0x03;
    public const int SOURCE_TYPE_VIDEO_FRAME_UNKNOWN_SOURCE = 0x04;
    public const int SOURCE_TYPE_VIDEO_FRAME_ANALOG_CAM = 0x05;
    public const int SOURCE_TYPE_VIDEO_FRAME_DIGITAL_CAM = 0x06;
    public const int SOURCE_TYPE_UNKNOWN = 0x07;

    /// <summary>
    /// Feature points as described in Section 5.6.3 of ISO/IEC FCD 19794-5.
    /// </summary>
    /// <remarks>
    /// NOTE: preserved Java quirk -- Java's <c>FeaturePoint</c> does not override <c>equals()</c>/
    /// <c>hashCode()</c>, so <c>Arrays.equals</c>/<c>Arrays.hashCode</c> on a <c>FeaturePoint[]</c> in
    /// <see cref="FaceImageInfo"/>'s own <c>equals()</c>/<c>hashCode()</c> compare/hash by object
    /// *identity*, not by field content -- two structurally-identical <see cref="FaceImageInfo"/>
    /// instances built from the same bytes will generally NOT compare equal, because reading creates
    /// fresh <see cref="FeaturePoint"/> instances each time. Preserved here by likewise not overriding
    /// <see cref="object.Equals(object?)"/>/<see cref="object.GetHashCode"/> on this class, so C#'s
    /// default reference-identity semantics apply the same way.
    /// </remarks>
    public sealed class FeaturePoint
    {
        private readonly int _type;
        private readonly int _majorCode;
        private readonly int _minorCode;
        private readonly int _x;
        private readonly int _y;

        /// <summary>Constructs a new feature point.</summary>
        /// <param name="type">feature point type</param>
        /// <param name="majorCode">major code</param>
        /// <param name="minorCode">minor code</param>
        /// <param name="x">X-coordinate</param>
        /// <param name="y">Y-coordinate</param>
        public FeaturePoint(int type, int majorCode, int minorCode, int x, int y)
        {
            _type = type;
            _majorCode = majorCode;
            _minorCode = minorCode;
            _x = x;
            _y = y;
        }

        /// <summary>
        /// Constructs a new feature point from a combined major/minor code byte. Java package-private;
        /// <c>internal</c> here since it is only used when decoding a record (see <c>FaceImageInfo.ReadObject(Stream)</c>).
        /// </summary>
        /// <param name="type">feature point type</param>
        /// <param name="code">combined major and minor code</param>
        /// <param name="x">X-coordinate</param>
        /// <param name="y">Y-coordinate</param>
        internal FeaturePoint(int type, byte code, int x, int y)
            : this(type, (code & 0xF0) >> 4, code & 0x0F, x, y)
        {
        }

        /// <summary>Returns the major code of this point.</summary>
        public int GetMajorCode() => _majorCode;

        /// <summary>Returns the minor code of this point.</summary>
        public int GetMinorCode() => _minorCode;

        /// <summary>
        /// Returns the type of this point. Named <c>GetPointType</c> rather than Java's <c>getType()</c>,
        /// which would collide with <see cref="object.GetType"/> in C# (same rename rationale as
        /// <see cref="ImageInfo.GetImageType"/>).
        /// </summary>
        public int GetPointType() => _type;

        /// <summary>Returns the X-coordinate of this point.</summary>
        public int GetX() => _x;

        /// <summary>Returns the Y-coordinate of this point.</summary>
        public int GetY() => _y;

        /// <summary>Generates a textual representation of this point.</summary>
        public override string ToString() =>
            $"( point: {GetMajorCode()}.{GetMinorCode()}, type: {_type:x}, ({_x}, {_y}))";
    }

    /// <summary>Index into the pose angle array.</summary>
    private const int YAW = 0;

    /// <summary>Index into the pose angle array.</summary>
    private const int PITCH = 1;

    /// <summary>Index into the pose angle array.</summary>
    private const int ROLL = 2;

    private long _recordLength;
    private Gender _gender;
    private EyeColor _eyeColor;
    private int _hairColor;
    private int _featureMask;
    private int _expression;
    private int[] _poseAngle;
    private int[] _poseAngleUncertainty;
    private FeaturePoint[] _featurePoints;
    private int _faceImageType;
    private int _imageDataType;
    private int _colorSpace;
    private int _sourceType;
    private int _deviceType;
    private int _quality;

    /// <summary>Constructs a new face information data structure instance.</summary>
    /// <param name="gender">gender (<c>null</c> is treated as <see cref="Gender.Unspecified"/>, matching Java's null-tolerant field)</param>
    /// <param name="eyeColor">eye color (<c>null</c> is treated as <see cref="EyeColor.Unspecified"/>)</param>
    /// <param name="featureMask">feature mask (least significant 3 bytes)</param>
    /// <param name="hairColor">hair color</param>
    /// <param name="expression">expression</param>
    /// <param name="poseAngle">(encoded) pose angle, an array of length 3 (yaw, pitch, roll)</param>
    /// <param name="poseAngleUncertainty">pose angle uncertainty, an array of length 3</param>
    /// <param name="faceImageType">face image type</param>
    /// <param name="colorSpace">color space</param>
    /// <param name="sourceType">source type</param>
    /// <param name="deviceType">capture device type (unspecified is <c>0x00</c>)</param>
    /// <param name="quality">quality</param>
    /// <param name="featurePoints">feature points</param>
    /// <param name="width">width</param>
    /// <param name="height">height</param>
    /// <param name="imageInputStream">encoded image bytes</param>
    /// <param name="imageLength">length of encoded image</param>
    /// <param name="imageDataType">either <see cref="IMAGE_DATA_TYPE_JPEG"/> or <see cref="IMAGE_DATA_TYPE_JPEG2000"/></param>
    public FaceImageInfo(Gender? gender, EyeColor? eyeColor,
        int featureMask,
        int hairColor,
        int expression,
        int[] poseAngle, int[] poseAngleUncertainty,
        int faceImageType,
        int colorSpace,
        int sourceType,
        int deviceType,
        int quality,
        FeaturePoint[]? featurePoints,
        int width, int height,
        Stream imageInputStream, int imageLength, int imageDataType)
        : base(ImageInfo.TYPE_PORTRAIT, width, height, imageInputStream, imageLength, ToMimeType(imageDataType))
    {
        /* NOTE: preserved Java quirk -- Java's constructor calls super(...) (which already reads the
         * image bytes) before this null check, so a null stream would already have thrown a
         * NullPointerException inside the base constructor; this check is therefore dead code in the
         * original, and stays dead code here (base(...) runs before this body in C# too). Matches the
         * same precedent already applied in FingerImageInfo.cs. */
        if (imageInputStream == null)
        {
            throw new ArgumentException("Null image");
        }

        _gender = gender ?? SmartCards.Gender.Unspecified;
        _eyeColor = eyeColor ?? EyeColor.Unspecified;
        _featureMask = featureMask;
        _hairColor = hairColor;
        _expression = expression;
        _colorSpace = colorSpace;
        _sourceType = sourceType;
        _deviceType = deviceType;

        int featurePointCount = featurePoints?.Length ?? 0;
        _featurePoints = new FeaturePoint[featurePointCount];
        if (featurePointCount > 0)
        {
            Array.Copy(featurePoints!, 0, _featurePoints, 0, featurePointCount);
        }

        _poseAngle = new int[3];
        Array.Copy(poseAngle, 0, _poseAngle, 0, 3);
        _poseAngleUncertainty = new int[3];
        Array.Copy(poseAngleUncertainty, 0, _poseAngleUncertainty, 0, 3);
        _imageDataType = imageDataType;
        _recordLength = 20L + (8 * featurePointCount) + 12L + imageLength;

        _faceImageType = faceImageType;
        _colorSpace = colorSpace;
        _sourceType = sourceType;
        _deviceType = deviceType;
        _quality = quality;
    }

    /// <summary>Constructs a new face information structure from binary encoding.</summary>
    /// <param name="inputStream">an input stream</param>
    public FaceImageInfo(Stream inputStream)
        : base(ImageInfo.TYPE_PORTRAIT)
    {
        _gender = SmartCards.Gender.Unspecified;
        _eyeColor = EyeColor.Unspecified;
        _poseAngle = new int[3];
        _poseAngleUncertainty = new int[3];
        _featurePoints = [];
        ReadObject(inputStream);
    }

    /// <inheritdoc/>
    protected override void ReadObject(Stream inputStream)
    {
        /* Facial Information Block (20), see ISO 19794-5 5.5 */
        _recordLength = ReadUInt32BigEndian(inputStream); /* 4 */
        int featurePointCount = ReadUnsignedShort(inputStream); /* +2 = 6 */
        _gender = GenderFromCode(ReadUnsignedByte(inputStream)); /* +1 = 7 */
        _eyeColor = ToEyeColor(ReadUnsignedByte(inputStream)); /* +1 = 8 */
        _hairColor = ReadUnsignedByte(inputStream); /* +1 = 9 */
        _featureMask = ReadUnsignedByte(inputStream); /* +1 = 10 */
        _featureMask = (_featureMask << 16) | ReadUnsignedShort(inputStream); /* +2 = 12 */
        _expression = ReadInt16BigEndianSigned(inputStream); /* +2 = 14 */
        _poseAngle = new int[3];
        _poseAngle[YAW] = ReadUnsignedByte(inputStream); /* +1 = 15 */
        _poseAngle[PITCH] = ReadUnsignedByte(inputStream); /* +1 = 16 */
        _poseAngle[ROLL] = ReadUnsignedByte(inputStream); /* +1 = 17 */
        _poseAngleUncertainty = new int[3];
        _poseAngleUncertainty[YAW] = ReadUnsignedByte(inputStream); /* +1 = 18 */
        _poseAngleUncertainty[PITCH] = ReadUnsignedByte(inputStream); /* +1 = 19 */
        _poseAngleUncertainty[ROLL] = ReadUnsignedByte(inputStream); /* +1 = 20 */

        /* Feature Point(s) (optional) (8 * featurePointCount), see ISO 19794-5 5.8 */
        _featurePoints = new FeaturePoint[featurePointCount];
        for (int i = 0; i < featurePointCount; i++)
        {
            int featureType = ReadUnsignedByte(inputStream); /* 1 */
            byte featurePointCode = (byte)ReadUnsignedByte(inputStream); /* +1 = 2 */
            int x = ReadUnsignedShort(inputStream); /* +2 = 4 */
            int y = ReadUnsignedShort(inputStream); /* +2 = 6 */
            _ = ReadUnsignedShort(inputStream); /* +2 = 8, NOTE: 2 bytes reserved */
            _featurePoints[i] = new FeaturePoint(featureType, featurePointCode, x, y);
        }

        /* Image Information */
        _faceImageType = ReadUnsignedByte(inputStream); /* 1 */
        _imageDataType = ReadUnsignedByte(inputStream); /* +1 = 2 */
        SetWidth(ReadUnsignedShort(inputStream)); /* +2 = 4 */
        SetHeight(ReadUnsignedShort(inputStream)); /* +2 = 6 */
        _colorSpace = ReadUnsignedByte(inputStream); /* +1 = 7 */
        _sourceType = ReadUnsignedByte(inputStream); /* +1 = 8 */
        _deviceType = ReadUnsignedShort(inputStream); /* +2 = 10 */
        _quality = ReadUnsignedShort(inputStream); /* +2 = 12 */

        /* Temporarily fix width and height if 0. */
        if (GetWidth() <= 0)
        {
            SetWidth(800);
        }
        if (GetHeight() <= 0)
        {
            SetHeight(600);
        }

        /* Read image data, image data type code based on Section 5.8.1 ISO 19794-5. */
        SetMimeType(ToMimeType(_imageDataType));
        long imageLength = _recordLength - 20 - (8 * featurePointCount) - 12;

        ReadImage(inputStream, imageLength);
    }

    /// <summary>Writes this face image info to output stream.</summary>
    protected override void WriteObject(Stream outputStream)
    {
        using var recordOut = new MemoryStream();
        WriteFacialRecordData(recordOut);
        byte[] facialRecordData = recordOut.ToArray();
        long faceImageBlockLength = facialRecordData.Length + 4L;
        WriteInt32BigEndian(outputStream, unchecked((int)(faceImageBlockLength & 0xFFFFFFFFL)));
        outputStream.Write(facialRecordData, 0, facialRecordData.Length);
        outputStream.Flush();
    }

    /// <summary>
    /// Writes this face image info to a stream. Forwards to the protected <see cref="WriteObject(Stream)"/>
    /// override. Java's <c>FaceImageInfo.writeObject(...)</c> is actually declared <c>public</c> there
    /// (widening the base class's <c>protected</c> signature -- legal in Java), so
    /// <c>FaceInfo.writeObject(...)</c> can call <c>faceImageInfo.writeObject(dataOut)</c> directly. C#
    /// does not allow an override to widen accessibility (unlike Java), so <see cref="FaceInfo"/> (an
    /// unrelated type) needs this <c>internal</c> forwarder instead -- same pattern as
    /// <c>FingerImageInfo.WriteFingerImageObject</c> and <c>DisplayedImageInfo.WriteObject(TlvOutputStream)</c>.
    /// </summary>
    internal void WriteFaceImageObject(Stream outputStream) => WriteObject(outputStream);

    /// <summary>Returns the record length.</summary>
    public override long GetRecordLength() =>
        /* Should be equal to (20 + 8 * featurePoints.length + 12 + getImageLength()). */
        _recordLength;

    /// <summary>
    /// Returns the available feature points of this face. NOTE: preserved Java quirk -- unlike
    /// <see cref="GetPoseAngle"/>/<see cref="GetPoseAngleUncertainty"/> below (which defensively copy),
    /// Java's <c>getFeaturePoints()</c> returns the live internal array, not a copy; ported as-is.
    /// </summary>
    public FeaturePoint[] GetFeaturePoints() => _featurePoints;

    /// <summary>Returns the expression (neutral, smiling, eyebrow raised, etc).</summary>
    public int GetExpression() => _expression;

    /// <summary>Returns the eye color (black, blue, brown, etc).</summary>
    public EyeColor GetEyeColor() => _eyeColor;

    /// <summary>Returns the gender (male, female, etc).</summary>
    public Gender GetGender() => _gender;

    /// <summary>Returns the hair color (bald, black, blonde, etc).</summary>
    public int GetHairColor() => _hairColor;

    /// <summary>Returns the face image type (full frontal, token frontal, etc).</summary>
    public int GetFaceImageType() => _faceImageType;

    /// <summary>Returns the feature mask.</summary>
    public int GetFeatureMask() => _featureMask;

    /// <summary>Returns the quality as unsigned integer.</summary>
    public int GetQuality() => _quality;

    /// <summary>Returns the source type (camera, scanner, etc).</summary>
    public int GetSourceType() => _sourceType;

    /// <summary>Returns the image data type.</summary>
    public int GetImageDataType() => _imageDataType;

    /// <summary>Returns the image color space (rgb, grayscale, etc).</summary>
    public int GetColorSpace() => _colorSpace;

    /// <summary>Returns the device type.</summary>
    public int GetDeviceType() => _deviceType;

    /// <summary>Returns the pose angle as an integer array of length 3, containing yaw, pitch, and roll angle in encoded form.</summary>
    public int[] GetPoseAngle()
    {
        int[] result = new int[3];
        Array.Copy(_poseAngle, 0, result, 0, result.Length);
        return result;
    }

    /// <summary>Returns the pose angle uncertainty as an integer array of length 3, containing yaw, pitch, and roll angle uncertainty.</summary>
    public int[] GetPoseAngleUncertainty()
    {
        int[] result = new int[3];
        Array.Copy(_poseAngleUncertainty, 0, result, 0, result.Length);
        return result;
    }

    /// <summary>Generates a textual representation of this object.</summary>
    public override string ToString()
    {
        var outSb = new System.Text.StringBuilder();
        outSb.Append("FaceImageInfo [");
        outSb.Append("Image size: ").Append(GetWidth()).Append(" x ").Append(GetHeight()).Append(", ");
        outSb.Append("Gender: ").Append(_gender).Append(", ");
        outSb.Append("Eye color: ").Append(_eyeColor).Append(", ");
        outSb.Append("Hair color: ").Append(HairColorToString()).Append(", ");
        outSb.Append("Feature mask: ").Append(FeatureMaskToString()).Append(", ");
        outSb.Append("Expression: ").Append(ExpressionToString()).Append(", ");
        outSb.Append("Pose angle: ").Append(PoseAngleToString()).Append(", ");
        outSb.Append("Face image type: ").Append(FaceImageTypeToString()).Append(", ");
        outSb.Append("Source type: ").Append(SourceTypeToString()).Append(", ");
        outSb.Append("FeaturePoints [");
        if (_featurePoints.Length > 0)
        {
            bool isFirstFeaturePoint = true;
            foreach (FeaturePoint featurePoint in _featurePoints)
            {
                if (isFirstFeaturePoint)
                {
                    isFirstFeaturePoint = false;
                }
                else
                {
                    outSb.Append(", ");
                }
                outSb.Append(featurePoint.ToString());
            }
        }
        outSb.Append(']'); /* FeaturePoints. */
        outSb.Append(']'); /* FaceImageInfo. */
        return outSb.ToString();
    }

    public override int GetHashCode()
    {
        const int prime = 31;
        int result = base.GetHashCode();
        result = (prime * result) + _colorSpace;
        result = (prime * result) + _deviceType;
        result = (prime * result) + _expression;
        result = (prime * result) + _eyeColor.GetHashCode();
        result = (prime * result) + _faceImageType;
        result = (prime * result) + _featureMask;
        result = (prime * result) + ArrayHashCode(_featurePoints);
        result = (prime * result) + _gender.GetHashCode();
        result = (prime * result) + _hairColor;
        result = (prime * result) + _imageDataType;
        result = (prime * result) + IntArrayHashCode(_poseAngle);
        result = (prime * result) + IntArrayHashCode(_poseAngleUncertainty);
        result = (prime * result) + _quality;
        result = (prime * result) + (int)(_recordLength ^ (_recordLength >>> 32));
        result = (prime * result) + _sourceType;
        return result;
    }

    public override bool Equals(object? obj)
    {
        if (ReferenceEquals(this, obj))
        {
            return true;
        }
        if (!base.Equals(obj))
        {
            return false;
        }
        if (obj is null || GetType() != obj.GetType())
        {
            return false;
        }

        var other = (FaceImageInfo)obj;
        return _colorSpace == other._colorSpace
            && _deviceType == other._deviceType
            && _expression == other._expression
            && _eyeColor == other._eyeColor
            && _faceImageType == other._faceImageType
            && _featureMask == other._featureMask
            && _featurePoints.AsSpan().SequenceEqual(other._featurePoints) /* NOTE: identity-based, see FeaturePoint remarks */
            && _gender == other._gender
            && _hairColor == other._hairColor
            && _imageDataType == other._imageDataType
            && _poseAngle.AsSpan().SequenceEqual(other._poseAngle)
            && _poseAngleUncertainty.AsSpan().SequenceEqual(other._poseAngleUncertainty)
            && _quality == other._quality
            && _recordLength == other._recordLength
            && _sourceType == other._sourceType;
    }

    /* ONLY PRIVATE METHODS BELOW */

    /// <summary>Writes the record data to a stream.</summary>
    private void WriteFacialRecordData(Stream outputStream)
    {
        /* Facial Information (16) */
        WriteUnsignedShort(outputStream, _featurePoints.Length);                                     /* 2 */
        outputStream.WriteByte((byte)GenderToCode(_gender));                                          /* 1 */
        outputStream.WriteByte((byte)(int)_eyeColor);                                                 /* 1 */
        outputStream.WriteByte((byte)_hairColor);                                                    /* 1 */
        outputStream.WriteByte((byte)((_featureMask & 0xFF0000) >> 16));                             /* 1 */
        outputStream.WriteByte((byte)((_featureMask & 0x00FF00) >> 8));                              /* 1 */
        outputStream.WriteByte((byte)(_featureMask & 0x0000FF));                                     /* 1 */
        WriteUnsignedShort(outputStream, _expression);                                               /* 2 */
        for (int i = 0; i < 3; i++)                                                                  /* 3 */
        {
            outputStream.WriteByte((byte)_poseAngle[i]);
        }
        for (int i = 0; i < 3; i++)                                                                  /* 3 */
        {
            outputStream.WriteByte((byte)_poseAngleUncertainty[i]);
        }

        /* Feature Point(s) (optional) (8 * featurePointCount) */
        foreach (FeaturePoint fp in _featurePoints)
        {
            outputStream.WriteByte((byte)fp.GetPointType());
            outputStream.WriteByte((byte)((fp.GetMajorCode() << 4) | fp.GetMinorCode()));
            WriteUnsignedShort(outputStream, fp.GetX());
            WriteUnsignedShort(outputStream, fp.GetY());
            WriteUnsignedShort(outputStream, 0x00); /* 2 bytes RFU */
        }

        /* Image Information (12) */
        outputStream.WriteByte((byte)_faceImageType);   /* 1 */
        outputStream.WriteByte((byte)_imageDataType);    /* 1 */
        WriteUnsignedShort(outputStream, GetWidth());    /* 2 */
        WriteUnsignedShort(outputStream, GetHeight());   /* 2 */
        outputStream.WriteByte((byte)_colorSpace);       /* 1 */
        outputStream.WriteByte((byte)_sourceType);       /* 1 */
        WriteUnsignedShort(outputStream, _deviceType);   /* 2 */
        WriteUnsignedShort(outputStream, _quality);      /* 2 */

        /* Image data type code based on Section 5.8.1 ISO 19794-5. */
        WriteImage(outputStream);
        outputStream.Flush();
    }

    /// <summary>Converts a hair color value to a human readable string.</summary>
    private string HairColorToString() => _hairColor switch
    {
        HAIR_COLOR_UNSPECIFIED => "unspecified",
        HAIR_COLOR_BALD => "bald",
        HAIR_COLOR_BLACK => "black",
        HAIR_COLOR_BLONDE => "blonde",
        HAIR_COLOR_BROWN => "brown",
        HAIR_COLOR_GRAY => "gray",
        HAIR_COLOR_WHITE => "white",
        HAIR_COLOR_RED => "red",
        HAIR_COLOR_GREEN => "green",
        HAIR_COLOR_BLUE => "blue",
        _ => "unknown",
    };

    /// <summary>Returns a human readable string for the current feature mask.</summary>
    private string FeatureMaskToString()
    {
        if ((_featureMask & FEATURE_FEATURES_ARE_SPECIFIED_FLAG) == 0)
        {
            return "";
        }

        var features = new List<string>();
        if ((_featureMask & FEATURE_GLASSES_FLAG) != 0)
        {
            features.Add("glasses");
        }
        if ((_featureMask & FEATURE_MOUSTACHE_FLAG) != 0)
        {
            features.Add("moustache");
        }
        if ((_featureMask & FEATURE_BEARD_FLAG) != 0)
        {
            features.Add("beard");
        }
        if ((_featureMask & FEATURE_TEETH_VISIBLE_FLAG) != 0)
        {
            features.Add("teeth visible");
        }
        if ((_featureMask & FEATURE_BLINK_FLAG) != 0)
        {
            features.Add("blink");
        }
        if ((_featureMask & FEATURE_MOUTH_OPEN_FLAG) != 0)
        {
            features.Add("mouth open");
        }
        if ((_featureMask & FEATURE_LEFT_EYE_PATCH_FLAG) != 0)
        {
            features.Add("left eye patch");
        }
        if ((_featureMask & FEATURE_RIGHT_EYE_PATCH) != 0)
        {
            features.Add("right eye patch");
        }
        if ((_featureMask & FEATURE_DARK_GLASSES) != 0)
        {
            features.Add("dark glasses");
        }
        if ((_featureMask & FEATURE_DISTORTING_MEDICAL_CONDITION) != 0)
        {
            features.Add("distorting medical condition (which could impact feature point detection)");
        }

        return string.Join(", ", features);
    }

    /// <summary>Converts the current expression to a human readable string.</summary>
    private string ExpressionToString() => _expression switch
    {
        EXPRESSION_UNSPECIFIED => "unspecified",
        EXPRESSION_NEUTRAL => "neutral (non-smiling) with both eyes open and mouth closed",
        EXPRESSION_SMILE_CLOSED => "a smile where the inside of the mouth and/or teeth is not exposed (closed jaw)",
        EXPRESSION_SMILE_OPEN => "a smile where the inside of the mouth and/or teeth is exposed",
        EXPRESSION_RAISED_EYEBROWS => "raised eyebrows",
        EXPRESSION_EYES_LOOKING_AWAY => "eyes looking away from the camera",
        EXPRESSION_SQUINTING => "squinting",
        EXPRESSION_FROWNING => "frowning",
        _ => "unknown",
    };

    /// <summary>Converts the current pose angle to a human readable string.</summary>
    private string PoseAngleToString()
    {
        var outSb = new System.Text.StringBuilder();
        outSb.Append('(');
        outSb.Append("y: ").Append(_poseAngle[YAW]);
        if (_poseAngleUncertainty[YAW] != 0)
        {
            outSb.Append(" (").Append(_poseAngleUncertainty[YAW]).Append(')');
        }
        outSb.Append(", ");
        outSb.Append("p:").Append(_poseAngle[PITCH]);
        if (_poseAngleUncertainty[PITCH] != 0)
        {
            outSb.Append(" (").Append(_poseAngleUncertainty[PITCH]).Append(')');
        }
        outSb.Append(", ");
        outSb.Append("r: ").Append(_poseAngle[ROLL]);
        if (_poseAngleUncertainty[ROLL] != 0)
        {
            outSb.Append(" (").Append(_poseAngleUncertainty[ROLL]).Append(')');
        }
        outSb.Append(')');
        return outSb.ToString();
    }

    /// <summary>
    /// Returns a textual representation of the face image type (<c>"basic"</c>, <c>"full frontal"</c>,
    /// <c>"token frontal"</c>, or <c>"unknown"</c>).
    /// </summary>
    private string FaceImageTypeToString() => _faceImageType switch
    {
        FACE_IMAGE_TYPE_BASIC => "basic",
        FACE_IMAGE_TYPE_FULL_FRONTAL => "full frontal",
        FACE_IMAGE_TYPE_TOKEN_FRONTAL => "token frontal",
        _ => "unknown",
    };

    /// <summary>Returns a textual representation of the source type.</summary>
    private string SourceTypeToString() => _sourceType switch
    {
        SOURCE_TYPE_UNSPECIFIED => "unspecified",
        SOURCE_TYPE_STATIC_PHOTO_UNKNOWN_SOURCE => "static photograph from an unknown source",
        SOURCE_TYPE_STATIC_PHOTO_DIGITAL_CAM => "static photograph from a digital still-image camera",
        SOURCE_TYPE_STATIC_PHOTO_SCANNER => "static photograph from a scanner",
        SOURCE_TYPE_VIDEO_FRAME_UNKNOWN_SOURCE => "single video frame from an unknown source",
        SOURCE_TYPE_VIDEO_FRAME_ANALOG_CAM => "single video frame from an analogue camera",
        SOURCE_TYPE_VIDEO_FRAME_DIGITAL_CAM => "single video frame from a digital camera",
        _ => "unknown",
    };

    /// <summary>Returns a mime-type string for the compression algorithm code, or <c>null</c> for an unrecognized code.</summary>
    /// <param name="compressionAlg">the compression algorithm code as it occurs in the header</param>
    private static string? ToMimeType(int compressionAlg) => compressionAlg switch
    {
        IMAGE_DATA_TYPE_JPEG => ImageInfo.JPEG_MIME_TYPE,
        IMAGE_DATA_TYPE_JPEG2000 => ImageInfo.JPEG2000_MIME_TYPE,
        // NOTE: Java logs a warning here ("Unknown image type: ..."); omitted per precedent (see
        // D:\GIT\nMRTD\src\nMRTD\Lds\Icao\DG11File.cs and porting-conventions.md).
        _ => null,
    };

    /// <summary>Returns an eye color value for the given ISO 19794-5 code, defaulting to <see cref="EyeColor.Unknown"/>.</summary>
    private static EyeColor ToEyeColor(int code) => Enum.IsDefined(typeof(EyeColor), code) ? (EyeColor)code : EyeColor.Unknown;

    /// <summary>
    /// Maps the ISO/IEC 19794-5 Table 3 (Section 5.5.3) gender code to <see cref="Gender"/>.
    /// This is a local, spec-scoped mapping (not a general <c>Gender.getInstance(int)</c> port -- see
    /// the remark on <see cref="Gender"/> for why).
    /// </summary>
    private static Gender GenderFromCode(int code) => code switch
    {
        0x00 => SmartCards.Gender.Unspecified,
        0x01 => SmartCards.Gender.Male,
        0x02 => SmartCards.Gender.Female,
        _ => SmartCards.Gender.Unknown, /* includes 0xFF */
    };

    /// <summary>Inverse of <see cref="GenderFromCode"/>, for encoding.</summary>
    private static int GenderToCode(Gender gender) => gender switch
    {
        SmartCards.Gender.Unspecified => 0x00,
        SmartCards.Gender.Male => 0x01,
        SmartCards.Gender.Female => 0x02,
        _ => 0xFF, /* Unknown or any other value */
    };

    /// <summary>Java <c>Arrays.hashCode(Object[])</c> equivalent: identity-based per-element hash (see <see cref="FeaturePoint"/> remarks).</summary>
    private static int ArrayHashCode(FeaturePoint[] array)
    {
        int result = 1;
        foreach (FeaturePoint element in array)
        {
            result = (31 * result) + element.GetHashCode();
        }
        return result;
    }

    /// <summary>Java <c>Arrays.hashCode(int[])</c> equivalent.</summary>
    private static int IntArrayHashCode(int[] array)
    {
        int result = 1;
        foreach (int element in array)
        {
            result = (31 * result) + element;
        }
        return result;
    }

    /* Minimal big-endian binary I/O helpers (this port has no shared DataInputStream/DataOutputStream
     * equivalent; see the smaller sibling set in FingerImageInfo.cs and FingerInfo.cs). */

    private static int ReadUnsignedByte(Stream inputStream)
    {
        int b = inputStream.ReadByte();
        if (b < 0)
        {
            throw new EndOfStreamException();
        }
        return b;
    }

    private static int ReadUnsignedShort(Stream inputStream)
    {
        int hi = ReadUnsignedByte(inputStream);
        int lo = ReadUnsignedByte(inputStream);
        return (hi << 8) | lo;
    }

    /// <summary>Reads a big-endian signed 16-bit value, matching Java's <c>DataInputStream.readShort()</c>.</summary>
    private static int ReadInt16BigEndianSigned(Stream inputStream)
    {
        int hi = ReadUnsignedByte(inputStream);
        int lo = ReadUnsignedByte(inputStream);
        return (short)((hi << 8) | lo);
    }

    private static long ReadUInt32BigEndian(Stream inputStream)
    {
        long result = 0;
        for (int i = 0; i < 4; i++)
        {
            result = (result << 8) | (uint)ReadUnsignedByte(inputStream);
        }
        return result;
    }

    private static void WriteUnsignedShort(Stream outputStream, int value)
    {
        outputStream.WriteByte((byte)((value >> 8) & 0xFF));
        outputStream.WriteByte((byte)(value & 0xFF));
    }

    private static void WriteInt32BigEndian(Stream outputStream, int value)
    {
        outputStream.WriteByte((byte)((value >> 24) & 0xFF));
        outputStream.WriteByte((byte)((value >> 16) & 0xFF));
        outputStream.WriteByte((byte)((value >> 8) & 0xFF));
        outputStream.WriteByte((byte)(value & 0xFF));
    }
}
