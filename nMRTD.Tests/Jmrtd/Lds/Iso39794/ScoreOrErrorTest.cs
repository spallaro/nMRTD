using System.Text;
using nMRTD.Cbeff;
using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.Lds.Iso19794;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using nMRTD.Tests.Jmrtd.Lds.Icao;
using nMRTD.Lds.Iso39794;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;

namespace nMRTD.Tests.Jmrtd.Lds.Iso39794;

/// <summary>Port of JMRTD's <c>org.jmrtd.lds.iso39794.ScoreOrErrorTest</c>.</summary>
/// <remarks>ADAPTATION: Java's <c>getASN1Object(true)</c> (extension block fallback) is the ICAO 39794-5 eMRTD profile here.</remarks>
public class ScoreOrErrorTest
{

    [Fact]
    public void testScore()
    {
        ScoreOrError scoreOrError = new ScoreOrError(99);

        Assert.True(scoreOrError.IsScore());
        Assert.False(scoreOrError.IsError());
        Assert.Equal(99, scoreOrError.GetScore());
        Assert.Null(scoreOrError.GetErrorCode());
        Assert.Equal(scoreOrError, new ScoreOrError(scoreOrError.GetAsn1Object()));
    }

    [Fact]
    public void testFailureToAssessUsingBaseEncoding()
    {
        ScoreOrError scoreOrError = new ScoreOrError(ScoreOrError.ScoringErrorCode.FailureToAssess);

        Assert.False(scoreOrError.IsScore());
        Assert.True(scoreOrError.IsError());
        Assert.Null(scoreOrError.GetScore());
        Assert.Equal(ScoreOrError.ScoringErrorCode.FailureToAssess, scoreOrError.GetErrorCode());
        Assert.Equal(scoreOrError, new ScoreOrError(scoreOrError.GetAsn1Object()));
    }

    [Fact]
    public void testFailureToAssessUsingExtensionFallbackEncoding()
    {
        ScoreOrError scoreOrError = new ScoreOrError(ScoreOrError.ScoringErrorCode.FailureToAssess);

        Assert.Equal(scoreOrError, new ScoreOrError(scoreOrError.GetAsn1Object(ISO39794EncodingProfile.Icao39794_5EmrtdV1)));
        Assert.False(Enumerable.SequenceEqual(scoreOrError.GetAsn1Object().ToAsn1Object().GetEncoded(),
                scoreOrError.GetAsn1Object(ISO39794EncodingProfile.Icao39794_5EmrtdV1).ToAsn1Object().GetEncoded()));
    }

    [Fact]
    public void testLegacyQualityBlockErrorValue()
    {
        QualityBlock qualityBlock = new QualityBlock(new RegistryIdBlock(1, 1), -1);
        QualityBlock reconstructed = new QualityBlock(qualityBlock.GetAsn1Object());

        Assert.Equal(qualityBlock, reconstructed);
        Assert.Equal(-1, reconstructed.GetScore());
        Assert.Equal(ScoreOrError.ScoringErrorCode.FailureToAssess, reconstructed.GetScoreOrError().GetErrorCode());
    }

    [Fact]
    public void testLegacyPADScoreBlockErrorValue()
    {
        PADScoreBlock scoreBlock = new PADScoreBlock(new RegistryIdBlock(1, 1), -1);
        PADScoreBlock reconstructed = new PADScoreBlock(scoreBlock.GetAsn1Object());

        Assert.Equal(scoreBlock, reconstructed);
        Assert.Equal(-1, reconstructed.GetScore());
        Assert.Equal(ScoreOrError.ScoringErrorCode.FailureToAssess, reconstructed.GetScoreOrError().GetErrorCode());
    }

    [Fact]
    public void testFingerSegmentFailureToAssessIsNotAbsent()
    {
        FingerImageSegmentBlock segmentBlock = new FingerImageSegmentBlock(
                FingerImagePositionCode.RightIndexFinger,
                new List<CoordinateCartesian2DUnsignedShortBlock> { new CoordinateCartesian2DUnsignedShortBlock(0, 0),
                        new CoordinateCartesian2DUnsignedShortBlock(1, 1) },
                null, null, new ScoreOrError(ScoreOrError.ScoringErrorCode.FailureToAssess));
        FingerImageSegmentBlock reconstructed = new FingerImageSegmentBlock(segmentBlock.GetAsn1Object());

        Assert.Equal(segmentBlock, reconstructed);
        Assert.True(reconstructed.GetConfidenceScoreOrError()!.IsError());
        Assert.Equal(ScoreOrError.ScoringErrorCode.FailureToAssess,
                reconstructed.GetConfidenceScoreOrError()!.GetErrorCode()!);
    }
}
