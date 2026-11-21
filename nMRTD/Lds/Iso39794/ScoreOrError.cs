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

using Org.BouncyCastle.Asn1;

namespace nMRTD.Lds.Iso39794;

/// <summary>
/// Port of <c>org.jmrtd.lds.iso39794.ScoreOrError</c>: a biometric sample quality score or an error
/// indicating that no score could be determined. Java's <c>Serializable</c> marker is dropped (no
/// reflection-based serialization is needed in this port).
///
/// Java's version is a top-level <c>public final class</c>; <c>final</c> is ported as <c>sealed</c>.
/// </summary>
public sealed class ScoreOrError : Block
{
    /// <summary>
    /// The errors defined by ISO/IEC 39794-1.
    ///
    /// ADAPTATION: Java's version is <c>enum ScoringErrorCode implements EncodableEnum&lt;ScoringErrorCode&gt;</c>,
    /// using reflection-based <c>EncodableEnum.fromCode</c> lookup keyed on each constant's own
    /// <c>getCode()</c>. C# enums cannot implement interfaces or carry methods, and reflection-based enum
    /// scanning is not AOT-friendly, so this is ported as a plain enum with explicit numeric values
    /// matching each Java constant's <c>getCode()</c> (here, declaration order and code happen to coincide:
    /// <c>FAILURE_TO_ASSESS(0)</c>). "Decode from code" is <see cref="FromCode"/> (an
    /// <see cref="Enum.IsDefined(Type, object)"/> check plus a cast); "encode to code" is just a cast to
    /// <see langword="int"/>.
    /// </summary>
    public enum ScoringErrorCode
    {
        FailureToAssess = 0,
    }

    private static ScoringErrorCode? FromCode(int code) =>
        Enum.IsDefined(typeof(ScoringErrorCode), code) ? (ScoringErrorCode)code : null;

    private readonly int? _score;
    private readonly ScoringErrorCode? _errorCode;

    /// <summary>Constructs a score.</summary>
    /// <param name="score">a value in the inclusive range 0 through 100</param>
    public ScoreOrError(int score)
    {
        if (score is < 0 or > 100)
        {
            throw new ArgumentException("Score must be in range 0 through 100");
        }

        _score = score;
        _errorCode = null;
    }

    /// <summary>Constructs a scoring error.</summary>
    /// <param name="errorCode">the scoring error</param>
    public ScoreOrError(ScoringErrorCode errorCode)
    {
        _score = null;
        _errorCode = errorCode;
    }

    internal ScoreOrError(Asn1Encodable asn1Encodable)
    {
        Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
        if (taggedObjects.TryGetValue(0, out Asn1Encodable? scoreObject))
        {
            int decodedScore = ASN1Util.DecodeInt(scoreObject);
            if (decodedScore is < 0 or > 100)
            {
                throw new ArgumentException("Score must be in range 0 through 100");
            }

            _score = decodedScore;
            _errorCode = null;
            return;
        }

        if (taggedObjects.TryGetValue(1, out Asn1Encodable? errorObject))
        {
            _score = null;
            _errorCode = DecodeScoringError(errorObject);
            return;
        }

        throw new ArgumentException("Expected score or scoring error");
    }

    public bool IsScore() => _score != null;

    public bool IsError() => _errorCode != null;

    public int? GetScore() => _score;

    public ScoringErrorCode? GetErrorCode() => _errorCode;

    public override int GetHashCode() => HashCode.Combine(_errorCode, _score);

    public override bool Equals(object? other)
    {
        if (ReferenceEquals(this, other))
        {
            return true;
        }
        if (other == null || GetType() != other.GetType())
        {
            return false;
        }

        var otherBlock = (ScoreOrError)other;
        return _errorCode == otherBlock._errorCode && _score == otherBlock._score;
    }

    public override string ToString() =>
        _score != null ? $"ScoreOrError [score: {_score}]" : $"ScoreOrError [error: {_errorCode}]";

    internal override Asn1Encodable GetAsn1Object() => GetAsn1Object(useErrorExtensionBlock: false);

    internal override Asn1Encodable GetAsn1Object(ISO39794EncodingProfile profile) =>
        GetAsn1Object(profile.UsesExtensionBlockFallback(ChoiceType.ScoringError));

    /// <summary>
    /// Encodes this value, optionally using an extension block with a fallback error code.
    /// The latter form is required by some application profiles.
    /// </summary>
    internal Asn1Encodable GetAsn1Object(bool useErrorExtensionBlock)
    {
        var taggedObjects = new Dictionary<int, Asn1Encodable>();
        if (_score != null)
        {
            taggedObjects[0] = ASN1Util.EncodeInt(_score.Value);
        }
        else
        {
            taggedObjects[1] = EncodeScoringError(useErrorExtensionBlock);
        }

        return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
    }

    private static ScoringErrorCode DecodeScoringError(Asn1Encodable asn1Encodable)
    {
        Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
        int code;
        if (taggedObjects.TryGetValue(0, out Asn1Encodable? direct))
        {
            code = ASN1Util.DecodeInt(direct);
        }
        else if (taggedObjects.TryGetValue(1, out Asn1Encodable? extensionBlockObject))
        {
            Dictionary<int, Asn1Encodable> extensionBlock = ASN1Util.DecodeTaggedObjects(extensionBlockObject);
            code = ASN1Util.DecodeInt(extensionBlock[0]);
        }
        else
        {
            throw new ArgumentException("Expected scoring error code or extension block");
        }

        ScoringErrorCode? result = FromCode(code);
        if (result == null)
        {
            throw new ArgumentException($"Unknown scoring error code {code}");
        }

        return result.Value;
    }

    private Asn1Encodable EncodeScoringError(bool useErrorExtensionBlock)
    {
        var scoringError = new Dictionary<int, Asn1Encodable>();
        if (useErrorExtensionBlock)
        {
            var extensionBlock = new Dictionary<int, Asn1Encodable>
            {
                [0] = ASN1Util.EncodeInt((int)_errorCode!.Value),
            };
            scoringError[1] = ASN1Util.EncodeTaggedObjects(extensionBlock)!;
        }
        else
        {
            scoringError[0] = ASN1Util.EncodeInt((int)_errorCode!.Value);
        }

        return ASN1Util.EncodeTaggedObjects(scoringError)!;
    }
}
