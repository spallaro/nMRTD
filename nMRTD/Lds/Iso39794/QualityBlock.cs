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

//  QualityBlock ::= SEQUENCE {
//    algorithmIdBlock                [0] RegistryIdBlock,
//    scoreOrError                    [1] ScoreOrError,
//    ...
//  }

//  QualityBlocks ::= SEQUENCE OF QualityBlock

/// <summary>
/// Port of <c>org.jmrtd.lds.iso39794.QualityBlock</c>. Java's <c>Serializable</c> marker is dropped (no
/// reflection-based serialization is needed in this port).
/// </summary>
public class QualityBlock : Block
{
    private readonly RegistryIdBlock _algorithmIdBlock;
    private readonly ScoreOrError _scoreOrError;

    public QualityBlock(RegistryIdBlock algorithmIdBlock, int score)
        : this(algorithmIdBlock, score >= 0 ? new ScoreOrError(score) : new ScoreOrError(ScoreOrError.ScoringErrorCode.FailureToAssess))
    {
    }

    public QualityBlock(RegistryIdBlock algorithmIdBlock, ScoreOrError scoreOrError)
    {
        ArgumentNullException.ThrowIfNull(scoreOrError);
        _algorithmIdBlock = algorithmIdBlock;
        _scoreOrError = scoreOrError;
    }

    internal QualityBlock(Asn1Encodable asn1Encodable)
    {
        Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
        _algorithmIdBlock = new RegistryIdBlock(taggedObjects[0]);
        _scoreOrError = new ScoreOrError(taggedObjects[1]);
    }

    public RegistryIdBlock GetAlgorithmIdBlock() => _algorithmIdBlock;

    public int GetScore() => _scoreOrError.IsScore() ? _scoreOrError.GetScore()!.Value : -1;

    public ScoreOrError GetScoreOrError() => _scoreOrError;

    public override int GetHashCode() => HashCode.Combine(_algorithmIdBlock, _scoreOrError);

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

        var otherBlock = (QualityBlock)other;
        return Equals(_algorithmIdBlock, otherBlock._algorithmIdBlock) && Equals(_scoreOrError, otherBlock._scoreOrError);
    }

    public override string ToString() =>
        $"QualityBlock [algorithmIdBlock: {_algorithmIdBlock}, scoreOrError: {_scoreOrError}]";

    internal override Asn1Encodable GetAsn1Object() => GetAsn1Object(ISO39794EncodingProfile.Base);

    internal override Asn1Encodable GetAsn1Object(ISO39794EncodingProfile profile)
    {
        var taggedObjects = new Dictionary<int, Asn1Encodable>
        {
            [0] = _algorithmIdBlock.GetAsn1Object(),
            [1] = _scoreOrError.GetAsn1Object(profile),
        };
        return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
    }

    /* PACKAGE */

    internal static List<QualityBlock> DecodeQualityBlocks(Asn1Encodable asn1Encodable)
    {
        if (ASN1Util.IsSequenceOfSequences(asn1Encodable))
        {
            List<Asn1Encodable> blockAsn1Objects = ASN1Util.List(asn1Encodable)!;
            var blocks = new List<QualityBlock>(blockAsn1Objects.Count);
            foreach (Asn1Encodable blockAsn1Object in blockAsn1Objects)
            {
                blocks.Add(new QualityBlock(blockAsn1Object));
            }

            return blocks;
        }

        return [new QualityBlock(asn1Encodable)];
    }
}
