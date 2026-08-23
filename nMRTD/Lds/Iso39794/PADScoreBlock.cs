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

//  PADScoreBlock ::=       SEQUENCE {
//    mechanismIdBlock                [0] RegistryIdBlock,
//    scoreOrError                    [1] ScoreOrError,
//    ...
//  }

//  QualityBlocks ::= SEQUENCE OF PADScoreBlock

/// <summary>
/// Port of <c>org.jmrtd.lds.iso39794.PADScoreBlock</c>. Java's <c>Serializable</c> marker is dropped (no
/// reflection-based serialization is needed in this port).
///
/// ADAPTATION: Java's version is also a top-level <c>public class</c>, but this is <c>internal</c> since its
/// base class <see cref="Block"/> is <c>internal</c> in this port (see <c>VersionBlock</c>'s doc comment).
/// </summary>
internal class PADScoreBlock : Block
{
    private readonly RegistryIdBlock _mechanismIdBlock;
    private readonly ScoreOrError _scoreOrError;

    public PADScoreBlock(RegistryIdBlock mechanismIdBlock, int score)
        : this(mechanismIdBlock, score >= 0 ? new ScoreOrError(score) : new ScoreOrError(ScoreOrError.ScoringErrorCode.FailureToAssess))
    {
    }

    public PADScoreBlock(RegistryIdBlock mechanismIdBlock, ScoreOrError scoreOrError)
    {
        ArgumentNullException.ThrowIfNull(scoreOrError);
        _mechanismIdBlock = mechanismIdBlock;
        _scoreOrError = scoreOrError;
    }

    internal PADScoreBlock(Asn1Encodable asn1Encodable)
    {
        Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
        _mechanismIdBlock = new RegistryIdBlock(taggedObjects[0]);
        _scoreOrError = new ScoreOrError(taggedObjects[1]);
    }

    public RegistryIdBlock GetMechanismIdBlock() => _mechanismIdBlock;

    //  Score ::= INTEGER       (0..100)
    /* NOTE: -1 for error. */
    public int GetScore() => _scoreOrError.IsScore() ? _scoreOrError.GetScore()!.Value : -1;

    public ScoreOrError GetScoreOrError() => _scoreOrError;

    public override int GetHashCode() => HashCode.Combine(_mechanismIdBlock, _scoreOrError);

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

        var otherBlock = (PADScoreBlock)other;
        return Equals(_mechanismIdBlock, otherBlock._mechanismIdBlock) && Equals(_scoreOrError, otherBlock._scoreOrError);
    }

    public override string ToString() =>
        $"PADScoreBlock [mechanismIdBlock: {_mechanismIdBlock}, scoreOrError: {_scoreOrError}]";

    internal override Asn1Encodable GetAsn1Object() => GetAsn1Object(ISO39794EncodingProfile.Base);

    internal override Asn1Encodable GetAsn1Object(ISO39794EncodingProfile profile)
    {
        var taggedObjects = new Dictionary<int, Asn1Encodable>
        {
            [0] = _mechanismIdBlock.GetAsn1Object(),
            [1] = _scoreOrError.GetAsn1Object(profile),
        };
        return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
    }

    /* PACKAGE */

    internal static List<PADScoreBlock> DecodePADScoreBlocks(Asn1Encodable asn1Encodable)
    {
        if (ASN1Util.IsSequenceOfSequences(asn1Encodable))
        {
            List<Asn1Encodable> blockAsn1Objects = ASN1Util.List(asn1Encodable)!;
            var blocks = new List<PADScoreBlock>(blockAsn1Objects.Count);
            foreach (Asn1Encodable blockAsn1Object in blockAsn1Objects)
            {
                blocks.Add(new PADScoreBlock(blockAsn1Object));
            }

            return blocks;
        }

        return [new PADScoreBlock(asn1Encodable)];
    }
}
