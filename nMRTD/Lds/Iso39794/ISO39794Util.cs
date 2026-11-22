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
/// Port of <c>org.jmrtd.lds.iso39794.ISO39794Util</c>: shared ASN.1 encode/decode helpers for the "choice
/// with extension-block fallback" pattern and block-list encoding used throughout this package. Java's
/// version is package-private; ported as <c>internal</c>.
/// </summary>
internal static class ISO39794Util
{
    public static int? DecodeCodeFromChoiceExtensionBlockFallback(Asn1Encodable asn1Encodable)
    {
        Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
        if (taggedObjects.TryGetValue(0, out Asn1Encodable? direct))
        {
            return ASN1Util.DecodeInt(direct);
        }

        if (taggedObjects.TryGetValue(1, out Asn1Encodable? extensionBlock))
        {
            Dictionary<int, Asn1Encodable> extensionTaggedObjects = ASN1Util.DecodeTaggedObjects(extensionBlock);
            /* Fallback. */
            return ASN1Util.DecodeInt(extensionTaggedObjects[0]);
        }

        return null;
    }

    public static Asn1Encodable EncodeCodeAsChoiceExtensionBlockFallback(int code) =>
        EncodeCodeAsChoiceExtensionBlockFallback(code, useExtensionBlock: false);

    public static Asn1Encodable EncodeCodeAsChoiceExtensionBlockFallback(int code, ISO39794EncodingProfile profile, ChoiceType choiceType) =>
        EncodeCodeAsChoiceExtensionBlockFallback(code, profile.UsesExtensionBlockFallback(choiceType));

    private static DerSequence EncodeCodeAsChoiceExtensionBlockFallback(int code, bool useExtensionBlock)
    {
        if (!useExtensionBlock)
        {
            return new DerSequence(new DerTaggedObject(false, 0, ASN1Util.EncodeInt(code)));
        }

        Asn1Encodable fallback = new DerSequence(new DerTaggedObject(false, 0, ASN1Util.EncodeInt(code)));
        return new DerSequence(new DerTaggedObject(false, 1, fallback));
    }

    public static Asn1Encodable? EncodeBlocks(List<Block>? blocks) => EncodeBlocks(blocks, ISO39794EncodingProfile.Base);

    public static Asn1Encodable? EncodeBlocks(List<Block>? blocks, ISO39794EncodingProfile profile)
    {
        if (blocks == null)
        {
            return null;
        }

        var asn1Objects = new List<Asn1Encodable>(blocks.Count);
        foreach (Block? block in blocks)
        {
            if (block != null)
            {
                asn1Objects.Add(block.GetAsn1Object(profile));
            }
        }

        return new DerSequence(asn1Objects.ToArray());
    }
}
