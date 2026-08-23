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
using nMRTD.Cbeff;

namespace nMRTD.Lds.Iso39794;

//  IrisImageDataBlock ::= [APPLICATION 6] SEQUENCE {
//    versionBlock         [0]   VersionBlock,
//    representationBlocks [1]   RepresentationBlocks,
//    ...
//  }

/// <summary>
/// Port of <c>org.jmrtd.lds.iso39794.IrisImageDataBlock</c>. Java's <c>Serializable</c> marker is dropped
/// (no reflection-based serialization is needed in this port).
///
/// ADAPTATION: Java's version is a top-level <c>public class</c>; this port now matches that, since
/// <c>nMRTD.Lds.Icao.DG4File</c>'s public <c>CreateISO39794DG4File(List&lt;IrisImageDataBlock&gt;, ...)</c>
/// factory methods need to name this type by value (see <see cref="Block"/>'s doc comment for why this
/// required widening <c>Block</c> itself too). Unlike <c>FaceImageDataBlock</c>/<c>FingerImageDataBlock</c>,
/// this class never had a "build from parts" public constructor to reconcile.
/// <see cref="GetVersionBlock"/>/<see cref="GetRepresentationBlocks"/> are <c>internal</c>, since their
/// <c>VersionBlock</c>/<c>List&lt;IrisImageRepresentationBlock&gt;</c> return types remain <c>internal</c>
/// (a public method cannot have a less-accessible return type -- CS0051).
/// </summary>
public class IrisImageDataBlock : Block, BiometricDataBlock
{
    private StandardBiometricHeader? _sbh;

    private readonly VersionBlock _versionBlock;

    private readonly List<IrisImageRepresentationBlock> _representationBlocks;

    public IrisImageDataBlock(Stream inputStream)
        : this(null, inputStream)
    {
    }

    public IrisImageDataBlock(StandardBiometricHeader? sbh, Stream inputStream)
        : this(sbh, ASN1Util.ReadAsn1Object(inputStream))
    {
    }

    internal IrisImageDataBlock(StandardBiometricHeader? sbh, Asn1Encodable asn1Encodable)
    {
        _sbh = sbh;
        Asn1Encodable baseObject = ASN1Util.CheckTag(asn1Encodable, Asn1Tags.Application, 6);
        if (baseObject is not Asn1Sequence)
        {
            throw new ArgumentException("Cannot decode!");
        }

        Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(baseObject);

        _versionBlock = new VersionBlock(taggedObjects[0]);

        _representationBlocks = IrisImageRepresentationBlock.DecodeRepresentationBlocks(taggedObjects[1]);
    }

    internal VersionBlock GetVersionBlock() => _versionBlock;

    internal List<IrisImageRepresentationBlock> GetRepresentationBlocks() => _representationBlocks;

    /// <summary>Returns the standard biometric header of this iris info.</summary>
    /// <returns>the standard biometric header</returns>
    public StandardBiometricHeader GetStandardBiometricHeader()
    {
        if (_sbh == null)
        {
            byte[] biometricType = { (byte)CBEFFInfo<BiometricDataBlock>.BIOMETRIC_TYPE_IRIS };
            byte[] biometricSubtype = { (byte)GetBiometricSubtype() };
            byte[] formatOwner =
            {
                (byte)((StandardBiometricHeader.JTC1_SC37_FORMAT_OWNER_VALUE & 0xFF00) >> 8),
                (byte)(StandardBiometricHeader.JTC1_SC37_FORMAT_OWNER_VALUE & 0xFF),
            };
            byte[] formatType =
            {
                (byte)((StandardBiometricHeader.ISO_39794_IRIS_IMAGE_FORMAT_TYPE_VALUE & 0xFF00) >> 8),
                (byte)(StandardBiometricHeader.ISO_39794_IRIS_IMAGE_FORMAT_TYPE_VALUE & 0xFF),
            };

            var elements = new SortedDictionary<int, byte[]>
            {
                [ISO781611.BIOMETRIC_TYPE_TAG] = biometricType,
                [ISO781611.BIOMETRIC_SUBTYPE_TAG] = biometricSubtype,
                [ISO781611.FORMAT_OWNER_TAG] = formatOwner,
                [ISO781611.FORMAT_TYPE_TAG] = formatType,
            };

            _sbh = new StandardBiometricHeader(elements);
        }

        return _sbh;
    }

    public override int GetHashCode() =>
        JavaObjectsHash(JavaListHashCode(_representationBlocks), _sbh?.GetHashCode() ?? 0, _versionBlock.GetHashCode());

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

        var otherBlock = (IrisImageDataBlock)other;
        return ListEquals(_representationBlocks, otherBlock._representationBlocks)
            && Equals(_sbh, otherBlock._sbh)
            && Equals(_versionBlock, otherBlock._versionBlock);
    }

    public override string ToString() =>
        "IrisImageDataBlock ["
        + $"sbh: {_sbh?.ToString() ?? "null"}"
        + $", versionBlock: {_versionBlock}"
        + $", representationBlocks: {JavaListToString(_representationBlocks)}"
        + "]";

    /* PACKAGE */

    internal override Asn1Encodable GetAsn1Object() => GetAsn1Object(ISO39794EncodingProfile.Base);

    internal override Asn1Encodable GetAsn1Object(ISO39794EncodingProfile profile)
    {
        var taggedObjects = new Dictionary<int, Asn1Encodable>
        {
            [0] = _versionBlock.GetAsn1Object(),
            [1] = ISO39794Util.EncodeBlocks([.. _representationBlocks.Cast<Block>()], profile)!,
        };
        return new DerTaggedObject(false, Asn1Tags.Application, 0x06, ASN1Util.EncodeTaggedObjects(taggedObjects)!);
    }

    /* PRIVATE */

    /// <summary>Returns the biometric sub-type bit mask for the iris images.</summary>
    /// <returns>a biometric sub-type bit mask</returns>
    private int GetBiometricSubtype()
    {
        int result = CBEFFInfo<BiometricDataBlock>.BIOMETRIC_SUBTYPE_NONE;
        bool isFirst = true;

        List<IrisImageRepresentationBlock> blocks = GetRepresentationBlocks();
        foreach (IrisImageRepresentationBlock block in blocks)
        {
            int subType = block.GetBiometricSubtype();
            if (isFirst)
            {
                result = subType;
                isFirst = false;
            }
            else
            {
                result &= subType;
            }
        }

        return result;
    }

    private static string JavaListToString<T>(List<T>? list) => list == null ? "null" : $"[{string.Join(", ", list)}]";

    private static bool ListEquals<T>(List<T>? list1, List<T>? list2)
    {
        if (ReferenceEquals(list1, list2))
        {
            return true;
        }
        if (list1 == null || list2 == null)
        {
            return false;
        }

        return list1.SequenceEqual(list2);
    }

    /// <summary>Java-style content-based <c>List.hashCode()</c> (the <c>AbstractList</c> contract).</summary>
    private static int JavaListHashCode<T>(List<T>? list)
    {
        if (list == null)
        {
            return 0;
        }

        int hash = 1;
        foreach (T? element in list)
        {
            hash = (31 * hash) + (element?.GetHashCode() ?? 0);
        }

        return hash;
    }

    /// <summary>Java-style <c>Objects.hash(Object...)</c> (== <c>Arrays.hashCode(Object[])</c>): 1, then
    /// <c>31*hash + elementHash</c> per already-computed element hash, in order.</summary>
    private static int JavaObjectsHash(params int[] elementHashes)
    {
        int result = 1;
        foreach (int elementHash in elementHashes)
        {
            result = (31 * result) + elementHash;
        }

        return result;
    }
}
