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
using BigInteger = Org.BouncyCastle.Math.BigInteger;

namespace nMRTD;

/// <summary>Port of <c>org.jmrtd.ASN1Util</c>: some low-level ASN.1 helper functions built directly on
/// BouncyCastle's <c>Org.BouncyCastle.Asn1.*</c> API (no JCA-level type involved in this file, so the
/// port is a close to line-for-line translation).</summary>
public static class ASN1Util
{
    /// <summary>Reads a single ASN.1 object from the given stream.</summary>
    public static Asn1Encodable ReadAsn1Object(Stream inputStream)
    {
        var asn1InputStream = new Asn1InputStream(inputStream);
        return asn1InputStream.ReadObject();
    }

    /// <summary>Checks whether an ASN1 object is a tagged object with a specific tag class and tag number.
    /// Throws an unchecked exception if not.</summary>
    /// <param name="asn1Encodable">the ASN1 object</param>
    /// <param name="tagClass">the expected tag class</param>
    /// <param name="tagNo">the expected tag number</param>
    /// <returns>the base object</returns>
    public static Asn1Encodable CheckTag(Asn1Encodable? asn1Encodable, int tagClass, int tagNo)
    {
        if (asn1Encodable == null)
        {
            throw new ArgumentException("Expected a tagged object. Found null.");
        }

        if (asn1Encodable is not Asn1TaggedObject asn1TaggedObject)
        {
            throw new ArgumentException($"Expected a tagged object. Found {asn1Encodable.GetType()}");
        }

        if (asn1TaggedObject.TagClass != tagClass || asn1TaggedObject.TagNo != tagNo)
        {
            throw new ArgumentException(
                $"Expected [{TagClassToString(tagClass)} {tagNo}], found "
                + $"[{TagClassToString(asn1TaggedObject.TagClass)} {asn1TaggedObject.TagNo}]");
        }

        return asn1TaggedObject.GetBaseObject();
    }

    /// <summary>Checks whether an ASN1 object is itself a sequence and contains sequences.</summary>
    /// <param name="asn1Encodable">an ASN1 object</param>
    /// <returns>a boolean indicating whether the ASN1 object is a sequence of only sequences</returns>
    public static bool IsSequenceOfSequences(Asn1Encodable asn1Encodable)
    {
        if (asn1Encodable is not Asn1Sequence asn1Sequence)
        {
            return false;
        }

        for (int i = 0; i < asn1Sequence.Count; i++)
        {
            if (asn1Sequence[i] is not Asn1Sequence)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Converts an ASN1 sequence of tagged objects to a map. Maps tag numbers to base objects.</summary>
    /// <param name="asn1Encodable">an ASN1 sequence of tagged objects</param>
    /// <returns>a map</returns>
    public static Dictionary<int, Asn1Encodable> DecodeTaggedObjects(Asn1Encodable? asn1Encodable)
    {
        var taggedObjects = new Dictionary<int, Asn1Encodable>();
        if (asn1Encodable == null)
        {
            return taggedObjects;
        }

        if (asn1Encodable is Asn1Sequence asn1Sequence)
        {
            for (int i = 0; i < asn1Sequence.Count; i++)
            {
                Asn1Encodable asn1Object = asn1Sequence[i];
                if (asn1Object is not Asn1TaggedObject asn1TaggedObject)
                {
                    /* NOTE: Java logs a warning "Not a tagged object. Skipping ..." here; omitted per the
                     * non-essential-warning-omission precedent (see AbstractLDSFile.cs). */
                    continue;
                }

                int tagNo = asn1TaggedObject.TagNo;

                /* NOTE: Java logs a warning "Double key ..." here on a pre-existing key; omitted per the
                 * non-essential-warning-omission precedent (see AbstractLDSFile.cs). The later entry
                 * still wins, matching Java's Map.put behavior. */
                taggedObjects[tagNo] = asn1TaggedObject.GetBaseObject();
            }
        }
        else if (asn1Encodable is Asn1TaggedObject singleTaggedObject)
        {
            taggedObjects[singleTaggedObject.TagNo] = singleTaggedObject.GetBaseObject();
        }
        else
        {
            throw new ArgumentException($"Not a sequence and not a tagged object {asn1Encodable.GetType()}");
        }

        return taggedObjects;
    }

    /// <summary>Converts an ASN1 sequence to a list.</summary>
    /// <param name="asn1Encodable">the ASN1 sequence</param>
    /// <returns>a list with element ASN1 objects</returns>
    public static List<Asn1Encodable>? List(Asn1Encodable? asn1Encodable)
    {
        if (asn1Encodable == null)
        {
            return null;
        }

        if (asn1Encodable is Asn1Sequence asn1Sequence)
        {
            var result = new List<Asn1Encodable>(asn1Sequence.Count);
            for (int i = 0; i < asn1Sequence.Count; i++)
            {
                result.Add(asn1Sequence[i]);
            }

            return result;
        }

        return [asn1Encodable];
    }

    public static int DecodeInt(Asn1Encodable asn1Encodable)
    {
        BigInteger? bigInteger = DecodeBigInteger(asn1Encodable);
        if (bigInteger == null)
        {
            throw new FormatException("Could not parse integer");
        }

        return bigInteger.IntValue;
    }

    public static BigInteger DecodeBigInteger(Asn1Encodable asn1Encodable)
    {
        if (asn1Encodable is not Asn1OctetString octetString)
        {
            throw new FormatException("Could not parse integer");
        }

        byte[] octets = octetString.GetOctets();
        return new BigInteger(octets);
    }

    public static bool DecodeBoolean(Asn1Encodable asn1Encodable)
    {
        switch (asn1Encodable)
        {
            case DerBoolean asn1Boolean:
                return asn1Boolean.IsTrue;
            case Asn1OctetString octetString:
                byte[] octets = octetString.GetOctets();
                return (octets[0] & 0xFF) != 0x00;
            default:
                throw new ArgumentException($"Could not decode boolean from {asn1Encodable}");
        }
    }

    /// <summary>NOTE: unlike <see cref="DecodeBoolean"/> (which accepts both a proper ASN.1 BOOLEAN and
    /// an octet string), this always encodes as an octet string, matching a quirk in the Java original
    /// (which never emits a real ASN.1 BOOLEAN here either).</summary>
    public static Asn1Encodable EncodeBoolean(bool b) => new DerOctetString([(byte)(b ? 0xFF : 0x00)]);

    public static Asn1Encodable EncodeInt(int n) => EncodeBigInteger(BigInteger.ValueOf(n));

    public static Asn1Encodable EncodeBigInteger(BigInteger n) => new DerOctetString(n.ToByteArray());

    public static Asn1Encodable? EncodeTaggedObjects(Dictionary<int, Asn1Encodable>? taggedObjects)
    {
        if (taggedObjects == null)
        {
            return null;
        }

        var asn1Objects = new Asn1EncodableVector(taggedObjects.Count);
        foreach (var entry in taggedObjects)
        {
            if (entry.Value != null)
            {
                asn1Objects.Add(new DerTaggedObject(false, entry.Key, entry.Value));
            }
        }

        return new DLSequence(asn1Objects);
    }

    /* PRIVATE. */

    private static string TagClassToString(int tagClass)
    {
        if (tagClass == Asn1Tags.Application)
        {
            return "APPLICATION";
        }

        if (tagClass == Asn1Tags.Universal)
        {
            return "UNIVERSAL";
        }

        if (tagClass == Asn1Tags.ContextSpecific)
        {
            return "CONTEXT_SPECIFIC";
        }

        if (tagClass == Asn1Tags.Private)
        {
            return "PRIVATE";
        }

        return tagClass.ToString();
    }
}
