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

using System.Text;
using nMRTD.SmartCards;

namespace nMRTD.Cbeff;

/// <summary>
/// Port of <c>org.jmrtd.cbeff.StandardBiometricHeader</c>: a Standard Biometric Header preceeds a
/// Biometric Data Block. Java's <c>Serializable</c> marker is dropped (no reflection-based
/// serialization is needed in this port).
/// </summary>
public class StandardBiometricHeader
{
    /// <summary>
    /// Format owner identifier of ISO/IEC JTC1/SC37. See:
    /// https://www.ibia.org/cbeff/iso/bdb-format-identifiers.
    /// </summary>
    public const int JTC1_SC37_FORMAT_OWNER_VALUE = 0x0101;

    /// <summary>
    /// ISO/IEC JTC1/SC37 uses 0x0007. See:
    /// https://www.ibia.org/cbeff/iso/bdb-format-identifiers.
    /// (ISO FCD 19794-4 specified this as 0x0401).
    /// </summary>
    public const int ISO_19794_FINGER_IMAGE_FORMAT_TYPE_VALUE = 0x0007;

    /// <summary>
    /// ISO/IEC JTC1/SC37 uses 0x0008. See:
    /// https://www.ibia.org/cbeff/iso/bdb-format-identifiers.
    /// Also see supplement to Doc 9303: R3-p1_v2_sII_0001.
    /// (ISO FCD 19794-5 specified this as 0x0501).
    /// </summary>
    public const int ISO_19794_FACE_IMAGE_FORMAT_TYPE_VALUE = 0x0008;

    /// <summary>
    /// ISO/IEC JTC1/SC37 uses 0x0009. See:
    /// https://www.ibia.org/cbeff/iso/bdb-format-identifiers.
    /// (ISO FCD 19794-6 specified this as 0x0601).
    /// </summary>
    public const int ISO_19794_IRIS_IMAGE_FORMAT_TYPE_VALUE = 0x0009;

    /// <summary>
    /// Corresponds to <c>g3-binary-finger-image</c>. See:
    /// https://www.ibia.org/cbeff/iso/bdb-format-identifiers.
    /// </summary>
    public const int ISO_39794_FINGER_IMAGE_FORMAT_TYPE_VALUE = 0x0028;

    /// <summary>
    /// Corresponds to <c>g3-binary-face-image</c>. See:
    /// https://www.ibia.org/cbeff/iso/bdb-format-identifiers.
    /// </summary>
    public const int ISO_39794_FACE_IMAGE_FORMAT_TYPE_VALUE = 0x002A;

    /// <summary>
    /// Corresponds to <c>g3-binary-iris-image</c>. See:
    /// https://www.ibia.org/cbeff/iso/bdb-format-identifiers.
    /// </summary>
    public const int ISO_39794_IRIS_IMAGE_FORMAT_TYPE_VALUE = 0x002C;

    private readonly SortedDictionary<int, byte[]> _elements;

    /// <summary>Constructs a standard biometric header.</summary>
    /// <param name="elements">the elements, consisting of a tag and value</param>
    public StandardBiometricHeader(IDictionary<int, byte[]> elements)
    {
        _elements = new SortedDictionary<int, byte[]>(elements);
    }

    /// <summary>Returns the elements of this standard biometric header.</summary>
    /// <returns>the elements, each consisting of a tag and value</returns>
    public SortedDictionary<int, byte[]> GetElements() => new(_elements);

    /// <summary>Checks whether the format type is present and equals to the given value.</summary>
    /// <param name="formatTypeValue">a format type (short) value</param>
    /// <returns>a boolean indicating the format type is present and equal to the given value</returns>
    public bool HasFormatType(int formatTypeValue)
    {
        if (!_elements.TryGetValue(ISO781611.FORMAT_TYPE_TAG, out byte[]? actualFormatTypeValue))
        {
            return false;
        }
        if (actualFormatTypeValue.Length != 2)
        {
            return false;
        }

        int actualFormatTypeInt = ((actualFormatTypeValue[0] & 0xFF) << 8) | (actualFormatTypeValue[1] & 0xFF);
        return actualFormatTypeInt == formatTypeValue;
    }

    public override string ToString()
    {
        var result = new StringBuilder();
        result.Append("StandardBiometricHeader [");
        bool isFirst = true;
        foreach (KeyValuePair<int, byte[]> entry in _elements)
        {
            if (isFirst)
            {
                isFirst = false;
            }
            else
            {
                result.Append(", ");
            }
            result.Append(entry.Key.ToString("x")).Append(" -> ").Append(Hex.BytesToHexString(entry.Value));
        }
        result.Append(']');
        return result.ToString();
    }

    /*
     * Divergence from JMRTD: Java's Map.hashCode() sums each entry's key.hashCode() ^ value.hashCode(),
     * and a byte[] value has an identity-based hashCode() in Java, while equals() compares the values by
     * content (Arrays.equals). Two equal headers could then hash differently, which breaks hash-based
     * collections. The values are hashed by content here (as Arrays.hashCode would).
     */
    public override int GetHashCode()
    {
        const int prime = 31;
        int result = 1;
        result = (prime * result) + JavaMapHashCode(_elements);
        return result;
    }

    /// <summary>Java-style <c>Arrays.hashCode(byte[])</c>: content-based.</summary>
    private static int JavaArrayHashCode(byte[]? array)
    {
        if (array == null)
        {
            return 0;
        }

        int result = 1;
        foreach (byte b in array)
        {
            result = (31 * result) + (sbyte)b;
        }
        return result;
    }

    private static int JavaMapHashCode(SortedDictionary<int, byte[]> elements)
    {
        int hash = 0;
        foreach (KeyValuePair<int, byte[]> entry in elements)
        {
            hash += entry.Key.GetHashCode() ^ JavaArrayHashCode(entry.Value);
        }
        return hash;
    }

    public override bool Equals(object? obj)
    {
        if (ReferenceEquals(this, obj))
        {
            return true;
        }
        if (obj == null)
        {
            return false;
        }
        if (obj.GetType() != GetType())
        {
            return false;
        }

        var other = (StandardBiometricHeader)obj;
        return ElementsEqual(_elements, other._elements);
    }

    /// <summary>Determines whether the two maps have equal entry sets.</summary>
    /// <param name="elements1">the first map</param>
    /// <param name="elements2">the second map</param>
    /// <returns>a boolean indicating equality</returns>
    private static bool ElementsEqual(SortedDictionary<int, byte[]>? elements1, SortedDictionary<int, byte[]>? elements2)
    {
        if (elements1 == null && elements2 != null)
        {
            return false;
        }
        if (elements1 != null && elements2 == null)
        {
            return false;
        }
        if (ReferenceEquals(elements1, elements2))
        {
            return true;
        }

        if (!elements1!.Keys.SequenceEqual(elements2!.Keys))
        {
            return false;
        }

        foreach (KeyValuePair<int, byte[]> entry in elements1)
        {
            byte[]? otherBytes = elements2[entry.Key];
            if (!entry.Value.SequenceEqual(otherBytes))
            {
                return false;
            }
        }

        return true;
    }
}
