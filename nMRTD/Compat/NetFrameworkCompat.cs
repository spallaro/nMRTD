/*
 * nMRTD - A .Net API for accessing Machine Readable Travel Documents.
 *
 * Copyright (C) Sebastiano Pallaro.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * Distributed under the terms of GNU LGPL v3.
 * See LICENSE for more information.
 */

#if NETFRAMEWORK

using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace nMRTD.Compat;

/// <summary>
/// The members of the .NET 6+ base library that the code uses and .NET Framework 4.6.2/4.7.2 lacks, as extension
/// members with the same names, so that the code itself has no <c>#if</c>. Only compiled for .NET Framework.
/// </summary>
internal static class NetFrameworkCompat
{
    extension(ArgumentNullException)
    {
        /// <summary>See <c>ArgumentNullException.ThrowIfNull</c> (.NET 6).</summary>
        public static void ThrowIfNull([NotNull] object? argument, [CallerArgumentExpression(nameof(argument))] string? paramName = null)
        {
            if (argument is null)
            {
                throw new ArgumentNullException(paramName);
            }
        }
    }

    extension(RandomNumberGenerator)
    {
        /// <summary>See <c>RandomNumberGenerator.Fill</c> (.NET Core 2.1).</summary>
        public static void Fill(Span<byte> data)
        {
            byte[] bytes = new byte[data.Length];
            using (RandomNumberGenerator random = RandomNumberGenerator.Create())
            {
                random.GetBytes(bytes);
            }
            bytes.CopyTo(data);
        }
    }

    extension(Convert)
    {
        /// <summary>See <c>Convert.ToHexString</c> (.NET 5): upper case hexadecimal.</summary>
        public static string ToHexString(byte[] inArray)
        {
            var hex = new StringBuilder(inArray.Length * 2);
            foreach (byte b in inArray)
            {
                hex.Append(b.ToString("X2", System.Globalization.CultureInfo.InvariantCulture));
            }
            return hex.ToString();
        }

        /// <summary>See <c>Convert.FromHexString</c> (.NET 5).</summary>
        /// <exception cref="FormatException">if the string has an odd length or a character that is not hexadecimal</exception>
        public static byte[] FromHexString(string s)
        {
            if (s.Length % 2 != 0)
            {
                throw new FormatException("The input is not a valid hex string as its length is not a multiple of 2.");
            }
            byte[] result = new byte[s.Length / 2];
            for (int i = 0; i < result.Length; i++)
            {
                result[i] = (byte)((HexValue(s[2 * i]) << 4) | HexValue(s[(2 * i) + 1]));
            }
            return result;
        }
    }

    extension(Encoding)
    {
        /// <summary>See <c>Encoding.Latin1</c> (.NET 5): ISO-8859-1.</summary>
        public static Encoding Latin1 => Encoding.GetEncoding(28591);
    }

    /// <summary>See <c>Stream.Write(ReadOnlySpan&lt;byte&gt;)</c> (.NET Core 2.1).</summary>
    public static void Write(this Stream stream, ReadOnlySpan<byte> buffer)
    {
        byte[] bytes = buffer.ToArray();
        stream.Write(bytes, 0, bytes.Length);
    }

    /// <summary>See <c>HashCode.AddBytes</c> (.NET 6).</summary>
    public static void AddBytes(ref this HashCode hashCode, ReadOnlySpan<byte> value)
    {
        foreach (byte b in value)
        {
            hashCode.Add(b);
        }
    }

    /// <summary>See <c>string.GetHashCode(StringComparison)</c> (.NET Core 2.0).</summary>
    public static int GetHashCode(this string s, StringComparison comparisonType) => comparisonType switch
    {
        StringComparison.Ordinal => StringComparer.Ordinal.GetHashCode(s),
        StringComparison.OrdinalIgnoreCase => StringComparer.OrdinalIgnoreCase.GetHashCode(s),
        StringComparison.InvariantCulture => StringComparer.InvariantCulture.GetHashCode(s),
        StringComparison.InvariantCultureIgnoreCase => StringComparer.InvariantCultureIgnoreCase.GetHashCode(s),
        StringComparison.CurrentCultureIgnoreCase => StringComparer.CurrentCultureIgnoreCase.GetHashCode(s),
        _ => StringComparer.CurrentCulture.GetHashCode(s),
    };

    /// <summary>See <c>string.StartsWith(char)</c> (.NET Core 2.0).</summary>
    public static bool StartsWith(this string s, char value) => s.Length > 0 && s[0] == value;

    /// <summary>See <c>string.Split(string, StringSplitOptions)</c> (.NET Core 2.0).</summary>
    public static string[] Split(this string s, string separator, StringSplitOptions options = StringSplitOptions.None) =>
        s.Split([separator], options);

    /// <summary>See <c>BigInteger.ToByteArray(bool, bool)</c> (.NET Core 2.1).</summary>
    public static byte[] ToByteArray(this System.Numerics.BigInteger value, bool isUnsigned, bool isBigEndian)
    {
        byte[] bytes = value.ToByteArray(); // little endian, two's complement
        if (isUnsigned)
        {
            if (value.Sign < 0)
            {
                throw new OverflowException("Negative values do not have an unsigned representation.");
            }
            if (bytes.Length > 1 && bytes[^1] == 0)
            {
                Array.Resize(ref bytes, bytes.Length - 1);
            }
        }
        if (isBigEndian)
        {
            Array.Reverse(bytes);
        }
        return bytes;
    }

    private static int HexValue(char c) => c switch
    {
        >= '0' and <= '9' => c - '0',
        >= 'a' and <= 'f' => c - 'a' + 10,
        >= 'A' and <= 'F' => c - 'A' + 10,
        _ => throw new FormatException($"The input is not a valid hex string as it contains a non-hex character '{c}'."),
    };
}

#endif
