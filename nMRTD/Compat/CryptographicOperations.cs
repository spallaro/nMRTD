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

using System.Runtime.CompilerServices;

namespace System.Security.Cryptography;

/// <summary>
/// The part of <c>System.Security.Cryptography.CryptographicOperations</c> (.NET Core 2.1) that the code uses, for
/// .NET Framework, where the type does not exist. Internal, so it never clashes with the framework's own.
/// </summary>
internal static class CryptographicOperations
{
    /// <summary>Compares two byte sequences in a time that depends only on their length (constant time for equal
    /// lengths), so that the comparison of a MAC or a checksum does not leak where they differ.</summary>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static bool FixedTimeEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        if (left.Length != right.Length)
        {
            return false;
        }
        int difference = 0;
        for (int i = 0; i < left.Length; i++)
        {
            difference |= left[i] ^ right[i];
        }
        return difference == 0;
    }
}

#endif
