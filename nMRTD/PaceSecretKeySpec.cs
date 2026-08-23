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

namespace nMRTD;

/// <summary>
/// Port of <c>org.jmrtd.PACESecretKeySpec</c>: a secret key for PACE. Java's version extends
/// <c>javax.crypto.spec.SecretKeySpec</c>; this port does not mirror that class hierarchy (no other
/// nMRTD type needs a generic "secret key" abstraction), it simply holds the key bytes, algorithm name
/// and PACE key reference directly.
/// </summary>
public class PaceSecretKeySpec : IAccessKeySpec
{
    private readonly byte[] _key;

    /// <summary>The name of the secret-key algorithm associated with the key material.</summary>
    public string Algorithm { get; }

    /// <summary>A reference specifying the type of key from BSI TR-03110 (Appendix B).</summary>
    public byte KeyReference { get; }

    /// <summary>
    /// Constructs a secret key from the given byte array, using the first <paramref name="len"/> bytes
    /// of <paramref name="key"/>, starting at <paramref name="offset"/> inclusive.
    /// </summary>
    /// <param name="key">the key bytes</param>
    /// <param name="offset">the offset within <paramref name="key"/></param>
    /// <param name="len">the length of the key within <paramref name="key"/></param>
    /// <param name="algorithm">the name of the secret-key algorithm to be associated with the given key material</param>
    /// <param name="paceKeyReference">a reference specifying the type of key from BSI TR-03110 (Appendix B)</param>
    public PaceSecretKeySpec(byte[] key, int offset, int len, string algorithm, byte paceKeyReference)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(algorithm);
        if (offset < 0 || len < 0 || offset + len > key.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(len));
        }

        _key = new byte[len];
        Array.Copy(key, offset, _key, 0, len);
        Algorithm = algorithm;
        KeyReference = paceKeyReference;
    }

    /// <summary>Constructs a secret key from the given byte array.</summary>
    /// <param name="key">the key bytes</param>
    /// <param name="algorithm">the name of the secret-key algorithm to be associated with the given key material</param>
    /// <param name="paceKeyReference">a reference specifying the type of key from BSI TR-03110 (Appendix B)</param>
    public PaceSecretKeySpec(byte[] key, string algorithm, byte paceKeyReference)
        : this(key, 0, (key ?? throw new ArgumentNullException(nameof(key))).Length, algorithm, paceKeyReference)
    {
    }

    /// <summary>Returns the type of access key: constant "PACE".</summary>
    /// <returns>the type of access key</returns>
    public string GetAlgorithm() => Algorithm;

    /// <summary>Returns the encoded key (key seed) used in key derivation.</summary>
    /// <returns>the encoded key</returns>
    public byte[] GetKey() => (byte[])_key.Clone();

    public override int GetHashCode()
    {
        const int prime = 31;
        int result = ComputeKeyMaterialHashCode();
        result = (prime * result) + KeyReference;
        return result;
    }

    public override bool Equals(object? obj)
    {
        if (ReferenceEquals(this, obj))
        {
            return true;
        }

        if (obj is not PaceSecretKeySpec other || GetType() != obj.GetType())
        {
            return false;
        }

        return Algorithm.Equals(other.Algorithm, StringComparison.OrdinalIgnoreCase)
            && _key.AsSpan().SequenceEqual(other._key)
            && KeyReference == other.KeyReference;
    }

    /// <summary>
    /// Combines the key bytes and a case-insensitive algorithm hash, mirroring the documented
    /// <c>javax.crypto.spec.SecretKeySpec.hashCode()</c> contract (which the Java class inherited).
    /// </summary>
    private int ComputeKeyMaterialHashCode()
    {
        int result = 0;
        for (int i = 1; i < _key.Length; i++)
        {
            result += _key[i] * i;
        }

        string normalizedAlgorithm = Algorithm.Equals("TripleDES", StringComparison.OrdinalIgnoreCase)
            ? "DESede"
            : Algorithm.ToLowerInvariant();
        result ^= normalizedAlgorithm.GetHashCode(StringComparison.Ordinal);
        return result;
    }
}
