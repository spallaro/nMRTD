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

namespace nMRTD.Protocol;

/// <summary>
/// Port of <c>org.jmrtd.protocol.PACEMappingResult</c>: the result of the PACE nonce mapping step. This
/// is the abstract super type; specific implementations (<see cref="PACEGMMappingResult"/> and its
/// subtypes, <see cref="PACEIMMappingResult"/>) contain more relevant details. Java's <c>Serializable</c>
/// marker is dropped per porting-conventions.md (no reflection-based serialization is needed in this
/// port).
///
/// Java's <c>AlgorithmParameterSpec</c> (a JCA marker interface implemented by both
/// <c>DHParameterSpec</c> and <c>ECParameterSpec</c>) has no BC lightweight-API equivalent, so it is
/// ported as a plain <c>object</c> here -- callers downcast to
/// <see cref="Org.BouncyCastle.Crypto.Parameters.DHParameters"/> or
/// <see cref="Org.BouncyCastle.Crypto.Parameters.ECDomainParameters"/> as appropriate, exactly as
/// <c>Util.GetAlgorithmParams</c> and <c>PACEDomainParameterInfo.GetParameters</c> already do elsewhere in
/// this port.
///
/// <see cref="ArrayHashCode"/>/<see cref="ArraysEqual"/> are exposed as <c>protected</c> (rather than
/// private, as in the non-hierarchical <c>BACResult</c>/<c>AAResult</c>) so the several subclasses in
/// this file group can share them without duplicating the byte-array hash/equality helpers already
/// established in this port's <c>Result</c>-style classes (see <c>AAResult.cs</c>).
/// </summary>
public abstract class PACEMappingResult
{
    private readonly byte[]? _piccNonce;

    /// <summary>The static agreement parameters.</summary>
    public object? StaticParameters { get; }

    /// <summary>The resulting ephemeral (derived) agreement parameters.</summary>
    public object? EphemeralParameters { get; }

    /// <summary>Constructs a mapping result.</summary>
    /// <param name="staticParameters">the static agreement parameters</param>
    /// <param name="piccNonce">the nonce that was sent by the PICC</param>
    /// <param name="ephemeralParameters">the resulting ephemeral parameters</param>
    protected PACEMappingResult(object? staticParameters, byte[]? piccNonce, object? ephemeralParameters)
    {
        StaticParameters = staticParameters;
        EphemeralParameters = ephemeralParameters;
        _piccNonce = piccNonce == null ? null : (byte[])piccNonce.Clone();
    }

    /// <summary>Returns the nonce that was sent by the PICC.</summary>
    /// <returns>the nonce</returns>
    public byte[]? GetPiccNonce() => _piccNonce == null ? null : (byte[])_piccNonce.Clone();

    public override int GetHashCode()
    {
        const int prime = 31;
        int result = 1;
        result = (prime * result) + (EphemeralParameters?.GetHashCode() ?? 0);
        result = (prime * result) + ArrayHashCode(_piccNonce);
        result = (prime * result) + (StaticParameters?.GetHashCode() ?? 0);
        return result;
    }

    public override bool Equals(object? obj)
    {
        if (ReferenceEquals(this, obj))
        {
            return true;
        }

        if (obj is null || GetType() != obj.GetType())
        {
            return false;
        }

        var other = (PACEMappingResult)obj;
        return Equals(EphemeralParameters, other.EphemeralParameters)
            && ArraysEqual(_piccNonce, other._piccNonce)
            && Equals(StaticParameters, other.StaticParameters);
    }

    /// <summary>Java-style <c>Arrays.hashCode</c> for a (possibly <c>null</c>) byte array, shared by the
    /// subclasses in this file group.</summary>
    protected static int ArrayHashCode(byte[]? array)
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

    /// <summary>Java-style <c>Arrays.equals</c> for (possibly <c>null</c>) byte arrays, shared by the
    /// subclasses in this file group.</summary>
    protected static bool ArraysEqual(byte[]? a, byte[]? b)
    {
        if (a == null || b == null)
        {
            return a == b;
        }

        return a.AsSpan().SequenceEqual(b);
    }
}
