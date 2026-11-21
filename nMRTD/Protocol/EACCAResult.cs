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

using BigInteger = Org.BouncyCastle.Math.BigInteger;

using Org.BouncyCastle.Crypto;

using nMRTD.SmartCards;

namespace nMRTD.Protocol;

/// <summary>
/// Port of <c>org.jmrtd.protocol.EACCAResult</c>: result of EAC Chip Authentication protocol. Java's
/// <c>Serializable</c> marker is dropped per porting-conventions.md (no reflection-based serialization is
/// needed in this port). Java's <c>java.security.PublicKey</c>/<c>PrivateKey</c> become BC's
/// <see cref="AsymmetricKeyParameter"/>, per the convention already established throughout this port (see
/// <c>AAResult.cs</c>). <c>keyId</c> uses <see cref="Org.BouncyCastle.Math.BigInteger"/>, the type of the
/// key IDs in <c>ChipAuthenticationInfo</c>/<c>ChipAuthenticationPublicKeyInfo</c> (DG14), so that they can be
/// passed through unchanged.
/// </summary>
public sealed class EACCAResult
{
    private readonly byte[]? _keyHash;

    /// <summary>The ICC's public key identifier, or <c>null</c>.</summary>
    public BigInteger? KeyId { get; }

    /// <summary>The PICC's public key that was used as input to the chip authentication protocol.</summary>
    public AsymmetricKeyParameter? PublicKey { get; }

    /// <summary>The resulting secure messaging wrapper.</summary>
    public SecureMessagingWrapper Wrapper { get; }

    /// <summary>The ephemeral public key of the terminal that was used in the key exchange.</summary>
    public AsymmetricKeyParameter? PCDPublicKey { get; }

    /// <summary>The ephemeral private key of the terminal that was used in the key exchange.</summary>
    public AsymmetricKeyParameter? PCDPrivateKey { get; }

    /// <summary>Creates a result.</summary>
    /// <param name="keyId">the key identifier of the ICC's public key or <c>null</c></param>
    /// <param name="piccPublicKey">the ICC's public key</param>
    /// <param name="keyHash">the hash of the PCD's public key</param>
    /// <param name="pcdPublicKey">the public key of the terminal</param>
    /// <param name="pcdPrivateKey">the private key of the terminal</param>
    /// <param name="wrapper">secure messaging wrapper</param>
    public EACCAResult(BigInteger? keyId, AsymmetricKeyParameter? piccPublicKey, byte[]? keyHash, AsymmetricKeyParameter? pcdPublicKey, AsymmetricKeyParameter? pcdPrivateKey, SecureMessagingWrapper wrapper)
    {
        KeyId = keyId;
        PublicKey = piccPublicKey;
        _keyHash = keyHash == null ? null : (byte[])keyHash.Clone();
        PCDPublicKey = pcdPublicKey;
        PCDPrivateKey = pcdPrivateKey;
        Wrapper = wrapper;
    }

    /// <summary>Returns the hash of the ephemeral public key of the terminal.</summary>
    /// <returns>the hash of the ephemeral public key of the terminal</returns>
    public byte[]? GetKeyHash() => _keyHash == null ? null : (byte[])_keyHash.Clone();

    public override string ToString() =>
        "EACCAResult [keyId: " + (KeyId?.ToString() ?? "-")
        + ", PICC public key: " + (PublicKey?.ToString() ?? "-")
        + ", wrapper: " + Wrapper
        + ", key hash: " + ToHexOrDash(_keyHash)
        + ", PCD public key: " + Util.GetDetailedPublicKeyAlgorithm(PCDPublicKey)
        + ", PCD private key: " + Util.GetDetailedPrivateKeyAlgorithm(PCDPrivateKey)
        + "]";

    public override int GetHashCode()
    {
        const int prime = 31;
        int result = 1;
        result = (prime * result) + ArrayHashCode(_keyHash);
        result = (prime * result) + (KeyId?.GetHashCode() ?? 0);
        result = (prime * result) + (PublicKey?.GetHashCode() ?? 0);
        result = (prime * result) + (PCDPublicKey?.GetHashCode() ?? 0);
        result = (prime * result) + (PCDPrivateKey?.GetHashCode() ?? 0);
        result = (prime * result) + Wrapper.GetHashCode();
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

        var other = (EACCAResult)obj;
        return ArraysEqual(_keyHash, other._keyHash)
            && Equals(KeyId, other.KeyId)
            && Equals(PublicKey, other.PublicKey)
            && Equals(PCDPublicKey, other.PCDPublicKey)
            && Equals(PCDPrivateKey, other.PCDPrivateKey)
            && Equals(Wrapper, other.Wrapper);
    }

    /// <summary>
    /// Renders a (possibly <c>null</c>) byte array as hex, or <c>"-"</c> when <c>null</c> -- mirrors the
    /// null-safety already used elsewhere in this port's <c>Result</c>-style <c>ToString</c> methods (see
    /// <c>AAResult.cs</c>), since <see cref="Hex.BytesToHexString"/> (unlike scuba's Java original) throws
    /// on a <c>null</c> argument.
    /// </summary>
    private static string ToHexOrDash(byte[]? bytes) => bytes == null ? "-" : Hex.BytesToHexString(bytes);

    private static int ArrayHashCode(byte[]? array)
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

    private static bool ArraysEqual(byte[]? a, byte[]? b)
    {
        if (a == null || b == null)
        {
            return a == b;
        }

        return a.AsSpan().SequenceEqual(b);
    }
}
