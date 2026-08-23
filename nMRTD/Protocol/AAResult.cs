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

using Org.BouncyCastle.Crypto;

using nMRTD.SmartCards;

namespace nMRTD.Protocol;

/// <summary>
/// Port of <c>org.jmrtd.protocol.AAResult</c>: result from the Active Authentication protocol. Java's
/// <c>Serializable</c> marker is dropped per porting-conventions.md (no reflection-based serialization is
/// needed in this port). Java's <c>java.security.PublicKey</c> becomes BC's
/// <see cref="AsymmetricKeyParameter"/>, per the convention already established throughout this port
/// (see <c>Util.cs</c>'s doc comment).
/// </summary>
public sealed class AAResult
{
    private readonly byte[]? _challenge;
    private readonly byte[]? _response;

    /// <summary>The AA public key that was used.</summary>
    public AsymmetricKeyParameter? PublicKey { get; }

    /// <summary>The digest algorithm that was used.</summary>
    public string? DigestAlgorithm { get; }

    /// <summary>The signature algorithm that was used.</summary>
    public string? SignatureAlgorithm { get; }

    /// <summary>The result of an Active Authentication protocol run.</summary>
    /// <param name="publicKey">the AA public key that was used</param>
    /// <param name="digestAlgorithm">the digest algorithm that was used</param>
    /// <param name="signatureAlgorithm">the signature algorithm that was used</param>
    /// <param name="challenge">the challenge that was used</param>
    /// <param name="response">the response that resulted</param>
    public AAResult(AsymmetricKeyParameter? publicKey, string? digestAlgorithm, string? signatureAlgorithm, byte[]? challenge, byte[]? response)
    {
        PublicKey = publicKey;
        DigestAlgorithm = digestAlgorithm;
        SignatureAlgorithm = signatureAlgorithm;
        _challenge = challenge == null ? null : (byte[])challenge.Clone();
        _response = response == null ? null : (byte[])response.Clone();
    }

    /// <summary>Returns the challenge that was initially used.</summary>
    /// <returns>the challenge</returns>
    public byte[]? GetChallenge() => _challenge == null ? null : (byte[])_challenge.Clone();

    /// <summary>Returns the response that was sent back by the ICC.</summary>
    /// <returns>the response that was sent back by the ICC</returns>
    public byte[]? GetResponse() => _response == null ? null : (byte[])_response.Clone();

    public override string ToString() =>
        $"AAResult [publicKey: {Util.GetDetailedPublicKeyAlgorithm(PublicKey)}"
        + $", digestAlgorithm: {DigestAlgorithm}"
        + $", signatureAlgorithm: {SignatureAlgorithm}"
        + $", challenge: {ToHexOrDash(_challenge)}"
        + $", response: {ToHexOrDash(_response)}]";

    public override int GetHashCode()
    {
        const int prime = 1991;
        int result = 1234567891;
        result = (prime * result) + ArrayHashCode(_challenge);
        result = (prime * result) + (DigestAlgorithm?.GetHashCode() ?? 0);
        result = (prime * result) + (PublicKey?.GetHashCode() ?? 0);
        result = (prime * result) + ArrayHashCode(_response);
        result = (prime * result) + (SignatureAlgorithm?.GetHashCode() ?? 0);
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

        var other = (AAResult)obj;
        return ArraysEqual(_challenge, other._challenge)
            && string.Equals(DigestAlgorithm, other.DigestAlgorithm, StringComparison.Ordinal)
            && Equals(PublicKey, other.PublicKey)
            && ArraysEqual(_response, other._response)
            && string.Equals(SignatureAlgorithm, other.SignatureAlgorithm, StringComparison.Ordinal);
    }

    /// <summary>
    /// Renders a (possibly <c>null</c>) byte array as hex, or <c>"-"</c> when <c>null</c> -- mirrors the
    /// null-safety already used elsewhere in this port's <c>Result</c>-style <c>ToString</c> methods (see
    /// <c>BACResult.cs</c>), since <see cref="Hex.BytesToHexString"/> (unlike scuba's Java original) throws
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
