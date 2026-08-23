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

using System.Linq;

using Org.BouncyCastle.Crypto;

using nMRTD.Cert;
using nMRTD.SmartCards;

namespace nMRTD.Protocol;

/// <summary>
/// Port of <c>org.jmrtd.protocol.EACTAResult</c>: result of EAC Terminal Authentication protocol. Java's
/// <c>Serializable</c> marker is dropped per porting-conventions.md (no reflection-based serialization is
/// needed in this port). Java's <c>java.security.PrivateKey</c> becomes BC's
/// <see cref="AsymmetricKeyParameter"/>, per the convention already established throughout this port (see
/// <c>AAResult.cs</c>).
/// </summary>
public sealed class EACTAResult
{
    private readonly List<CardVerifiableCertificate> _terminalCertificates = [];
    private readonly byte[]? _cardChallenge;

    /// <summary>The chip authentication result.</summary>
    public EACCAResult? ChipAuthenticationResult { get; }

    /// <summary>CA certificate's reference used during EAC-TA.</summary>
    public CVCPrincipal? CAReference { get; }

    /// <summary>The chain of card verifiable certificates that is to be used for authenticating the PCD to the ICC.</summary>
    public IReadOnlyList<CardVerifiableCertificate> CVCertificates => _terminalCertificates;

    /// <summary>The PCD's private key used during EAC.</summary>
    public AsymmetricKeyParameter? TerminalKey { get; }

    /// <summary>The identifier of the card used during EAC.</summary>
    public string? DocumentNumber { get; }

    /// <summary>Creates a new terminal authentication result.</summary>
    /// <param name="caResult">the chip authentication result</param>
    /// <param name="caReference">the certificate authority</param>
    /// <param name="terminalCertificates">terminal certificates</param>
    /// <param name="terminalKey">the terminal's private key</param>
    /// <param name="documentNumber">the documentNumber</param>
    /// <param name="cardChallenge">the challenge</param>
    public EACTAResult(EACCAResult? caResult, CVCPrincipal? caReference, IEnumerable<CardVerifiableCertificate> terminalCertificates, AsymmetricKeyParameter? terminalKey, string? documentNumber, byte[]? cardChallenge)
    {
        ChipAuthenticationResult = caResult;
        CAReference = caReference;

        // NOTE: preserved Java structure -- Java's constructor iterates terminalCertificates unconditionally
        // (no null check), which throws a NullPointerException if it is null; C#'s foreach throws the
        // equivalent NullReferenceException here for the same reason.
        foreach (CardVerifiableCertificate terminalCertificate in terminalCertificates)
        {
            _terminalCertificates.Add(terminalCertificate);
        }

        TerminalKey = terminalKey;
        DocumentNumber = documentNumber;
        _cardChallenge = cardChallenge == null ? null : (byte[])cardChallenge.Clone();
    }

    /// <summary>Returns the card's challenge generated during EAC.</summary>
    /// <returns>the card's challenge</returns>
    public byte[]? GetCardChallenge() => _cardChallenge == null ? null : (byte[])_cardChallenge.Clone();

    /// <summary>Returns a textual representation of this terminal authentication result.</summary>
    /// <returns>a textual representation of this terminal authentication result</returns>
    public override string ToString()
    {
        var result = new System.Text.StringBuilder();
        result.Append("TAResult [chipAuthenticationResult: ").Append(ChipAuthenticationResult?.ToString() ?? "-").Append(", ");
        result.Append("caReference: ").Append(CAReference?.ToString() ?? "-").Append(", ");
        result.Append("terminalCertificates: [");
        bool isFirst = true;
        foreach (CardVerifiableCertificate cert in _terminalCertificates)
        {
            if (isFirst)
            {
                isFirst = false;
            }
            else
            {
                result.Append(", ");
            }

            result.Append(CertificateToString(cert));
        }

        result.Append("terminalKey = ").Append(Util.GetDetailedPrivateKeyAlgorithm(TerminalKey)).Append(", ");
        result.Append("documentNumber = ").Append(DocumentNumber).Append(", ");
        result.Append("cardChallenge = ").Append(ToHexOrDash(_cardChallenge)).Append(", ");
        result.Append(']');
        return result.ToString();
    }

    public override int GetHashCode()
    {
        const int prime = 31;
        int result = 1;
        result = (prime * result) + (CAReference?.GetHashCode() ?? 0);
        result = (prime * result) + ArrayHashCode(_cardChallenge);
        result = (prime * result) + (ChipAuthenticationResult?.GetHashCode() ?? 0);
        result = (prime * result) + (DocumentNumber?.GetHashCode() ?? 0);
        result = (prime * result) + ListHashCode(_terminalCertificates);
        result = (prime * result) + (TerminalKey?.GetHashCode() ?? 0);
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

        var other = (EACTAResult)obj;
        return Equals(CAReference, other.CAReference)
            && ArraysEqual(_cardChallenge, other._cardChallenge)
            && Equals(ChipAuthenticationResult, other.ChipAuthenticationResult)
            && string.Equals(DocumentNumber, other.DocumentNumber, StringComparison.Ordinal)
            && _terminalCertificates.SequenceEqual(other._terminalCertificates)
            && Equals(TerminalKey, other.TerminalKey);
    }

    /// <summary>
    /// Returns a textual representation of the certificate.
    ///
    /// NOTE: Java wraps this in a try/catch for a checked <c>CertificateException</c> around
    /// <c>getHolderReference()</c> that is structurally unreachable in this port --
    /// <see cref="CardVerifiableCertificate.HolderReference"/> is a plain property here, not a
    /// checked-throwing accessor -- so that try/catch is omitted. Java also dereferences
    /// <c>caReference</c> here without a null check (<c>caReference.equals(reference)</c>); preserved
    /// faithfully via the null-forgiving <c>CAReference!</c> below -- this throws if
    /// <see cref="CAReference"/> is <c>null</c>, exactly as Java's <c>NullPointerException</c> would,
    /// though in practice <see cref="EACTAProtocol"/> always resolves a non-null CA reference before
    /// constructing a result.
    /// </summary>
    private string CertificateToString(CardVerifiableCertificate certificate)
    {
        var result = new System.Text.StringBuilder();
        result.Append("CardVerifiableCertificate [");
        CVCPrincipal reference = certificate.HolderReference;
        if (!CAReference!.Equals(reference))
        {
            result.Append("holderReference: ").Append(reference);
        }

        result.Append(']');
        return result.ToString();
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

    /// <summary>Reproduces Java's <c>java.util.List.hashCode()</c> algorithm for <see cref="_terminalCertificates"/>.</summary>
    private static int ListHashCode(IReadOnlyList<CardVerifiableCertificate> list)
    {
        int hash = 1;
        foreach (CardVerifiableCertificate item in list)
        {
            hash = (31 * hash) + item.GetHashCode();
        }

        return hash;
    }
}
