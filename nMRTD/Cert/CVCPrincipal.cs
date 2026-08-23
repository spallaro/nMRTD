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

namespace nMRTD.Cert;

/// <summary>
/// Port of <c>org.jmrtd.cert.CVCPrincipal</c>: a Card Verifiable Certificate reference field (used for
/// both the Certification Authority Reference, tag <c>0x42</c>, and the Certificate Holder Reference, tag
/// <c>0x5F20</c>), per BSI TR-03110-3. Format: <c>&lt;Country (2)&gt;&lt;Mnemonic (1-9)&gt;&lt;SeqNumber (5)&gt;</c>,
/// flat printable ASCII, 8-16 bytes total, no further internal tagging -- the length is determined entirely
/// by the outer TLV element's length.
/// </summary>
public sealed class CVCPrincipal : IEquatable<CVCPrincipal>
{
    public string CountryCode { get; }

    public string Mnemonic { get; }

    public string SeqNumber { get; }

    /// <summary>Constructs a principal from its concatenated <c>&lt;Country (2F)&gt;&lt;Mnemonic (9V)&gt;&lt;SeqNum (5F)&gt;</c> form.</summary>
    public CVCPrincipal(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        if (name.Length < 2 + 5 || name.Length > 2 + 9 + 5)
        {
            throw new ArgumentException($"Name should be <Country (2F)><Mnemonic (9V)><SeqNum (5F)> formatted, found \"{name}\".", nameof(name));
        }

        CountryCode = name[..2].ToUpperInvariant();
        Mnemonic = name[2..^5];
        SeqNumber = name[^5..];
    }

    /// <summary>Constructs a principal without requiring the country code to be recognized.</summary>
    public CVCPrincipal(string countryCode, string mnemonic, string seqNumber)
    {
        ArgumentNullException.ThrowIfNull(countryCode);
        ArgumentNullException.ThrowIfNull(mnemonic);
        ArgumentNullException.ThrowIfNull(seqNumber);
        if (countryCode.Length != 2)
        {
            throw new ArgumentException("Wrong length countryCode", nameof(countryCode));
        }
        if (mnemonic.Length > 9)
        {
            throw new ArgumentException("Wrong length mnemonic", nameof(mnemonic));
        }
        if (seqNumber.Length != 5)
        {
            throw new ArgumentException("Wrong length seqNumber", nameof(seqNumber));
        }

        CountryCode = countryCode.ToUpperInvariant();
        Mnemonic = mnemonic;
        SeqNumber = seqNumber;
    }

    public CVCPrincipal(Country country, string mnemonic, string seqNumber)
        : this((country ?? throw new ArgumentNullException(nameof(country))).ToAlpha2Code(), mnemonic, seqNumber)
    {
    }

    /// <summary>Concatenation of country code (2), mnemonic (&lt;=9) and sequence number (5).</summary>
    public string Name => CountryCode + Mnemonic + SeqNumber;

    public override string ToString() => $"{CountryCode}/{Mnemonic}/{SeqNumber}";

    /// <summary>
    /// Resolves the country. Falls back to a placeholder "Unknown" <see cref="SmartCards.Country"/>
    /// (alpha-2 preserved, alpha-3 "XXX") for a code not in the ISO 3166-1 table, mirroring
    /// <c>CVCPrincipal.getCountry()</c>'s catch-and-substitute behavior in JMRTD -- a CV certificate CAR/CHR
    /// is not guaranteed to carry a real ISO country code (some national eID schemes use non-ISO issuer
    /// mnemonics in that field), so this must not throw.
    /// </summary>
    public Country Country
    {
        get
        {
            try
            {
                return SmartCards.Country.GetInstanceByAlpha2(CountryCode);
            }
            catch (ArgumentException)
            {
                return SmartCards.Country.CreateUnknown(CountryCode);
            }
        }
    }

    public bool Equals(CVCPrincipal? other)
    {
        if (other is null)
        {
            return false;
        }
        if (ReferenceEquals(other, this))
        {
            return true;
        }
        return CountryCode == other.CountryCode && Mnemonic == other.Mnemonic && SeqNumber == other.SeqNumber;
    }

    public override bool Equals(object? obj) => Equals(obj as CVCPrincipal);

    public override int GetHashCode() => 2 * Name.GetHashCode(StringComparison.Ordinal) + 1231211;

    /// <summary>Raw value octets of a <c>0x42</c>/<c>0x5F20</c> TLV element: the flat ASCII <see cref="Name"/>, no further tagging.</summary>
    internal byte[] EncodeValue() => Encoding.ASCII.GetBytes(Name);

    /// <summary>Decodes the value octets of a <c>0x42</c>/<c>0x5F20</c> TLV element.</summary>
    internal static CVCPrincipal DecodeValue(byte[] value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return new CVCPrincipal(Encoding.ASCII.GetString(value));
    }
}
