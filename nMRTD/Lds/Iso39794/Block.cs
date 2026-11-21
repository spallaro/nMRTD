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

namespace nMRTD.Lds.Iso39794;

/// <summary>
/// Port of <c>org.jmrtd.lds.iso39794.Block</c>: shared abstract base for every ISO/IEC 39794 ASN.1 "block"
/// type in this package. Java's version is package-private (no <c>public</c> modifier), but every other
/// class in this package that extends it is itself <c>public</c> -- Java allows a public class to extend a
/// package-private one. C# has no equivalent: a <c>public</c> type cannot extend an <c>internal</c> base
/// (CS0060), so <see cref="Block"/> is <c>public</c> here, with its encoding method kept <c>internal</c>.
/// The block types themselves keep Java's visibility: the types and their accessors are public, while the
/// decoding constructors and decoders that are package-private in Java are <c>internal</c>.
///
/// Java's <c>Serializable</c> marker is dropped (no reflection-based serialization is needed in this port).
/// The <c>profile == null</c> guard in Java's <c>getEncoded(ISO39794EncodingProfile)</c> is omitted: unlike
/// Java's reference type, <see cref="ISO39794EncodingProfile"/> is a C# <c>enum</c> (a value type) and so
/// cannot be null here in the first place.
/// </summary>
public abstract class Block
{
    internal abstract Asn1Encodable GetAsn1Object();

    internal virtual Asn1Encodable GetAsn1Object(ISO39794EncodingProfile profile) => GetAsn1Object();

    /// <summary>Encodes this block using the unconstrained ISO/IEC 39794 base-standard encoding.</summary>
    /// <returns>the DER encoding, or <see langword="null"/> on error</returns>
    public byte[]? GetEncoded() => GetEncoded(ISO39794EncodingProfile.Base);

    /// <summary>Encodes this block using the given encoding profile.</summary>
    /// <returns>the DER encoding, or <see langword="null"/> on error</returns>
    public byte[]? GetEncoded(ISO39794EncodingProfile profile)
    {
        try
        {
            return GetAsn1Object(profile).ToAsn1Object().GetDerEncoded();
        }
        catch (IOException)
        {
            // NOTE: Java logs a warning here; omitted per this port's established non-essential-warning-
            // omission precedent (see AbstractLDSFile.cs).
            return null;
        }
    }

    public abstract override int GetHashCode();

    public abstract override bool Equals(object? other);
}
