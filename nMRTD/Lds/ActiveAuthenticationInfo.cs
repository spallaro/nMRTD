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

namespace nMRTD.Lds;

/*
 * ActiveAuthenticationInfo ::= SEQUENCE {
 *    protocol id-icao-mrtd-security-aaProtocolObject,
 *    version INTEGER -- MUST be 1
 *    signatureAlgorithm OBJECT IDENTIFIER
 * }
 *
 * -- Object Identifiers
 * id-icao OBJECT IDENTIFIER ::= {2 23 136}
 * id-icao-mrtd OBJECT IDENTIFIER ::= {id-icao 1}
 * id-icao-mrtd-security OBJECT IDENTIFIER ::= {id-icao-mrtd 1}
 *
 * id-icao-mrtd-security-aaProtocolObject OBJECT IDENTIFIER ::= {id-icao-mrtd-security 5}
 */

/// <summary>Port of <c>org.jmrtd.lds.ActiveAuthenticationInfo</c>: a concrete SecurityInfo structure that
/// stores active authentication info, see TR-LDS-PKI Maintenance V1.0.
///
/// NOTE on a preserved JMRTD quirk: <see cref="CheckFields"/> below rejects a <c>null</c>
/// <c>signatureAlgorithmOID</c> (every <c>OID.Equals(null)</c> comparison is false, so the "none of the
/// known OIDs match" branch is taken and it throws) -- yet <see cref="SecurityInfo.GetInstance"/> calls
/// the 3-arg constructor with a <c>null</c> signature algorithm OID whenever the encoded SEQUENCE has no
/// optional third element. That code path in upstream JMRTD therefore always throws
/// "Malformed ActiveAuthenticationInfo" instead of producing a valid instance. Ported byte-for-byte
/// rather than "fixed", per this codebase's quirk-preservation policy (see AdditionalDetailDataGroup.cs).</summary>
public class ActiveAuthenticationInfo : SecurityInfo
{
    public const int VERSION_1 = 1;

    /// <summary>Specified in BSI TR 03111 Section 5.2.1.</summary>
    public const string ECDSA_PLAIN_SIGNATURES = "0.4.0.127.0.7.1.1.4.1";
    public const string ECDSA_PLAIN_SHA1_OID = ECDSA_PLAIN_SIGNATURES + ".1"; /* 0.4.0.127.0.7.1.1.4.1.1, ecdsa-plain-SHA1 */
    public const string ECDSA_PLAIN_SHA224_OID = ECDSA_PLAIN_SIGNATURES + ".2"; /* 0.4.0.127.0.7.1.1.4.1.2, ecdsa-plain-SHA224 */
    public const string ECDSA_PLAIN_SHA256_OID = ECDSA_PLAIN_SIGNATURES + ".3"; /* 0.4.0.127.0.7.1.1.4.1.3, ecdsa-plain-SHA256 */
    public const string ECDSA_PLAIN_SHA384_OID = ECDSA_PLAIN_SIGNATURES + ".4"; /* 0.4.0.127.0.7.1.1.4.1.4, ecdsa-plain-SHA384 */
    public const string ECDSA_PLAIN_SHA512_OID = ECDSA_PLAIN_SIGNATURES + ".5"; /* 0.4.0.127.0.7.1.1.4.1.5, ecdsa-plain-SHA512 */
    public const string ECDSA_PLAIN_RIPEMD160_OID = ECDSA_PLAIN_SIGNATURES + ".6"; /* 0.4.0.127.0.7.1.1.4.1.6, ecdsa-plain-RIPEMD160 */

    private readonly string oid;
    private readonly int version;
    private readonly string? signatureAlgorithmOID;

    /// <param name="oid">the id_AA identifier</param>
    /// <param name="version">has to be 1</param>
    /// <param name="signatureAlgorithmOID">the signature algorithm OID</param>
    internal ActiveAuthenticationInfo(string oid, int version, string? signatureAlgorithmOID)
    {
        this.oid = oid;
        this.version = version;
        this.signatureAlgorithmOID = signatureAlgorithmOID;
        CheckFields();
    }

    /// <param name="signatureAlgorithmOID">the signature algorithm OID</param>
    public ActiveAuthenticationInfo(string signatureAlgorithmOID)
        : this(ID_AA, VERSION_1, signatureAlgorithmOID)
    {
    }

    [Obsolete("This method will be removed from the visible interface (because of dependency on BC API)")]
    public override Asn1Object GetDERObject()
    {
        var v = new Asn1EncodableVector
        {
            new DerObjectIdentifier(oid),
            new DerInteger(version),
        };
        if (signatureAlgorithmOID != null)
        {
            v.Add(new DerObjectIdentifier(signatureAlgorithmOID));
        }
        return new DLSequence(v);
    }

    /// <summary>Returns the protocol object identifier of this AA security info.</summary>
    public override string GetObjectIdentifier() => oid;

    /// <summary>Returns the version of the Active Authentication protocol (should be 1).</summary>
    public int GetVersion() => version;

    public override string GetProtocolOIDString() => ToProtocolOIDString(oid);

    /// <summary>Returns the signature algorithm object identifier.</summary>
    public string? GetSignatureAlgorithmOID() => signatureAlgorithmOID;

    public override string ToString()
    {
        return "ActiveAuthenticationInfo ["
            + "protocol: " + ToProtocolOIDString(oid)
            + ", version: " + version
            + ", signatureAlgorithmOID: " + ToSignatureAlgorithmOIDString(GetSignatureAlgorithmOID())
            + "]";
    }

    public override bool Equals(object? other)
    {
        if (other == null)
        {
            return false;
        }
        if (ReferenceEquals(other, this))
        {
            return true;
        }
        if (other.GetType() != typeof(ActiveAuthenticationInfo))
        {
            return false;
        }
        var otherActiveAuthenticationInfo = (ActiveAuthenticationInfo)other;
        return Equals(oid, otherActiveAuthenticationInfo.oid)
            && version == otherActiveAuthenticationInfo.version
            && Equals(signatureAlgorithmOID, otherActiveAuthenticationInfo.signatureAlgorithmOID);
    }

    public override int GetHashCode()
    {
        return 12345
            + 3 * (oid == null ? 0 : oid.GetHashCode())
            + 5 * version
            + 11 * (signatureAlgorithmOID == null ? 1 : signatureAlgorithmOID.GetHashCode());
    }

    /// <summary>Translates an OID string to a .NET mnemonic algorithm string.</summary>
    /// <exception cref="ArgumentException">if the OID was not recognized (Java: checked
    /// <c>NoSuchAlgorithmException</c>)</exception>
    public static string LookupMnemonicByOID(string oid)
    {
        if (ECDSA_PLAIN_SHA1_OID.Equals(oid))
        {
            return "SHA1withECDSA";
        }
        if (ECDSA_PLAIN_SHA224_OID.Equals(oid))
        {
            return "SHA224withECDSA";
        }
        if (ECDSA_PLAIN_SHA256_OID.Equals(oid))
        {
            return "SHA256withECDSA";
        }
        if (ECDSA_PLAIN_SHA384_OID.Equals(oid))
        {
            return "SHA384withECDSA";
        }
        if (ECDSA_PLAIN_SHA512_OID.Equals(oid))
        {
            return "SHA512withECDSA";
        }
        if (ECDSA_PLAIN_RIPEMD160_OID.Equals(oid))
        {
            return "RIPEMD160withECDSA";
        }

        throw new ArgumentException("Unknown OID " + oid);
    }

    /// <summary>Checks whether the given object identifier identifies an ActiveAuthenticationInfo structure.</summary>
    internal static bool CheckRequiredIdentifier(string id) => ID_AA.Equals(id);

    /// <summary>Checks the correctness of the data for this instance of <see cref="SecurityInfo"/>.</summary>
    private void CheckFields()
    {
        try
        {
            if (!CheckRequiredIdentifier(oid))
            {
                throw new ArgumentException("Wrong identifier: " + oid);
            }
            if (version != VERSION_1)
            {
                /* NOTE: Java logs a warning here; omitted per the non-essential-warning-omission
                 * precedent (see AbstractLDSFile.cs). */
            }

            /* FIXME check to see if signatureAlgorithmOID is valid. */

            if (!ECDSA_PLAIN_SHA1_OID.Equals(signatureAlgorithmOID)
                && !ECDSA_PLAIN_SHA224_OID.Equals(signatureAlgorithmOID)
                && !ECDSA_PLAIN_SHA256_OID.Equals(signatureAlgorithmOID)
                && !ECDSA_PLAIN_SHA384_OID.Equals(signatureAlgorithmOID)
                && !ECDSA_PLAIN_SHA512_OID.Equals(signatureAlgorithmOID)
                && !ECDSA_PLAIN_RIPEMD160_OID.Equals(signatureAlgorithmOID))
            {
                throw new ArgumentException("Wrong signature algorithm OID: " + signatureAlgorithmOID);
            }
        }
        catch (Exception e)
        {
            throw new ArgumentException("Malformed ActiveAuthenticationInfo", e);
        }
    }

    private static string ToProtocolOIDString(string oid) => ID_AA.Equals(oid) ? "id-AA" : oid;

    public static string ToSignatureAlgorithmOIDString(string? oid)
    {
        if (ECDSA_PLAIN_SHA1_OID.Equals(oid))
        {
            return "ecdsa-plain-SHA1";
        }
        if (ECDSA_PLAIN_SHA224_OID.Equals(oid))
        {
            return "ecdsa-plain-SHA224";
        }
        if (ECDSA_PLAIN_SHA256_OID.Equals(oid))
        {
            return "ecdsa-plain-SHA256";
        }
        if (ECDSA_PLAIN_SHA384_OID.Equals(oid))
        {
            return "ecdsa-plain-SHA384";
        }
        if (ECDSA_PLAIN_SHA512_OID.Equals(oid))
        {
            return "ecdsa-plain-SHA512";
        }
        if (ECDSA_PLAIN_RIPEMD160_OID.Equals(oid))
        {
            return "ecdsa-plain-RIPEMD160";
        }

        return oid ?? "null";
    }
}
