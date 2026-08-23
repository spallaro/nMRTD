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
using BigInteger = Org.BouncyCastle.Math.BigInteger;

namespace nMRTD.Lds;

/// <summary>Port of <c>org.jmrtd.lds.ChipAuthenticationInfo</c>: a concrete SecurityInfo structure that
/// stores chip authentication info, see EAC 1.11 specification.
///
/// This data structure provides detailed information on an implementation of Chip Authentication.
/// <list type="bullet">
/// <item>The object identifier <c>protocol</c> SHALL identify the algorithms to be used (i.e. key
/// agreement, symmetric cipher and MAC).</item>
/// <item>The integer <c>version</c> SHALL identify the version of the protocol. Currently, versions 1
/// and 2 are supported.</item>
/// <item>The integer <c>keyId</c> MAY be used to indicate the local key identifier. It MUST be used if
/// the MRTD chip provides multiple public keys for Chip Authentication.</item>
/// </list></summary>
public class ChipAuthenticationInfo : SecurityInfo
{
    /// <summary>Chip Authentication version 1.</summary>
    public const int VERSION_1 = 1;

    /// <summary>Chip Authentication version 2.</summary>
    public const int VERSION_2 = 2;

    private readonly string oid;
    private readonly int version;
    private readonly BigInteger? keyId;

    /// <param name="oid">a proper EAC identifier</param>
    /// <param name="version">has to be 1 or 2</param>
    public ChipAuthenticationInfo(string oid, int version)
        : this(oid, version, null)
    {
    }

    /// <param name="oid">a proper EAC identifier</param>
    /// <param name="version">has to be 1 or 2</param>
    /// <param name="keyId">the key identifier</param>
    public ChipAuthenticationInfo(string oid, int version, BigInteger? keyId)
    {
        this.oid = oid;
        this.version = version;
        this.keyId = keyId;
        CheckFields();
    }

    [Obsolete("This method will be removed from the visible interface (because of dependency on BC API)")]
    public override Asn1Object GetDERObject()
    {
        var v = new Asn1EncodableVector
        {
            new DerObjectIdentifier(oid),
            new DerInteger(version),
        };
        if (keyId != null)
        {
            v.Add(new DerInteger(keyId));
        }
        return new DLSequence(v);
    }

    /// <summary>Returns the protocol object identifier, the <c>ID_CA_</c> object identifier indicating the
    /// Chip Authentication protocol.</summary>
    public override string GetObjectIdentifier() => oid;

    /// <summary>Returns the Chip Authentication version (either 1 or 2).</summary>
    public int GetVersion() => version;

    public override string GetProtocolOIDString() => ToProtocolOIDString(oid);

    /// <summary>Returns a key identifier stored in this ChipAuthenticationInfo structure, <c>null</c> if
    /// not present.</summary>
    public BigInteger? GetKeyId() => keyId;

    /// <summary>Checks the correctness of the data for this instance of SecurityInfo.</summary>
    /// <exception cref="ArgumentException">when not correct</exception>
    protected void CheckFields()
    {
        try
        {
            if (!CheckRequiredIdentifier(oid))
            {
                throw new ArgumentException("Wrong identifier: " + oid);
            }
            if (version != VERSION_1 && version != VERSION_2)
            {
                /* NOTE: Java logs a warning here; omitted per the non-essential-warning-omission
                 * precedent (see AbstractLDSFile.cs). */
            }
        }
        catch (Exception e)
        {
            throw new ArgumentException("Malformed ChipAuthenticationInfo.", e);
        }
    }

    /// <summary>Checks whether the given object identifier identifies a ChipAuthenticationInfo structure.</summary>
    /// <remarks>FIXME: for EAC 1.11 only the 3DES OIDs are allowed.</remarks>
    internal static bool CheckRequiredIdentifier(string oid)
    {
        return ID_CA_DH_3DES_CBC_CBC.Equals(oid)
            || ID_CA_ECDH_3DES_CBC_CBC.Equals(oid)
            || ID_CA_DH_AES_CBC_CMAC_128.Equals(oid)
            || ID_CA_DH_AES_CBC_CMAC_192.Equals(oid)
            || ID_CA_DH_AES_CBC_CMAC_256.Equals(oid)
            || ID_CA_ECDH_AES_CBC_CMAC_128.Equals(oid)
            || ID_CA_ECDH_AES_CBC_CMAC_192.Equals(oid)
            || ID_CA_ECDH_AES_CBC_CMAC_256.Equals(oid);
    }

    public override string ToString()
    {
        return "ChipAuthenticationInfo ["
            + "protocol: " + ToProtocolOIDString(oid)
            + ", version: " + version
            + ", keyId: " + (keyId == null ? "-" : keyId.ToString()) + "]";
    }

    public override int GetHashCode()
    {
        return 3 + 11 * (oid == null ? 0 : oid.GetHashCode()) + 61 * version + 1991 * (keyId == null ? 111 : keyId.GetHashCode());
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
        if (other.GetType() != typeof(ChipAuthenticationInfo))
        {
            return false;
        }

        var otherChipAuthenticationInfo = (ChipAuthenticationInfo)other;
        return oid.Equals(otherChipAuthenticationInfo.oid)
            && version == otherChipAuthenticationInfo.version
            && (keyId == null && otherChipAuthenticationInfo.keyId == null
                || keyId != null && keyId.Equals(otherChipAuthenticationInfo.keyId));
    }

    /// <summary>Returns the key agreement algorithm (<c>"DH"</c> or <c>"ECDH"</c>) for the given Chip
    /// Authentication info object identifier.</summary>
    /// <exception cref="FormatException">if the OID is not recognized (Java: unchecked
    /// <c>NumberFormatException</c>)</exception>
    public static string ToKeyAgreementAlgorithm(string? oid)
    {
        if (oid == null)
        {
            throw new FormatException("Unknown OID: null");
        }

        if (ID_CA_DH_3DES_CBC_CBC.Equals(oid)
            || ID_CA_DH_AES_CBC_CMAC_128.Equals(oid)
            || ID_CA_DH_AES_CBC_CMAC_192.Equals(oid)
            || ID_CA_DH_AES_CBC_CMAC_256.Equals(oid))
        {
            return "DH";
        }
        if (ID_CA_ECDH_3DES_CBC_CBC.Equals(oid)
            || ID_CA_ECDH_AES_CBC_CMAC_128.Equals(oid)
            || ID_CA_ECDH_AES_CBC_CMAC_192.Equals(oid)
            || ID_CA_ECDH_AES_CBC_CMAC_256.Equals(oid))
        {
            return "ECDH";
        }

        throw new FormatException($"Unknown OID: \"{oid}\"");
    }

    /// <summary>Returns the encryption algorithm (<c>"DESede"</c> or <c>"AES"</c>) for the given EAC-CA
    /// info object identifier.</summary>
    public static string ToCipherAlgorithm(string oid)
    {
        if (ID_CA_DH_3DES_CBC_CBC.Equals(oid) || ID_CA_ECDH_3DES_CBC_CBC.Equals(oid))
        {
            return "DESede";
        }
        if (ID_CA_DH_AES_CBC_CMAC_128.Equals(oid)
            || ID_CA_DH_AES_CBC_CMAC_192.Equals(oid)
            || ID_CA_DH_AES_CBC_CMAC_256.Equals(oid)
            || ID_CA_ECDH_AES_CBC_CMAC_128.Equals(oid)
            || ID_CA_ECDH_AES_CBC_CMAC_192.Equals(oid)
            || ID_CA_ECDH_AES_CBC_CMAC_256.Equals(oid))
        {
            return "AES";
        }

        throw new FormatException($"Unknown OID: \"{oid}\"");
    }

    /// <summary>Returns the digest algorithm (<c>"SHA-1"</c> or <c>"SHA-256"</c>) for the given EAC-CA
    /// protocol object identifier.</summary>
    public static string ToDigestAlgorithm(string oid)
    {
        if (ID_CA_DH_3DES_CBC_CBC.Equals(oid)
            || ID_CA_ECDH_3DES_CBC_CBC.Equals(oid)
            || ID_CA_DH_AES_CBC_CMAC_128.Equals(oid)
            || ID_CA_ECDH_AES_CBC_CMAC_128.Equals(oid))
        {
            return "SHA-1";
        }
        if (ID_CA_DH_AES_CBC_CMAC_192.Equals(oid)
            || ID_CA_ECDH_AES_CBC_CMAC_192.Equals(oid)
            || ID_CA_DH_AES_CBC_CMAC_256.Equals(oid)
            || ID_CA_ECDH_AES_CBC_CMAC_256.Equals(oid))
        {
            return "SHA-256";
        }

        throw new FormatException($"Unknown OID: \"{oid}\"");
    }

    /// <summary>Returns the key length in bits (128, 192, or 256) for the given EAC-CA protocol object
    /// identifier.</summary>
    public static int ToKeyLength(string oid)
    {
        if (ID_CA_DH_3DES_CBC_CBC.Equals(oid)
            || ID_CA_ECDH_3DES_CBC_CBC.Equals(oid)
            || ID_CA_DH_AES_CBC_CMAC_128.Equals(oid)
            || ID_CA_ECDH_AES_CBC_CMAC_128.Equals(oid))
        {
            return 128;
        }
        if (ID_CA_DH_AES_CBC_CMAC_192.Equals(oid) || ID_CA_ECDH_AES_CBC_CMAC_192.Equals(oid))
        {
            return 192;
        }
        if (ID_CA_DH_AES_CBC_CMAC_256.Equals(oid) || ID_CA_ECDH_AES_CBC_CMAC_256.Equals(oid))
        {
            return 256;
        }

        throw new FormatException($"Unknown OID: \"{oid}\"");
    }

    private static string ToProtocolOIDString(string oid)
    {
        if (ID_CA_DH_3DES_CBC_CBC.Equals(oid))
        {
            return "id-CA-DH-3DES-CBC-CBC";
        }
        if (ID_CA_DH_AES_CBC_CMAC_128.Equals(oid))
        {
            return "id-CA-DH-AES-CBC-CMAC-128";
        }
        if (ID_CA_DH_AES_CBC_CMAC_192.Equals(oid))
        {
            return "id-CA-DH-AES-CBC-CMAC-192";
        }
        if (ID_CA_DH_AES_CBC_CMAC_256.Equals(oid))
        {
            return "id-CA-DH-AES-CBC-CMAC-256";
        }
        if (ID_CA_ECDH_3DES_CBC_CBC.Equals(oid))
        {
            return "id-CA-ECDH-3DES-CBC-CBC";
        }
        if (ID_CA_ECDH_AES_CBC_CMAC_128.Equals(oid))
        {
            return "id-CA-ECDH-AES-CBC-CMAC-128";
        }
        if (ID_CA_ECDH_AES_CBC_CMAC_192.Equals(oid))
        {
            return "id-CA-ECDH-AES-CBC-CMAC-192";
        }
        if (ID_CA_ECDH_AES_CBC_CMAC_256.Equals(oid))
        {
            return "id-CA-ECDH-AES-CBC-CMAC-256";
        }

        return oid;
    }
}
