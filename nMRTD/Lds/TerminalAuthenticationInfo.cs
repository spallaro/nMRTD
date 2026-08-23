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

/// <summary>Port of <c>org.jmrtd.lds.TerminalAuthenticationInfo</c>: a concrete SecurityInfo structure
/// that stores terminal authentication info, see EAC 1.11 specification.
///
/// This data structure provides detailed information on an implementation of Terminal Authentication.
/// <list type="bullet">
/// <item>The object identifier <c>protocol</c> SHALL identify the Terminal Authentication Protocol as
/// the specific protocol may change over time.</item>
/// <item>The integer <c>version</c> SHALL identify the version of the protocol. Currently, versions 1
/// and 2 are supported.</item>
/// <item>The sequence <c>efCVCA</c> MAY be used to indicate a (short) file identifier of the file
/// EF.CVCA. It MUST be used, if the default (short) file identifier is not used.</item>
/// </list></summary>
public class TerminalAuthenticationInfo : SecurityInfo
{
    public const int VERSION_1 = 1;
    private const int VERSION_2 = 2;

    private readonly string oid;
    private readonly int version;

    /// <summary>Contains just a file identifier, and possibly a short file identifier.</summary>
    private readonly Asn1Sequence? efCVCA;

    /// <param name="oid">the id_TA identifier</param>
    /// <param name="version">has to be 1 or 2</param>
    /// <param name="efCVCA">the file ID information of the efCVCA file</param>
    internal TerminalAuthenticationInfo(string oid, int version, Asn1Sequence? efCVCA)
    {
        this.oid = oid;
        this.version = version;
        this.efCVCA = efCVCA;
        CheckFields();
    }

    /// <param name="identifier">the id_TA identifier</param>
    /// <param name="version">has to be 1 or 2</param>
    internal TerminalAuthenticationInfo(string identifier, int version)
        : this(identifier, version, null)
    {
    }

    /// <summary>Constructs a terminal authentication info using id_TA identifier <see cref="SecurityInfo.ID_TA"/>
    /// and version <see cref="VERSION_1"/>.</summary>
    public TerminalAuthenticationInfo()
        : this(ID_TA, VERSION_1)
    {
    }

    /// <summary>Constructs a new Terminal Authentication info with the required object identifier and
    /// version number 1, and file identifier and short file identifier (possibly -1).</summary>
    /// <param name="fileId">a file identifier reference to the efCVCA file</param>
    /// <param name="shortFileId">short file id for the above file, -1 if none</param>
    public TerminalAuthenticationInfo(short fileId, sbyte shortFileId)
        : this(ID_TA, VERSION_1, ConstructEFCVCA(fileId, shortFileId))
    {
    }

    /// <summary>Returns the version. This will be 1 or 2.</summary>
    public int GetVersion() => version;

    [Obsolete("This method will be removed from the visible interface (because of dependency on BC API)")]
    public override Asn1Object GetDERObject()
    {
        var v = new Asn1EncodableVector
        {
            new DerObjectIdentifier(oid),
            new DerInteger(version),
        };
        if (efCVCA != null)
        {
            v.Add(efCVCA);
        }
        return new DLSequence(v);
    }

    public override string GetObjectIdentifier() => oid;

    public override string GetProtocolOIDString() => ToProtocolOIDString(oid);

    /// <summary>Returns the efCVCA file identifier stored in this file, -1 if none.</summary>
    public int GetFileId() => GetFID(efCVCA);

    /// <summary>Returns the efCVCA short file identifier stored in this file, -1 if none or not present.</summary>
    public sbyte GetShortFileId() => GetSFI(efCVCA);

    public override string ToString()
    {
        return "TerminalAuthenticationInfo ["
            + "protocol: " + ToProtocolOIDString(oid) + ", "
            + "version: " + version + ", "
            + "fileID: " + GetFileId() + ", "
            + "shortFileID: " + GetShortFileId()
            + "]";
    }

    public override int GetHashCode()
    {
        return 123
            + 7 * (oid == null ? 0 : oid.GetHashCode())
            + 5 * version
            + 3 * (efCVCA == null ? 1 : efCVCA.GetHashCode());
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
        if (other.GetType() != typeof(TerminalAuthenticationInfo))
        {
            return false;
        }
        var otherTerminalAuthenticationInfo = (TerminalAuthenticationInfo)other;
        if (efCVCA == null && otherTerminalAuthenticationInfo.efCVCA != null)
        {
            return false;
        }
        if (efCVCA != null && otherTerminalAuthenticationInfo.efCVCA == null)
        {
            return false;
        }

        return GetDERObject().Equals(otherTerminalAuthenticationInfo.GetDERObject());
    }

    /// <summary>Checks whether the given object identifier identifies a TerminalAuthenticationInfo structure.</summary>
    internal static bool CheckRequiredIdentifier(string id) => ID_TA.Equals(id);

    /// <summary>Checks the correctness of the data for this instance of <see cref="SecurityInfo"/>.</summary>
    private void CheckFields()
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
            if (efCVCA != null)
            {
                var fid = (Asn1OctetString)efCVCA[0];
                if (fid.GetOctets().Length != 2)
                {
                    throw new ArgumentException("Malformed FID.");
                }
                if (efCVCA.Count == 2)
                {
                    var sfi = (Asn1OctetString)efCVCA[1];
                    if (sfi.GetOctets().Length != 1)
                    {
                        throw new ArgumentException("Malformed SFI.");
                    }
                }
            }
        }
        catch (Exception e)
        {
            throw new ArgumentException("Malformed TerminalAuthenticationInfo", e);
        }
    }

    /// <summary>Encodes the BC object representing a reference to a CVCA file.</summary>
    private static Asn1Sequence ConstructEFCVCA(short fid, sbyte sfi)
    {
        if (sfi != -1)
        {
            return new DLSequence(
                new DerOctetString([(byte)((fid & 0xFF00) >> 8), (byte)(fid & 0xFF)]),
                new DerOctetString([(byte)(sfi & 0xFF)]));
        }

        return new DLSequence(new DerOctetString([(byte)((fid & 0xFF00) >> 8), (byte)(fid & 0xFF)]));
    }

    /// <summary>Returns the file identifier encoded in a BC ASN1 sequence.</summary>
    private static short GetFID(Asn1Sequence? efCVCA)
    {
        if (efCVCA == null)
        {
            return -1;
        }
        var fid = (Asn1OctetString)efCVCA[0];
        byte[] bytes = fid.GetOctets();
        return (short)(((bytes[0] & 0xFF) << 8) | (bytes[1] & 0xFF));
    }

    /// <summary>Returns the short file identifier encoded in a BC ASN1 sequence.</summary>
    private static sbyte GetSFI(Asn1Sequence? efCVCA)
    {
        if (efCVCA == null || efCVCA.Count != 2)
        {
            return -1;
        }
        return (sbyte)((Asn1OctetString)efCVCA[1]).GetOctets()[0];
    }

    private string ToProtocolOIDString(string oid)
    {
        if (ID_TA.Equals(oid))
        {
            return "id-TA";
        }
        if (ID_TA_RSA.Equals(oid))
        {
            return "id-TA-RSA";
        }
        if (ID_TA_RSA_V1_5_SHA_1.Equals(oid))
        {
            return "id-TA-RSA-v1-5-SHA-1";
        }
        if (ID_TA_RSA_V1_5_SHA_256.Equals(oid))
        {
            return "id-TA-RSA-v1-5-SHA-256";
        }
        if (ID_TA_RSA_PSS_SHA_1.Equals(oid))
        {
            return "id-TA-RSA-PSS-SHA-1";
        }
        if (ID_TA_RSA_PSS_SHA_256.Equals(oid))
        {
            return "id-TA-RSA-PSS-SHA-256";
        }
        if (ID_TA_ECDSA.Equals(oid))
        {
            return "id-TA-ECDSA";
        }
        if (ID_TA_ECDSA_SHA_1.Equals(oid))
        {
            return "id-TA-ECDSA-SHA-1";
        }
        if (ID_TA_ECDSA_SHA_224.Equals(oid))
        {
            return "id-TA-ECDSA-SHA-224";
        }
        if (ID_TA_ECDSA_SHA_256.Equals(oid))
        {
            return "id-TA-ECDSA-SHA-256";
        }

        return oid;
    }
}
