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

namespace nMRTD.Lds.Icao;

/// <summary>
/// Port of <c>org.jmrtd.lds.icao.DG14File</c>: data group 14 stores a set of <see cref="SecurityInfo"/>s
/// for EAC and PACE, see BSI EAC 1.11 and ICAO TR-SAC-1.01. To us the interesting bits are: the map of
/// public keys (EC or DH), the map of protocol identifiers which should match the key's map (not checked
/// here!), and the file identifier of the EF.CVCA file.
///
/// ADAPTATION: mirrors <c>CardAccessFile.cs</c>'s own ASN1 SET read/write pattern (the closest already-
/// ported sibling with the same "unordered set of <see cref="SecurityInfo"/>" shape) rather than
/// reproducing Java's separate <c>ASN1InputStream</c>/<c>ASN1EncodableVector</c>/<c>DLSet</c> plumbing
/// verbatim.
/// </summary>
public class DG14File : DataGroup
{
    /// <summary>
    /// The security infos that make up this file. Initialized here, not in the stream constructor's body:
    /// field initializers run before the base constructor, which calls <see cref="ReadContent"/> to fill it.
    /// </summary>
    private HashSet<SecurityInfo> securityInfos = [];

    /// <summary>Constructs a new DG14 file from the provided data.</summary>
    /// <param name="securityInfos">a list of security infos</param>
    public DG14File(IEnumerable<SecurityInfo> securityInfos)
        : base(LDSFile.EF_DG14_TAG)
    {
        ArgumentNullException.ThrowIfNull(securityInfos);
        this.securityInfos = [.. securityInfos];
    }

    /// <summary>Constructs a new DG14 file from the data in an input stream.</summary>
    /// <param name="inputStream">the input stream to parse the data from</param>
    public DG14File(Stream inputStream)
        : base(LDSFile.EF_DG14_TAG, inputStream)
    {
    }

    protected override void ReadContent(Stream inputStream)
    {
        Asn1Set set;
        try
        {
            var asn1In = new Asn1InputStream(inputStream);
            Asn1Object? content = asn1In.ReadObject();
            if (content is not Asn1Set contentSet)
            {
                throw new IOException($"Was expecting an Asn1Set, found {(content == null ? "no content" : content.GetType().Name)}");
            }
            set = contentSet;
        }
        catch (Exception e) when (e is InvalidOperationException or ArgumentException or InvalidCastException)
        {
            // BouncyCastle signals malformed ASN.1 with unchecked exceptions; an empty DG14 used to throw a
            // NullReferenceException (JMRTD 0.8.10, 737881b8).
            throw new IOException("Malformed set of security infos", e);
        }
        securityInfos = new HashSet<SecurityInfo>(set.Count);
        for (int i = 0; i < set.Count; i++)
        {
            try
            {
                Asn1Object obj = set[i].ToAsn1Object();
                SecurityInfo? securityInfo = SecurityInfo.GetInstance(obj);
                if (securityInfo == null)
                {
                    // NOTE: Java logs a warning ("Skipping this unsupported SecurityInfo") here; omitted
                    // per the non-essential-warning-omission precedent used elsewhere in this port.
                    continue;
                }

                securityInfos.Add(securityInfo);
            }
            catch (Exception)
            {
                // NOTE: Java logs a warning ("Skipping Security Info") here; omitted per precedent.
            }
        }
    }

    /* FIXME: rewrite (using writeObject instead of getDERObject) to remove interface dependency on BC (carried over from Java source comment). */
    protected override void WriteContent(Stream outputStream)
    {
        var vector = new Asn1EncodableVector();
        foreach (SecurityInfo securityInfo in securityInfos)
        {
            vector.Add(securityInfo.ToDerObject());
        }

        Asn1Set derSet = new DLSet(vector);
        byte[] encoded = derSet.GetDerEncoded();
        outputStream.Write(encoded, 0, encoded.Length);
    }

    /// <summary>Returns the Terminal Authentication infos.</summary>
    /// <returns>the Terminal Authentication infos</returns>
    [Obsolete("Use GetSecurityInfos() and filter that collection.")]
    public List<TerminalAuthenticationInfo> GetTerminalAuthenticationInfos()
    {
        var terminalAuthenticationInfos = new List<TerminalAuthenticationInfo>();
        foreach (SecurityInfo securityInfo in securityInfos)
        {
            if (securityInfo is TerminalAuthenticationInfo terminalAuthenticationInfo)
            {
                terminalAuthenticationInfos.Add(terminalAuthenticationInfo);
            }
        }

        return terminalAuthenticationInfos;
    }

    /// <summary>Returns the Chip Authentication infos.</summary>
    /// <returns>the Chip Authentication infos</returns>
    [Obsolete("Use GetSecurityInfos() and filter that collection.")]
    public List<ChipAuthenticationInfo> GetChipAuthenticationInfos()
    {
        var map = new List<ChipAuthenticationInfo>();
        foreach (SecurityInfo securityInfo in securityInfos)
        {
            if (securityInfo is ChipAuthenticationInfo chipAuthNInfo)
            {
                map.Add(chipAuthNInfo);

                // NOTE: preserved Java quirk -- iteration stops (and returns) as soon as a
                // ChipAuthenticationInfo with a null key id is encountered, silently dropping any
                // further entries (including further ChipAuthenticationInfo ones) that would otherwise
                // still be in the (unordered) set. Not "fixed" per this port's quirk-preservation policy.
                if (chipAuthNInfo.GetKeyId() == null)
                {
                    return map;
                }
            }
        }

        return map;
    }

    /// <summary>Returns the mapping of key identifiers to public keys. The key identifier may be <c>-1</c> if there is only one key.</summary>
    /// <returns>the mapping of key identifiers to public keys</returns>
    [Obsolete("Use GetSecurityInfos() and filter that collection.")]
    public List<ChipAuthenticationPublicKeyInfo> GetChipAuthenticationPublicKeyInfos()
    {
        var publicKeys = new List<ChipAuthenticationPublicKeyInfo>();
        foreach (SecurityInfo securityInfo in securityInfos)
        {
            if (securityInfo is ChipAuthenticationPublicKeyInfo publicKeyInfo)
            {
                publicKeys.Add(publicKeyInfo);
            }
        }

        return publicKeys;
    }

    /// <summary>Returns the Active Authentication security infos.</summary>
    /// <returns>the Active Authentication security infos</returns>
    [Obsolete("Use GetSecurityInfos() and filter that collection.")]
    public List<ActiveAuthenticationInfo> GetActiveAuthenticationInfos()
    {
        var resultList = new List<ActiveAuthenticationInfo>();
        foreach (SecurityInfo securityInfo in securityInfos)
        {
            if (securityInfo is ActiveAuthenticationInfo activeAuthenticationInfo)
            {
                resultList.Add(activeAuthenticationInfo);
            }
        }

        return resultList;
    }

    /// <summary>Returns the security infos as an unordered collection.</summary>
    /// <returns>security infos</returns>
    public IReadOnlyCollection<SecurityInfo> GetSecurityInfos() => securityInfos;

    public override string ToString() => $"DG14File [{string.Join(", ", securityInfos)}]";

    public override bool Equals(object? obj)
    {
        if (obj == null)
        {
            return false;
        }

        if (obj.GetType() != GetType())
        {
            return false;
        }

        var other = (DG14File)obj;
        return securityInfos.SetEquals(other.securityInfos);
    }

    public override int GetHashCode()
    {
        int hash = 0;
        foreach (SecurityInfo securityInfo in securityInfos)
        {
            hash += securityInfo.GetHashCode();
        }

        return (5 * hash) + 41;
    }
}
