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

/// <summary>
/// Port of <c>org.jmrtd.lds.CardAccessFile</c>: card access file stores a set of <see cref="SecurityInfo"/>s for PACE.
/// </summary>
public class CardAccessFile
{
    /// <summary>The security infos that make up this file.</summary>
    private HashSet<SecurityInfo> _securityInfos;

    /// <summary>Constructs a new file from the provided data.</summary>
    /// <param name="securityInfos">a non-empty list of security infos</param>
    public CardAccessFile(IEnumerable<SecurityInfo> securityInfos)
    {
        ArgumentNullException.ThrowIfNull(securityInfos);
        _securityInfos = [.. securityInfos];
    }

    /// <summary>Constructs a new file from the data in an input stream.</summary>
    public CardAccessFile(Stream inputStream)
    {
        _securityInfos = [];
        ReadContent(inputStream);
    }

    /// <summary>Reads the contents as a card access file from a stream.</summary>
    protected void ReadContent(Stream inputStream)
    {
        _securityInfos = [];
        var asn1In = new Asn1InputStream(inputStream);
        var set = (Asn1Set)asn1In.ReadObject();
        for (int i = 0; i < set.Count; i++)
        {
            Asn1Object obj = set[i].ToAsn1Object();
            try
            {
                SecurityInfo? securityInfo = SecurityInfo.GetInstance(obj);
                if (securityInfo == null)
                {
                    /* NOTE: skipping this unsupported SecurityInfo */
                    continue;
                }
                _securityInfos.Add(securityInfo);
            }
            catch (Exception)
            {
                /* NOTE: skipping this unsupported SecurityInfo. */
                continue;
            }
        }
    }

    /// <summary>Writes the contents of this file to a stream.</summary>
    protected void WriteContent(Stream outputStream)
    {
        var vector = new Asn1EncodableVector();
        foreach (SecurityInfo securityInfo in _securityInfos)
        {
            vector.Add(securityInfo.ToDerObject());
        }
        Asn1Set derSet = new DLSet(vector);
        byte[] encoded = derSet.GetDerEncoded();
        outputStream.Write(encoded, 0, encoded.Length);
    }

    /// <summary>Returns a DER encoded of this file.</summary>
    public byte[]? GetEncoded()
    {
        using var byteArrayOutputStream = new MemoryStream();
        try
        {
            WriteContent(byteArrayOutputStream);
            return byteArrayOutputStream.ToArray();
        }
        catch (IOException)
        {
            return null;
        }
    }

    /// <summary>Returns the security infos as an unordered collection.</summary>
    public IReadOnlyCollection<SecurityInfo> GetSecurityInfos() => _securityInfos;

    public override string ToString() => $"CardAccessFile [{string.Join(", ", _securityInfos)}]";

    public override bool Equals(object? otherObj)
    {
        if (otherObj == null)
        {
            return false;
        }
        if (otherObj.GetType() != GetType())
        {
            return false;
        }

        var other = (CardAccessFile)otherObj;
        return _securityInfos.SetEquals(other._securityInfos);
    }

    public override int GetHashCode()
    {
        int hash = 0;
        foreach (SecurityInfo securityInfo in _securityInfos)
        {
            hash += securityInfo.GetHashCode();
        }
        return (7 * hash) + 61;
    }
}
