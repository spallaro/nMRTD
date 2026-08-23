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

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;

namespace nMRTD.Lds.Icao;

/// <summary>
/// Port of <c>org.jmrtd.lds.icao.DG15File</c>: file structure for the EF.DG15 file. Data group 15 contains
/// the public key used in Active Authentication.
///
/// ADAPTATION: Java's <c>PublicKey</c> becomes BC's <see cref="AsymmetricKeyParameter"/>, per the
/// convention already established throughout this port (see <c>Util.cs</c>'s doc comment). Unlike Java's
/// <c>getPublicKey(byte[])</c>, which must loop over a hardcoded list of candidate JCA algorithm names
/// (<c>"RSA"</c>, <c>"EC"</c>) because JCA's <c>KeyFactory</c> requires the algorithm to be known upfront,
/// BC's <c>PublicKeyFactory.CreateKey</c> (used by <see cref="Util.ToPublicKey"/>) inspects the
/// <c>AlgorithmIdentifier</c> OID already embedded in the X.509 <see cref="SubjectPublicKeyInfo"/>
/// structure itself and dispatches accordingly -- no algorithm-name loop is needed here.
/// </summary>
public class DG15File : DataGroup
{
    private AsymmetricKeyParameter? publicKey;

    /// <summary>Constructs a new file.</summary>
    /// <param name="publicKey">the key to store in this file</param>
    public DG15File(AsymmetricKeyParameter publicKey)
        : base(LDSFile.EF_DG15_TAG)
    {
        this.publicKey = publicKey;
    }

    /// <summary>Constructs a new file from binary representation.</summary>
    /// <param name="inputStream">an input stream</param>
    public DG15File(Stream inputStream)
        : base(LDSFile.EF_DG15_TAG, inputStream)
    {
    }

    protected override void ReadContent(Stream inputStream)
    {
        try
        {
            byte[] value = new byte[GetLength()];
            int totalRead = 0;
            while (totalRead < value.Length)
            {
                int read = inputStream.Read(value, totalRead, value.Length - totalRead);
                if (read == 0)
                {
                    throw new EndOfStreamException();
                }

                totalRead += read;
            }

            publicKey = GetPublicKey(value);
        }
        catch (Exception)
        {
            // NOTE: Java logs a warning ("Unexpected exception while reading DG15 content") here; omitted
            // per the non-essential-warning-omission precedent used elsewhere in this port.
        }
    }

    /// <summary>Constructs a public key from the given key bytes. Public keys of type RSA and EC in X.509 encoding are supported.</summary>
    /// <param name="keyBytes">an X.509 encoded public key</param>
    /// <returns>a public key</returns>
    /// <exception cref="ArgumentException">when the bytes cannot be interpreted as a public key</exception>
    private static AsymmetricKeyParameter GetPublicKey(byte[] keyBytes)
    {
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.GetInstance(keyBytes);
        return Util.ToPublicKey(subjectPublicKeyInfo) ?? throw new ArgumentException("Could not decode public key");
    }

    protected override void WriteContent(Stream outputStream)
    {
        byte[] encoded = Util.ToSubjectPublicKeyInfo(publicKey!)!.GetEncoded();
        outputStream.Write(encoded, 0, encoded.Length);
    }

    /// <summary>Returns the public key stored in this file.</summary>
    /// <returns>the public key</returns>
    public AsymmetricKeyParameter? GetPublicKey() => publicKey;

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

        var other = (DG15File)obj;
        return Equals(publicKey, other.publicKey);
    }

    public override int GetHashCode() => (5 * (publicKey?.GetHashCode() ?? 0)) + 61;

    public override string ToString() => $"DG15File [{Util.GetDetailedPublicKeyAlgorithm(publicKey)}]";
}
