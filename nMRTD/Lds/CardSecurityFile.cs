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
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;

namespace nMRTD.Lds;

/// <summary>
/// Port of <c>org.jmrtd.lds.CardSecurityFile</c>: card security file stores a set of
/// <see cref="SecurityInfo"/>s for PACE with Chip Authentication Mapping (CAM). This is a CMS
/// <c>SignedData</c> wrapping a DER SET of <see cref="SecurityInfo"/> (the same content shape as
/// <see cref="CardAccessFile"/>), signed by the document/chip signer -- see <see cref="SignedDataUtil"/>.
/// </summary>
public class CardSecurityFile
{
    // FIXME (matches JMRTD's own inline comment): this OID has no authoritative published reference.
    private const string ContentTypeOid = "0.4.0.127.0.7.3.2.1";

    private string? _digestAlgorithm;

    private string? _digestEncryptionAlgorithm;

    /// <summary>The security infos that make up this file.</summary>
    private HashSet<SecurityInfo> _securityInfos;

    /// <summary>The signature bytes.</summary>
    private byte[]? _encryptedDigest;

    /// <summary>The embedded document signer certificate.</summary>
    private X509Certificate? _certificate;

    /// <summary>Constructs a new file from the provided data, signing it with <paramref name="privateKey"/>.</summary>
    /// <param name="digestAlgorithm">the digest algorithm as JCE-style mnemonic</param>
    /// <param name="digestEncryptionAlgorithm">the signature algorithm as JCE-style mnemonic</param>
    /// <param name="securityInfos">a non-empty list of security infos</param>
    /// <param name="privateKey">the private signing key</param>
    /// <param name="certificate">the certificate to embed, which should correspond to the given private key</param>
    public CardSecurityFile(string digestAlgorithm, string digestEncryptionAlgorithm, IEnumerable<SecurityInfo> securityInfos, AsymmetricKeyParameter privateKey, X509Certificate certificate)
        : this(digestAlgorithm, digestEncryptionAlgorithm, securityInfos, (byte[]?)null, certificate)
    {
        ContentInfo contentInfo = ToContentInfo(ContentTypeOid, _securityInfos);
        _encryptedDigest = SignedDataUtil.SignData(digestAlgorithm, digestEncryptionAlgorithm, ContentTypeOid, contentInfo, privateKey);
    }

    /// <summary>Constructs a new file from the provided data.</summary>
    /// <param name="digestAlgorithm">the digest algorithm as JCE-style mnemonic</param>
    /// <param name="digestEncryptionAlgorithm">the signature algorithm as JCE-style mnemonic</param>
    /// <param name="securityInfos">a non-empty list of security infos</param>
    /// <param name="encryptedDigest">the signature</param>
    /// <param name="certificate">the certificate to embed</param>
    public CardSecurityFile(string digestAlgorithm, string digestEncryptionAlgorithm, IEnumerable<SecurityInfo> securityInfos, byte[]? encryptedDigest, X509Certificate certificate)
    {
        ArgumentNullException.ThrowIfNull(securityInfos);
        ArgumentNullException.ThrowIfNull(certificate);

        _digestAlgorithm = digestAlgorithm;
        _digestEncryptionAlgorithm = digestEncryptionAlgorithm;
        _securityInfos = [.. securityInfos];
        _encryptedDigest = encryptedDigest;
        _certificate = certificate;
    }

    /// <summary>Constructs a new file from the data in an input stream.</summary>
    public CardSecurityFile(Stream inputStream)
    {
        _securityInfos = [];
        ReadContent(inputStream);
    }

    /// <summary>Returns the digest algorithm.</summary>
    public string? GetDigestAlgorithm() => _digestAlgorithm;

    /// <summary>Returns the signature algorithm.</summary>
    public string? GetDigestEncryptionAlgorithm() => _digestEncryptionAlgorithm;

    /// <summary>Returns the encrypted digest (signature bytes).</summary>
    public byte[]? GetEncryptedDigest() => _encryptedDigest == null ? null : [.. _encryptedDigest];

    /// <summary>Reads the contents of this file from a stream.</summary>
    protected void ReadContent(Stream inputStream)
    {
        SignedData signedData = SignedDataUtil.ReadSignedData(inputStream);

        _digestAlgorithm = SignedDataUtil.GetSignerInfoDigestAlgorithm(signedData);
        _digestEncryptionAlgorithm = SignedDataUtil.GetDigestEncryptionAlgorithm(signedData);

        List<X509Certificate> certificates = SignedDataUtil.GetCertificates(signedData);
        _certificate = certificates == null || certificates.Count == 0 ? null : certificates[^1];
        _securityInfos = GetSecurityInfos(signedData);

        _encryptedDigest = SignedDataUtil.GetEncryptedDigest(signedData);
    }

    /// <summary>Writes the contents of this file to a stream.</summary>
    protected void WriteContent(Stream outputStream)
    {
        ContentInfo contentInfo = ToContentInfo(ContentTypeOid, _securityInfos);
        SignedData signedData = SignedDataUtil.CreateSignedData(_digestAlgorithm!, _digestEncryptionAlgorithm!, ContentTypeOid, contentInfo, _encryptedDigest!, _certificate!);
        SignedDataUtil.WriteData(signedData, outputStream);
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

    /// <summary>
    /// Returns the PACE infos embedded in this card access file. If no infos are present, an empty list
    /// is returned.
    /// </summary>
    public List<PACEInfo> GetPACEInfos() => [.. _securityInfos.OfType<PACEInfo>()];

    /// <summary>
    /// Returns the CA infos embedded in this card access file. If no infos are present, an empty list is
    /// returned.
    /// </summary>
    public List<ChipAuthenticationInfo> GetChipAuthenticationInfos() => [.. _securityInfos.OfType<ChipAuthenticationInfo>()];

    /// <summary>
    /// Returns the CA public key infos embedded in this card access file. If no infos are present, an
    /// empty list is returned.
    /// </summary>
    public List<ChipAuthenticationPublicKeyInfo> GetChipAuthenticationPublicKeyInfos() => [.. _securityInfos.OfType<ChipAuthenticationPublicKeyInfo>()];

    public override string ToString() => $"CardSecurityFile [{string.Join(", ", _securityInfos)}]";

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
        var other = (CardSecurityFile)otherObj;
        return _securityInfos.SetEquals(other._securityInfos);
    }

    public override int GetHashCode()
    {
        int hash = 0;
        foreach (SecurityInfo securityInfo in _securityInfos)
        {
            hash += securityInfo.GetHashCode();
        }
        return (3 * hash) + 63;
    }

    /// <summary>Computes content info from the given list of security infos.</summary>
    private static ContentInfo ToContentInfo(string contentTypeOid, IEnumerable<SecurityInfo> securityInfos)
    {
        var vector = new Asn1EncodableVector();
        foreach (SecurityInfo securityInfo in securityInfos)
        {
            vector.Add(securityInfo.ToDerObject());
        }
        Asn1Set derSet = new DLSet(vector);

        return new ContentInfo(new DerObjectIdentifier(contentTypeOid), new DerOctetString(derSet));
    }

    /// <summary>
    /// Attempts to interpret the contents of the given signed data structure as a collection of security
    /// infos. If the data does not contain any security infos, the empty set is returned.
    /// </summary>
    private static HashSet<SecurityInfo> GetSecurityInfos(SignedData signedData)
    {
        Asn1Object? encapsulatedContent = SignedDataUtil.GetContent(signedData);

        if (encapsulatedContent is not Asn1Set set)
        {
            throw new IOException($"Was expecting an Asn1Set, found {encapsulatedContent?.GetType()}");
        }

        var securityInfos = new HashSet<SecurityInfo>();
        for (int i = 0; i < set.Count; i++)
        {
            Asn1Encodable obj = set[i];
            try
            {
                SecurityInfo? securityInfo = SecurityInfo.GetInstance(obj);
                if (securityInfo == null)
                {
                    continue;
                }
                securityInfos.Add(securityInfo);
            }
            catch (Exception)
            {
                // Skip unsupported/unparseable security infos, matching JMRTD's own log-and-continue behavior.
            }
        }

        return securityInfos;
    }
}
