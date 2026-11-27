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

using System.Numerics;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Icao;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;

// See SignedDataUtil.cs remarks: Org.BouncyCastle.Asn1.Pkcs also declares SignedData/ContentInfo/
// SignerInfo/IssuerAndSerialNumber, which collide by name with the Cms.* versions used throughout this
// file -- alias only the one Pkcs type actually used here.
using RsassaPssParameters = Org.BouncyCastle.Asn1.Pkcs.RsassaPssParameters;

namespace nMRTD.Lds;

/// <summary>
/// Port of <c>org.jmrtd.lds.SODFile</c>: file structure for the EF.SOD file (the Document Security
/// Object). Based on Appendix 3 of Doc 9303 Part 1 Vol 2. The Document Security Object is a
/// <c>SignedData</c> type as specified in RFC 3369.
/// </summary>
/// <remarks>
/// Java's many overloaded constructors each take a JCA <c>provider</c> string; per porting-conventions.md
/// that parameter is dropped here (see <see cref="SignedDataUtil"/>'s own remarks) since it has no
/// meaning against a single crypto backend. Java's <c>AlgorithmParameterSpec digestEncryptionParameters</c>
/// maps to <see cref="RsassaPssParameters"/>? directly (the actual RSASSA/PSS ASN.1 parameters), and
/// <c>PrivateKey</c>/<c>X509Certificate</c> map to BouncyCastle's own key/certificate types.
/// </remarks>
public class SODFile : AbstractTaggedLDSFile
{
    /// <summary>
    /// The object identifier to indicate content-type in encapContentInfo:
    /// id-icao-ldsSecurityObject.
    /// </summary>
    private const string IcaoLdsSodOid = "2.23.136.1.1.1";

    /// <summary>
    /// Apparently used in "PKI for Machine Readable Travel Documents Offering ICC Read-Only Access
    /// Version - 1.1, Annex C". Seen in live French and Belgian MRTDs.
    /// </summary>
    private const string IcaoLdsSodAltOid = "1.3.27.1.1.1";

    /// <summary>Used in some test MRTDs; appears to originate from a "worked example" somewhere.</summary>
    private const string SduLdsSodOid = "1.2.528.1.1006.1.20.1";

    private SignedData _signedData = null!;

    /// <summary>Constructs a Security Object data structure.</summary>
    /// <param name="digestAlgorithm">a digest algorithm, such as "SHA1" or "SHA256"</param>
    /// <param name="digestEncryptionAlgorithm">a digest encryption algorithm, such as "SHA256withRSA"</param>
    /// <param name="dataGroupHashes">maps datagroup numbers (1 to 16) to hashes of the data groups</param>
    /// <param name="privateKey">private key to sign the data</param>
    /// <param name="docSigningCertificate">the document signing certificate</param>
    public SODFile(string digestAlgorithm, string digestEncryptionAlgorithm,
        IReadOnlyDictionary<int, byte[]> dataGroupHashes,
        AsymmetricKeyParameter privateKey,
        X509Certificate docSigningCertificate)
        : this(digestAlgorithm, digestEncryptionAlgorithm, null, dataGroupHashes, privateKey, docSigningCertificate, null, null)
    {
    }

    /// <summary>Constructs a Security Object data structure.</summary>
    public SODFile(string digestAlgorithm, string digestEncryptionAlgorithm,
        RsassaPssParameters? digestEncryptionParameters,
        IReadOnlyDictionary<int, byte[]> dataGroupHashes,
        AsymmetricKeyParameter privateKey,
        X509Certificate docSigningCertificate)
        : this(digestAlgorithm, digestEncryptionAlgorithm, digestEncryptionParameters, dataGroupHashes, privateKey, docSigningCertificate, null, null)
    {
    }

    /// <summary>Constructs a Security Object data structure.</summary>
    /// <param name="digestAlgorithm">a digest algorithm, such as "SHA-1" or "SHA-256"</param>
    /// <param name="digestEncryptionAlgorithm">a digest encryption algorithm, such as "SHA256withRSA"</param>
    /// <param name="dataGroupHashes">maps data group numbers (1 to 16) to hashes of the data groups</param>
    /// <param name="privateKey">private key to sign the contents</param>
    /// <param name="docSigningCertificate">the document signing certificate to embed</param>
    /// <param name="ldsVersion">LDS version</param>
    /// <param name="unicodeVersion">Unicode version</param>
    public SODFile(string digestAlgorithm, string digestEncryptionAlgorithm,
        IReadOnlyDictionary<int, byte[]> dataGroupHashes,
        AsymmetricKeyParameter privateKey,
        X509Certificate docSigningCertificate,
        string? ldsVersion, string? unicodeVersion)
        : this(digestAlgorithm, digestEncryptionAlgorithm, null, dataGroupHashes, privateKey, docSigningCertificate, ldsVersion, unicodeVersion)
    {
    }

    /// <summary>Constructs a Security Object data structure.</summary>
    /// <param name="digestAlgorithm">a digest algorithm, such as "SHA-1" or "SHA-256"</param>
    /// <param name="digestEncryptionAlgorithm">a digest encryption algorithm, such as "SHA256withRSA"</param>
    /// <param name="digestEncryptionParameters">the digest encryption algorithm parameters (for RSASSA-PSS), or <see langword="null"/></param>
    /// <param name="dataGroupHashes">maps data group numbers (1 to 16) to hashes of the data groups</param>
    /// <param name="privateKey">private key to sign the contents</param>
    /// <param name="docSigningCertificate">the document signing certificate to embed</param>
    /// <param name="ldsVersion">LDS version</param>
    /// <param name="unicodeVersion">Unicode version</param>
    public SODFile(string digestAlgorithm, string digestEncryptionAlgorithm,
        RsassaPssParameters? digestEncryptionParameters,
        IReadOnlyDictionary<int, byte[]> dataGroupHashes,
        AsymmetricKeyParameter privateKey,
        X509Certificate docSigningCertificate,
        string? ldsVersion, string? unicodeVersion)
        : base(LDSFileTags.EF_SOD_TAG)
    {
        ContentInfo contentInfo = ToContentInfo(IcaoLdsSodOid, digestAlgorithm, dataGroupHashes, ldsVersion, unicodeVersion);
        byte[]? encryptedDigest = SignedDataUtil.SignData(digestAlgorithm, digestEncryptionAlgorithm, digestEncryptionParameters, IcaoLdsSodOid, contentInfo, privateKey);
        if (encryptedDigest == null)
        {
            throw new ArgumentException("Could not sign the security object content.");
        }

        _signedData = SignedDataUtil.CreateSignedData(digestAlgorithm, digestEncryptionAlgorithm, digestEncryptionParameters, IcaoLdsSodOid, contentInfo, encryptedDigest, docSigningCertificate);
    }

    /// <summary>Constructs a Security Object data structure with an already-computed (externally signed) signature.</summary>
    /// <param name="digestAlgorithm">a digest algorithm, such as "SHA-1" or "SHA-256"</param>
    /// <param name="digestEncryptionAlgorithm">a digest encryption algorithm, such as "SHA256withRSA"</param>
    /// <param name="dataGroupHashes">maps data group numbers (1 to 16) to hashes of the data groups</param>
    /// <param name="encryptedDigest">externally signed contents</param>
    /// <param name="docSigningCertificate">the document signing certificate to embed</param>
    public SODFile(string digestAlgorithm, string digestEncryptionAlgorithm,
        IReadOnlyDictionary<int, byte[]> dataGroupHashes,
        byte[] encryptedDigest,
        X509Certificate docSigningCertificate)
        : this(digestAlgorithm, digestEncryptionAlgorithm, null, dataGroupHashes, encryptedDigest, docSigningCertificate)
    {
    }

    /// <summary>Constructs a Security Object data structure with an already-computed (externally signed) signature.</summary>
    /// <param name="digestAlgorithm">a digest algorithm, such as "SHA-1" or "SHA-256"</param>
    /// <param name="digestEncryptionAlgorithm">a digest encryption algorithm, such as "SHA256withRSA"</param>
    /// <param name="digestEncryptionParameters">the digest encryption algorithm parameters (for RSASSA-PSS), or <see langword="null"/></param>
    /// <param name="dataGroupHashes">maps data group numbers (1 to 16) to hashes of the data groups</param>
    /// <param name="encryptedDigest">externally signed contents</param>
    /// <param name="docSigningCertificate">the document signing certificate to embed</param>
    public SODFile(string digestAlgorithm, string digestEncryptionAlgorithm,
        RsassaPssParameters? digestEncryptionParameters,
        IReadOnlyDictionary<int, byte[]> dataGroupHashes,
        byte[] encryptedDigest,
        X509Certificate docSigningCertificate)
        : base(LDSFileTags.EF_SOD_TAG)
    {
        ArgumentNullException.ThrowIfNull(dataGroupHashes);

        ContentInfo contentInfo = ToContentInfo(IcaoLdsSodOid, digestAlgorithm, dataGroupHashes, null, null);
        _signedData = SignedDataUtil.CreateSignedData(digestAlgorithm, digestEncryptionAlgorithm, digestEncryptionParameters, IcaoLdsSodOid, contentInfo, encryptedDigest, docSigningCertificate);
    }

    /// <summary>Constructs a Security Object data structure from binary representation.</summary>
    public SODFile(Stream inputStream)
        : base(LDSFileTags.EF_SOD_TAG, inputStream)
    {
        /* Will throw if no signer info. */
        SignedDataUtil.GetSignerInfo(_signedData);
    }

    protected override void ReadContent(Stream inputStream)
    {
        _signedData = SignedDataUtil.ReadSignedData(inputStream);

        // Parse the security object now, so that the getters do not throw on malformed chip data later (JMRTD 0.8.11,
        // da548b20).
        try
        {
            LdsSecurityObject ldsSecurityObject = GetLdsSecurityObject(_signedData);
            _ = ldsSecurityObject.DigestAlgorithmIdentifier;
            _ = ldsSecurityObject.GetDatagroupHash();
        }
        catch (Exception e) when (e is InvalidOperationException or ArgumentException or InvalidCastException or NullReferenceException)
        {
            throw new IOException("Could not read security object in signed data", e);
        }
    }

    protected override void WriteContent(Stream outputStream)
    {
        SignedDataUtil.WriteData(_signedData, outputStream);
    }

    /// <summary>Returns the stored data group hashes indexed by data group number.</summary>
    /// <returns>data group hashes indexed by data group number (1 to 16)</returns>
    public SortedDictionary<int, byte[]> GetDataGroupHashes()
    {
        DataGroupHash[] hashObjects = GetLdsSecurityObject(_signedData).GetDatagroupHash();
        var hashMap = new SortedDictionary<int, byte[]>();
        foreach (DataGroupHash hashObject in hashObjects)
        {
            int number = hashObject.DataGroupNumber;
            byte[] hashValue = hashObject.DataGroupHashValue.GetOctets();
            hashMap[number] = hashValue;
        }
        return hashMap;
    }

    /// <summary>Returns the signature (the encrypted digest) over the hashes.</summary>
    public byte[] GetEncryptedDigest() => SignedDataUtil.GetEncryptedDigest(_signedData);

    /// <summary>
    /// Returns the parameters of the digest encryption (signature) algorithm -- for instance for
    /// RSASSA/PSS this includes the hash algorithm and the salt length.
    /// </summary>
    public RsassaPssParameters? GetDigestEncryptionAlgorithmParams() => SignedDataUtil.GetDigestEncryptionAlgorithmParams(_signedData);

    /// <summary>Returns the encoded contents of the signed data over which the signature is to be computed.</summary>
    public byte[] GetEContent() => SignedDataUtil.GetEContent(_signedData);

    /// <summary>Returns the name of the algorithm used in the data group hashes.</summary>
    /// <returns>an algorithm string such as "SHA-1" or "SHA-256"</returns>
    public string? GetDigestAlgorithm() => GetDigestAlgorithm(GetLdsSecurityObject(_signedData));

    /// <summary>Extracts the digest algorithm from the security object.</summary>
    private static string? GetDigestAlgorithm(LdsSecurityObject ldsSecurityObject)
    {
        try
        {
            return SignedDataUtil.LookupMnemonicByOid(ldsSecurityObject.DigestAlgorithmIdentifier.Algorithm.Id);
        }
        catch (NotSupportedException)
        {
            return null;
        }
    }

    /// <summary>Returns the name of the digest algorithm used in the signature.</summary>
    public string? GetSignerInfoDigestAlgorithm() => SignedDataUtil.GetSignerInfoDigestAlgorithm(_signedData);

    /// <summary>Returns the name of the digest encryption algorithm used in the signature.</summary>
    public string? GetDigestEncryptionAlgorithm() => SignedDataUtil.GetDigestEncryptionAlgorithm(_signedData);

    /// <summary>Returns the version of the LDS if stored in the Security Object (SOd).</summary>
    /// <returns>the version of the LDS in "aabb" format or <c>null</c> if LDS &lt; V1.8</returns>
    public string? GetLDSVersion()
    {
        LdsVersionInfo? ldsVersionInfo = GetLdsSecurityObject(_signedData).VersionInfo;
        return ldsVersionInfo?.GetLdsVersion();
    }

    /// <summary>Returns the version of unicode if stored in the Security Object (SOd).</summary>
    /// <returns>the unicode version in "aabbcc" format or <c>null</c> if LDS &lt; V1.8</returns>
    public string? GetUnicodeVersion()
    {
        LdsVersionInfo? ldsVersionInfo = GetLdsSecurityObject(_signedData).VersionInfo;
        return ldsVersionInfo?.GetUnicodeVersion();
    }

    /// <summary>
    /// Returns any embedded (document signing) certificates. If the document signing certificate is
    /// embedded, a list of size 1 is returned. Doc 9303 part 10 (in our interpretation) does not allow
    /// multiple certificates here, PKCS7 does allow this.
    /// </summary>
    public List<X509Certificate> GetDocSigningCertificates() => SignedDataUtil.GetCertificates(_signedData);

    /// <summary>
    /// Returns the embedded document signing certificate (if present) or <c>null</c> if not present. Use
    /// this certificate to verify that <i>eSignature</i> is a valid signature for <i>eContent</i>. This
    /// certificate itself is signed using the country signing certificate.
    /// </summary>
    public X509Certificate? GetDocSigningCertificate()
    {
        List<X509Certificate> certificates = GetDocSigningCertificates();
        return certificates == null || certificates.Count == 0 ? null : certificates[^1];
    }

    /// <summary>
    /// Returns the issuer name of the document signing certificate as it appears in the signer-info in
    /// the signed-data structure. Returns <c>null</c> when the signer is identified through
    /// subject-key-identifier instead. Named <c>GetIssuerName</c> rather than Java's
    /// <c>getIssuerX500Principal()</c> since .NET/BouncyCastle has no <c>X500Principal</c> equivalent --
    /// <see cref="X509Name"/> is BouncyCastle's native representation of the same DN.
    /// </summary>
    public X509Name? GetIssuerName()
    {
        IssuerAndSerialNumber? issuerAndSerialNumber = SignedDataUtil.GetIssuerAndSerialNumber(_signedData);
        return issuerAndSerialNumber?.Issuer;
    }

    /// <summary>
    /// Returns the serial number as it appears in the signer-info in the signed-data structure. Returns
    /// <c>null</c> when the signer is identified through subject-key-identifier instead.
    /// </summary>
    public BigInteger? GetSerialNumber()
    {
        IssuerAndSerialNumber? issuerAndSerialNumber = SignedDataUtil.GetIssuerAndSerialNumber(_signedData);
        if (issuerAndSerialNumber == null)
        {
            return null;
        }

        // Big endian two's complement, reversed for the little endian constructor (available on every target).
        return new BigInteger(Enumerable.Reverse(issuerAndSerialNumber.SerialNumber.Value.ToByteArray()).ToArray());
    }

    /// <summary>
    /// Returns the signer's subject-key-identifier as it appears in the signer-info in the signed-data
    /// structure. Returns <c>null</c> when the signer is identified through issuer name and serial instead.
    /// </summary>
    public byte[]? GetSubjectKeyIdentifier() => SignedDataUtil.GetSubjectKeyIdentifier(_signedData);

    /// <summary>Returns a textual representation of this file.</summary>
    public override string ToString()
    {
        try
        {
            var result = new System.Text.StringBuilder();
            result.Append("SODFile ");
            List<X509Certificate> certificates = GetDocSigningCertificates();
            foreach (X509Certificate certificate in certificates)
            {
                result.Append(certificate.IssuerDN);
                result.Append(", ");
            }
            return result.ToString();
        }
        catch (Exception)
        {
            return "SODFile";
        }
    }

    public override bool Equals(object? obj)
    {
        if (obj == null)
        {
            return false;
        }
        if (ReferenceEquals(obj, this))
        {
            return true;
        }
        if (obj.GetType() != GetType())
        {
            return false;
        }

        var other = (SODFile)obj;
        byte[]? mine = GetEncoded();
        byte[]? theirs = other.GetEncoded();
        return mine != null && theirs != null && mine.AsSpan().SequenceEqual(theirs);
    }

    public override int GetHashCode()
    {
        byte[]? encoded = GetEncoded();
        int hash = 17;
        if (encoded != null)
        {
            foreach (byte b in encoded)
            {
                hash = (hash * 31) + b;
            }
        }
        return (11 * hash) + 111;
    }

    /* ONLY PRIVATE METHODS BELOW */

    /// <summary>Encodes a content info for the hash table.</summary>
    private static ContentInfo ToContentInfo(string contentTypeOid, string digestAlgorithm,
        IReadOnlyDictionary<int, byte[]> dataGroupHashes,
        string? ldsVersion, string? unicodeVersion)
    {
        var dataGroupHashesArray = new DataGroupHash[dataGroupHashes.Count];

        int i = 0;
        foreach (KeyValuePair<int, byte[]> entry in dataGroupHashes)
        {
            var hash = new DataGroupHash(entry.Key, new DerOctetString(entry.Value));
            dataGroupHashesArray[i++] = hash;
        }

        var digestAlgorithmIdentifier = new AlgorithmIdentifier(new DerObjectIdentifier(SignedDataUtil.LookupOidByMnemonic(digestAlgorithm)));
        LdsSecurityObject securityObject = ldsVersion == null
            ? new LdsSecurityObject(digestAlgorithmIdentifier, dataGroupHashesArray)
            : new LdsSecurityObject(digestAlgorithmIdentifier, dataGroupHashesArray, new LdsVersionInfo(ldsVersion, unicodeVersion));

        return new ContentInfo(new DerObjectIdentifier(contentTypeOid), new DerOctetString(securityObject));
    }

    /// <summary>Reads the security object (containing the hashes of the data groups) found in the <c>SignedData</c> field.</summary>
    private static LdsSecurityObject GetLdsSecurityObject(SignedData signedData)
    {
        ContentInfo encapContentInfo = signedData.EncapContentInfo;
        string contentType = encapContentInfo.ContentType.Id;
        var eContent = (Asn1OctetString)encapContentInfo.Content;
        if (contentType != IcaoLdsSodOid && contentType != SduLdsSodOid && contentType != IcaoLdsSodAltOid)
        {
            // NOTE: JMRTD logs a warning here ("SignedData does not appear to contain an LDS SOd").
            // Per porting-conventions.md this non-essential warning branch is simply not logged.
        }

        using var stream = new MemoryStream(eContent.GetOctets(), writable: false);
        var inputStream = new Asn1InputStream(stream);
        Asn1Object? firstObject = inputStream.ReadObject();
        if (firstObject is not Asn1Sequence)
        {
            throw new InvalidOperationException($"Expected Asn1Sequence, found {firstObject?.GetType().Name}");
        }
        LdsSecurityObject sod = LdsSecurityObject.GetInstance(firstObject);

        // NOTE: JMRTD logs a warning here if there's a trailing extra object; not logged for the same reason as above.
        inputStream.ReadObject();

        return sod;
    }
}
