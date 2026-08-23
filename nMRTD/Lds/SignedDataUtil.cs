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
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

// Alias to disambiguate Org.BouncyCastle.Asn1.Cms.Attribute (a CMS SignerInfo attribute) from
// System.Attribute (in scope via ImplicitUsings), which share the bare name "Attribute".
using CmsAttribute = Org.BouncyCastle.Asn1.Cms.Attribute;

// Org.BouncyCastle.Asn1.Pkcs also declares SignedData/ContentInfo/SignerInfo/IssuerAndSerialNumber
// (the legacy PKCS#7 shapes) which collide by name with the Cms.* versions above -- alias only the one
// Pkcs type actually used here instead of a wholesale `using Org.BouncyCastle.Asn1.Pkcs;`.
using RsassaPssParameters = Org.BouncyCastle.Asn1.Pkcs.RsassaPssParameters;

namespace nMRTD.Lds;

/// <summary>
/// Port of <c>org.jmrtd.lds.SignedDataUtil</c>: shared CMS <c>SignedData</c> (RFC 3369 / PKCS#7) helper
/// used by both <see cref="CardSecurityFile"/> and <see cref="SODFile"/>.
/// </summary>
/// <remarks>
/// Java's <c>signData</c>/<c>createSignedData</c>/<c>createSignerInfo</c> take a JCA <c>provider</c>
/// string parameter used to select which security provider performs the signature. Per
/// porting-conventions.md, that is pure JCA provider-registry plumbing with no meaning against a single
/// crypto backend (BouncyCastle.Cryptography) and is dropped here rather than carried along as a
/// vestigial unused parameter. Similarly, Java's <c>PrivateKey</c>/<c>X509Certificate</c> (JCA types) map
/// to BouncyCastle's own <see cref="AsymmetricKeyParameter"/>/<see cref="X509Certificate"/> here, since
/// this whole file interoperates directly with BC's ASN.1/CMS object model.
/// </remarks>
public static class SignedDataUtil
{
    /// <summary>SignedData related object identifier: id-signedData.</summary>
    public const string Rfc3369SignedDataOid = "1.2.840.113549.1.7.2";

    /// <summary>SignedData related object identifier.</summary>
    public const string Rfc3369ContentTypeOid = "1.2.840.113549.1.9.3";

    /// <summary>SignedData related object identifier.</summary>
    public const string Rfc3369MessageDigestOid = "1.2.840.113549.1.9.4";

    /// <summary>SignedData related object identifier.</summary>
    public const string Pkcs1RsaOid = "1.2.840.113549.1.1.1";

    /// <summary>SignedData related object identifier.</summary>
    public const string Pkcs1Md2WithRsaOid = "1.2.840.113549.1.1.2";

    /// <summary>SignedData related object identifier.</summary>
    public const string Pkcs1Md4WithRsaOid = "1.2.840.113549.1.1.3";

    /// <summary>SignedData related object identifier.</summary>
    public const string Pkcs1Md5WithRsaOid = "1.2.840.113549.1.1.4";

    /// <summary>SignedData related object identifier.</summary>
    public const string Pkcs1Sha1WithRsaOid = "1.2.840.113549.1.1.5";

    /// <summary>SignedData related object identifier.</summary>
    public const string Pkcs1Mgf1Oid = "1.2.840.113549.1.1.8";

    /// <summary>SignedData related object identifier.</summary>
    public const string Pkcs1RsaSsaPssOid = "1.2.840.113549.1.1.10";

    /// <summary>SignedData related object identifier.</summary>
    public const string Pkcs1Sha256WithRsaOid = "1.2.840.113549.1.1.11";

    /// <summary>SignedData related object identifier.</summary>
    public const string Pkcs1Sha384WithRsaOid = "1.2.840.113549.1.1.12";

    /// <summary>SignedData related object identifier.</summary>
    public const string Pkcs1Sha512WithRsaOid = "1.2.840.113549.1.1.13";

    /// <summary>SignedData related object identifier.</summary>
    public const string Pkcs1Sha224WithRsaOid = "1.2.840.113549.1.1.14";

    /// <summary>SignedData related object identifier.</summary>
    public const string X9Sha1WithEcdsaOid = "1.2.840.10045.4.1";

    /// <summary>SignedData related object identifier.</summary>
    public const string X9Sha224WithEcdsaOid = "1.2.840.10045.4.3.1";

    /// <summary>SignedData related object identifier.</summary>
    public const string X9Sha256WithEcdsaOid = "1.2.840.10045.4.3.2";

    /// <summary>SignedData related object identifier.</summary>
    public const string X9Sha384WithEcdsaOid = "1.2.840.10045.4.3.3";

    /// <summary>SignedData related object identifier.</summary>
    public const string X9Sha512WithEcdsaOid = "1.2.840.10045.4.3.4";

    /// <summary>SignedData related object identifier.</summary>
    public const string IeeeP1363Sha1Oid = "1.3.14.3.2.26";

    /// <summary>Reads a signed data structure from a stream.</summary>
    public static SignedData ReadSignedData(Stream inputStream)
    {
        var asn1InputStream = new Asn1InputStream(inputStream);
        var sequence = Asn1Sequence.GetInstance(asn1InputStream.ReadObject());

        if (sequence.Count != 2)
        {
            throw new IOException($"Was expecting a DER sequence of length 2, found a DER sequence of length {sequence.Count}");
        }

        string contentTypeOid = ((DerObjectIdentifier)sequence[0]).Id;
        if (contentTypeOid != Rfc3369SignedDataOid)
        {
            throw new IOException($"Was expecting signed-data content type OID ({Rfc3369SignedDataOid}), found {contentTypeOid}");
        }

        Asn1Object asn1SequenceWithSignedData = GetObjectFromTaggedObject(sequence[1]);

        if (asn1SequenceWithSignedData is not Asn1Sequence)
        {
            throw new IOException("Was expecting an ASN.1 sequence as content");
        }

        return SignedData.GetInstance(asn1SequenceWithSignedData);
    }

    /// <summary>Writes a signed data structure to a stream.</summary>
    public static void WriteData(SignedData signedData, Stream outputStream)
    {
        var v = new Asn1EncodableVector
        {
            new DerObjectIdentifier(Rfc3369SignedDataOid),
            new DerTaggedObject(0, signedData),
        };
        Asn1Sequence fileContentsObject = new DLSequence(v);
        byte[] fileContentsBytes = fileContentsObject.GetDerEncoded();
        outputStream.Write(fileContentsBytes, 0, fileContentsBytes.Length);
    }

    /// <summary>Extracts the content from a signed data structure.</summary>
    public static Asn1Object? GetContent(SignedData signedData)
    {
        ContentInfo encapContentInfo = signedData.EncapContentInfo;
        var eContent = (Asn1OctetString)encapContentInfo.Content;

        try
        {
            using var stream = new MemoryStream(eContent.GetOctets(), writable: false);
            var inputStream = new Asn1InputStream(stream);
            return inputStream.ReadObject();
        }
        catch (IOException)
        {
            return null;
        }
    }

    /// <summary>Removes the tag from a tagged object.</summary>
    public static Asn1Object GetObjectFromTaggedObject(Asn1Encodable asn1Encodable)
    {
        if (asn1Encodable is not Asn1TaggedObject asn1TaggedObject)
        {
            throw new IOException($"Was expecting an Asn1TaggedObject, found {asn1Encodable.GetType().FullName}");
        }

        int tagClass = asn1TaggedObject.TagClass;
        if (tagClass != Asn1Tags.ContextSpecific)
        {
            throw new IOException($"Was expecting CONTEXT_SPECIFIC tag class in ASN1 tagged object, found {tagClass:X}");
        }

        int tagNo = asn1TaggedObject.TagNo;
        if (tagNo != 0)
        {
            throw new IOException($"Was expecting tag 0, found {tagNo:X}");
        }

        return asn1TaggedObject.GetExplicitBaseObject().ToAsn1Object();
    }

    /// <summary>Returns the digest algorithm used in the signer info in a signed data structure.</summary>
    public static string? GetSignerInfoDigestAlgorithm(SignedData signedData)
    {
        try
        {
            SignerInfo signerInfo = GetSignerInfo(signedData);
            string digestAlgOid = signerInfo.DigestAlgorithm.Algorithm.Id;
            return LookupMnemonicByOid(digestAlgOid);
        }
        catch (NotSupportedException)
        {
            return null;
        }
    }

    /// <summary>
    /// Returns the parameters of the digest encryption (signature) algorithm used in the given signed
    /// data object -- for instance for RSASSA/PSS this includes the hash algorithm and the salt length.
    /// </summary>
    /// <returns>the RSASSA/PSS parameters, or <c>null</c> for non-PSS algorithms or on error</returns>
    public static RsassaPssParameters? GetDigestEncryptionAlgorithmParams(SignedData signedData)
    {
        try
        {
            SignerInfo signerInfo = GetSignerInfo(signedData);
            AlgorithmIdentifier digestEncryptionAlgorithm = signerInfo.DigestEncryptionAlgorithm;
            string digestEncryptionAlgorithmOid = digestEncryptionAlgorithm.Algorithm.Id;
            if (digestEncryptionAlgorithmOid != Pkcs1RsaSsaPssOid)
            {
                /* We only support additional parameters for RSASSA/PSS signature algorithm. */
                return null;
            }

            Asn1Encodable? parameters = digestEncryptionAlgorithm.Parameters;
            if (parameters == null)
            {
                return null;
            }

            return RsassaPssParameters.GetInstance(parameters);
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>Returns the signature algorithm used in the given signed data structure.</summary>
    public static string? GetDigestEncryptionAlgorithm(SignedData signedData)
    {
        try
        {
            SignerInfo signerInfo = GetSignerInfo(signedData);
            string? digestEncryptionAlgorithmOid = signerInfo.DigestEncryptionAlgorithm.Algorithm.Id;
            if (digestEncryptionAlgorithmOid == null)
            {
                return null;
            }
            return LookupMnemonicByOid(digestEncryptionAlgorithmOid);
        }
        catch (NotSupportedException)
        {
            return null;
        }
    }

    /// <summary>
    /// Returns the contents of the signed data over which the signature is to be computed. See RFC
    /// 3369, Cryptographic Message Syntax, August 2002, Section 5.4 for details.
    /// </summary>
    public static byte[] GetEContent(SignedData signedData)
    {
        SignerInfo signerInfo = GetSignerInfo(signedData);
        Asn1Set signedAttributesSet = signerInfo.AuthenticatedAttributes;

        ContentInfo contentInfo = signedData.EncapContentInfo;
        byte[] contentBytes = ((Asn1OctetString)contentInfo.Content).GetOctets();

        if (signedAttributesSet == null || signedAttributesSet.Count == 0)
        {
            /* Signed attributes absent, return content to be signed. */
            return contentBytes;
        }

        /* Signed attributes present (a structure containing a hash of the content), return that
         * structure to be signed. This is the option taken by ICAO passports. */
        string digAlg = signerInfo.DigestAlgorithm.Algorithm.Id;

        try
        {
            byte[] attributesBytes = signedAttributesSet.GetDerEncoded();
            CheckEContent(GetAttributes(signedAttributesSet), digAlg, contentBytes);
            return attributesBytes;
        }
        catch (Exception e) when (e is not IOException)
        {
            throw new IOException("Error checking eContent", e);
        }
    }

    /// <summary>Returns the stored signature of the security object.</summary>
    public static byte[] GetEncryptedDigest(SignedData signedData)
    {
        SignerInfo signerInfo = GetSignerInfo(signedData);
        return signerInfo.EncryptedDigest.GetOctets();
    }

    /// <summary>Returns the issuer and serial number stored in the given signed data structure.</summary>
    public static IssuerAndSerialNumber? GetIssuerAndSerialNumber(SignedData signedData)
    {
        SignerInfo signerInfo = GetSignerInfo(signedData);
        SignerIdentifier signerIdentifier = signerInfo.SignerID;
        Asn1Encodable signerIdentifierId = signerIdentifier.ID;
        if (signerIdentifierId is not (Asn1Sequence or IssuerAndSerialNumber))
        {
            /* NOTE: DE MasterList appears to use DER octet string here. */
            return null;
        }

        return IssuerAndSerialNumber.GetInstance(signerIdentifierId);
    }

    /// <summary>
    /// Returns the subject-key-identifier in the given signed-data structure if the signer is identified
    /// through a subject-key-identifier. Returns <c>null</c> if the signer is identified through issuer
    /// name and serial number instead.
    /// </summary>
    public static byte[]? GetSubjectKeyIdentifier(SignedData signedData)
    {
        SignerInfo signerInfo = GetSignerInfo(signedData);
        SignerIdentifier? signerIdentifier = signerInfo.SignerID;
        if (signerIdentifier == null)
        {
            return null;
        }

        Asn1Encodable? signerIdentifierId = signerIdentifier.ID;
        if (signerIdentifierId is not Asn1OctetString octetString)
        {
            return null;
        }

        return octetString.GetOctets();
    }

    /// <summary>Reads any objects in the given ASN1 octet string (as an ASN1 input stream).</summary>
    public static List<Asn1Object> GetObjectsFromOctetString(Asn1OctetString octetString)
    {
        var result = new List<Asn1Object>();
        byte[] octets = octetString.GetOctets();
        using var stream = new MemoryStream(octets, writable: false);
        var derInputStream = new Asn1InputStream(stream);
        try
        {
            while (true)
            {
                Asn1Object? derObject = derInputStream.ReadObject();
                if (derObject == null)
                {
                    break;
                }
                result.Add(derObject);
            }
        }
        catch (IOException)
        {
            // Best-effort, matching JMRTD's own log-and-continue behavior here.
        }

        return result;
    }

    /// <summary>Extracts the list of embedded certificates from a signed data object.</summary>
    public static List<X509Certificate> GetCertificates(SignedData signedData)
    {
        Asn1Set? encodedCertificates = signedData.Certificates;
        int certificateCount = encodedCertificates?.Count ?? 0;

        var result = new List<X509Certificate>(certificateCount);
        if (certificateCount <= 0)
        {
            return result;
        }

        for (int i = 0; i < certificateCount; i++)
        {
            try
            {
                X509CertificateStructure certAsAsn1Object = X509CertificateStructure.GetInstance(encodedCertificates![i]);
                result.Add(DecodeCertificate(certAsAsn1Object));
            }
            catch (Exception)
            {
                // Skip certificates that fail to decode, matching JMRTD's own log-and-continue behavior.
            }
        }

        return result;
    }

    /// <summary>Decodes an ASN1 encoded BC certificate structure to a BC X509Certificate object.</summary>
    public static X509Certificate DecodeCertificate(X509CertificateStructure certAsAsn1Object)
    {
        byte[] certSpec = certAsAsn1Object.GetDerEncoded();
        var parser = new X509CertificateParser();
        return parser.ReadCertificate(certSpec);
    }

    /// <summary>Creates a signed data structure, for inclusion in a security object.</summary>
    public static SignedData CreateSignedData(string digestAlgorithm, string digestEncryptionAlgorithm,
        string contentTypeOid, ContentInfo contentInfo, byte[] encryptedDigest,
        X509Certificate docSigningCertificate) =>
        CreateSignedData(digestAlgorithm, digestEncryptionAlgorithm, null, contentTypeOid, contentInfo, encryptedDigest, docSigningCertificate);

    /// <summary>Creates a signed data structure, for inclusion in a security object.</summary>
    public static SignedData CreateSignedData(string digestAlgorithm, string digestEncryptionAlgorithm, RsassaPssParameters? digestEncryptionParameters,
        string contentTypeOid, ContentInfo contentInfo, byte[] encryptedDigest,
        X509Certificate docSigningCertificate)
    {
        Asn1Set digestAlgorithmsSet = CreateSingletonSet(CreateDigestAlgorithms(digestAlgorithm));
        Asn1Set certificates = CreateSingletonSet(CreateCertificate(docSigningCertificate));
        Asn1Set? crls = null;
        Asn1Set signerInfos = CreateSingletonSet(
            CreateSignerInfo(digestAlgorithm, digestEncryptionAlgorithm, digestEncryptionParameters, contentTypeOid, contentInfo, encryptedDigest, docSigningCertificate)
                .ToAsn1Object());
        return new SignedData(digestAlgorithmsSet, contentInfo, certificates, crls, signerInfos);
    }

    /// <summary>Creates a signer info structure.</summary>
    public static SignerInfo CreateSignerInfo(string digestAlgorithm,
        string digestEncryptionAlgorithm, string contentTypeOid, ContentInfo contentInfo,
        byte[] encryptedDigest, X509Certificate docSigningCertificate) =>
        CreateSignerInfo(digestAlgorithm, digestEncryptionAlgorithm, null, contentTypeOid, contentInfo, encryptedDigest, docSigningCertificate);

    /// <summary>Creates a signer info structure.</summary>
    public static SignerInfo CreateSignerInfo(string digestAlgorithm,
        string digestEncryptionAlgorithm, RsassaPssParameters? digestEncryptionParameters, string contentTypeOid, ContentInfo contentInfo,
        byte[] encryptedDigest, X509Certificate docSigningCertificate)
    {
        ArgumentNullException.ThrowIfNull(encryptedDigest);

        /* Get the issuer name and serial number from the cert and put it in a SignerIdentifier struct. */
        X509Name docSignerName = docSigningCertificate.IssuerDN;
        Org.BouncyCastle.Math.BigInteger serial = docSigningCertificate.SerialNumber;
        var sid = new SignerIdentifier(new IssuerAndSerialNumber(docSignerName, serial));

        var digestAlgorithmObject = new AlgorithmIdentifier(new DerObjectIdentifier(LookupOidByMnemonic(digestAlgorithm)));
        AlgorithmIdentifier digestEncryptionAlgorithmObject = GetDigestEncryptionAlgorithmObject(digestEncryptionAlgorithm, digestEncryptionParameters);

        Asn1Set authenticatedAttributes = CreateAuthenticatedAttributes(digestAlgorithm, contentTypeOid, contentInfo);
        Asn1OctetString encryptedDigestObject = new DerOctetString(encryptedDigest);
        Asn1Set? unAuthenticatedAttributes = null;

        return new SignerInfo(sid, digestAlgorithmObject, authenticatedAttributes, digestEncryptionAlgorithmObject, encryptedDigestObject, unAuthenticatedAttributes);
    }

    /// <summary>Creates the authenticated attributes to be signed.</summary>
    public static Asn1Set CreateAuthenticatedAttributes(string digestAlgorithm, string contentTypeOid, ContentInfo contentInfo)
    {
        /* Check bug found by Paulo Assumpco. */
        if (digestAlgorithm == "SHA256")
        {
            digestAlgorithm = "SHA-256";
        }
        byte[] contentBytes = ((Asn1OctetString)contentInfo.Content).GetOctets();
        byte[] digestedContentBytes = DigestUtilities.CalculateDigest(digestAlgorithm, contentBytes);
        Asn1OctetString digestedContent = new DerOctetString(digestedContentBytes);
        var contentTypeAttribute = new CmsAttribute(new DerObjectIdentifier(Rfc3369ContentTypeOid), CreateSingletonSet(new DerObjectIdentifier(contentTypeOid)));
        var messageDigestAttribute = new CmsAttribute(new DerObjectIdentifier(Rfc3369MessageDigestOid), CreateSingletonSet(digestedContent));
        return new DLSet(new Asn1Encodable[] { contentTypeAttribute.ToAsn1Object(), messageDigestAttribute.ToAsn1Object() });
    }

    /// <summary>Encodes the given JCE mnemonic digest algorithm as a BC ASN1 sequence.</summary>
    public static Asn1Sequence CreateDigestAlgorithms(string digestAlgorithm)
    {
        var algorithmIdentifier = new DerObjectIdentifier(LookupOidByMnemonic(digestAlgorithm));
        var v = new Asn1EncodableVector { algorithmIdentifier };
        return new DLSequence(v);
    }

    /// <summary>Encodes an X509 certificate as its BC certificate structure, ready to embed in a SignedData certificates set.</summary>
    public static X509CertificateStructure CreateCertificate(X509Certificate certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return certificate.CertificateStructure;
    }

    /// <summary>Signs the (authenticated attributes derived from the given) data.</summary>
    /// <returns>the signature bytes, or <c>null</c> on error</returns>
    public static byte[]? SignData(string digestAlgorithm, string digestEncryptionAlgorithm, string contentTypeOid, ContentInfo contentInfo, AsymmetricKeyParameter privateKey) =>
        SignData(digestAlgorithm, digestEncryptionAlgorithm, null, contentTypeOid, contentInfo, privateKey);

    /// <summary>Signs the (authenticated attributes derived from the given) data.</summary>
    /// <returns>the signature bytes, or <c>null</c> on error</returns>
    public static byte[]? SignData(string digestAlgorithm, string digestEncryptionAlgorithm, RsassaPssParameters? digestEncryptionParameters, string contentTypeOid, ContentInfo contentInfo, AsymmetricKeyParameter privateKey)
    {
        try
        {
            byte[] dataToBeSigned = CreateAuthenticatedAttributes(digestAlgorithm, contentTypeOid, contentInfo).GetDerEncoded();
            ISigner signer = CreateSigner(digestEncryptionAlgorithm, digestEncryptionParameters);
            signer.Init(true, privateKey);
            signer.BlockUpdate(dataToBeSigned, 0, dataToBeSigned.Length);
            return signer.GenerateSignature();
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>Extracts the signer info structure from a signed data structure.</summary>
    public static SignerInfo GetSignerInfo(SignedData signedData)
    {
        Asn1Set signerInfos = signedData.SignerInfos;
        if (signerInfos == null || signerInfos.Count <= 0)
        {
            throw new ArgumentException("No signer info in signed data");
        }

        return SignerInfo.GetInstance(signerInfos[0]);
    }

    /// <summary>Returns the common mnemonic string (such as "SHA1", "SHA256withRSA") given an OID.</summary>
    /// <exception cref="NotSupportedException">if the provided OID is not yet supported</exception>
    public static string? LookupMnemonicByOid(string? oid)
    {
        if (oid == null)
        {
            return null;
        }
        if (oid == X509ObjectIdentifiers.Organization.Id)
        {
            return "O";
        }
        if (oid == X509ObjectIdentifiers.OrganizationalUnitName.Id)
        {
            return "OU";
        }
        if (oid == X509ObjectIdentifiers.CommonName.Id)
        {
            return "CN";
        }
        if (oid == X509ObjectIdentifiers.CountryName.Id)
        {
            return "C";
        }
        if (oid == X509ObjectIdentifiers.StateOrProvinceName.Id)
        {
            return "ST";
        }
        if (oid == X509ObjectIdentifiers.LocalityName.Id)
        {
            return "L";
        }
        if (oid == X509ObjectIdentifiers.IdSha1.Id)
        {
            return "SHA-1";
        }
        if (oid == NistObjectIdentifiers.IdSha224.Id)
        {
            return "SHA-224";
        }
        if (oid == NistObjectIdentifiers.IdSha256.Id)
        {
            return "SHA-256";
        }
        if (oid == NistObjectIdentifiers.IdSha384.Id)
        {
            return "SHA-384";
        }
        if (oid == NistObjectIdentifiers.IdSha512.Id)
        {
            return "SHA-512";
        }
        if (oid == X9Sha1WithEcdsaOid)
        {
            return "SHA1withECDSA";
        }
        if (oid == X9Sha224WithEcdsaOid)
        {
            return "SHA224withECDSA";
        }
        if (oid == X9Sha256WithEcdsaOid)
        {
            return "SHA256withECDSA";
        }
        if (oid == X9Sha384WithEcdsaOid)
        {
            return "SHA384withECDSA";
        }
        if (oid == X9Sha512WithEcdsaOid)
        {
            return "SHA512withECDSA";
        }
        if (oid == Pkcs1RsaOid)
        {
            return "RSA";
        }
        if (oid == Pkcs1Md2WithRsaOid)
        {
            return "MD2withRSA";
        }
        if (oid == Pkcs1Md4WithRsaOid)
        {
            return "MD4withRSA";
        }
        if (oid == Pkcs1Md5WithRsaOid)
        {
            return "MD5withRSA";
        }
        if (oid == Pkcs1Sha1WithRsaOid)
        {
            return "SHA1withRSA";
        }
        if (oid == Pkcs1Sha256WithRsaOid)
        {
            return "SHA256withRSA";
        }
        if (oid == Pkcs1Sha384WithRsaOid)
        {
            return "SHA384withRSA";
        }
        if (oid == Pkcs1Sha512WithRsaOid)
        {
            return "SHA512withRSA";
        }
        if (oid == Pkcs1Sha224WithRsaOid)
        {
            return "SHA224withRSA";
        }
        if (oid == IeeeP1363Sha1Oid)
        {
            return "SHA-1";
        }
        if (oid == Pkcs1RsaSsaPssOid)
        {
            return "SSAwithRSA/PSS";
        }
        if (oid == Pkcs1Mgf1Oid)
        {
            return "MGF1";
        }

        throw new NotSupportedException($"Unknown OID {oid}");
    }

    /// <summary>Looks up an object identifier for the given JCE mnemonic.</summary>
    /// <exception cref="NotSupportedException">if the mnemonic does not correspond to a known object identifier</exception>
    public static string LookupOidByMnemonic(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        if (name == "O")
        {
            return X509ObjectIdentifiers.Organization.Id;
        }
        if (name == "OU")
        {
            return X509ObjectIdentifiers.OrganizationalUnitName.Id;
        }
        if (name == "CN")
        {
            return X509ObjectIdentifiers.CommonName.Id;
        }
        if (name == "C")
        {
            return X509ObjectIdentifiers.CountryName.Id;
        }
        if (name == "ST")
        {
            return X509ObjectIdentifiers.StateOrProvinceName.Id;
        }
        if (name == "L")
        {
            return X509ObjectIdentifiers.LocalityName.Id;
        }
        if (string.Equals(name, "SHA-1", StringComparison.OrdinalIgnoreCase) || string.Equals(name, "SHA1", StringComparison.OrdinalIgnoreCase))
        {
            return X509ObjectIdentifiers.IdSha1.Id;
        }
        if (string.Equals(name, "SHA-224", StringComparison.OrdinalIgnoreCase) || string.Equals(name, "SHA224", StringComparison.OrdinalIgnoreCase))
        {
            return NistObjectIdentifiers.IdSha224.Id;
        }
        if (string.Equals(name, "SHA-256", StringComparison.OrdinalIgnoreCase) || string.Equals(name, "SHA256", StringComparison.OrdinalIgnoreCase))
        {
            return NistObjectIdentifiers.IdSha256.Id;
        }
        if (string.Equals(name, "SHA-384", StringComparison.OrdinalIgnoreCase) || string.Equals(name, "SHA384", StringComparison.OrdinalIgnoreCase))
        {
            return NistObjectIdentifiers.IdSha384.Id;
        }
        if (string.Equals(name, "SHA-512", StringComparison.OrdinalIgnoreCase) || string.Equals(name, "SHA512", StringComparison.OrdinalIgnoreCase))
        {
            return NistObjectIdentifiers.IdSha512.Id;
        }
        if (string.Equals(name, "RSA", StringComparison.OrdinalIgnoreCase))
        {
            return Pkcs1RsaOid;
        }
        if (string.Equals(name, "MD2withRSA", StringComparison.OrdinalIgnoreCase))
        {
            return Pkcs1Md2WithRsaOid;
        }
        if (string.Equals(name, "MD4withRSA", StringComparison.OrdinalIgnoreCase))
        {
            return Pkcs1Md4WithRsaOid;
        }
        if (string.Equals(name, "MD5withRSA", StringComparison.OrdinalIgnoreCase))
        {
            return Pkcs1Md5WithRsaOid;
        }
        if (string.Equals(name, "SHA1withRSA", StringComparison.OrdinalIgnoreCase))
        {
            return Pkcs1Sha1WithRsaOid;
        }
        if (string.Equals(name, "SHA256withRSA", StringComparison.OrdinalIgnoreCase))
        {
            return Pkcs1Sha256WithRsaOid;
        }
        if (string.Equals(name, "SHA384withRSA", StringComparison.OrdinalIgnoreCase))
        {
            return Pkcs1Sha384WithRsaOid;
        }
        if (string.Equals(name, "SHA512withRSA", StringComparison.OrdinalIgnoreCase))
        {
            return Pkcs1Sha512WithRsaOid;
        }
        if (string.Equals(name, "SHA224withRSA", StringComparison.OrdinalIgnoreCase))
        {
            return Pkcs1Sha224WithRsaOid;
        }
        if (string.Equals(name, "SHA1withECDSA", StringComparison.OrdinalIgnoreCase))
        {
            return X9Sha1WithEcdsaOid;
        }
        if (string.Equals(name, "SHA224withECDSA", StringComparison.OrdinalIgnoreCase))
        {
            return X9Sha224WithEcdsaOid;
        }
        if (string.Equals(name, "SHA256withECDSA", StringComparison.OrdinalIgnoreCase))
        {
            return X9Sha256WithEcdsaOid;
        }
        if (string.Equals(name, "SHA384withECDSA", StringComparison.OrdinalIgnoreCase))
        {
            return X9Sha384WithEcdsaOid;
        }
        if (string.Equals(name, "SHA512withECDSA", StringComparison.OrdinalIgnoreCase))
        {
            return X9Sha512WithEcdsaOid;
        }
        if (string.Equals(name, "SAwithRSA/PSS", StringComparison.OrdinalIgnoreCase)
            || string.Equals(name, "SSAwithRSA/PSS", StringComparison.OrdinalIgnoreCase)
            || string.Equals(name, "RSASSA-PSS", StringComparison.OrdinalIgnoreCase))
        {
            return Pkcs1RsaSsaPssOid;
        }
        if (string.Equals(name, "MGF1", StringComparison.OrdinalIgnoreCase)
            || string.Equals(name, "SHA256withRSAandMGF1", StringComparison.OrdinalIgnoreCase)
            || string.Equals(name, "SHA512withRSAandMGF1", StringComparison.OrdinalIgnoreCase))
        {
            return Pkcs1Mgf1Oid;
        }

        throw new NotSupportedException($"Unknown name {name}");
    }

    /* PRIVATE BELOW */

    /// <summary>Checks that the content actually digests to the hash value contained in the message digest attribute.</summary>
    private static void CheckEContent(List<CmsAttribute> attributes, string digAlg, byte[] contentBytes)
    {
        foreach (CmsAttribute attribute in attributes)
        {
            if (attribute.AttrType.Id != Rfc3369MessageDigestOid)
            {
                continue;
            }

            Asn1Set attrValuesSet = attribute.AttrValues;
            byte[] storedDigestedContent = ((Asn1OctetString)attrValuesSet[0]).GetOctets();

            byte[] computedDigestedContent = DigestUtilities.CalculateDigest(digAlg, contentBytes);
            if (!storedDigestedContent.AsSpan().SequenceEqual(computedDigestedContent))
            {
                throw new IOException("Error checking signedAttribute message digest in eContent!");
            }
        }
    }

    /// <summary>Extracts the attributes as a list from the BC ASN1 encoded signed attributes set structure.</summary>
    private static List<CmsAttribute> GetAttributes(Asn1Set signedAttributesSet)
    {
        var attributes = new List<CmsAttribute>(signedAttributesSet.Count);
        for (int i = 0; i < signedAttributesSet.Count; i++)
        {
            attributes.Add(CmsAttribute.GetInstance(signedAttributesSet[i]));
        }
        return attributes;
    }

    /// <summary>
    /// Constructs the BC algorithm identifier for the given signature algorithm, taking into account
    /// the RSASSA/PSS parameters if given.
    /// </summary>
    private static AlgorithmIdentifier GetDigestEncryptionAlgorithmObject(string digestEncryptionAlgorithm, RsassaPssParameters? digestEncryptionParameters)
    {
        var digestEncryptionAlgOid = new DerObjectIdentifier(LookupOidByMnemonic(digestEncryptionAlgorithm));
        if (digestEncryptionParameters == null)
        {
            return new AlgorithmIdentifier(digestEncryptionAlgOid);
        }

        return new AlgorithmIdentifier(digestEncryptionAlgOid, digestEncryptionParameters);
    }

    /// <summary>
    /// Builds a BC <see cref="ISigner"/> for the given JCE mnemonic signature algorithm. When explicit
    /// RSASSA/PSS parameters are given, a <see cref="PssSigner"/> is built directly from them (matching
    /// Java's <c>Signature.setParameter(PSSParameterSpec)</c> path); otherwise the algorithm mnemonic
    /// alone determines the signer (BC applies RSASSA/PSS default parameters -- salt length equal to the
    /// hash length, trailer 0xBC -- for mnemonics such as "SHA256withRSAandMGF1", matching the common
    /// case JMRTD itself relies on almost everywhere).
    /// </summary>
    private static ISigner CreateSigner(string digestEncryptionAlgorithm, RsassaPssParameters? digestEncryptionParameters)
    {
        if (digestEncryptionParameters == null)
        {
            return SignerUtilities.GetSigner(digestEncryptionAlgorithm);
        }

        IDigest contentDigest = DigestUtilities.GetDigest(digestEncryptionParameters.HashAlgorithm.Algorithm.Id);
        AlgorithmIdentifier mgfHashAlgorithm = AlgorithmIdentifier.GetInstance(digestEncryptionParameters.MaskGenAlgorithm.Parameters);
        IDigest mgfDigest = DigestUtilities.GetDigest(mgfHashAlgorithm.Algorithm.Id);
        int saltLength = digestEncryptionParameters.SaltLength.IntValueExact;
        return new PssSigner(new RsaBlindedEngine(), contentDigest, mgfDigest, saltLength);
    }

    /// <summary>Creates a singleton ASN1 set containing the given BC ASN1 object.</summary>
    private static Asn1Set CreateSingletonSet(Asn1Encodable e) => new DLSet(e);
}
