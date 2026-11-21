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

using System.Security.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Eac;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using nMRTD.SmartCards;

namespace nMRTD.Cert;

/// <summary>
/// Port of <c>org.jmrtd.cert.CardVerifiableCertificate</c>: a Card Verifiable Certificate as specified in
/// BSI TR-03110-3, used for EAC Terminal Authentication trust chains (CVCA -&gt; DV -&gt; terminal).
///
/// ADAPTATION: the Java class is a thin wrapper around an external Maven dependency,
/// <c>org.ejbca.cvc.CVCertificate</c>, whose source is not available (see docs/cvc-api-surface.md). This
/// port does not attempt to mirror that library's own class hierarchy (<c>CVCertificateBody</c>,
/// <c>CVCPublicKey</c>, <c>ReferenceField</c>, ...) -- instead the TLV encode/decode/sign/verify logic
/// specified by TR-03110-3 Appendix C is implemented directly here, inlined, using
/// <see cref="TlvInputStream"/>/<see cref="TlvOutputStream"/>/<see cref="TlvUtil"/> for BER-TLV framing and
/// BouncyCastle.Cryptography for RSA/EC signing and verification. It also does not extend any
/// <c>java.security.cert.Certificate</c>-style JCA abstraction (dropped per porting-conventions.md); this
/// is a plain, self-contained class exposing the same operations under the same names (PascalCased).
/// Also per porting-conventions.md, JCA's provider-selection <c>verify(key, provider)</c> overload is
/// dropped -- BouncyCastle.Cryptography is the sole crypto backend, so there is nothing to select.
/// </summary>
public sealed class CardVerifiableCertificate : IEquatable<CardVerifiableCertificate>
{
    // --- BER-TLV tags, BSI TR-03110-3 Appendix C (see docs/cvc-api-surface.md section 1). ---
    private const int CvCertificateTag = 0x7F21;
    private const int CertificateBodyTag = 0x7F4E;
    private const int ProfileIdentifierTag = 0x5F29;
    private const int AuthorityReferenceTag = 0x42;
    private const int PublicKeyTag = 0x7F49;
    private const int HolderReferenceTag = 0x5F20;
    private const int AuthorizationTemplateTag = 0x7F4C;
    private const int EffectiveDateTag = 0x5F25;
    private const int ExpirationDateTag = 0x5F24;
    private const int SignatureTag = 0x5F37;

    // --- Public key (0x7F49) inner tags -- see docs/cvc-api-surface.md section 3. RSA and EC tag sets
    // overlap (0x81/0x82 mean different things for each algorithm family), so decoding always resolves
    // the algorithm family from the OID first. ---
    private const int PublicKeyOidTag = 0x06;
    private const int RsaModulusTag = 0x81;
    private const int RsaExponentTag = 0x82;
    private const int EcPrimeModulusTag = 0x81;
    private const int EcFirstCoefficientTag = 0x82;
    private const int EcSecondCoefficientTag = 0x83;
    private const int EcBasePointTag = 0x84;
    private const int EcOrderTag = 0x85;
    private const int EcPublicPointTag = 0x86;
    private const int EcCofactorTag = 0x87;

    /// <summary>Current TR-03110 certificate profile identifier -- the only value ever produced by JMRTD.</summary>
    private const byte CurrentProfileIdentifier = 0x00;

    /// <summary>
    /// Bundles the decoded/encoded contents of a <c>0x7F49</c> Public Key element. Exactly one of
    /// (<see cref="Modulus"/>, <see cref="Exponent"/>) or (<see cref="P"/>, <see cref="A"/>,
    /// <see cref="B"/>, <see cref="G"/>, <see cref="Order"/>, <see cref="Y"/>) is populated, per
    /// <see cref="Oid"/>'s algorithm family. For EC, explicit domain parameters
    /// (<see cref="P"/>/<see cref="A"/>/<see cref="B"/>/<see cref="G"/>/<see cref="Order"/>/
    /// <see cref="Cofactor"/>) are optional -- real-world DV/terminal certificates typically omit them,
    /// inheriting domain parameters from the issuing CVCA out-of-band; only <see cref="Y"/> (the actual
    /// public point) is always present for EC. See docs/cvc-api-surface.md section 3.
    /// </summary>
    private readonly record struct PublicKeyFields(
        DerObjectIdentifier Oid,
        BigInteger? Modulus,
        BigInteger? Exponent,
        BigInteger? P,
        BigInteger? A,
        BigInteger? B,
        byte[]? G,
        BigInteger? Order,
        byte[]? Y,
        BigInteger? Cofactor);

    /// <summary>
    /// Maps EAC Terminal Authentication algorithm OIDs (<c>Org.BouncyCastle.Asn1.Eac.EacObjectIdentifiers
    /// .id_TA_*</c>) to the JCE-style signature algorithm mnemonic BouncyCastle's <c>SignerUtilities</c>
    /// recognizes (e.g. "SHA256withECDSA"). Per docs/cvc-api-surface.md section 3, OIDs are always sourced
    /// from BouncyCastle's own EAC OID table, never hand-derived.
    /// </summary>
    private static readonly Dictionary<string, string> OidToAlgorithmName = new()
    {
        [EacObjectIdentifiers.id_TA_RSA_v1_5_SHA_1.Id] = "SHA1withRSA",
        [EacObjectIdentifiers.id_TA_RSA_v1_5_SHA_256.Id] = "SHA256withRSA",
        [EacObjectIdentifiers.id_TA_RSA_PSS_SHA_1.Id] = "SHA1withRSAandMGF1",
        [EacObjectIdentifiers.id_TA_RSA_PSS_SHA_256.Id] = "SHA256withRSAandMGF1",
        [EacObjectIdentifiers.id_TA_ECDSA_SHA_1.Id] = "SHA1withECDSA",
        [EacObjectIdentifiers.id_TA_ECDSA_SHA_224.Id] = "SHA224withECDSA",
        [EacObjectIdentifiers.id_TA_ECDSA_SHA_256.Id] = "SHA256withECDSA",
        [EacObjectIdentifiers.id_TA_ECDSA_SHA_384.Id] = "SHA384withECDSA",
        [EacObjectIdentifiers.id_TA_ECDSA_SHA_512.Id] = "SHA512withECDSA",
    };

    /// <summary>Reverse of <see cref="OidToAlgorithmName"/>, used when building a certificate from an algorithm mnemonic.</summary>
    private static readonly Dictionary<string, DerObjectIdentifier> AlgorithmNameToOid = new(StringComparer.OrdinalIgnoreCase)
    {
        ["SHA1withRSA"] = EacObjectIdentifiers.id_TA_RSA_v1_5_SHA_1,
        ["SHA256withRSA"] = EacObjectIdentifiers.id_TA_RSA_v1_5_SHA_256,
        ["SHA1withRSAandMGF1"] = EacObjectIdentifiers.id_TA_RSA_PSS_SHA_1,
        ["SHA256withRSAandMGF1"] = EacObjectIdentifiers.id_TA_RSA_PSS_SHA_256,
        ["SHA1withECDSA"] = EacObjectIdentifiers.id_TA_ECDSA_SHA_1,
        ["SHA224withECDSA"] = EacObjectIdentifiers.id_TA_ECDSA_SHA_224,
        ["SHA256withECDSA"] = EacObjectIdentifiers.id_TA_ECDSA_SHA_256,
        ["SHA384withECDSA"] = EacObjectIdentifiers.id_TA_ECDSA_SHA_384,
        ["SHA512withECDSA"] = EacObjectIdentifiers.id_TA_ECDSA_SHA_512,
    };

    private readonly byte _certificateProfileIdentifier;
    private readonly PublicKeyFields _publicKey;

    /// <summary>
    /// Raw bytes (tag+length+value) of an optional trailing Certificate Extensions element (<c>0x65</c>)
    /// or any other unrecognized trailing element found while decoding, preserved verbatim so a
    /// re-encoded certificate round-trips byte-for-byte. JMRTD itself never reads extensions content --
    /// see docs/cvc-api-surface.md section 1.
    /// </summary>
    private readonly byte[]? _extensionsRaw;

    /// <summary>Certification Authority Reference (CAR, tag <c>0x42</c>): the issuer of this certificate.</summary>
    public CVCPrincipal AuthorityReference { get; }

    /// <summary>Certificate Holder Reference (CHR, tag <c>0x5F20</c>): the subject of this certificate.</summary>
    public CVCPrincipal HolderReference { get; }

    /// <summary>Certificate Holder Authorization Template (CHAT, tag <c>0x7F4C</c>).</summary>
    public CVCAuthorizationTemplate AuthorizationTemplate { get; }

    /// <summary>Certificate Effective Date (tag <c>0x5F25</c>).</summary>
    public DateOnly NotBefore { get; }

    /// <summary>Certificate Expiration Date (tag <c>0x5F24</c>).</summary>
    public DateOnly NotAfter { get; }

    /// <summary>Signature bytes (tag <c>0x5F37</c>'s value only, no tag/length), raw (non-DER) form -- see docs/cvc-api-surface.md section 6.</summary>
    public byte[] Signature { get; }

    /// <summary>
    /// Canonical constructor: assembles a certificate from already-decoded/already-resolved parts. Used
    /// both by <see cref="Parse(Stream)"/> (decoding) and by the internal build path used by
    /// <see cref="CVCertificateBuilder"/> (encoding). <c>internal</c> rather than <c>private</c> so the
    /// builder can construct an unsigned certificate (to obtain <see cref="GetCertBodyData"/> to sign)
    /// and then the final signed certificate.
    /// </summary>
    private CardVerifiableCertificate(
        byte certificateProfileIdentifier,
        CVCPrincipal authorityReference,
        CVCPrincipal holderReference,
        CVCAuthorizationTemplate authorizationTemplate,
        DateOnly notBefore,
        DateOnly notAfter,
        PublicKeyFields publicKey,
        byte[]? extensionsRaw,
        byte[] signature)
    {
        _certificateProfileIdentifier = certificateProfileIdentifier;
        AuthorityReference = authorityReference;
        HolderReference = holderReference;
        AuthorizationTemplate = authorizationTemplate;
        NotBefore = notBefore;
        NotAfter = notAfter;
        _publicKey = publicKey;
        _extensionsRaw = extensionsRaw;
        Signature = signature;
    }

    /// <summary>
    /// Constructs a certificate from an already-computed signature (the signature is not computed by this
    /// constructor -- mirrors JMRTD's own public 9-argument constructor, which likewise just wraps
    /// caller-supplied signature bytes). <paramref name="algorithm"/> is a JCE-style mnemonic such as
    /// "SHA256withECDSA" or "SHA256withRSA".
    /// </summary>
    public CardVerifiableCertificate(
        CVCPrincipal authorityReference,
        CVCPrincipal holderReference,
        AsymmetricKeyParameter publicKey,
        string algorithm,
        DateOnly notBefore,
        DateOnly notAfter,
        CVCAuthorizationTemplate.Role role,
        CVCAuthorizationTemplate.Permission permission,
        byte[] signatureData)
        : this(
            CurrentProfileIdentifier,
            authorityReference,
            holderReference,
            new CVCAuthorizationTemplate(role, permission),
            notBefore,
            notAfter,
            ExtractPublicKeyFields(publicKey, algorithm),
            extensionsRaw: null,
            signatureData)
    {
    }

    /// <summary>Signature algorithm mnemonic (e.g. "SHA256withECDSA"), resolved from the public key's algorithm OID, or <c>null</c> if unrecognized.</summary>
    public string? SigAlgName => OidToAlgorithmName.TryGetValue(_publicKey.Oid.Id, out string? name) ? name : null;

    /// <summary>Signature algorithm object identifier, dotted string form.</summary>
    public string SigAlgOid => _publicKey.Oid.Id;

    /// <summary>
    /// The public key, or <c>null</c> if this is an EC key without explicit domain parameters (the common
    /// case for DV/terminal certificates, which inherit domain parameters from the issuing CVCA
    /// out-of-band -- see docs/cvc-api-surface.md section 3). In that case use
    /// <see cref="RawEcPublicKeyPoint"/> together with domain parameters obtained elsewhere.
    /// </summary>
    public AsymmetricKeyParameter? PublicKey
    {
        get
        {
            if (_publicKey.Modulus != null && _publicKey.Exponent != null)
            {
                return new RsaKeyParameters(isPrivate: false, _publicKey.Modulus, _publicKey.Exponent);
            }

            if (_publicKey.Y != null && _publicKey.P != null && _publicKey.A != null && _publicKey.B != null && _publicKey.G != null && _publicKey.Order != null)
            {
                BigInteger cofactor = _publicKey.Cofactor ?? BigInteger.One;
                var curve = new FpCurve(_publicKey.P, _publicKey.A, _publicKey.B, _publicKey.Order, cofactor);
                Org.BouncyCastle.Math.EC.ECPoint g = curve.DecodePoint(_publicKey.G);
                var domain = new ECDomainParameters(curve, g, _publicKey.Order, cofactor);
                Org.BouncyCastle.Math.EC.ECPoint y = curve.DecodePoint(_publicKey.Y);
                return new ECPublicKeyParameters(y, domain);
            }

            return null;
        }
    }

    /// <summary>
    /// The raw (uncompressed, <c>0x04‖X‖Y</c>) EC public point bytes, always present for an EC key
    /// regardless of whether explicit domain parameters were included. <c>null</c> for an RSA key.
    /// </summary>
    public byte[]? RawEcPublicKeyPoint => _publicKey.Y;

    /// <summary>Full <c>0x7F21</c> TLV (tag+length+value): the DER-encoded form of this certificate.</summary>
    public byte[] GetEncoded()
    {
        byte[] body = GetCertBodyData();
        using var stream = new MemoryStream(body.Length + Signature.Length + 8);
        stream.Write(body, 0, body.Length);
        WriteTlv(stream, SignatureTag, Signature);
        return TlvUtil.TlvEncode(CvCertificateTag, stream.ToArray());
    }

    /// <summary>
    /// The DER-encoded certificate body (full <c>0x7F4E</c> TLV) -- this is exactly the to-be-signed (TBS)
    /// data; the signature in <see cref="Signature"/> covers this element's tag+length+value bytes
    /// verbatim (see docs/cvc-api-surface.md section 6).
    /// </summary>
    public byte[] GetCertBodyData()
    {
        using var stream = new MemoryStream();
        WriteTlv(stream, ProfileIdentifierTag, [_certificateProfileIdentifier]);
        WriteTlv(stream, AuthorityReferenceTag, AuthorityReference.EncodeValue());
        byte[] publicKeyTlv = EncodePublicKey(_publicKey);
        stream.Write(publicKeyTlv, 0, publicKeyTlv.Length);
        WriteTlv(stream, HolderReferenceTag, HolderReference.EncodeValue());
        byte[] chatTlv = AuthorizationTemplate.Encode();
        stream.Write(chatTlv, 0, chatTlv.Length);
        WriteTlv(stream, EffectiveDateTag, EncodeBcdDate(NotBefore));
        WriteTlv(stream, ExpirationDateTag, EncodeBcdDate(NotAfter));
        if (_extensionsRaw != null)
        {
            stream.Write(_extensionsRaw, 0, _extensionsRaw.Length);
        }

        return TlvUtil.TlvEncode(CertificateBodyTag, stream.ToArray());
    }

    /// <summary>
    /// Verifies that this certificate was signed using the private key corresponding to
    /// <paramref name="issuerPublicKey"/>. Throws <see cref="CryptographicException"/> if verification
    /// fails or the signature algorithm cannot be determined.
    /// </summary>
    public void Verify(AsymmetricKeyParameter issuerPublicKey)
    {
        ArgumentNullException.ThrowIfNull(issuerPublicKey);
        string? sigAlgName = SigAlgName;
        if (sigAlgName == null)
        {
            throw new CryptographicException($"Could not determine signature algorithm for object identifier {SigAlgOid}.");
        }

        byte[] tbs = GetCertBodyData();
        byte[] signatureToVerify = Signature;

        ISigner signer = SignerUtilities.GetSigner(sigAlgName);
        if (issuerPublicKey is ECPublicKeyParameters ecKey)
        {
            // EAC/TR-03110 signatures are raw r||s (see docs/cvc-api-surface.md section 6), but BC's
            // ECDSA signer verifies the ASN.1 DER SEQUENCE{r,s} form -- convert before verifying.
            int componentSize = (ecKey.Parameters.Curve.FieldSize + 7) / 8;
            signatureToVerify = RawToDerEcdsaSignature(Signature, componentSize);
        }

        signer.Init(forSigning: false, issuerPublicKey);
        signer.BlockUpdate(tbs, 0, tbs.Length);
        if (!signer.VerifySignature(signatureToVerify))
        {
            throw new CryptographicException($"CV certificate signature verification failed for holder {HolderReference}.");
        }
    }

    public override string ToString() =>
        $"CVC[{AuthorityReference} -> {HolderReference}, {AuthorizationTemplate}, {NotBefore:yyyy-MM-dd}..{NotAfter:yyyy-MM-dd}]";

    public bool Equals(CardVerifiableCertificate? other)
    {
        if (other is null)
        {
            return false;
        }
        if (ReferenceEquals(other, this))
        {
            return true;
        }

        return GetEncoded().AsSpan().SequenceEqual(other.GetEncoded());
    }

    public override bool Equals(object? obj) => Equals(obj as CardVerifiableCertificate);

    public override int GetHashCode()
    {
        byte[] encoded = GetEncoded();
        var hash = new HashCode();
        hash.AddBytes(encoded);
        return hash.ToHashCode();
    }

    /// <summary>Parses a single CV certificate (<c>0x7F21</c>) from the given stream. Bytes after the certificate are ignored.</summary>
    public static CardVerifiableCertificate Parse(Stream inputStream)
    {
        ArgumentNullException.ThrowIfNull(inputStream);
        using var tlvIn = new TlvInputStream(inputStream, leaveOpen: true);
        int tag = tlvIn.ReadTag();
        if (tag != CvCertificateTag)
        {
            throw new IOException($"Expected CV certificate tag 0x{CvCertificateTag:X}, found 0x{tag:X}.");
        }
        tlvIn.ReadLength();
        byte[] value = tlvIn.ReadValue();
        return ParseValue(value);
    }

    /// <summary>Parses a single CV certificate (<c>0x7F21</c>) from the given bytes. Trailing bytes are ignored.</summary>
    public static CardVerifiableCertificate Parse(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        using var stream = new MemoryStream(data, writable: false);
        return Parse(stream);
    }

    /// <summary>Builds an as-yet-unsigned certificate for the given fields -- used only by <see cref="CVCertificateBuilder"/> to obtain <see cref="GetCertBodyData"/> to sign.</summary>
    internal static CardVerifiableCertificate CreateUnsigned(
        CVCPrincipal authorityReference,
        CVCPrincipal holderReference,
        AsymmetricKeyParameter publicKey,
        string algorithmName,
        CVCAuthorizationTemplate authorizationTemplate,
        DateOnly notBefore,
        DateOnly notAfter) =>
        new(
            CurrentProfileIdentifier,
            authorityReference,
            holderReference,
            authorizationTemplate,
            notBefore,
            notAfter,
            ExtractPublicKeyFields(publicKey, algorithmName),
            extensionsRaw: null,
            signature: []);

    /// <summary>Returns a copy of <paramref name="unsigned"/> with the given signature bytes attached -- used only by <see cref="CVCertificateBuilder"/>.</summary>
    internal static CardVerifiableCertificate WithSignature(CardVerifiableCertificate unsigned, byte[] signature) =>
        new(
            unsigned._certificateProfileIdentifier,
            unsigned.AuthorityReference,
            unsigned.HolderReference,
            unsigned.AuthorizationTemplate,
            unsigned.NotBefore,
            unsigned.NotAfter,
            unsigned._publicKey,
            unsigned._extensionsRaw,
            signature);

    /// <summary>
    /// Converts a DER-encoded ASN.1 <c>SEQUENCE{r,s}</c> ECDSA signature (as produced by BouncyCastle's
    /// ECDSA signer) to the raw <c>r‖s</c> form TR-03110/EAC 1.11 requires, each component left-padded
    /// with zero bytes to <paramref name="componentSize"/> -- used only by <see cref="CVCertificateBuilder"/>.
    /// Implemented locally (rather than deferring to <c>nMRTD.Util.GetRawECDSASignature</c>, which covers
    /// the same conversion for other EAC/PACE contexts) because this correctness-critical crypto path
    /// should not depend on the exact method signature/name of a concurrently-in-progress port.
    /// </summary>
    internal static byte[] DerToRawEcdsaSignature(byte[] derSignature, int componentSize)
    {
        Asn1Sequence sequence = Asn1Sequence.GetInstance(derSignature);
        BigInteger r = DerInteger.GetInstance(sequence[0]).PositiveValue;
        BigInteger s = DerInteger.GetInstance(sequence[1]).PositiveValue;

        byte[] result = new byte[2 * componentSize];
        byte[] rBytes = AlignToSize(r.ToByteArrayUnsigned(), componentSize);
        byte[] sBytes = AlignToSize(s.ToByteArrayUnsigned(), componentSize);
        Buffer.BlockCopy(rBytes, 0, result, 0, componentSize);
        Buffer.BlockCopy(sBytes, 0, result, componentSize, componentSize);
        return result;
    }

    /// <summary>Inverse of <see cref="DerToRawEcdsaSignature"/>: raw <c>r‖s</c> to a DER <c>SEQUENCE{r,s}</c>, for verifying with BC's ECDSA signer.</summary>
    private static byte[] RawToDerEcdsaSignature(byte[] rawSignature, int componentSize)
    {
        if (rawSignature.Length != 2 * componentSize)
        {
            // Be lenient about a size mismatch (e.g. a shorter/longer raw signature than the verifying
            // key's own field size would suggest) rather than failing outright -- split evenly.
            componentSize = rawSignature.Length / 2;
        }

        var r = new BigInteger(1, rawSignature, 0, componentSize);
        var s = new BigInteger(1, rawSignature, componentSize, rawSignature.Length - componentSize);
        return new DerSequence(new DerInteger(r), new DerInteger(s)).GetDerEncoded();
    }

    /// <summary>Left-pads (or truncates from the left, if too long) <paramref name="data"/> to exactly <paramref name="size"/> bytes -- mirrors <c>Util.alignKeyDataToSize</c>'s semantics.</summary>
    private static byte[] AlignToSize(byte[] data, int size)
    {
        if (data.Length == size)
        {
            return data;
        }

        byte[] result = new byte[size];
        int copyLength = Math.Min(data.Length, size);
        Buffer.BlockCopy(data, data.Length - copyLength, result, size - copyLength, copyLength);
        return result;
    }

    /// <summary>
    /// Unpacked-BCD <c>YYMMDD</c> encoding of a certificate date (BSI TR-03110-3, D.2.1.3): 6 bytes, one
    /// decimal digit (0x00-0x09) per byte. Two-digit years are interpreted as 2000-2099.
    /// </summary>
    private static byte[] EncodeBcdDate(DateOnly date)
    {
        if (date.Year < 2000 || date.Year > 2099)
        {
            throw new ArgumentOutOfRangeException(nameof(date), date, "Certificate dates must be in 2000-2099.");
        }

        int yy = date.Year % 100;
        return
        [
            (byte)(yy / 10), (byte)(yy % 10),
            (byte)(date.Month / 10), (byte)(date.Month % 10),
            (byte)(date.Day / 10), (byte)(date.Day % 10),
        ];
    }

    private static DateOnly DecodeBcdDate(byte[] value)
    {
        if (value.Length != 6)
        {
            throw new IOException($"Expected a 6-byte unpacked BCD date, found {value.Length} bytes.");
        }

        foreach (byte digit in value)
        {
            if (digit > 9)
            {
                throw new IOException($"Invalid unpacked BCD digit 0x{digit:X2} in date.");
            }
        }

        int yy = (10 * value[0]) + value[1];
        int mm = (10 * value[2]) + value[3];
        int dd = (10 * value[4]) + value[5];
        try
        {
            return new DateOnly(2000 + yy, mm, dd);
        }
        catch (ArgumentOutOfRangeException e)
        {
            throw new IOException($"Invalid date {yy:D2}{mm:D2}{dd:D2}.", e);
        }
    }

    /// <summary>Resolves an EAC OID to the <see cref="AsymmetricKeyParameter"/>'s public key fields, given a JCE-style algorithm mnemonic.</summary>
    private static PublicKeyFields ExtractPublicKeyFields(AsymmetricKeyParameter publicKey, string algorithmName)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(algorithmName);
        if (!AlgorithmNameToOid.TryGetValue(algorithmName, out DerObjectIdentifier? oid))
        {
            throw new NotSupportedException($"Unsupported CV certificate signature algorithm \"{algorithmName}\".");
        }

        if (publicKey is RsaKeyParameters { IsPrivate: false } rsaKey)
        {
            return new PublicKeyFields(oid, rsaKey.Modulus, rsaKey.Exponent, null, null, null, null, null, null, null);
        }

        if (publicKey is ECPublicKeyParameters ecKey)
        {
            if (ecKey.Parameters.Curve is not FpCurve fpCurve)
            {
                throw new NotSupportedException("Only prime-field (Fp) EC curves are supported for CV certificate public keys.");
            }

            byte[] g = ecKey.Parameters.G.GetEncoded(compressed: false);
            byte[] y = ecKey.Q.GetEncoded(compressed: false);
            return new PublicKeyFields(oid, null, null, fpCurve.Q, fpCurve.A.ToBigInteger(), fpCurve.B.ToBigInteger(), g, ecKey.Parameters.N, y, ecKey.Parameters.H);
        }

        throw new NotSupportedException($"Unsupported public key type {publicKey.GetType().FullName}; expected an RSA or EC public key.");
    }

    /// <summary>Encodes the full <c>0x7F49</c> Public Key TLV.</summary>
    private static byte[] EncodePublicKey(PublicKeyFields fields)
    {
        using var stream = new MemoryStream();
        byte[] oidTlv = fields.Oid.GetDerEncoded();
        stream.Write(oidTlv, 0, oidTlv.Length);

        if (fields.Modulus != null && fields.Exponent != null)
        {
            WriteTlv(stream, RsaModulusTag, fields.Modulus.ToByteArrayUnsigned());
            WriteTlv(stream, RsaExponentTag, fields.Exponent.ToByteArrayUnsigned());
        }
        else
        {
            if (fields.P != null)
            {
                WriteTlv(stream, EcPrimeModulusTag, fields.P.ToByteArrayUnsigned());
            }
            if (fields.A != null)
            {
                WriteTlv(stream, EcFirstCoefficientTag, fields.A.ToByteArrayUnsigned());
            }
            if (fields.B != null)
            {
                WriteTlv(stream, EcSecondCoefficientTag, fields.B.ToByteArrayUnsigned());
            }
            if (fields.G != null)
            {
                WriteTlv(stream, EcBasePointTag, fields.G);
            }
            if (fields.Order != null)
            {
                WriteTlv(stream, EcOrderTag, fields.Order.ToByteArrayUnsigned());
            }
            if (fields.Y != null)
            {
                WriteTlv(stream, EcPublicPointTag, fields.Y);
            }
            if (fields.Cofactor != null)
            {
                WriteTlv(stream, EcCofactorTag, fields.Cofactor.ToByteArrayUnsigned());
            }
        }

        return TlvUtil.TlvEncode(PublicKeyTag, stream.ToArray());
    }

    /// <summary>Decodes the value octets of a <c>0x7F49</c> element.</summary>
    private static PublicKeyFields DecodePublicKey(byte[] value)
    {
        using var stream = new MemoryStream(value, writable: false);
        using var tlvIn = new TlvInputStream(stream, leaveOpen: true);

        int oidTag = tlvIn.ReadTag();
        if (oidTag != PublicKeyOidTag)
        {
            throw new IOException($"Expected OID tag 0x{PublicKeyOidTag:X} in public key, found 0x{oidTag:X}.");
        }
        tlvIn.ReadLength();
        byte[] oidValue = tlvIn.ReadValue();
        var oid = (DerObjectIdentifier)Asn1Object.FromByteArray(TlvUtil.TlvEncode(PublicKeyOidTag, oidValue));

        bool isRsa = OidIsInArc(oid, EacObjectIdentifiers.id_TA_RSA);
        bool isEcdsa = !isRsa && OidIsInArc(oid, EacObjectIdentifiers.id_TA_ECDSA);
        if (!isRsa && !isEcdsa)
        {
            throw new NotSupportedException($"Unsupported CV certificate public key algorithm OID {oid.Id}.");
        }

        BigInteger? modulus = null;
        BigInteger? exponent = null;
        BigInteger? p = null;
        BigInteger? a = null;
        BigInteger? b = null;
        BigInteger? order = null;
        BigInteger? cofactor = null;
        byte[]? g = null;
        byte[]? y = null;

        while (stream.Position < stream.Length)
        {
            int tag = tlvIn.ReadTag();
            tlvIn.ReadLength();
            byte[] tagValue = tlvIn.ReadValue();

            if (isRsa)
            {
                switch (tag)
                {
                    case RsaModulusTag:
                        modulus = new BigInteger(1, tagValue);
                        break;
                    case RsaExponentTag:
                        exponent = new BigInteger(1, tagValue);
                        break;
                    default:
                        // Unrecognized field within a supposedly-RSA public key: ignore rather than fail,
                        // matching the general "tolerate unrecognized trailing content" posture recommended
                        // in docs/cvc-api-surface.md.
                        break;
                }
            }
            else
            {
                switch (tag)
                {
                    case EcPrimeModulusTag:
                        p = new BigInteger(1, tagValue);
                        break;
                    case EcFirstCoefficientTag:
                        a = new BigInteger(1, tagValue);
                        break;
                    case EcSecondCoefficientTag:
                        b = new BigInteger(1, tagValue);
                        break;
                    case EcBasePointTag:
                        g = tagValue;
                        break;
                    case EcOrderTag:
                        order = new BigInteger(1, tagValue);
                        break;
                    case EcPublicPointTag:
                        y = tagValue;
                        break;
                    case EcCofactorTag:
                        cofactor = new BigInteger(1, tagValue);
                        break;
                    default:
                        break;
                }
            }
        }

        return new PublicKeyFields(oid, modulus, exponent, p, a, b, g, order, y, cofactor);
    }

    /// <summary>Whether <paramref name="oid"/> is <paramref name="arc"/> itself or a child of it.</summary>
    private static bool OidIsInArc(DerObjectIdentifier oid, DerObjectIdentifier arc) =>
        oid.Id == arc.Id || oid.Id.StartsWith(arc.Id + ".", StringComparison.Ordinal);

    private static void WriteTlv(Stream stream, int tag, byte[] value)
    {
        byte[] encoded = TlvUtil.TlvEncode(tag, value);
        stream.Write(encoded, 0, encoded.Length);
    }

    private static CardVerifiableCertificate ParseValue(byte[] value)
    {
        using var stream = new MemoryStream(value, writable: false);
        using var tlvIn = new TlvInputStream(stream, leaveOpen: true);

        int bodyTag = tlvIn.ReadTag();
        if (bodyTag != CertificateBodyTag)
        {
            throw new IOException($"Expected certificate body tag 0x{CertificateBodyTag:X}, found 0x{bodyTag:X}.");
        }
        tlvIn.ReadLength();
        byte[] bodyValue = tlvIn.ReadValue();

        int sigTag = tlvIn.ReadTag();
        if (sigTag != SignatureTag)
        {
            throw new IOException($"Expected signature tag 0x{SignatureTag:X}, found 0x{sigTag:X}.");
        }
        tlvIn.ReadLength();
        byte[] signature = tlvIn.ReadValue();

        return ParseBody(bodyValue, signature);
    }

    private static CardVerifiableCertificate ParseBody(byte[] bodyValue, byte[] signature)
    {
        using var stream = new MemoryStream(bodyValue, writable: false);
        using var tlvIn = new TlvInputStream(stream, leaveOpen: true);

        byte profileId = ReadFixedElement(tlvIn, ProfileIdentifierTag) is { Length: > 0 } profileBytes ? profileBytes[0] : CurrentProfileIdentifier;
        var authorityReference = CVCPrincipal.DecodeValue(ReadFixedElement(tlvIn, AuthorityReferenceTag));
        PublicKeyFields publicKeyFields = DecodePublicKey(ReadFixedElement(tlvIn, PublicKeyTag));
        var holderReference = CVCPrincipal.DecodeValue(ReadFixedElement(tlvIn, HolderReferenceTag));
        var authorizationTemplate = CVCAuthorizationTemplate.Decode(ReadFixedElement(tlvIn, 0x7F4C));
        DateOnly notBefore = DecodeBcdDate(ReadFixedElement(tlvIn, EffectiveDateTag));
        DateOnly notAfter = DecodeBcdDate(ReadFixedElement(tlvIn, ExpirationDateTag));

        byte[]? extensionsRaw = null;
        if (stream.Position < stream.Length)
        {
            // Optional Certificate Extensions (0x65), or any other unrecognized trailing element: preserve
            // raw bytes verbatim without interpreting contents -- see docs/cvc-api-surface.md section 1.
            int extTag = tlvIn.ReadTag();
            tlvIn.ReadLength();
            byte[] extValue = tlvIn.ReadValue();
            extensionsRaw = TlvUtil.TlvEncode(extTag, extValue);
        }

        return new CardVerifiableCertificate(profileId, authorityReference, holderReference, authorizationTemplate, notBefore, notAfter, publicKeyFields, extensionsRaw, signature);
    }

    private static byte[] ReadFixedElement(TlvInputStream tlvIn, int expectedTag)
    {
        int tag = tlvIn.ReadTag();
        if (tag != expectedTag)
        {
            throw new IOException($"Expected tag 0x{expectedTag:X} in CV certificate body, found 0x{tag:X}.");
        }
        tlvIn.ReadLength();
        return tlvIn.ReadValue();
    }
}
