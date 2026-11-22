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
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.X509;
using BigInteger = Org.BouncyCastle.Math.BigInteger;

namespace nMRTD.Lds;

/// <summary>Port of <c>org.jmrtd.lds.ChipAuthenticationPublicKeyInfo</c>: a concrete SecurityInfo
/// structure that stores chip authentication public key info, see EAC TR 03110 1.11 specification.
///
/// This data structure provides a Chip Authentication Public Key of the MRTD chip.
/// <list type="bullet">
/// <item>The object identifier <c>protocol</c> SHALL identify the type of the public key (i.e. DH or ECDH).</item>
/// <item>The sequence <c>chipAuthenticationPublicKey</c> SHALL contain the public key in encoded form.</item>
/// <item>The integer <c>keyId</c> MAY be used to indicate the local key identifier. It MUST be used if
/// the MRTD chip provides multiple public keys for Chip Authentication.</item>
/// </list>
///
/// NOTE: Java's <c>PublicKey</c> is ported as BouncyCastle's <see cref="AsymmetricKeyParameter"/>
/// throughout (per porting conventions, this port works directly against BC's own crypto object model
/// rather than a JCA-provider abstraction). Java's <c>org.jmrtd.Util.reconstructPublicKey</c> existed to
/// paper over JCA providers sometimes handing back <c>PublicKey</c> implementations with unreliable
/// <c>equals()</c>/<c>getEncoded()</c>; BC's own <see cref="AsymmetricKeyParameter"/> subclasses
/// (<see cref="DHPublicKeyParameters"/>, <see cref="ECPublicKeyParameters"/>) already have correct
/// value-based equality, so that reconstruction step is a no-op here (kept as a named method for
/// traceability against the Java source).</summary>
public class ChipAuthenticationPublicKeyInfo : SecurityInfo
{
    private readonly string oid;

    /// <summary>Optional, use <c>null</c> if implicit.</summary>
    private readonly BigInteger? keyId;

    private readonly AsymmetricKeyParameter publicKey;

    /// <summary>Creates a public key info structure with implicit key identifier.</summary>
    /// <param name="publicKey">either a DH public key or an EC public key</param>
    public ChipAuthenticationPublicKeyInfo(AsymmetricKeyParameter publicKey)
        : this(publicKey, null)
    {
    }

    /// <param name="publicKey">either a DH public key or an EC public key</param>
    /// <param name="keyId">key identifier</param>
    public ChipAuthenticationPublicKeyInfo(AsymmetricKeyParameter publicKey, BigInteger? keyId)
        : this(InferProtocolIdentifier(publicKey), publicKey, keyId)
    {
    }

    /// <summary>Creates a public key info structure with implicit key identifier.</summary>
    /// <param name="oid">a proper public key identifier</param>
    /// <param name="publicKey">appropriate public key</param>
    public ChipAuthenticationPublicKeyInfo(string oid, AsymmetricKeyParameter publicKey)
        : this(oid, publicKey, null)
    {
    }

    /// <param name="oid">a proper public key identifier</param>
    /// <param name="publicKey">appropriate public key</param>
    /// <param name="keyId">the key identifier or <c>null</c> if not present</param>
    public ChipAuthenticationPublicKeyInfo(string oid, AsymmetricKeyParameter publicKey, BigInteger? keyId)
    {
        this.oid = oid;
        this.publicKey = ReconstructPublicKey(publicKey);
        this.keyId = keyId;
        CheckFields();
    }

    [Obsolete("This method will be removed from the visible interface (because of dependency on BC API)")]
    public override Asn1Object GetDERObject()
    {
        var vector = new Asn1EncodableVector();
        SubjectPublicKeyInfo subjectPublicKeyInfo = ToSubjectPublicKeyInfo(publicKey);
        vector.Add(new DerObjectIdentifier(oid));
        vector.Add(subjectPublicKeyInfo.ToAsn1Object());
        if (keyId != null)
        {
            vector.Add(new DerInteger(keyId));
        }
        return new DLSequence(vector);
    }

    /// <summary>
    /// Encodes the public key. A DH key whose domain parameters include the subgroup order q is encoded
    /// as an X9.42 <c>dhpublicnumber</c> key (RFC 3279: p, g, q and the optional j and validation
    /// parameters), the form TR-03110 and ICAO Doc 9303-11 refer to; any other key is encoded by Bouncy
    /// Castle as before (a DH key without q as PKCS #3 <c>dhKeyAgreement</c>).
    /// </summary>
    /// <remarks>
    /// Divergence from JMRTD: <c>Util.toSubjectPublicKeyInfo</c> always writes PKCS #3 parameters (p, g, l)
    /// under the key's algorithm identifier, as does Bouncy Castle's <c>SubjectPublicKeyInfoFactory</c>.
    /// So q was lost, and a key read from an X9.42 encoding was written back with the
    /// <c>dhpublicnumber</c> identifier but PKCS #3 parameters, which no longer decodes to the same key.
    /// </remarks>
    private static SubjectPublicKeyInfo ToSubjectPublicKeyInfo(AsymmetricKeyParameter publicKey)
    {
        if (publicKey is DHPublicKeyParameters { Parameters.Q: not null } dhPublicKey)
        {
            DHParameters parameters = dhPublicKey.Parameters;
            DHValidationParameters? validation = parameters.ValidationParameters;
            var domainParameters = new DHDomainParameters(
                new DerInteger(parameters.P),
                new DerInteger(parameters.G),
                new DerInteger(parameters.Q),
                parameters.J == null ? null : new DerInteger(parameters.J),
                validation == null ? null : new DHValidationParms(new DerBitString(validation.GetSeed()), new DerInteger(validation.Counter)));
            return new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(X9ObjectIdentifiers.DHPublicNumber, domainParameters),
                new DerInteger(dhPublicKey.Y));
        }
        return SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
    }

    public override string GetObjectIdentifier() => oid;

    public override string GetProtocolOIDString() => ToProtocolOIDString(oid);

    /// <summary>Returns a key identifier stored in this ChipAuthenticationPublicKeyInfo structure,
    /// <c>null</c> if not present.</summary>
    public BigInteger? GetKeyId() => keyId;

    /// <summary>Returns the subject public key contained in this ChipAuthenticationPublicKeyInfo structure.</summary>
    public AsymmetricKeyParameter GetSubjectPublicKey() => publicKey;

    /// <summary>Checks the correctness of the data for this instance of <see cref="SecurityInfo"/>.</summary>
    /// <remarks>FIXME: also check type of public key.</remarks>
    protected void CheckFields()
    {
        try
        {
            if (!CheckRequiredIdentifier(oid))
            {
                throw new ArgumentException("Wrong identifier: " + oid);
            }
        }
        catch (Exception e)
        {
            throw new ArgumentException("Malformed ChipAuthenticationInfo", e);
        }
    }

    /// <summary>Checks whether the given object identifier identifies a ChipAuthenticationPublicKeyInfo structure.</summary>
    public static bool CheckRequiredIdentifier(string oid) => ID_PK_DH.Equals(oid) || ID_PK_ECDH.Equals(oid);

    public override string ToString()
    {
        return "ChipAuthenticationPublicKeyInfo ["
            + "protocol: " + ToProtocolOIDString(oid) + ", "
            + "chipAuthenticationPublicKey: " + GetDetailedPublicKeyAlgorithm(GetSubjectPublicKey()) + ", "
            + "keyId: " + (keyId == null ? "-" : keyId.ToString())
            + "]";
    }

    public override int GetHashCode()
    {
        return 123 + 1337 * (oid.GetHashCode() + (keyId == null ? 111 : keyId.GetHashCode()) + publicKey.GetHashCode());
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
        if (other.GetType() != typeof(ChipAuthenticationPublicKeyInfo))
        {
            return false;
        }

        var otherInfo = (ChipAuthenticationPublicKeyInfo)other;
        return oid.Equals(otherInfo.oid)
            && (keyId == null && otherInfo.keyId == null || keyId != null && keyId.Equals(otherInfo.keyId))
            && publicKey.Equals(otherInfo.publicKey);
    }

    /// <summary>Returns the key agreement algorithm (<c>"DH"</c> or <c>"ECDH"</c>) for the given Chip
    /// Authentication Public Key info object identifier.</summary>
    /// <exception cref="FormatException">if the OID is not a known Chip Authentication Public Key info
    /// object identifier (Java: unchecked <c>NumberFormatException</c>)</exception>
    public static string ToKeyAgreementAlgorithm(string? oid)
    {
        if (oid == null)
        {
            throw new FormatException("Unknown OID: null");
        }
        if (ID_PK_DH.Equals(oid))
        {
            return "DH";
        }
        if (ID_PK_ECDH.Equals(oid))
        {
            return "ECDH";
        }

        throw new FormatException($"Unknown OID: \"{oid}\"");
    }

    /// <summary>Infers the protocol object identifier (<see cref="SecurityInfo.ID_PK_DH"/> or
    /// <see cref="SecurityInfo.ID_PK_ECDH"/>) from the concrete type of a public key. Port of
    /// <c>org.jmrtd.Util.inferProtocolIdentifier</c> (inlined here since <c>Util</c> itself is outside
    /// this port's scope).</summary>
    private static string InferProtocolIdentifier(AsymmetricKeyParameter publicKey)
    {
        return publicKey switch
        {
            DHPublicKeyParameters => ID_PK_DH,
            ECPublicKeyParameters => ID_PK_ECDH,
            _ => throw new ArgumentException("Unsupported public key type: " + publicKey.GetType()),
        };
    }

    /// <summary>Port of <c>org.jmrtd.Util.reconstructPublicKey</c>; a no-op here, see this class's doc comment.</summary>
    private static AsymmetricKeyParameter ReconstructPublicKey(AsymmetricKeyParameter publicKey) => publicKey;

    /// <summary>Human readable description of a public key's algorithm and size, for
    /// <see cref="ToString"/> only. Port of <c>org.jmrtd.Util.getDetailedPublicKeyAlgorithm</c> (inlined,
    /// simplified: this is diagnostic text only, not used for any protocol decision).</summary>
    private static string GetDetailedPublicKeyAlgorithm(AsymmetricKeyParameter publicKey)
    {
        return publicKey switch
        {
            DHPublicKeyParameters dh => $"DH ({dh.Parameters.P.BitLength} bit)",
            ECPublicKeyParameters ec => $"EC ({ec.Parameters.Curve.FieldSize} bit)",
            _ => publicKey.GetType().Name,
        };
    }

    private static string ToProtocolOIDString(string oid)
    {
        if (ID_PK_DH.Equals(oid))
        {
            return "id-PK-DH";
        }
        if (ID_PK_ECDH.Equals(oid))
        {
            return "id-PK-ECDH";
        }

        return oid;
    }
}
