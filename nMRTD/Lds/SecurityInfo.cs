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
using Org.BouncyCastle.Asn1.Eac;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Security;
using BigInteger = Org.BouncyCastle.Math.BigInteger;

namespace nMRTD.Lds;

/* FIXME: dependency on BC in interface? (carried over from JMRTD source comment) */

/// <summary>Port of <c>org.jmrtd.lds.SecurityInfo</c>: abstract base class for security info structure.
/// See the BSI EAC 1.11 specification. See the ICAO TR - SAC v1.1 specification.
///
/// NOTE on BigInteger: unlike the general porting rule (Java <c>java.math.BigInteger</c> →
/// <c>System.Numerics.BigInteger</c>), this class and its subclasses use
/// <see cref="Org.BouncyCastle.Math.BigInteger"/> throughout, because every value here is produced by or
/// fed straight into BouncyCastle ASN.1 objects (<c>DerInteger</c> etc.) -- exactly the "heavy BC
/// interop" case the porting conventions call out as the exception to the general rule.</summary>
public abstract class SecurityInfo : AbstractLDSInfo
{
    /// <summary>Used in ECDSA based Active Authentication.
    /// <c>{joint-iso-itu-t(2) international-organizations(23) 136 mrtd(1) security(1) aaProtocolObject(5)}</c>.</summary>
    public const string ID_AA = "2.23.136.1.1.5";

    public static readonly string ID_PK_DH = EacObjectIdentifiers.id_PK_DH.Id;
    public static readonly string ID_PK_ECDH = EacObjectIdentifiers.id_PK_ECDH.Id;

    /// <summary>Used in Chip Authentication 1 and 2.</summary>
    public static readonly string ID_CA_DH_3DES_CBC_CBC = EacObjectIdentifiers.id_CA_DH_3DES_CBC_CBC.Id;

    /// <summary>Used in Chip Authentication 1 and 2.</summary>
    public static readonly string ID_CA_ECDH_3DES_CBC_CBC = EacObjectIdentifiers.id_CA_ECDH_3DES_CBC_CBC.Id;

    /// <summary>Used in Chip Authentication 1 and 2.</summary>
    public const string ID_CA_DH_AES_CBC_CMAC_128 = "0.4.0.127.0.7.2.2.3.1.2";

    /// <summary>Used in Chip Authentication 1 and 2.</summary>
    public const string ID_CA_DH_AES_CBC_CMAC_192 = "0.4.0.127.0.7.2.2.3.1.3";

    /// <summary>Used in Chip Authentication 1 and 2.</summary>
    public const string ID_CA_DH_AES_CBC_CMAC_256 = "0.4.0.127.0.7.2.2.3.1.4";

    /// <summary>Used in Chip Authentication 1 and 2.</summary>
    public const string ID_CA_ECDH_AES_CBC_CMAC_128 = "0.4.0.127.0.7.2.2.3.2.2";

    /// <summary>Used in Chip Authentication 1 and 2.</summary>
    public const string ID_CA_ECDH_AES_CBC_CMAC_192 = "0.4.0.127.0.7.2.2.3.2.3";

    /// <summary>Used in Chip Authentication 1 and 2.</summary>
    public const string ID_CA_ECDH_AES_CBC_CMAC_256 = "0.4.0.127.0.7.2.2.3.2.4";

    /// <summary>Used in Terminal Authentication 1 and 2.</summary>
    public static readonly string ID_TA = EacObjectIdentifiers.id_TA.Id;

    /// <summary>Used in Terminal Authentication 1 and 2.</summary>
    public static readonly string ID_TA_RSA = EacObjectIdentifiers.id_TA_RSA.Id;

    /// <summary>Used in Terminal Authentication 1 and 2.</summary>
    public static readonly string ID_TA_RSA_V1_5_SHA_1 = EacObjectIdentifiers.id_TA_RSA_v1_5_SHA_1.Id;

    /// <summary>Used in Terminal Authentication 1 and 2.</summary>
    public static readonly string ID_TA_RSA_V1_5_SHA_256 = EacObjectIdentifiers.id_TA_RSA_v1_5_SHA_256.Id;

    /// <summary>Used in Terminal Authentication 1 and 2.</summary>
    public static readonly string ID_TA_RSA_PSS_SHA_1 = EacObjectIdentifiers.id_TA_RSA_PSS_SHA_1.Id;

    /// <summary>Used in Terminal Authentication 1 and 2.</summary>
    public static readonly string ID_TA_RSA_PSS_SHA_256 = EacObjectIdentifiers.id_TA_RSA_PSS_SHA_256.Id;

    /// <summary>Used in Terminal Authentication 1 and 2.</summary>
    public static readonly string ID_TA_ECDSA = EacObjectIdentifiers.id_TA_ECDSA.Id;

    /// <summary>Used in Terminal Authentication 1 and 2.</summary>
    public static readonly string ID_TA_ECDSA_SHA_1 = EacObjectIdentifiers.id_TA_ECDSA_SHA_1.Id;

    /// <summary>Used in Terminal Authentication 1 and 2.</summary>
    public static readonly string ID_TA_ECDSA_SHA_224 = EacObjectIdentifiers.id_TA_ECDSA_SHA_224.Id;

    /// <summary>Used in Terminal Authentication 1 and 2. NOTE: "id-TA-ECDSA-SHA-256" is 0.4.0.127.0.7.2.2.2.2.3</summary>
    public static readonly string ID_TA_ECDSA_SHA_256 = EacObjectIdentifiers.id_TA_ECDSA_SHA_256.Id;

    public static readonly string ID_EC_PUBLIC_KEY_TYPE = X9ObjectIdentifiers.id_publicKeyType.Id;

    public static readonly string ID_EC_PUBLIC_KEY = X9ObjectIdentifiers.IdECPublicKey.Id;

    private const string ID_BSI = "0.4.0.127.0.7";

    /* protocols (2), smartcard (2), PACE (4) */
    public const string ID_PACE = ID_BSI + ".2.2.4";

    public const string ID_PACE_DH_GM = ID_PACE + ".1";
    public const string ID_PACE_DH_GM_3DES_CBC_CBC = ID_PACE_DH_GM + ".1"; /* 0.4.0.127.0.7.2.2.4.1.1, id-PACE-DH-GM-3DES-CBC-CBC */
    public const string ID_PACE_DH_GM_AES_CBC_CMAC_128 = ID_PACE_DH_GM + ".2"; /* 0.4.0.127.0.7.2.2.4.1.2, id-PACE-DH-GM-AES-CBC-CMAC-128 */
    public const string ID_PACE_DH_GM_AES_CBC_CMAC_192 = ID_PACE_DH_GM + ".3"; /* 0.4.0.127.0.7.2.2.4.1.3, id-PACE-DH-GM-AES-CBC-CMAC-192 */
    public const string ID_PACE_DH_GM_AES_CBC_CMAC_256 = ID_PACE_DH_GM + ".4"; /* 0.4.0.127.0.7.2.2.4.1.4, id-PACE-DH-GM-AES-CBC-CMAC-256 */

    public const string ID_PACE_ECDH_GM = ID_PACE + ".2";
    public const string ID_PACE_ECDH_GM_3DES_CBC_CBC = ID_PACE_ECDH_GM + ".1"; /* 0.4.0.127.0.7.2.2.4.2.1, id-PACE-ECDH-GM-3DES-CBC-CBC */
    public const string ID_PACE_ECDH_GM_AES_CBC_CMAC_128 = ID_PACE_ECDH_GM + ".2"; /* 0.4.0.127.0.7.2.2.4.2.2, id-PACE-ECDH-GM-AES-CBC-CMAC-128 */
    public const string ID_PACE_ECDH_GM_AES_CBC_CMAC_192 = ID_PACE_ECDH_GM + ".3"; /* 0.4.0.127.0.7.2.2.4.2.3, id-PACE-ECDH-GM-AES-CBC-CMAC-192 */
    public const string ID_PACE_ECDH_GM_AES_CBC_CMAC_256 = ID_PACE_ECDH_GM + ".4"; /* 0.4.0.127.0.7.2.2.4.2.4, id-PACE-ECDH-GM-AES-CBC-CMAC-256 */

    public const string ID_PACE_DH_IM = ID_PACE + ".3";
    public const string ID_PACE_DH_IM_3DES_CBC_CBC = ID_PACE_DH_IM + ".1"; /* 0.4.0.127.0.7.2.2.4.3.1, id-PACE-DH-IM-3DES-CBC-CBC */
    public const string ID_PACE_DH_IM_AES_CBC_CMAC_128 = ID_PACE_DH_IM + ".2"; /* 0.4.0.127.0.7.2.2.4.3.2, id-PACE-DH-IM-AES-CBC-CMAC-128 */
    public const string ID_PACE_DH_IM_AES_CBC_CMAC_192 = ID_PACE_DH_IM + ".3"; /* 0.4.0.127.0.7.2.2.4.3.3, id-PACE-DH-IM-AES-CBC-CMAC-192 */
    public const string ID_PACE_DH_IM_AES_CBC_CMAC_256 = ID_PACE_DH_IM + ".4"; /* 0.4.0.127.0.7.2.2.4.3.4, id-PACE-DH-IM-AES-CBC-CMAC-256 */

    public const string ID_PACE_ECDH_IM = ID_PACE + ".4";
    public const string ID_PACE_ECDH_IM_3DES_CBC_CBC = ID_PACE_ECDH_IM + ".1"; /* 0.4.0.127.0.7.2.2.4.4.1, id-PACE-ECDH-IM-3DES-CBC-CBC */
    public const string ID_PACE_ECDH_IM_AES_CBC_CMAC_128 = ID_PACE_ECDH_IM + ".2"; /* 0.4.0.127.0.7.2.2.4.4.2, id-PACE-ECDH-IM-AES-CBC-CMAC-128 */
    public const string ID_PACE_ECDH_IM_AES_CBC_CMAC_192 = ID_PACE_ECDH_IM + ".3"; /* 0.4.0.127.0.7.2.2.4.4.3, id-PACE-ECDH-IM-AES-CBC-CMAC-192 */
    public const string ID_PACE_ECDH_IM_AES_CBC_CMAC_256 = ID_PACE_ECDH_IM + ".4"; /* 0.4.0.127.0.7.2.2.4.4.4, id-PACE-ECDH-IM-AES-CBC-CMAC-256 */

    public const string ID_PACE_ECDH_CAM = ID_PACE + ".6";
    public const string ID_PACE_ECDH_CAM_AES_CBC_CMAC_128 = ID_PACE_ECDH_CAM + ".2"; /* 0.4.0.127.0.7.2.2.4.6.2, id-PACE-ECDH-CAM-AES-CBC-CMAC-128 */
    public const string ID_PACE_ECDH_CAM_AES_CBC_CMAC_192 = ID_PACE_ECDH_CAM + ".3"; /* 0.4.0.127.0.7.2.2.4.6.3, id-PACE-ECDH-CAM-AES-CBC-CMAC-192 */
    public const string ID_PACE_ECDH_CAM_AES_CBC_CMAC_256 = ID_PACE_ECDH_CAM + ".4"; /* 0.4.0.127.0.7.2.2.4.6.4, id-PACE-ECDH-CAM-AES-CBC-CMAC-256 */

    /// <summary>Returns a DER object with this SecurityInfo data (DER sequence).</summary>
    [Obsolete("This method will be removed from the visible interface (because of dependency on BC API)")]
    public abstract Asn1Object GetDERObject();

    /// <summary>
    /// Returns a DER object with this SecurityInfo data, for use inside this library. Keeps the internal
    /// callers off the obsolete public <see cref="GetDERObject"/> (deprecated upstream for the same reason).
    /// </summary>
    internal Asn1Object ToDerObject()
    {
#pragma warning disable CS0618 // The public method stays obsolete; this is the single internal call site.
        return GetDERObject();
#pragma warning restore CS0618
    }

    /// <summary>Writes this SecurityInfo to output stream.</summary>
    public override void WriteObject(Stream outputStream)
    {
        Asn1Object derEncoded = ToDerObject();
        byte[] derEncodedBytes = derEncoded.GetEncoded(Asn1Encodable.Der);
        outputStream.Write(derEncodedBytes, 0, derEncodedBytes.Length);
    }

    /// <summary>Returns the protocol object identifier of this SecurityInfo.</summary>
    public abstract string GetObjectIdentifier();

    /// <summary>Returns the protocol object identifier as a human readable string.</summary>
    public abstract string GetProtocolOIDString();

    /// <summary>Factory method for creating security info objects given an input.</summary>
    /// <param name="obj">the input</param>
    /// <returns>a concrete security info object, or <c>null</c> if the OID is not recognized</returns>
    /// <exception cref="ArgumentException">if the input is malformed</exception>
    public static SecurityInfo? GetInstance(Asn1Encodable obj)
    {
        try
        {
            List<Asn1Encodable> sequence = AsList(obj);
            string oid = DerObjectIdentifier.GetInstance(sequence[0]).Id;
            Asn1Encodable requiredData = sequence[1];
            Asn1Encodable? optionalData = sequence.Count <= 2 ? null : sequence[2];

            if (ActiveAuthenticationInfo.CheckRequiredIdentifier(oid))
            {
                int version = DerInteger.GetInstance(requiredData).Value.IntValue;
                if (optionalData == null)
                {
                    return new ActiveAuthenticationInfo(oid, version, null);
                }

                string signatureAlgorithmOID = DerObjectIdentifier.GetInstance(optionalData).Id;
                return new ActiveAuthenticationInfo(oid, version, signatureAlgorithmOID);
            }

            if (ChipAuthenticationPublicKeyInfo.CheckRequiredIdentifier(oid))
            {
                SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.GetInstance(requiredData);
                var publicKey = PublicKeyFactory.CreateKey(subjectPublicKeyInfo);
                if (optionalData == null)
                {
                    return new ChipAuthenticationPublicKeyInfo(oid, publicKey);
                }

                BigInteger keyId = DerInteger.GetInstance(optionalData).Value;
                return new ChipAuthenticationPublicKeyInfo(oid, publicKey, keyId);
            }

            if (ChipAuthenticationInfo.CheckRequiredIdentifier(oid))
            {
                int version = DerInteger.GetInstance(requiredData).Value.IntValue;
                if (optionalData == null)
                {
                    return new ChipAuthenticationInfo(oid, version);
                }

                BigInteger keyId = DerInteger.GetInstance(optionalData).Value;
                return new ChipAuthenticationInfo(oid, version, keyId);
            }

            if (TerminalAuthenticationInfo.CheckRequiredIdentifier(oid))
            {
                int version = DerInteger.GetInstance(requiredData).Value.IntValue;
                if (optionalData == null)
                {
                    return new TerminalAuthenticationInfo(oid, version);
                }

                Asn1Sequence efCVCA = Asn1Sequence.GetInstance(optionalData);
                return new TerminalAuthenticationInfo(oid, version, efCVCA);
            }

            if (PACEInfo.CheckRequiredIdentifier(oid))
            {
                int version = DerInteger.GetInstance(requiredData).Value.IntValue;
                BigInteger parameterId = BigInteger.ValueOf(-1);
                if (optionalData != null)
                {
                    parameterId = DerInteger.GetInstance(optionalData).Value;
                }
                return new PACEInfo(oid, version, parameterId);
            }

            if (PACEDomainParameterInfo.CheckRequiredIdentifier(oid))
            {
                AlgorithmIdentifier domainParameters = AlgorithmIdentifier.GetInstance(requiredData);
                if (optionalData != null)
                {
                    BigInteger parameterId = DerInteger.GetInstance(optionalData).Value;
                    return new PACEDomainParameterInfo(oid, domainParameters, parameterId);
                }
                return new PACEDomainParameterInfo(oid, domainParameters);
            }

            /* NOTE: Java logs a warning "Unsupported SecurityInfo, oid = ..." here; omitted per the
             * non-essential-warning-omission precedent (see AbstractLDSFile.cs). */
            return null;
        }
        catch (Exception e) when (e is not ArgumentException)
        {
            throw new ArgumentException("Malformed input stream.", e);
        }
    }

    /// <summary>Converts an ASN1 sequence to a list. Port of <c>org.jmrtd.ASN1Util.list</c> (inlined here
    /// since the rest of <c>ASN1Util</c> is outside this port's scope).</summary>
    private static List<Asn1Encodable> AsList(Asn1Encodable asn1Encodable)
    {
        if (asn1Encodable is Asn1Sequence asn1Sequence)
        {
            var result = new List<Asn1Encodable>(asn1Sequence.Count);
            for (int i = 0; i < asn1Sequence.Count; i++)
            {
                result.Add(asn1Sequence[i]);
            }
            return result;
        }

        return [asn1Encodable];
    }
}
