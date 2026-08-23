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
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using BigInteger = Org.BouncyCastle.Math.BigInteger;

namespace nMRTD.Lds;

/// <summary>Port of <c>org.jmrtd.lds.PACEInfo</c>: PACE Info object as per SAC TR 1.01, November 11, 2010.
///
/// NOTE on domain parameter types: Java's JCA <c>DHParameterSpec</c>/<c>ECParameterSpec</c> are ported as
/// BouncyCastle's <see cref="DHParameters"/>/<see cref="ECDomainParameters"/> (per porting conventions,
/// this port works directly against BC's crypto object model). Java's nested <c>DHCParameterSpec</c>
/// class existed only to bolt a subgroup order <c>q</c> onto JCA's <c>DHParameterSpec</c> (which lacks
/// one); BC's own <see cref="DHParameters"/> already carries <c>Q</c> natively, so that nested type has
/// no C# equivalent -- <see cref="DHParameters"/> is used directly everywhere it would have appeared.
/// Similarly, Java's <c>Util.toExplicitDHParameterSpec</c>/<c>toExplicitECParameterSpec</c> conversions
/// (needed to strip JCA provider-specific named-curve wrappers) are unnecessary here since
/// <see cref="ECDomainParameters"/> built from <see cref="ECNamedCurveTable"/> is already an explicit,
/// provider-independent representation.</summary>
public class PACEInfo : SecurityInfo
{
    private const int VERSION_2 = 2;

    /// <summary>Generic mapping and Integrated mapping and CAM mapping.</summary>
    public enum MappingType
    {
        /// <summary>Generic Mapping.</summary>
        GM,

        /// <summary>Integrated Mapping.</summary>
        IM,

        /// <summary>Chip Authentication Mapping.</summary>
        CAM,
    }

    /// <summary>Standardized domain parameters. Based on Table 6.</summary>
    public const int PARAM_ID_GFP_1024_160 = 0;

    /// <summary>Standardized domain parameters. Based on Table 6.</summary>
    public const int PARAM_ID_GFP_2048_224 = 1;

    /// <summary>Standardized domain parameters. Based on Table 6.</summary>
    public const int PARAM_ID_GFP_2048_256 = 2;

    /* RFU 3 - 7 */

    /// <summary>Standardized domain parameters. Based on Table 6.</summary>
    public const int PARAM_ID_ECP_NIST_P192_R1 = 8;

    /// <summary>Standardized domain parameters. Based on Table 6.</summary>
    public const int PARAM_ID_ECP_BRAINPOOL_P192_R1 = 9;

    /// <summary>Standardized domain parameters. Based on Table 6.</summary>
    public const int PARAM_ID_ECP_NIST_P224_R1 = 10;

    /// <summary>Standardized domain parameters. Based on Table 6.</summary>
    public const int PARAM_ID_ECP_BRAINPOOL_P224_R1 = 11;

    /// <summary>Standardized domain parameters. Based on Table 6.</summary>
    public const int PARAM_ID_ECP_NIST_P256_R1 = 12;

    /// <summary>Standardized domain parameters. Based on Table 6.</summary>
    public const int PARAM_ID_ECP_BRAINPOOL_P256_R1 = 13;

    /// <summary>Standardized domain parameters. Based on Table 6.</summary>
    public const int PARAM_ID_ECP_BRAINPOOL_P320_R1 = 14;

    /// <summary>Standardized domain parameters. Based on Table 6.</summary>
    public const int PARAM_ID_ECP_NIST_P384_R1 = 15;

    /// <summary>Standardized domain parameters. Based on Table 6.</summary>
    public const int PARAM_ID_ECP_BRAINPOOL_P384_R1 = 16;

    /// <summary>Standardized domain parameters. Based on Table 6.</summary>
    public const int PARAM_ID_ECP_BRAINPOOL_P512_R1 = 17;

    /// <summary>Standardized domain parameters. Based on Table 6.</summary>
    public const int PARAM_ID_ECP_NIST_P521_R1 = 18;

    /* RFU 19-31 */

    /* RFC 5114 explicit (p, g, q) DH groups. */
    private const string RFC5114_1024_160_P =
        "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6" +
        "9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0" +
        "13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70" +
        "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0" +
        "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708" +
        "DF1FB2BC2E4A4371";
    private const string RFC5114_1024_160_G =
        "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F" +
        "D6406CFF14266D31266FEA1E5C41564B777E690F5504F213" +
        "160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1" +
        "909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A" +
        "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24" +
        "855E6EEB22B3B2E5";
    private const string RFC5114_1024_160_Q = "F518AA8781A8DF278ABA4E7D64B7CB9D49462353";

    private const string RFC5114_2048_224_P =
        "AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1" +
        "B54B1597B61D0A75E6FA141DF95A56DBAF9A3C407BA1DF15" +
        "EB3D688A309C180E1DE6B85A1274A0A66D3F8152AD6AC212" +
        "9037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207" +
        "C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708" +
        "B3BF8A317091883681286130BC8985DB1602E714415D9330" +
        "278273C7DE31EFDC7310F7121FD5A07415987D9ADC0A486D" +
        "CDF93ACC44328387315D75E198C641A480CD86A1B9E587E8" +
        "BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763" +
        "C9B53DCF4BA80A29E3FB73C16B8E75B97EF363E2FFA31F71" +
        "CF9DE5384E71B81C0AC4DFFE0C10E64F";
    private const string RFC5114_2048_224_G =
        "AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF" +
        "74866A08CFE4FFE3A6824A4E10B9A6F0DD921F01A70C4AFA" +
        "AB739D7700C29F52C57DB17C620A8652BE5E9001A8D66AD7" +
        "C17669101999024AF4D027275AC1348BB8A762D0521BC98A" +
        "E247150422EA1ED409939D54DA7460CDB5F6C6B250717CBE" +
        "F180EB34118E98D119529A45D6F834566E3025E316A330EF" +
        "BB77A86F0C1AB15B051AE3D428C8F8ACB70A8137150B8EEB" +
        "10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381" +
        "B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269" +
        "EDFE72FE9B6AA4BD7B5A0F1C71CFFF4C19C418E1F6EC0179" +
        "81BC087F2A7065B384B890D3191F2BFA";
    private const string RFC5114_2048_224_Q = "801C0D34C58D93FE997177101F80535A4738CEBCBF389A99B36371EB";

    private const string RFC5114_2048_256_P =
        "87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F2" +
        "5D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA30" +
        "16C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD" +
        "5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B" +
        "6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C" +
        "4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0E" +
        "F13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D9" +
        "67E144E5140564251CCACB83E6B486F6B3CA3F7971506026" +
        "C0B857F689962856DED4010ABD0BE621C3A3960A54E710C3" +
        "75F26375D7014103A4B54330C198AF126116D2276E11715F" +
        "693877FAD7EF09CADB094AE91E1A1597";
    private const string RFC5114_2048_256_G =
        "3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF2054" +
        "07F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555" +
        "BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18" +
        "A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B" +
        "777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC83" +
        "1D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55" +
        "A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14" +
        "C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915" +
        "B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6" +
        "184B523D1DB246C32F63078490F00EF8D647D148D4795451" +
        "5E2327CFEF98C582664B4C0F6CC41659";
    private const string RFC5114_2048_256_Q = "8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3";

    /// <summary>Deprecated in upstream JMRTD too: existence of a "hidden SNFS" backdoor cannot be ruled
    /// out for the RFC 5114 groups. See https://eprint.iacr.org/2016/961.pdf</summary>
    private static readonly DHParameters PARAMS_GFP_1024_160 = FromPGQ(RFC5114_1024_160_P, RFC5114_1024_160_G, RFC5114_1024_160_Q);

    private static readonly DHParameters PARAMS_GFP_2048_224 = FromPGQ(RFC5114_2048_224_P, RFC5114_2048_224_G, RFC5114_2048_224_Q);

    private static readonly DHParameters PARAMS_GFP_2048_256 = FromPGQ(RFC5114_2048_256_P, RFC5114_2048_256_G, RFC5114_2048_256_Q);

    private static readonly ECDomainParameters PARAMS_ECP_NIST_P192_R1 = FromNamedCurve("secp192r1");
    private static readonly ECDomainParameters PARAMS_ECP_NIST_P224_R1 = FromNamedCurve("secp224r1");
    private static readonly ECDomainParameters PARAMS_ECP_NIST_P256_R1 = FromNamedCurve("secp256r1");
    private static readonly ECDomainParameters PARAMS_ECP_NIST_P384_R1 = FromNamedCurve("secp384r1");
    private static readonly ECDomainParameters PARAMS_ECP_NIST_P521_R1 = FromNamedCurve("secp521r1");
    private static readonly ECDomainParameters PARAMS_ECP_BRAINPOOL_P192_R1 = FromNamedCurve("brainpoolP192r1");
    private static readonly ECDomainParameters PARAMS_ECP_BRAINPOOL_P224_R1 = FromNamedCurve("brainpoolP224r1");
    private static readonly ECDomainParameters PARAMS_ECP_BRAINPOOL_P256_R1 = FromNamedCurve("brainpoolP256r1");
    private static readonly ECDomainParameters PARAMS_ECP_BRAINPOOL_P320_R1 = FromNamedCurve("brainpoolP320r1");
    private static readonly ECDomainParameters PARAMS_ECP_BRAINPOOL_P384_R1 = FromNamedCurve("brainpoolP384r1");
    private static readonly ECDomainParameters PARAMS_ECP_BRAINPOOL_P512_R1 = FromNamedCurve("brainpoolP512r1");

    private static readonly HashSet<string> ALLOWED_REQUIRED_IDENTIFIERS =
    [
        ID_PACE_DH_GM_3DES_CBC_CBC,
        ID_PACE_DH_GM_AES_CBC_CMAC_128,
        ID_PACE_DH_GM_AES_CBC_CMAC_192,
        ID_PACE_DH_GM_AES_CBC_CMAC_256,
        ID_PACE_DH_IM_3DES_CBC_CBC,
        ID_PACE_DH_IM_AES_CBC_CMAC_128,
        ID_PACE_DH_IM_AES_CBC_CMAC_192,
        ID_PACE_DH_IM_AES_CBC_CMAC_256,
        ID_PACE_ECDH_GM_3DES_CBC_CBC,
        ID_PACE_ECDH_GM_AES_CBC_CMAC_128,
        ID_PACE_ECDH_GM_AES_CBC_CMAC_192,
        ID_PACE_ECDH_GM_AES_CBC_CMAC_256,
        ID_PACE_ECDH_IM_3DES_CBC_CBC,
        ID_PACE_ECDH_IM_AES_CBC_CMAC_128,
        ID_PACE_ECDH_IM_AES_CBC_CMAC_192,
        ID_PACE_ECDH_IM_AES_CBC_CMAC_256,
        ID_PACE_ECDH_CAM_AES_CBC_CMAC_128,
        ID_PACE_ECDH_CAM_AES_CBC_CMAC_192,
        ID_PACE_ECDH_CAM_AES_CBC_CMAC_256,
    ];

    private readonly string protocolOID;
    private readonly int version;
    private readonly BigInteger? parameterId;

    /// <param name="oid">the object identifier, indicating what PACE variant is to be used (agreement
    /// protocol, mapping type, and secure channel properties)</param>
    /// <param name="version">a version number, which should be 2</param>
    /// <param name="parameterId">either a standardized domain parameter id from table 6 or a proprietary
    /// domain parameter</param>
    public PACEInfo(string oid, int version, int parameterId)
        : this(oid, version, BigInteger.ValueOf(parameterId))
    {
    }

    /// <param name="oid">the object identifier, indicating what PACE variant is to be used (agreement
    /// protocol, mapping type, and secure channel properties)</param>
    /// <param name="version">a version number, which should be 2</param>
    /// <param name="parameterId">either a standardized domain parameter id from table 6 or a proprietary
    /// domain parameter</param>
    public PACEInfo(string oid, int version, BigInteger? parameterId)
    {
        if (!CheckRequiredIdentifier(oid))
        {
            throw new ArgumentException("Invalid OID");
        }
        if (version != VERSION_2)
        {
            /* NOTE: Java logs a warning here; omitted per the non-essential-warning-omission precedent
             * (see AbstractLDSFile.cs). */
        }
        protocolOID = oid;
        this.version = version;
        this.parameterId = parameterId;
    }

    /// <summary>Creates a PACE info from an encoding.</summary>
    /// <param name="paceInfoBytes">the encoded bytes</param>
    /// <returns>a PACE info object</returns>
    public static PACEInfo CreatePACEInfo(byte[] paceInfoBytes)
    {
        /*
         * FIXME: Should add a constructor to PACEInfo that takes byte[] or InputStream, or align this
         * with SecurityInfo.GetInstance().
         */
        Asn1Sequence sequence = Asn1Sequence.GetInstance(paceInfoBytes);
        string oid = ((DerObjectIdentifier)sequence[0]).Id;
        Asn1Object requiredData = sequence[1].ToAsn1Object();
        Asn1Object? optionalData = null;
        if (sequence.Count == 3)
        {
            optionalData = sequence[2].ToAsn1Object();
        }

        int version = ((DerInteger)requiredData).Value.IntValue;
        BigInteger? parameterId = null;
        if (optionalData != null)
        {
            parameterId = ((DerInteger)optionalData).Value;
        }

        return new PACEInfo(oid, version, parameterId);
    }

    /// <summary>Returns the PACE protocol object identifier.</summary>
    public override string GetObjectIdentifier() => protocolOID;

    public override string GetProtocolOIDString() => ToProtocolOIDString(protocolOID);

    /// <summary>Returns the version.</summary>
    public int GetVersion() => version;

    /// <summary>Returns the parameter identifier.</summary>
    public BigInteger? GetParameterId() => parameterId;

    [Obsolete("This method will be removed from the visible interface (because of dependency on BC API)")]
    public override Asn1Object GetDERObject()
    {
        var vector = new Asn1EncodableVector
        {
            new DerObjectIdentifier(protocolOID),
            new DerInteger(version),
        };
        if (parameterId != null)
        {
            vector.Add(new DerInteger(parameterId));
        }
        return new DLSequence(vector);
    }

    public override string ToString()
    {
        var result = new System.Text.StringBuilder();
        result.Append("PACEInfo [");
        result.Append("protocol: ").Append(ToProtocolOIDString(protocolOID));
        result.Append(", version: ").Append(version);
        if (parameterId != null)
        {
            result.Append(", parameterId: ").Append(ToStandardizedParamIdString(parameterId));
        }
        result.Append(']');
        return result.ToString();
    }

    public override int GetHashCode()
    {
        return 1234567891
            + 7 * protocolOID.GetHashCode()
            + 5 * version
            + 3 * (parameterId == null ? 1991 : parameterId.GetHashCode());
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
        if (other.GetType() != typeof(PACEInfo))
        {
            return false;
        }

        var otherPACEInfo = (PACEInfo)other;

        if (protocolOID == null && otherPACEInfo.protocolOID != null)
        {
            return false;
        }
        if (protocolOID != null && !protocolOID.Equals(otherPACEInfo.protocolOID))
        {
            return false;
        }
        if (version != otherPACEInfo.version)
        {
            return false;
        }
        if (parameterId == null && otherPACEInfo.parameterId != null)
        {
            return false;
        }
        if (parameterId != null && !parameterId.Equals(otherPACEInfo.parameterId))
        {
            return false;
        }

        return true;
    }

    /// <summary>Checks whether the object identifier is valid for describing a PACE protocol.</summary>
    public static bool CheckRequiredIdentifier(string oid) => ALLOWED_REQUIRED_IDENTIFIERS.Contains(oid);

    /*
     * FIXME: perhaps we should introduce an enum for PACE identifiers (with a String toOID() method), so
     * that we can get rid of static methods below. -- MO (carried over from JMRTD source comment)
     */

    /// <summary>Returns the mapping type for a given PACE protocol object identifier.</summary>
    public static MappingType ToMappingType(string oid)
    {
        if (ID_PACE_DH_GM_3DES_CBC_CBC.Equals(oid)
            || ID_PACE_DH_GM_AES_CBC_CMAC_128.Equals(oid)
            || ID_PACE_DH_GM_AES_CBC_CMAC_192.Equals(oid)
            || ID_PACE_DH_GM_AES_CBC_CMAC_256.Equals(oid)
            || ID_PACE_ECDH_GM_3DES_CBC_CBC.Equals(oid)
            || ID_PACE_ECDH_GM_AES_CBC_CMAC_128.Equals(oid)
            || ID_PACE_ECDH_GM_AES_CBC_CMAC_192.Equals(oid)
            || ID_PACE_ECDH_GM_AES_CBC_CMAC_256.Equals(oid))
        {
            return MappingType.GM;
        }
        if (ID_PACE_DH_IM_3DES_CBC_CBC.Equals(oid)
            || ID_PACE_DH_IM_AES_CBC_CMAC_128.Equals(oid)
            || ID_PACE_DH_IM_AES_CBC_CMAC_192.Equals(oid)
            || ID_PACE_DH_IM_AES_CBC_CMAC_256.Equals(oid)
            || ID_PACE_ECDH_IM_3DES_CBC_CBC.Equals(oid)
            || ID_PACE_ECDH_IM_AES_CBC_CMAC_128.Equals(oid)
            || ID_PACE_ECDH_IM_AES_CBC_CMAC_192.Equals(oid)
            || ID_PACE_ECDH_IM_AES_CBC_CMAC_256.Equals(oid))
        {
            return MappingType.IM;
        }
        if (ID_PACE_ECDH_CAM_AES_CBC_CMAC_128.Equals(oid)
            || ID_PACE_ECDH_CAM_AES_CBC_CMAC_192.Equals(oid)
            || ID_PACE_ECDH_CAM_AES_CBC_CMAC_256.Equals(oid))
        {
            return MappingType.CAM;
        }

        throw new FormatException($"Unknown OID: \"{oid}\"");
    }

    /// <summary>Returns the key agreement algorithm (<c>"DH"</c> or <c>"ECDH"</c>) for a PACE protocol
    /// object identifier.</summary>
    public static string ToKeyAgreementAlgorithm(string oid)
    {
        if (ID_PACE_DH_GM_3DES_CBC_CBC.Equals(oid)
            || ID_PACE_DH_GM_AES_CBC_CMAC_128.Equals(oid)
            || ID_PACE_DH_GM_AES_CBC_CMAC_192.Equals(oid)
            || ID_PACE_DH_GM_AES_CBC_CMAC_256.Equals(oid)
            || ID_PACE_DH_IM_3DES_CBC_CBC.Equals(oid)
            || ID_PACE_DH_IM_AES_CBC_CMAC_128.Equals(oid)
            || ID_PACE_DH_IM_AES_CBC_CMAC_192.Equals(oid)
            || ID_PACE_DH_IM_AES_CBC_CMAC_256.Equals(oid))
        {
            return "DH";
        }
        if (ID_PACE_ECDH_GM_3DES_CBC_CBC.Equals(oid)
            || ID_PACE_ECDH_GM_AES_CBC_CMAC_128.Equals(oid)
            || ID_PACE_ECDH_GM_AES_CBC_CMAC_192.Equals(oid)
            || ID_PACE_ECDH_GM_AES_CBC_CMAC_256.Equals(oid)
            || ID_PACE_ECDH_IM_3DES_CBC_CBC.Equals(oid)
            || ID_PACE_ECDH_IM_AES_CBC_CMAC_128.Equals(oid)
            || ID_PACE_ECDH_IM_AES_CBC_CMAC_192.Equals(oid)
            || ID_PACE_ECDH_IM_AES_CBC_CMAC_256.Equals(oid)
            || ID_PACE_ECDH_CAM_AES_CBC_CMAC_128.Equals(oid)
            || ID_PACE_ECDH_CAM_AES_CBC_CMAC_192.Equals(oid)
            || ID_PACE_ECDH_CAM_AES_CBC_CMAC_256.Equals(oid))
        {
            return "ECDH";
        }

        throw new FormatException($"Unknown OID: \"{oid}\"");
    }

    /// <summary>Returns the encryption algorithm described in the PACE protocol object identifier.</summary>
    public static string ToCipherAlgorithm(string oid)
    {
        if (ID_PACE_DH_GM_3DES_CBC_CBC.Equals(oid)
            || ID_PACE_DH_IM_3DES_CBC_CBC.Equals(oid)
            || ID_PACE_ECDH_GM_3DES_CBC_CBC.Equals(oid)
            || ID_PACE_ECDH_IM_3DES_CBC_CBC.Equals(oid))
        {
            return "DESede";
        }
        if (ID_PACE_DH_GM_AES_CBC_CMAC_128.Equals(oid)
            || ID_PACE_DH_GM_AES_CBC_CMAC_192.Equals(oid)
            || ID_PACE_DH_GM_AES_CBC_CMAC_256.Equals(oid)
            || ID_PACE_DH_IM_AES_CBC_CMAC_128.Equals(oid)
            || ID_PACE_DH_IM_AES_CBC_CMAC_192.Equals(oid)
            || ID_PACE_DH_IM_AES_CBC_CMAC_256.Equals(oid)
            || ID_PACE_ECDH_GM_AES_CBC_CMAC_128.Equals(oid)
            || ID_PACE_ECDH_GM_AES_CBC_CMAC_192.Equals(oid)
            || ID_PACE_ECDH_GM_AES_CBC_CMAC_256.Equals(oid)
            || ID_PACE_ECDH_IM_AES_CBC_CMAC_128.Equals(oid)
            || ID_PACE_ECDH_IM_AES_CBC_CMAC_192.Equals(oid)
            || ID_PACE_ECDH_IM_AES_CBC_CMAC_256.Equals(oid)
            || ID_PACE_ECDH_CAM_AES_CBC_CMAC_128.Equals(oid)
            || ID_PACE_ECDH_CAM_AES_CBC_CMAC_192.Equals(oid)
            || ID_PACE_ECDH_CAM_AES_CBC_CMAC_256.Equals(oid))
        {
            return "AES";
        }

        throw new FormatException($"Unknown OID: \"{oid}\"");
    }

    /// <summary>Returns the digest algorithm described in the PACE protocol object identifier.</summary>
    public static string ToDigestAlgorithm(string oid)
    {
        if (ID_PACE_DH_GM_3DES_CBC_CBC.Equals(oid)
            || ID_PACE_DH_IM_3DES_CBC_CBC.Equals(oid)
            || ID_PACE_ECDH_GM_3DES_CBC_CBC.Equals(oid)
            || ID_PACE_ECDH_IM_3DES_CBC_CBC.Equals(oid)
            || ID_PACE_DH_GM_AES_CBC_CMAC_128.Equals(oid)
            || ID_PACE_DH_IM_AES_CBC_CMAC_128.Equals(oid)
            || ID_PACE_ECDH_GM_AES_CBC_CMAC_128.Equals(oid)
            || ID_PACE_ECDH_IM_AES_CBC_CMAC_128.Equals(oid)
            || ID_PACE_ECDH_CAM_AES_CBC_CMAC_128.Equals(oid))
        {
            return "SHA-1";
        }
        if (ID_PACE_DH_GM_AES_CBC_CMAC_192.Equals(oid)
            || ID_PACE_DH_IM_AES_CBC_CMAC_192.Equals(oid)
            || ID_PACE_ECDH_GM_AES_CBC_CMAC_192.Equals(oid)
            || ID_PACE_ECDH_IM_AES_CBC_CMAC_192.Equals(oid)
            || ID_PACE_ECDH_CAM_AES_CBC_CMAC_192.Equals(oid)
            || ID_PACE_DH_GM_AES_CBC_CMAC_256.Equals(oid)
            || ID_PACE_DH_IM_AES_CBC_CMAC_256.Equals(oid)
            || ID_PACE_ECDH_GM_AES_CBC_CMAC_256.Equals(oid)
            || ID_PACE_ECDH_IM_AES_CBC_CMAC_256.Equals(oid)
            || ID_PACE_ECDH_CAM_AES_CBC_CMAC_256.Equals(oid))
        {
            return "SHA-256";
        }

        throw new FormatException($"Unknown OID: \"{oid}\"");
    }

    /// <summary>Returns the key length (128, 192, or 256) described in the given PACE protocol object identifier.</summary>
    public static int ToKeyLength(string oid)
    {
        if (ID_PACE_DH_GM_3DES_CBC_CBC.Equals(oid)
            || ID_PACE_DH_IM_3DES_CBC_CBC.Equals(oid)
            || ID_PACE_ECDH_GM_3DES_CBC_CBC.Equals(oid)
            || ID_PACE_ECDH_IM_3DES_CBC_CBC.Equals(oid)
            || ID_PACE_DH_GM_AES_CBC_CMAC_128.Equals(oid)
            || ID_PACE_DH_IM_AES_CBC_CMAC_128.Equals(oid)
            || ID_PACE_ECDH_GM_AES_CBC_CMAC_128.Equals(oid)
            || ID_PACE_ECDH_IM_AES_CBC_CMAC_128.Equals(oid)
            || ID_PACE_ECDH_CAM_AES_CBC_CMAC_128.Equals(oid))
        {
            return 128;
        }
        if (ID_PACE_DH_GM_AES_CBC_CMAC_192.Equals(oid)
            || ID_PACE_ECDH_GM_AES_CBC_CMAC_192.Equals(oid)
            || ID_PACE_DH_IM_AES_CBC_CMAC_192.Equals(oid)
            || ID_PACE_ECDH_IM_AES_CBC_CMAC_192.Equals(oid)
            || ID_PACE_ECDH_CAM_AES_CBC_CMAC_192.Equals(oid))
        {
            return 192;
        }
        if (ID_PACE_DH_GM_AES_CBC_CMAC_256.Equals(oid)
            || ID_PACE_DH_IM_AES_CBC_CMAC_256.Equals(oid)
            || ID_PACE_ECDH_GM_AES_CBC_CMAC_256.Equals(oid)
            || ID_PACE_ECDH_IM_AES_CBC_CMAC_256.Equals(oid)
            || ID_PACE_ECDH_CAM_AES_CBC_CMAC_256.Equals(oid))
        {
            return 256;
        }

        throw new FormatException($"Unknown OID: \"{oid}\"");
    }

    /// <summary>Derives domain parameters (<see cref="DHParameters"/> or <see cref="ECDomainParameters"/>,
    /// callers downcast based on the standard domain parameter id) from a PACE standard domain parameter integer.</summary>
    public static object ToParameterSpec(BigInteger stdDomainParam) => ToParameterSpec(stdDomainParam.IntValue);

    /// <summary>Derives domain parameters (<see cref="DHParameters"/> or <see cref="ECDomainParameters"/>,
    /// callers downcast based on the standard domain parameter id) from a PACE standard domain parameter integer.</summary>
    public static object ToParameterSpec(int stdDomainParam)
    {
        return stdDomainParam switch
        {
            PARAM_ID_GFP_1024_160 => PARAMS_GFP_1024_160,
            PARAM_ID_GFP_2048_224 => PARAMS_GFP_2048_224,
            PARAM_ID_GFP_2048_256 => PARAMS_GFP_2048_256,
            PARAM_ID_ECP_NIST_P192_R1 => PARAMS_ECP_NIST_P192_R1,
            PARAM_ID_ECP_BRAINPOOL_P192_R1 => PARAMS_ECP_BRAINPOOL_P192_R1,
            PARAM_ID_ECP_NIST_P224_R1 => PARAMS_ECP_NIST_P224_R1,
            PARAM_ID_ECP_BRAINPOOL_P224_R1 => PARAMS_ECP_BRAINPOOL_P224_R1,
            PARAM_ID_ECP_NIST_P256_R1 => PARAMS_ECP_NIST_P256_R1,
            PARAM_ID_ECP_BRAINPOOL_P256_R1 => PARAMS_ECP_BRAINPOOL_P256_R1,
            PARAM_ID_ECP_BRAINPOOL_P320_R1 => PARAMS_ECP_BRAINPOOL_P320_R1,
            PARAM_ID_ECP_NIST_P384_R1 => PARAMS_ECP_NIST_P384_R1,
            PARAM_ID_ECP_BRAINPOOL_P384_R1 => PARAMS_ECP_BRAINPOOL_P384_R1,
            PARAM_ID_ECP_BRAINPOOL_P512_R1 => PARAMS_ECP_BRAINPOOL_P512_R1,
            PARAM_ID_ECP_NIST_P521_R1 => PARAMS_ECP_NIST_P521_R1,
            _ => throw new FormatException("Unknown standardized domain parameters " + stdDomainParam),
        };
    }

    /// <summary>Derives a human readable algorithm description from a PACE standard domain parameter integer.</summary>
    public static string ToStandardizedParamIdString(BigInteger? stdDomainParam)
    {
        if (stdDomainParam == null)
        {
            return "null";
        }

        return stdDomainParam.IntValue switch
        {
            PARAM_ID_GFP_1024_160 => "1024-bit MODP Group with 160-bit Prime Order Subgroup",
            PARAM_ID_GFP_2048_224 => "2048-bit MODP Group with 224-bit Prime Order Subgroup",
            PARAM_ID_GFP_2048_256 => "2048-bit MODP Group with 256-bit Prime Order Subgroup",
            /* 3 - 7 RFU */
            PARAM_ID_ECP_NIST_P192_R1 => "NIST P-192 (secp192r1)",
            PARAM_ID_ECP_BRAINPOOL_P192_R1 => "BrainpoolP192r1",
            PARAM_ID_ECP_NIST_P224_R1 => "NIST P-224 (secp224r1)",
            PARAM_ID_ECP_BRAINPOOL_P224_R1 => "BrainpoolP224r1",
            PARAM_ID_ECP_NIST_P256_R1 => "NIST P-256 (secp256r1)",
            PARAM_ID_ECP_BRAINPOOL_P256_R1 => "BrainpoolP256r1",
            PARAM_ID_ECP_BRAINPOOL_P320_R1 => "BrainpoolP320r1",
            PARAM_ID_ECP_NIST_P384_R1 => "NIST P-384 (secp384r1)",
            PARAM_ID_ECP_BRAINPOOL_P384_R1 => "BrainpoolP384r1",
            PARAM_ID_ECP_BRAINPOOL_P512_R1 => "BrainpoolP512r1",
            PARAM_ID_ECP_NIST_P521_R1 => "NIST P-521 (secp521r1)",
            /* 19-31 RFU */
            _ => stdDomainParam.ToString(),
        };
    }

    /// <summary>Returns an ASN1 name for the given object identifier.</summary>
    private string ToProtocolOIDString(string oid)
    {
        if (ID_PACE_DH_GM_3DES_CBC_CBC.Equals(oid))
        {
            return "id-PACE-DH-GM-3DES-CBC-CBC";
        }
        if (ID_PACE_DH_GM_AES_CBC_CMAC_128.Equals(oid))
        {
            return "id-PACE-DH-GM-AES-CBC-CMAC-128";
        }
        if (ID_PACE_DH_GM_AES_CBC_CMAC_192.Equals(oid))
        {
            return "id-PACE-DH-GM-AES-CBC-CMAC-192";
        }
        if (ID_PACE_DH_GM_AES_CBC_CMAC_256.Equals(oid))
        {
            return "id-PACE-DH-GM-AES-CBC-CMAC-256";
        }
        if (ID_PACE_DH_IM_3DES_CBC_CBC.Equals(oid))
        {
            return "id-PACE-DH-IM-3DES-CBC-CBC";
        }
        if (ID_PACE_DH_IM_AES_CBC_CMAC_128.Equals(oid))
        {
            return "id-PACE-DH-IM-AES-CBC-CMAC-128";
        }
        if (ID_PACE_DH_IM_AES_CBC_CMAC_192.Equals(oid))
        {
            return "id-PACE-DH-IM-AES-CBC-CMAC-192";
        }
        if (ID_PACE_DH_IM_AES_CBC_CMAC_256.Equals(oid))
        {
            return "id-PACE-DH-IM-AES-CBC-CMAC-256";
        }
        if (ID_PACE_ECDH_GM_3DES_CBC_CBC.Equals(oid))
        {
            return "id-PACE-ECDH-GM-3DES-CBC-CBC";
        }
        if (ID_PACE_ECDH_GM_AES_CBC_CMAC_128.Equals(oid))
        {
            return "id-PACE-ECDH-GM-AES-CBC-CMAC-128";
        }
        if (ID_PACE_ECDH_GM_AES_CBC_CMAC_192.Equals(oid))
        {
            return "id-PACE-ECDH-GM-AES-CBC-CMAC-192";
        }
        if (ID_PACE_ECDH_GM_AES_CBC_CMAC_256.Equals(oid))
        {
            return "id-PACE-ECDH-GM-AES-CBC-CMAC-256";
        }
        if (ID_PACE_ECDH_IM_3DES_CBC_CBC.Equals(oid))
        {
            return "id-PACE-ECDH-IM-3DES-CBC-CBC";
        }
        if (ID_PACE_ECDH_IM_AES_CBC_CMAC_128.Equals(oid))
        {
            return "id-PACE-ECDH-IM-AES-CBC-CMAC-128";
        }
        if (ID_PACE_ECDH_IM_AES_CBC_CMAC_192.Equals(oid))
        {
            return "id-PACE-ECDH-IM-AES-CBC-CMAC-192";
        }
        if (ID_PACE_ECDH_IM_AES_CBC_CMAC_256.Equals(oid))
        {
            return "id-PACE-ECDH-IM-AES-CBC-CMAC-256";
        }
        if (ID_PACE_ECDH_CAM_AES_CBC_CMAC_128.Equals(oid))
        {
            return "id-PACE-ECDH-CAM-AES-CBC-CMAC-128";
        }
        if (ID_PACE_ECDH_CAM_AES_CBC_CMAC_192.Equals(oid))
        {
            return "id-PACE-ECDH-CAM-AES-CBC-CMAC-192";
        }
        if (ID_PACE_ECDH_CAM_AES_CBC_CMAC_256.Equals(oid))
        {
            return "id-PACE-ECDH-CAM-AES-CBC-CMAC-256";
        }

        return oid;
    }

    private static DHParameters FromPGQ(string hexP, string hexG, string hexQ)
        => new(FromHex(hexP), FromHex(hexG), FromHex(hexQ));

    private static BigInteger FromHex(string hex) => new(1, Org.BouncyCastle.Utilities.Encoders.Hex.DecodeStrict(hex));

    private static ECDomainParameters FromNamedCurve(string name) => new(ECNamedCurveTable.GetByName(name));
}
