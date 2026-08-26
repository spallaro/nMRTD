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
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC;
using BigInteger = Org.BouncyCastle.Math.BigInteger;

namespace nMRTD.Lds;

/// <summary>Port of <c>org.jmrtd.lds.PACEDomainParameterInfo</c>: PACE Domain Parameter Info object as
/// per SAC TR 1.01, November 11, 2010.
///
/// The object identifier dhpublicnumber or ecPublicKey for DH or ECDH, respectively, SHALL be used to
/// reference explicit domain parameters in an AlgorithmIdentifier (cf. Section 9.1):
/// <code>
///    dhpublicnumber OBJECT IDENTIFIER ::= {
///        iso(1) member-body(2) us(840) ansi-x942(10046) number-type(2) 1
///    }
/// </code>
/// <code>
///    ecPublicKey OBJECT IDENTIFIER ::= {
///        iso(1) member-body(2) us(840) ansi-x962(10045) keyType(2) 1
///    }
/// </code>
///
/// In the case of elliptic curves, domain parameters MUST be described explicitly in the ECParameters
/// structure, contained as parameters in the AlgorithmIdentifier, i.e. named curves and implicit domain
/// parameters MUST NOT be used.
///
/// NOTE: Java's <c>ECParameterSpec</c>/<c>DHParameterSpec</c> (JCA) are ported as BouncyCastle's
/// <see cref="ECDomainParameters"/>/<see cref="DHParameters"/> throughout (per porting conventions).
/// <see cref="GetParameters"/> therefore returns <c>object</c> (mirroring Java's
/// <c>AlgorithmParameterSpec</c> marker interface) which callers downcast, exactly as in Java.</summary>
public class PACEDomainParameterInfo : SecurityInfo
{
    /// <summary>Value for parameter algorithm OID (part of parameters AlgorithmIdentifier).</summary>
    public const string ID_PRIME_FIELD = "1.2.840.10045.1.1";

    /// <summary>Value for parameter algorithm OID (part of parameters AlgorithmIdentifier).
    /// <c>ecPublicKey OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) ansi-x962(10045) keyType(2) 1 }</c>.
    /// NOTE: Java re-declares this constant with the same value as the inherited
    /// <see cref="SecurityInfo.ID_EC_PUBLIC_KEY"/> (harmless duplication in the original source); the
    /// <c>new</c> keyword here just makes that intentional shadowing explicit to the C# compiler.</summary>
    public new const string ID_EC_PUBLIC_KEY = "1.2.840.10045.2.1";

    /// <summary>Value for parameter algorithm OID (part of parameters AlgorithmIdentifier).
    /// <c>dhpublicnumber OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) ansi-x942(10046) number-type(2) 1 }</c>.</summary>
    public const string ID_DH_PUBLIC_NUMBER = "1.2.840.10046.2.1";

    private readonly string oid;

    private readonly AlgorithmIdentifier domainParameter;

    private readonly BigInteger? parameterId;

    /// <param name="protocolOID">must be <see cref="SecurityInfo.ID_PACE_DH_GM"/>,
    /// <see cref="SecurityInfo.ID_PACE_ECDH_GM"/>, <see cref="SecurityInfo.ID_PACE_DH_IM"/>, or
    /// <see cref="SecurityInfo.ID_PACE_ECDH_IM"/></param>
    /// <param name="domainParameter">parameters in the form of algorithm identifier with algorithm
    /// 1.2.840.10046.2.1 (DH public number) or 1.2.840.10045.2.1 (EC public key)</param>
    public PACEDomainParameterInfo(string protocolOID, AlgorithmIdentifier domainParameter)
        : this(protocolOID, domainParameter, null)
    {
    }

    /// <param name="protocolOID">must be <see cref="SecurityInfo.ID_PACE_DH_GM"/>,
    /// <see cref="SecurityInfo.ID_PACE_ECDH_GM"/>, <see cref="SecurityInfo.ID_PACE_DH_IM"/>, or
    /// <see cref="SecurityInfo.ID_PACE_ECDH_IM"/></param>
    /// <param name="domainParameter">parameters in the form of algorithm identifier with algorithm
    /// 1.2.840.10046.2.1 (DH public number) or 1.2.840.10045.2.1 (EC public key)</param>
    /// <param name="parameterId">an identifier to identify this info</param>
    public PACEDomainParameterInfo(string protocolOID, AlgorithmIdentifier domainParameter, BigInteger? parameterId)
    {
        if (!CheckRequiredIdentifier(protocolOID))
        {
            throw new ArgumentException("Invalid protocol id: " + protocolOID);
        }

        oid = protocolOID;
        this.domainParameter = domainParameter;
        this.parameterId = parameterId;
    }

    public override string GetObjectIdentifier() => oid;

    public override string GetProtocolOIDString() => ToProtocolOIDString(oid);

    /// <summary>Returns the parameter id, or <c>null</c> if this is the only domain parameter info.</summary>
    public BigInteger? GetParameterId() => parameterId;

    /// <summary>Returns the parameters in the form of algorithm identifier with algorithm 1.2.840.10046.2.1
    /// (DH public number) or 1.2.840.10045.2.1 (EC public key), as <see cref="DHParameters"/> or
    /// <see cref="ECDomainParameters"/> respectively -- callers must downcast based on
    /// <see cref="GetObjectIdentifier"/>.</summary>
    public object GetParameters()
    {
        if (ID_DH_PUBLIC_NUMBER.Equals(oid))
        {
            throw new InvalidOperationException("DH PACEDomainParameterInfo not yet implemented"); // FIXME
        }
        if (ID_EC_PUBLIC_KEY.Equals(oid))
        {
            return ToECDomainParameters(domainParameter);
        }

        throw new InvalidOperationException("Unsupported PACEDomainParameterInfo type " + oid);
    }

    [Obsolete("This method will be removed from the visible interface (because of dependency on BC API)")]
    public override Asn1Object GetDERObject()
    {
        var vector = new Asn1EncodableVector
        {
            new DerObjectIdentifier(oid),
            domainParameter,
        };
        if (parameterId != null)
        {
            vector.Add(new DerInteger(parameterId));
        }
        return new DLSequence(vector);
    }

    public override string ToString()
    {
        return "PACEDomainParameterInfo"
            + "["
            + "protocol: " + ToProtocolOIDString(oid)
            + ", "
            + "domainParameter: ["
            + "algorithm: " + domainParameter.Algorithm.Id
            + ", "
            + "parameters: " + domainParameter.Parameters
            + (parameterId == null ? "" : ", parameterId: " + parameterId)
            + "]";
    }

    public override int GetHashCode()
    {
        return 111111111
            + 7 * oid.GetHashCode()
            + 5 * domainParameter.GetHashCode()
            + 3 * (parameterId == null ? 333 : parameterId.GetHashCode());
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
        if (other.GetType() != typeof(PACEDomainParameterInfo))
        {
            return false;
        }

        var otherPACEDomainParameterInfo = (PACEDomainParameterInfo)other;
        return Equals(oid, otherPACEDomainParameterInfo.oid)
            && Equals(domainParameter, otherPACEDomainParameterInfo.domainParameter)
            && Equals(parameterId, otherPACEDomainParameterInfo.parameterId);
    }

    /// <summary>Checks whether the object identifier is an allowed PACE related object identifier.</summary>
    public static bool CheckRequiredIdentifier(string oid)
    {
        return ID_PACE_DH_GM.Equals(oid)
            || ID_PACE_ECDH_GM.Equals(oid)
            || ID_PACE_DH_IM.Equals(oid)
            || ID_PACE_ECDH_IM.Equals(oid)
            || ID_PACE_ECDH_CAM.Equals(oid);
    }

    /* TODO: toAlgorithmIdentifier for DH case. */

    /// <summary>Returns a BC algorithm identifier object from EC domain parameters.</summary>
    [Obsolete("Visibility will be restricted")]
    public static AlgorithmIdentifier ToAlgorithmIdentifier(ECDomainParameters ecDomainParameters)
    {
        var paramSequenceList = new Asn1EncodableVector
        {
            new DerInteger(BigInteger.One),
        };

        var fieldIdOID = new DerObjectIdentifier(ID_PRIME_FIELD);
        var curve = ecDomainParameters.Curve;
        var p = new DerInteger(curve.Field.Characteristic);
        var fieldIdObject = new DLSequence(fieldIdOID, p);
        paramSequenceList.Add(fieldIdObject);

        var aObject = new DerOctetString(curve.A.ToBigInteger().ToByteArrayUnsigned());
        var bObject = new DerOctetString(curve.B.ToBigInteger().ToByteArrayUnsigned());
        var curveObject = new DLSequence(aObject, bObject);
        paramSequenceList.Add(curveObject);

        var basePointObject = new DerOctetString(ecDomainParameters.G.GetEncoded(false));
        paramSequenceList.Add(basePointObject);

        paramSequenceList.Add(new DerInteger(ecDomainParameters.N));
        paramSequenceList.Add(new DerInteger(ecDomainParameters.H));

        var paramSequence = new DLSequence(paramSequenceList);
        return new AlgorithmIdentifier(new DerObjectIdentifier(ID_EC_PUBLIC_KEY), paramSequence);
    }

    /* TODO: toDHParameterSpec for DH case. */

    /// <summary>Returns the EC domain parameters from the BC algorithm identifier object.</summary>
    [Obsolete("Visibility will be restricted")]
    public static ECDomainParameters ToECDomainParameters(AlgorithmIdentifier domainParameter)
    {
        Asn1Encodable parameters = domainParameter.Parameters;

        if (parameters is not Asn1Sequence)
        {
            throw new ArgumentException("Was expecting an ASN.1 sequence");
        }

        /* We support named EC curves, even though they are actually not allowed here. */
        try
        {
            X962Parameters x962Params = X962Parameters.GetInstance(parameters);
            if (x962Params.IsNamedCurve)
            {
                var namedCurveOid = (DerObjectIdentifier)x962Params.Parameters;
                X9ECParameters x9ECParams = X962NamedCurves.GetByOid(namedCurveOid);
                return new ECDomainParameters(x9ECParams);
            }
        }
        catch (Exception)
        {
            /* NOTE: Java logs a warning here; omitted per the non-essential-warning-omission precedent
             * (see AbstractLDSFile.cs). Falls through to explicit parameter parsing below. */
        }

        /* Explicit EC parameters.
         *
         * ECParameters ::= SEQUENCE {
         *     version INTEGER { ecpVer1(1) } (ecpVer1),
         *     fieldID FieldID {{FieldTypes}},
         *     curve Curve,
         *     base ECPoint,
         *     order INTEGER,
         *     cofactor INTEGER OPTIONAL,
         *     ...
         * }
         */

        var paramSequence = (Asn1Sequence)parameters;

        if (paramSequence.Count < 5)
        {
            throw new ArgumentException("Was expecting an ASN.1 sequence of length 5 or longer");
        }

        try
        {
            /* version = DerInteger.GetInstance(paramSequence[0]).Value; -- parsed but unused, same as the Java original. */

            var fieldIdObject = (Asn1Sequence)paramSequence[1];
            /* fieldIdOID = ((DerObjectIdentifier)fieldIdObject[0]).Id; -- parsed but unused, same as the Java original. */
            BigInteger p = ((DerInteger)fieldIdObject[1]).PositiveValue;

            var curveObject = (Asn1Sequence)paramSequence[2];
            var aObject = (Asn1OctetString)curveObject[0];
            var bObject = (Asn1OctetString)curveObject[1];
            BigInteger a = new(1, aObject.GetOctets());
            BigInteger b = new(1, bObject.GetOctets());

            var curve = new FpCurve(p, a, b);

            var basePointObject = (Asn1OctetString)paramSequence[3];
            ECPoint g = curve.DecodePoint(basePointObject.GetOctets());

            var orderObject = (DerInteger)paramSequence[4];
            BigInteger n = orderObject.PositiveValue;

            if (paramSequence.Count <= 5)
            {
                return new ECDomainParameters(curve, g, n, BigInteger.One);
            }

            var coFactorObject = (DerInteger)paramSequence[5];
            BigInteger coFactor = coFactorObject.Value;
            return new ECDomainParameters(curve, g, n, coFactor);
        }
        catch (Exception e)
        {
            throw new ArgumentException("Could not get EC parameters from explicit parameters", e);
        }
    }

    /* ONLY PRIVATE METHODS BELOW */

    /// <summary>Returns a BC algorithm identifier for the given protocol object identifier.</summary>
    private static AlgorithmIdentifier ToAlgorithmIdentifier(string protocolOID, Asn1Encodable parameters)
    {
        if (ID_PACE_DH_GM.Equals(protocolOID) || ID_PACE_DH_IM.Equals(protocolOID))
        {
            return new AlgorithmIdentifier(new DerObjectIdentifier(ID_DH_PUBLIC_NUMBER), parameters);
        }
        if (ID_PACE_ECDH_GM.Equals(protocolOID) || ID_PACE_ECDH_IM.Equals(protocolOID) || ID_PACE_ECDH_CAM.Equals(protocolOID))
        {
            return new AlgorithmIdentifier(new DerObjectIdentifier(ID_EC_PUBLIC_KEY), parameters);
        }
        throw new ArgumentException("Cannot infer algorithm OID from protocol OID: " + protocolOID);
    }

    /// <summary>Returns an ASN1 name for the given object identifier.</summary>
    private static string ToProtocolOIDString(string oid)
    {
        if (ID_PACE_DH_GM.Equals(oid))
        {
            return "id-PACE-DH-GM";
        }
        if (ID_PACE_ECDH_GM.Equals(oid))
        {
            return "id-PACE-ECDH-GM";
        }
        if (ID_PACE_DH_IM.Equals(oid))
        {
            return "id-PACE-DH-IM";
        }
        if (ID_PACE_ECDH_IM.Equals(oid))
        {
            return "id-PACE-ECDH-IM";
        }
        if (ID_PACE_ECDH_CAM.Equals(oid))
        {
            return "id-PACE-ECDH-CAM";
        }

        return oid;
    }
}
