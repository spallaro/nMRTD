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

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace nMRTD.Cert;

/// <summary>
/// Port of <c>org.jmrtd.cert.CVCertificateBuilder</c>: builds and signs Card Verifiable Certificates.
///
/// ADAPTATION: the Java class delegates the actual TLV assembly and signing to the external
/// <c>org.ejbca.cvc</c> library (<c>CertificateGenerator.createCertificate</c>); that logic is instead
/// implemented directly against <see cref="CardVerifiableCertificate"/>'s own encode/sign machinery (see
/// that type's doc comment and its internal <c>CreateUnsigned</c>/<c>WithSignature</c> factory methods,
/// which exist specifically to support this builder). Per porting-conventions.md, the JCA provider-name
/// parameter is dropped -- BouncyCastle.Cryptography is the sole crypto backend, so there is nothing to
/// select.
/// </summary>
public static class CVCertificateBuilder
{
    /// <summary>
    /// Produces a signed card verifiable certificate.
    /// </summary>
    /// <param name="publicKey">the public key to certify</param>
    /// <param name="signerKey">the issuer's private key, used to sign the certificate</param>
    /// <param name="algorithmName">a JCE-style signature algorithm mnemonic, e.g. "SHA256withECDSA" or "SHA256withRSA"</param>
    /// <param name="caRef">the Certification Authority Reference (issuer)</param>
    /// <param name="holderRef">the Certificate Holder Reference (subject)</param>
    /// <param name="authZTemplate">the Certificate Holder Authorization Template</param>
    /// <param name="validFrom">the certificate's effective date</param>
    /// <param name="validTo">the certificate's expiration date</param>
    /// <returns>a signed card verifiable certificate</returns>
    public static CardVerifiableCertificate CreateCertificate(
        AsymmetricKeyParameter publicKey,
        AsymmetricKeyParameter signerKey,
        string algorithmName,
        CVCPrincipal caRef,
        CVCPrincipal holderRef,
        CVCAuthorizationTemplate authZTemplate,
        DateOnly validFrom,
        DateOnly validTo)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(signerKey);
        ArgumentNullException.ThrowIfNull(algorithmName);
        ArgumentNullException.ThrowIfNull(caRef);
        ArgumentNullException.ThrowIfNull(holderRef);
        ArgumentNullException.ThrowIfNull(authZTemplate);

        CardVerifiableCertificate unsigned = CardVerifiableCertificate.CreateUnsigned(
            caRef, holderRef, publicKey, algorithmName, authZTemplate, validFrom, validTo);

        byte[] tbs = unsigned.GetCertBodyData();

        ISigner signer = SignerUtilities.GetSigner(algorithmName);
        signer.Init(forSigning: true, signerKey);
        signer.BlockUpdate(tbs, 0, tbs.Length);
        byte[] signature = signer.GenerateSignature();

        if (signerKey is ECPrivateKeyParameters ecKey)
        {
            // BC's ECDSA signer produces a DER SEQUENCE{r,s}, but EAC/TR-03110 certificates carry the
            // signature in raw r||s form (see CardVerifiableCertificate.Verify's mirror-image conversion).
            int componentSize = (ecKey.Parameters.Curve.FieldSize + 7) / 8;
            signature = CardVerifiableCertificate.DerToRawEcdsaSignature(signature, componentSize);
        }

        return CardVerifiableCertificate.WithSignature(unsigned, signature);
    }
}
