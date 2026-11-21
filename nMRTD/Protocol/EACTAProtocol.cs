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

using nMRTD.Cert;
using nMRTD.Lds.Icao;
using nMRTD.Logging;
using nMRTD.SmartCards;

namespace nMRTD.Protocol;

/// <summary>
/// Signs the EAC-TA challenge (<c>dataToBeSigned</c>) with a terminal private key that is not available as an
/// in-memory <see cref="AsymmetricKeyParameter"/> -- e.g. a key backed by an HSM or smart card, exposed through
/// .NET's own <c>ECDsa</c>/<c>RSA</c> abstractions (which can themselves be CNG/PKCS#11-backed and never export
/// the private key material). The returned signature must use the same encoding a BouncyCastle
/// <see cref="ISigner"/> for <paramref name="sigAlg"/> would produce (DER-encoded for ECDSA, raw for RSA).
/// </summary>
/// <param name="sigAlg">the signature algorithm name, as reported by the terminal certificate</param>
/// <param name="dataToBeSigned">the challenge bytes to sign</param>
public delegate byte[] TerminalKeySigner(string sigAlg, byte[] dataToBeSigned);

/// <summary>Port of <c>org.jmrtd.protocol.EACTAProtocol</c>: the EAC Terminal Authentication protocol.</summary>
public class EACTAProtocol
{
    private const int TagCvCertificateSignature = 0x5F37;
    private const string LogCategory = "EAC-TA";

    private readonly IApduLevelEacTACapable _service;

    private readonly SecureMessagingWrapper _wrapper;

    private readonly LogSource _log;

    /// <summary>Creates a protocol instance.</summary>
    /// <param name="service">the card service for APDU communication</param>
    /// <param name="wrapper">the secure messaging wrapper</param>
    /// <param name="log">the log/trace registry to raise protocol-step and error events on, or <c>null</c> for a private (unobserved) one</param>
    public EACTAProtocol(IApduLevelEacTACapable service, SecureMessagingWrapper wrapper, LogSource? log = null)
    {
        _service = service;
        _wrapper = wrapper;
        _log = log ?? new LogSource();
    }

    /*
     * From BSI-03110 v1.1, B.2:
     *
     * The following sequence of commands SHALL be used to implement Terminal Authentication:
     *    1. MSE:Set DST
     *    2. PSO:Verify Certificate
     *    3. MSE:Set AT
     *    4. Get Challenge
     *    5. External Authenticate
     *
     * Steps 1 and 2 are repeated for every CV certificate to be verified
     * (CVCA Link Certificates, DV Certificate, IS Certificate).
     */

    /// <summary>
    /// Perform the EAC-TA (Terminal Authentication) part of EAC (version 1). For details see TR-03110
    /// ver. 1.11. In short, we feed the sequence of terminal certificates to the card for verification,
    /// get a challenge from the card, sign it with terminal private key, and send back to the card for
    /// verification.
    /// </summary>
    /// <param name="caReference">a reference to the issuer</param>
    /// <param name="terminalCertificates">the terminal certificate chain</param>
    /// <param name="terminalKey">the terminal private key</param>
    /// <param name="taAlg">the algorithm</param>
    /// <param name="chipAuthenticationResult">the chip authentication result</param>
    /// <param name="documentNumber">the document number from which the chip key hash will be derived</param>
    /// <param name="terminalKeySigner">when <paramref name="terminalKey"/> is <c>null</c>, used instead to sign
    /// the challenge with a terminal key that lives outside BouncyCastle's key model (e.g. an HSM/smart-card
    /// key exposed through .NET's <c>ECDsa</c>/<c>RSA</c>)</param>
    /// <param name="terminalKeyEcDomainParameters">for an ECDSA terminal certificate signed via
    /// <paramref name="terminalKeySigner"/>, the terminal key's public curve parameters (never the private
    /// scalar), needed to determine the raw ECDSA signature length; unused for RSA or when
    /// <paramref name="terminalKey"/> is a BouncyCastle <see cref="ECPrivateKeyParameters"/></param>
    /// <returns>the Terminal Authentication result</returns>
    /// <exception cref="CardServiceException">on error</exception>
    public EACTAResult DoEACTA(CVCPrincipal? caReference, IReadOnlyList<CardVerifiableCertificate> terminalCertificates,
        AsymmetricKeyParameter? terminalKey, string? taAlg, EACCAResult? chipAuthenticationResult, string? documentNumber,
        TerminalKeySigner? terminalKeySigner = null, ECDomainParameters? terminalKeyEcDomainParameters = null)
    {
        byte[]? idPICC = DeriveIdentifier(documentNumber);
        return DoTA(caReference, terminalCertificates, terminalKey, taAlg, chipAuthenticationResult, idPICC, terminalKeySigner, terminalKeyEcDomainParameters);
    }

    /// <summary>
    /// Perform TA (Terminal Authentication) part of EAC (version 1). For details see TR-03110 ver. 1.11.
    /// In short, we feed the sequence of terminal certificates to the card for verification, get a
    /// challenge from the card, sign it with terminal private key, and send back to the card for
    /// verification.
    /// </summary>
    /// <param name="caReference">reference issuer</param>
    /// <param name="terminalCertificates">terminal certificate chain</param>
    /// <param name="terminalKey">terminal private key</param>
    /// <param name="taAlg">the algorithm</param>
    /// <param name="chipAuthenticationResult">the chip authentication result</param>
    /// <param name="paceResult">the PACE result from which the chip key hash will be derived</param>
    /// <param name="terminalKeySigner">when <paramref name="terminalKey"/> is <c>null</c>, used instead to sign
    /// the challenge with a terminal key that lives outside BouncyCastle's key model (e.g. an HSM/smart-card
    /// key exposed through .NET's <c>ECDsa</c>/<c>RSA</c>)</param>
    /// <param name="terminalKeyEcDomainParameters">for an ECDSA terminal certificate signed via
    /// <paramref name="terminalKeySigner"/>, the terminal key's public curve parameters (never the private
    /// scalar), needed to determine the raw ECDSA signature length; unused for RSA or when
    /// <paramref name="terminalKey"/> is a BouncyCastle <see cref="ECPrivateKeyParameters"/></param>
    /// <returns>the Terminal Authentication result</returns>
    /// <exception cref="CardServiceException">on error</exception>
    public EACTAResult DoTA(CVCPrincipal? caReference, IReadOnlyList<CardVerifiableCertificate> terminalCertificates,
        AsymmetricKeyParameter? terminalKey, string? taAlg, EACCAResult? chipAuthenticationResult, PACEResult paceResult,
        TerminalKeySigner? terminalKeySigner = null, ECDomainParameters? terminalKeyEcDomainParameters = null)
    {
        try
        {
            byte[]? idPICC = DeriveIdentifier(paceResult.PiccPublicKey);
            return DoTA(caReference, terminalCertificates, terminalKey, taAlg, chipAuthenticationResult, idPICC, terminalKeySigner, terminalKeyEcDomainParameters);
        }
        catch (ArgumentException e)
        {
            // NOTE: stands in for Java's checked NoSuchAlgorithmException (thrown by DeriveIdentifier below
            // for an unsupported public key algorithm); this port has no equivalent checked-exception
            // family (see Util.cs's doc comment on the dropped JCA provider-lookup methods).
            throw new CardServiceException("No such algorithm", e);
        }
    }

    /// <summary>Executes the Terminal Authentication protocol.</summary>
    /// <param name="caReference">the certificate authority</param>
    /// <param name="terminalCertificates">the chain of certificates to send</param>
    /// <param name="terminalKey">the inspection system's private key</param>
    /// <param name="taAlg">the algorithm -- NOTE: preserved Java quirk, this parameter is accepted but
    /// never actually used; the algorithm actually used is derived from the terminal certificate's own
    /// <see cref="CardVerifiableCertificate.SigAlgName"/>, not from this parameter, exactly as in JMRTD's
    /// own <c>EACTAProtocol.doTA(CVCPrincipal, List, PrivateKey, String, EACCAResult, byte[])</c>.</param>
    /// <param name="chipAuthenticationResult">the result of the Chip Authentication protocol execution</param>
    /// <param name="idPICC">the chip identifier</param>
    /// <param name="terminalKeySigner">when <paramref name="terminalKey"/> is <c>null</c>, used instead to sign
    /// the challenge with a terminal key that lives outside BouncyCastle's key model (e.g. an HSM/smart-card
    /// key exposed through .NET's <c>ECDsa</c>/<c>RSA</c>)</param>
    /// <param name="terminalKeyEcDomainParameters">for an ECDSA terminal certificate signed via
    /// <paramref name="terminalKeySigner"/>, the terminal key's public curve parameters (never the private
    /// scalar), needed to determine the raw ECDSA signature length; unused for RSA or when
    /// <paramref name="terminalKey"/> is a BouncyCastle <see cref="ECPrivateKeyParameters"/></param>
    /// <returns>the result of Terminal Authentication</returns>
    /// <exception cref="CardServiceException">on error</exception>
    public EACTAResult DoTA(CVCPrincipal? caReference, IReadOnlyList<CardVerifiableCertificate> terminalCertificates,
        AsymmetricKeyParameter? terminalKey, string? taAlg, EACCAResult? chipAuthenticationResult, byte[]? idPICC,
        TerminalKeySigner? terminalKeySigner = null, ECDomainParameters? terminalKeyEcDomainParameters = null)
    {
        _log.Info(LogCategory, $"Starting Terminal Authentication ({terminalCertificates?.Count ?? 0} certificate(s)).");
        try
        {
            if (terminalCertificates == null || terminalCertificates.Count == 0)
            {
                throw new ArgumentException($"Need at least 1 certificate to perform TA, found: {(terminalCertificates == null ? "null" : "[]")}");
            }

            if (chipAuthenticationResult == null)
            {
                throw new ArgumentException("Could not get EAC-CA key hash");
            }

            byte[]? caKeyHash = chipAuthenticationResult.GetKeyHash();

            /* The key hash that resulted from CA. */
            if (caKeyHash == null)
            {
                throw new ArgumentException("Could nnot get EAC-CA key hash"); // NOTE: preserved Java typo "nnot".
            }

            /*
             * FIXME: check that terminalCertificates holds a (inverted, i.e. issuer before subject) chain.
             */

            /*
             * Work on a copy because a self-signed CVCA certificate is a local trust-anchor marker, not a
             * certificate that should be sent to the IC.
             */
            var certificatesToSend = new List<CardVerifiableCertificate>(terminalCertificates);
            CardVerifiableCertificate firstCert = certificatesToSend[0];
            CVCAuthorizationTemplate.Role firstCertRole = firstCert.AuthorizationTemplate.AuthorizationRole;
            if (firstCertRole == CVCAuthorizationTemplate.Role.Cvca)
            {
                CVCPrincipal firstCertAuthorityReference = firstCert.AuthorityReference;
                CVCPrincipal firstCertHolderReference = firstCert.HolderReference;
                bool isSelfSignedTrustAnchor = firstCertAuthorityReference.Equals(firstCertHolderReference);
                if (isSelfSignedTrustAnchor)
                {
                    if (caReference != null && !caReference.Equals(firstCertHolderReference))
                    {
                        throw new CardServiceException($"First certificate holds wrong authority, found \"{firstCertHolderReference.Name}\", expected \"{caReference.Name}\"");
                    }

                    caReference ??= firstCertHolderReference;
                    certificatesToSend.RemoveAt(0);
                    if (certificatesToSend.Count == 0)
                    {
                        throw new CardServiceException("Certificate chain only contains a self-signed CVCA certificate");
                    }
                }
            }

            firstCert = certificatesToSend[0];
            CVCPrincipal firstCertAuthorityReference2 = firstCert.AuthorityReference;
            if (caReference != null && !caReference.Equals(firstCertAuthorityReference2))
            {
                throw new CardServiceException($"First certificate not signed by expected CA, found {firstCertAuthorityReference2.Name}, expected {caReference.Name}");
            }

            caReference ??= firstCertAuthorityReference2;

            /* Check if the last cert is an IS cert. */
            CardVerifiableCertificate lastCert = certificatesToSend[^1];
            CVCAuthorizationTemplate.Role lastCertRole = lastCert.AuthorizationTemplate.AuthorizationRole;
            if (lastCertRole != CVCAuthorizationTemplate.Role.Is)
            {
                throw new CardServiceException($"Last certificate in chain ({lastCert.HolderReference.Name}) does not have role IS, but has role {lastCertRole}");
            }

            CardVerifiableCertificate terminalCert = lastCert;

            /* Have the MRTD check our chain. */
            foreach (CardVerifiableCertificate cert in certificatesToSend)
            {
                try
                {
                    CVCPrincipal authorityReference = cert.AuthorityReference;

                    /* Step 1: MSE:SetDST */
                    /*
                     * Manage Security Environment: Set for verification: Digital Signature Template,
                     * indicate authority of cert to check.
                     */
                    byte[] authorityRefBytes = TlvUtil.WrapDO(0x83, Iso88591GetBytes(authorityReference.Name));
                    _service.SendMseSetDst(_wrapper, authorityRefBytes);
                }
                catch (Exception e)
                {
                    throw new CardServiceProtocolException("Exception in MSE:SetDST", 1, e);
                }

                try
                {
                    /* Cert body is already in TLV format. */
                    byte[] body = cert.GetCertBodyData();

                    /* Signature not yet in TLV format, prefix it with tag and length. */
                    byte[] signatureTlv = TlvUtil.TlvEncode(TagCvCertificateSignature, cert.Signature);

                    /* Step 2: PSO:Verify Certificate */
                    _service.SendPsoExtendedLengthMode(_wrapper, body, signatureTlv);
                }
                catch (Exception e)
                {
                    /* FIXME: Does this mean we failed to authenticate? -- MO (carried over from Java source comment) */
                    throw new CardServiceProtocolException("Exception", 2, e);
                }
            }

            if (terminalKey == null && terminalKeySigner == null)
            {
                throw new CardServiceException("No terminal key");
            }

            /* Step 3: MSE Set AT */
            try
            {
                CVCPrincipal holderRef = terminalCert.HolderReference;
                byte[] holderRefBytes = TlvUtil.WrapDO(0x83, Iso88591GetBytes(holderRef.Name));

                /*
                 * Manage Security Environment: Set for external authentication: Authentication Template.
                 */
                _service.SendMseSetAtExtAuth(_wrapper, holderRefBytes);
            }
            catch (Exception e)
            {
                throw new CardServiceProtocolException("Exception in MSE Set AT", 3, e);
            }

            /* Step 4: send get challenge */
            byte[] rPICC;
            try
            {
                rPICC = _service.SendGetChallenge(_wrapper);
            }
            catch (Exception e)
            {
                throw new CardServiceProtocolException("Exception in Get Challenge", 4, e);
            }

            /* Step 5: external authenticate. */
            try
            {
                using var dtbs = new MemoryStream();
                if (idPICC != null)
                {
                    dtbs.Write(idPICC, 0, idPICC.Length);
                }

                dtbs.Write(rPICC, 0, rPICC.Length);
                dtbs.Write(caKeyHash, 0, caKeyHash.Length);
                byte[] dtbsBytes = dtbs.ToArray();

                string? sigAlg = terminalCert.SigAlgName;
                if (sigAlg == null)
                {
                    throw new InvalidOperationException($"Could not determine signature algorithm for terminal certificate {terminalCert.HolderReference.Name}");
                }

                byte[] signedData;
                if (terminalKeySigner != null)
                {
                    /*
                     * External signer path (HSM/smart-card-backed terminal key, e.g. .NET's ECDsa/RSA over
                     * CNG/PKCS#11): never touch a private scalar here, the delegate itself owns signing.
                     */
                    signedData = terminalKeySigner(sigAlg, dtbsBytes);
                }
                else
                {
                    ISigner sig = SignerUtilities.GetSigner(sigAlg);
                    sig.Init(forSigning: true, terminalKey);
                    sig.BlockUpdate(dtbsBytes, 0, dtbsBytes.Length);
                    signedData = sig.GenerateSignature();
                }

                if (sigAlg.ToUpperInvariant().EndsWith("ECDSA", StringComparison.Ordinal))
                {
                    /*
                     * Field size only, deliberately not the private scalar: terminalKey may be null (external
                     * signer path) or, per upstream jMRTD Bug #45, a non-extractable HSM/smart-card key whose
                     * private material must never be materialized just to size the signature.
                     */
                    ECDomainParameters ecDomainParameters = terminalKey is ECPrivateKeyParameters ecTerminalKey
                        ? ecTerminalKey.Parameters
                        : terminalKeyEcDomainParameters
                            ?? throw new InvalidOperationException("Expected an EC private key, or terminalKeyEcDomainParameters, for an ECDSA terminal signature algorithm.");

                    int keySize = (int)Math.Ceiling(ecDomainParameters.Curve.FieldSize / 8.0);
                    signedData = Util.GetRawECDSASignature(signedData, keySize);
                }

                _service.SendMutualAuthenticate(_wrapper, signedData);
                _log.Info(LogCategory, "Terminal Authentication completed.");
                return new EACTAResult(chipAuthenticationResult, caReference, certificatesToSend, terminalKey, null, rPICC);
            }
            catch (Exception e)
            {
                // NOTE: Java logs a warning here; omitted per the non-essential-warning-omission
                // precedent used elsewhere in this port.
                throw new CardServiceProtocolException("Exception in External Authenticate", 5, e);
            }
        }
        catch (CardServiceException e)
        {
            _log.Error(LogCategory, "Terminal Authentication failed.", e);
            throw;
        }
        catch (Exception e)
        {
            _log.Error(LogCategory, "Terminal Authentication failed.", e);
            throw new CardServiceException("Unexpected exception", e);
        }
    }

    /// <summary>Derives a chip identifier from the document number (BAC MRZ based case).</summary>
    /// <param name="documentNumber">the document number that was used for primary access control (typically BAC)</param>
    /// <returns>the chip identifier</returns>
    public static byte[]? DeriveIdentifier(string? documentNumber)
    {
        if (documentNumber == null)
        {
            return null;
        }

        int documentNumberLength = documentNumber.Length;
        byte[] idPICC = new byte[documentNumberLength + 1];

        // NOTE: Java wraps this in a try/catch for a checked UnsupportedEncodingException that never
        // happens in practice (ISO-8859-1 is always supported); omitted here since .NET's Encoding.Latin1
        // cannot throw for this reason either.
        byte[] docBytes = Iso88591GetBytes(documentNumber);
        Array.Copy(docBytes, 0, idPICC, 0, documentNumberLength);
        idPICC[documentNumberLength] = (byte)MRZInfo.CheckDigit(documentNumber);
        return idPICC;
    }

    /// <summary>Derives a chip identifier from a PACE result (PACE case).</summary>
    /// <param name="publicKey">the PACE result's PICC public key</param>
    /// <returns>the chip identifier</returns>
    /// <exception cref="ArgumentException">on error (Java: checked <c>NoSuchAlgorithmException</c>)</exception>
    public static byte[]? DeriveIdentifier(AsymmetricKeyParameter? publicKey)
    {
        if (publicKey == null)
        {
            return null;
        }

        if (publicKey is DHPublicKeyParameters dhPublicKey)
        {
            /* Comp(PK) for DH: SHA-1 of the public value (Doc 9303 - Part 11, 7.1.4.1.3), an unsigned integer (9.4.1). */
            IDigest md = DigestUtilities.GetDigest("SHA-1");
            byte[] data = Util.I2os(dhPublicKey.Y);
            md.BlockUpdate(data, 0, data.Length);
            byte[] result = new byte[md.GetDigestSize()];
            md.DoFinal(result, 0);
            return result;
        }

        if (publicKey is ECPublicKeyParameters piccECPublicKey)
        {
            /* Comp(PK) for ECDH: the x-coordinate, fixed length (Doc 9303 - Part 11, 7.1.4.2.3). */
            byte[] t = Util.I2os(piccECPublicKey.Q.AffineXCoord.ToBigInteger());
            return Util.AlignKeyDataToSize(t, (int)Math.Ceiling(piccECPublicKey.Parameters.Curve.FieldSize / 8.0));
        }

        throw new ArgumentException($"Unsupported agreement algorithm {publicKey.GetType().Name}");
    }

    private static byte[] Iso88591GetBytes(string s) => System.Text.Encoding.Latin1.GetBytes(s);
}
