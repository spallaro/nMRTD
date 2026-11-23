/*
 * nMRTD - A .Net API for accessing Machine Readable Travel Documents.
 *
 * Copyright (C) Sebastiano Pallaro.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * Distributed under the terms of GNU LGPL v3.
 * See LICENSE for more information.
 */

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Icao;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace nMRTD.Cli;

/// <summary>
/// Country Signing CA certificates the user trusts (<c>--csca</c>), and the check that a Document Signer
/// certificate was issued by one of them: the last step of Passive Authentication (ICAO Doc 9303-12), which
/// the library deliberately leaves to the application.
/// </summary>
/// <remarks>
/// Certificates are read from files (<c>.cer</c>, <c>.crt</c>, <c>.der</c>, <c>.pem</c>, DER or PEM, one or
/// more per file) or ICAO CSCA master lists (<c>.ml</c>). The signature of a master list itself is not
/// verified: loading one means trusting where it came from. Revocation (CRLs) is not checked.
/// </remarks>
public sealed class CscaTrustStore
{
    private static readonly string[] CertificateExtensions = [".cer", ".crt", ".der", ".pem"];

    private readonly List<X509Certificate> certificates = [];

    /// <summary>The trusted CSCA certificates.</summary>
    public IReadOnlyList<X509Certificate> Certificates => certificates;

    /// <summary>Files that were skipped, with the reason.</summary>
    public List<string> Warnings { get; } = [];

    public CscaTrustStore(IEnumerable<X509Certificate> certificates)
    {
        this.certificates.AddRange(certificates);
    }

    /// <summary>Loads the certificates from a file, or from every certificate and master list file in a folder.</summary>
    /// <exception cref="FileNotFoundException">if <paramref name="path"/> is neither a file nor a folder</exception>
    public static CscaTrustStore Load(string path)
    {
        var store = new CscaTrustStore([]);
        if (Directory.Exists(path))
        {
            foreach (string file in Directory.EnumerateFiles(path).OrderBy(f => f, StringComparer.Ordinal))
            {
                string extension = Path.GetExtension(file).ToLowerInvariant();
                if (extension == ".ml" || CertificateExtensions.Contains(extension))
                {
                    store.LoadFile(file);
                }
            }
        }
        else if (File.Exists(path))
        {
            store.LoadFile(path);
        }
        else
        {
            throw new FileNotFoundException($"No CSCA certificate file or folder at {path}", path);
        }
        return store;
    }

    private void LoadFile(string file)
    {
        try
        {
            byte[] bytes = File.ReadAllBytes(file);
            if (Path.GetExtension(file).Equals(".ml", StringComparison.OrdinalIgnoreCase))
            {
                certificates.AddRange(ReadMasterList(bytes, out int skipped));
                if (skipped > 0)
                {
                    Warnings.Add($"{file}: {skipped} certificate(s) of the master list could not be read");
                }
            }
            else
            {
                ICollection<X509Certificate> read = new X509CertificateParser().ReadCertificates(bytes);
                if (read.Count == 0)
                {
                    Warnings.Add($"{file}: no certificate found");
                }
                certificates.AddRange(read);
            }
        }
        catch (Exception e) when (e is IOException or ArgumentException or InvalidOperationException
            or Org.BouncyCastle.Security.Certificates.CertificateException)
        {
            Warnings.Add($"{file}: {e.Message}");
        }
    }

    /// <summary>The certificates of an ICAO CSCA master list: CMS SignedData whose content
    /// (id-icao-cscaMasterList, 2.23.136.1.1.2) is a <c>CscaMasterList</c> (version, SET OF Certificate).
    /// Certificates that cannot be read are skipped and counted in <paramref name="skipped"/>.</summary>
    public static List<X509Certificate> ReadMasterList(byte[] encoded, out int skipped)
    {
        ContentInfo contentInfo = ContentInfo.GetInstance(Asn1Object.FromByteArray(encoded));
        SignedData signedData = SignedData.GetInstance(contentInfo.Content);
        ContentInfo content = signedData.EncapContentInfo;
        if (!IcaoObjectIdentifiers.IdIcaoCscaMasterList.Equals(content.ContentType))
        {
            throw new ArgumentException($"Not a CSCA master list (content type {content.ContentType})");
        }
        byte[] masterListBytes = Asn1OctetString.GetInstance(content.Content).GetOctets();
        Asn1Set certificateSet = Asn1Set.GetInstance(Asn1Sequence.GetInstance(Asn1Object.FromByteArray(masterListBytes))[1]);
        var result = new List<X509Certificate>();
        skipped = 0;
        foreach (Asn1Encodable element in certificateSet)
        {
            try
            {
                result.Add(new X509Certificate(X509CertificateStructure.GetInstance(element)));
            }
            catch (Exception)
            {
                skipped++;
            }
        }
        return result;
    }

    /// <summary>The outcome of checking a Document Signer certificate.</summary>
    /// <param name="Trusted">whether the certificate's signature verifies with a trusted CSCA's key</param>
    /// <param name="Csca">the CSCA certificate that verified it</param>
    /// <param name="Detail">why it is not trusted, or a note on the CSCA's validity</param>
    public sealed record Verification(bool Trusted, X509Certificate? Csca, string Detail);

    /// <summary>
    /// Checks that <paramref name="documentSigner"/> was signed by a trusted CSCA: candidates are the CSCAs
    /// whose subject is the certificate's issuer, narrowed by the authority key identifier when both sides have
    /// one; each is tried, since a country can have several CSCA keys under the same name. Validity dates are
    /// reported, not enforced: an expired document normally has an expired Document Signer certificate.
    /// </summary>
    public Verification Verify(X509Certificate documentSigner)
    {
        X509Name issuer = documentSigner.IssuerDN;
        byte[]? authorityKeyId = AuthorityKeyIdentifier(documentSigner);
        List<X509Certificate> candidates = certificates
            .Where(csca => csca.SubjectDN.Equivalent(issuer))
            .Where(csca => authorityKeyId == null || SubjectKeyIdentifier(csca) is not { } ski || ski.AsSpan().SequenceEqual(authorityKeyId))
            .ToList();
        if (candidates.Count == 0)
        {
            return new Verification(false, null, $"no trusted CSCA certificate for the issuer {issuer}");
        }

        foreach (X509Certificate csca in candidates)
        {
            try
            {
                documentSigner.Verify(csca.GetPublicKey());
                string validity = csca.IsValid(documentSigner.NotBefore)
                    ? "the CSCA certificate was valid when the Document Signer certificate was issued"
                    : "the CSCA certificate was NOT valid when the Document Signer certificate was issued";
                return new Verification(true, csca, validity);
            }
            catch (Exception)
            {
                // Signed with another key of the same CSCA name (or not at all): Bouncy Castle reports that
                // with different exception types depending on the algorithm. Try the next candidate.
            }
        }

        return new Verification(false, null,
            $"the signature does not verify with any of the {candidates.Count} trusted CSCA certificate(s) for {issuer}");
    }

    private static byte[]? AuthorityKeyIdentifier(X509Certificate certificate)
    {
        Asn1OctetString? value = certificate.GetExtensionValue(X509Extensions.AuthorityKeyIdentifier);
        return value == null ? null
            : Org.BouncyCastle.Asn1.X509.AuthorityKeyIdentifier.GetInstance(X509ExtensionUtilities.FromExtensionValue(value)).GetKeyIdentifier();
    }

    private static byte[]? SubjectKeyIdentifier(X509Certificate certificate)
    {
        Asn1OctetString? value = certificate.GetExtensionValue(X509Extensions.SubjectKeyIdentifier);
        return value == null ? null
            : Org.BouncyCastle.Asn1.X509.SubjectKeyIdentifier.GetInstance(X509ExtensionUtilities.FromExtensionValue(value)).GetKeyIdentifier();
    }
}
