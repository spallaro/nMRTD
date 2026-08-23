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

namespace nMRTD.Cert;

/// <summary>
/// Port of <c>org.jmrtd.cert.CVCertificateFactorySpi</c>: parses card verifiable certificates from a
/// stream.
///
/// ADAPTATION: the Java class is a <c>java.security.cert.CertificateFactorySpi</c> implementation, meant
/// to be registered with and looked up through the JCA <c>Provider</c>/<c>CertificateFactory.getInstance</c>
/// machinery (dynamic class lookup by algorithm name). Per porting-conventions.md, dynamic
/// reflection-based dispatch is avoided for AOT compatibility, and this codebase has no JCA
/// provider/SPI concept to begin with (see <c>CardVerifiableCertificate</c>'s own doc comment) -- so this
/// is a plain static class exposing the one meaningful operation (<c>engineGenerateCertificate</c>)
/// directly, which is already exactly what <see cref="CardVerifiableCertificate.Parse(Stream)"/> does.
/// The CRL-related methods (<c>engineGenerateCRL</c>, <c>engineGenerateCRLs</c>,
/// <c>engineGenerateCertificates</c>) were unimplemented stubs in JMRTD itself (each just returns
/// <c>null</c> with a <c>// TODO</c>) and are not ported.
/// </summary>
public static class CVCertificateFactorySpi
{
    /// <summary>Generates a card verifiable certificate from the given input stream.</summary>
    /// <param name="inputStream">the input source, positioned at the start of a <c>0x7F21</c> CV certificate TLV</param>
    /// <returns>the parsed certificate</returns>
    /// <exception cref="IOException">if the input could not be parsed</exception>
    public static CardVerifiableCertificate EngineGenerateCertificate(Stream inputStream) =>
        CardVerifiableCertificate.Parse(inputStream);
}
