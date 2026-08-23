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

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC;

namespace nMRTD.Protocol;

/// <summary>
/// Port of <c>org.jmrtd.protocol.PACEGMWithECDHAgreement</c>: an ECDH key agreement implementation used
/// by the PACE protocol for the Generic Mapping case, which is able to return the shared secret in the
/// form of a full EC point (both X and Y coordinates) instead of just the X coordinate that a standard
/// JCA <c>KeyAgreement</c>'s <c>generateSecret()</c> would return for ECDH.
///
/// ADAPTATION / role clarification: despite living alongside the <c>PACEXxxMappingResult</c> data holders
/// in this file group, this is <em>not</em> itself a mapping-result data holder, and it does not
/// implement the Generic Mapping point-mapping arithmetic (<c>G' = G*s + H</c>, TR-SAC 1.01 / BSI
/// TR-03110 4.2.1.1) -- that computation belongs to the not-yet-ported <c>PACEProtocol.java</c>. This
/// class is purely a two-step (<c>Init</c>/<c>DoPhase</c>, mirroring JCA's <c>javax.crypto.KeyAgreement</c>
/// shape) EC Diffie-Hellman point-multiplication helper: given a private key and the other party's public
/// key, it computes <c>privateKey.D * publicKey.Q</c> and returns the resulting point undecomposed. A
/// future port of <c>PACEProtocol.java</c> uses it (as the Java original does) to compute the actual
/// ephemeral ECDH shared secret from the already-mapped ephemeral key pair/public key -- i.e., it runs
/// after the generic mapping step, not as part of it. The Java class name is preserved for 1:1
/// traceability against that future call site, even though "Agreement" is a slightly misleading name for
/// what is really just a point-multiplication utility with the same two-call shape as
/// <c>javax.crypto.KeyAgreement</c>.
///
/// Java's <c>init</c>/<c>doPhase</c> accepted the generic JCA <c>PrivateKey</c>/<c>PublicKey</c> marker
/// types with a runtime <c>instanceof ECPrivateKey</c>/<c>instanceof ECPublicKey</c> check (throwing a
/// checked <c>InvalidKeyException</c> on mismatch), because JCA key agreement is provider-pluggable and
/// admits arbitrary key implementations. This port's key types are always already BC's own
/// <see cref="ECPrivateKeyParameters"/>/<see cref="ECPublicKeyParameters"/> (per this port's key-type
/// convention -- see <c>Util.cs</c>'s doc comment), so <see cref="Init"/>/<see cref="DoPhase"/> take those
/// types directly: the C# type system statically rules out the mismatch Java checked for at runtime, so
/// there is no equivalent to <c>InvalidKeyException</c> here. The <c>IllegalStateException</c>s for "not
/// yet initialized" and "resulting point is the point at infinity" are preserved as
/// <see cref="InvalidOperationException"/>, matching this port's general exception-translation convention.
/// </summary>
public sealed class PACEGMWithECDHAgreement
{
    private ECPrivateKeyParameters? _privateKey;

    /// <summary>Initializes the key agreement implementation.</summary>
    /// <param name="privateKey">this party's private key</param>
    public void Init(ECPrivateKeyParameters privateKey)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        _privateKey = privateKey;
    }

    /// <summary>Performs a key agreement protocol.</summary>
    /// <param name="publicKey">the other party's public key</param>
    /// <returns>the resulting shared secret in the form of an EC point</returns>
    /// <exception cref="InvalidOperationException">if this key agreement has not been initialized, or if
    /// the resulting point is the point at infinity</exception>
    public ECPoint DoPhase(ECPublicKeyParameters publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);

        if (_privateKey == null)
        {
            throw new InvalidOperationException("Not initialized!");
        }

        ECPoint p = publicKey.Q.Multiply(_privateKey.D).Normalize();
        if (p.IsInfinity)
        {
            throw new InvalidOperationException("Infinity");
        }

        return p;
    }
}
