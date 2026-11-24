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

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace nMRTD.Cli;

/// <summary>A public key's algorithm and size, for the result.</summary>
public static class KeyDescription
{
    /// <summary>
    /// "RSA [2048 bit]", "EC [brainpoolP256r1]" or "DH [2048 bit]" (with the subgroup order size when the key
    /// has it, "DH [2048 bit, q 224 bit]"). The library's <see cref="Util.GetDetailedPublicKeyAlgorithm"/>
    /// describes a DH key by its parameter lengths, as JMRTD does, which reads poorly in a report.
    /// </summary>
    public static string Of(AsymmetricKeyParameter? publicKey) => publicKey switch
    {
        DHPublicKeyParameters { Parameters: var parameters } => parameters.Q == null
            ? $"DH [{parameters.P.BitLength} bit]"
            : $"DH [{parameters.P.BitLength} bit, q {parameters.Q.BitLength} bit]",
        _ => Util.GetDetailedPublicKeyAlgorithm(publicKey),
    };
}
