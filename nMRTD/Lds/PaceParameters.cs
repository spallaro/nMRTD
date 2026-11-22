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

using BigInteger = Org.BouncyCastle.Math.BigInteger;

namespace nMRTD.Lds;

/// <summary>
/// Finds the static domain parameters to pass to <see cref="PassportService.DoPace"/> for a
/// <see cref="PACEInfo"/> read from EF.CardAccess. Not part of JMRTD, where the caller does this.
/// </summary>
/// <remarks>
/// As ICAO Doc 9303-11 (PACEInfo, PACEDomainParameterInfo) and BSI TR-03110-3 describe it:
/// <list type="bullet">
/// <item>a parameter id from 0 to 31 names standardized domain parameters (<see cref="PACEInfo.ToParameterSpec(BigInteger)"/>);</item>
/// <item>any other parameter id (32 and up) names the <see cref="PACEDomainParameterInfo"/> with the same
/// parameter id, which carries explicit domain parameters;</item>
/// <item>without a parameter id, the document has one set of explicit domain parameters, the only
/// <see cref="PACEDomainParameterInfo"/> for the protocol.</item>
/// </list>
/// A <see cref="PACEDomainParameterInfo"/> belongs to a PACEInfo when its protocol identifier (for example
/// <c>id-PACE-ECDH-GM</c>) is the prefix of the PACEInfo's (for example <c>id-PACE-ECDH-GM-AES-CBC-CMAC-128</c>).
/// </remarks>
public static class PaceParameters
{
    /// <summary>The largest parameter id of the standardized domain parameters (BSI TR-03110-3, table 4).</summary>
    public const int MaxStandardizedParameterId = 31;

    /// <summary>Returns the static domain parameters for <paramref name="paceInfo"/>:
    /// <see cref="Org.BouncyCastle.Crypto.Parameters.DHParameters"/> or
    /// <see cref="Org.BouncyCastle.Crypto.Parameters.ECDomainParameters"/>.</summary>
    /// <param name="paceInfo">the PACEInfo to use</param>
    /// <param name="securityInfos">all the security infos of EF.CardAccess, which hold the
    /// <see cref="PACEDomainParameterInfo"/>s for explicit domain parameters</param>
    /// <exception cref="ArgumentException">if the parameters cannot be found: an unknown standardized
    /// parameter id, or no single matching <see cref="PACEDomainParameterInfo"/></exception>
    public static object Resolve(PACEInfo paceInfo, IEnumerable<SecurityInfo> securityInfos)
    {
        ArgumentNullException.ThrowIfNull(paceInfo);
        ArgumentNullException.ThrowIfNull(securityInfos);

        BigInteger? parameterId = paceInfo.GetParameterId();
        if (parameterId != null && parameterId.SignValue >= 0 && parameterId.CompareTo(BigInteger.ValueOf(MaxStandardizedParameterId)) <= 0)
        {
            try
            {
                return PACEInfo.ToParameterSpec(parameterId);
            }
            catch (FormatException e)
            {
                throw new ArgumentException($"Unknown standardized PACE domain parameters {parameterId}", nameof(paceInfo), e);
            }
        }

        string protocol = paceInfo.GetObjectIdentifier();
        List<PACEDomainParameterInfo> candidates = securityInfos
            .OfType<PACEDomainParameterInfo>()
            .Where(info => protocol.StartsWith(info.GetObjectIdentifier() + ".", StringComparison.Ordinal))
            .Where(info => parameterId == null || parameterId.Equals(info.GetParameterId()))
            .ToList();
        if (candidates.Count != 1)
        {
            string wanted = parameterId == null ? "without a parameter id" : $"with parameter id {parameterId}";
            throw new ArgumentException(
                $"Expected one PACEDomainParameterInfo {wanted} for {protocol}, found {candidates.Count}", nameof(securityInfos));
        }

        try
        {
            return candidates[0].GetParameters();
        }
        catch (Exception e) when (e is InvalidOperationException or ArgumentException)
        {
            throw new ArgumentException($"Unusable PACEDomainParameterInfo for {protocol}: {e.Message}", nameof(securityInfos), e);
        }
    }
}
