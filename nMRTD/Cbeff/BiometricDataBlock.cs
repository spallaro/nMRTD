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

namespace nMRTD.Cbeff;

/// <summary>
/// Port of <c>org.jmrtd.cbeff.BiometricDataBlock</c>: biometric data block (BDB). Java's
/// <c>Serializable</c> marker is dropped (no reflection-based serialization is needed in this port).
/// Kept as the bare Java name (no <c>I</c> prefix) rather than <c>IBiometricDataBlock</c>: this
/// codebase is inconsistent about the prefix across porting sessions, and <c>org.jmrtd.lds.CBEFFDataGroup</c>
/// (an earlier wave) already forward-references this type by its bare name, which settles it here.
/// </summary>
public interface BiometricDataBlock
{
    /// <summary>Returns the standard biometric header of this biometric data block.</summary>
    /// <returns>the standard biometric header</returns>
    StandardBiometricHeader GetStandardBiometricHeader();
}
