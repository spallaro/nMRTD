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
using Org.BouncyCastle.Asn1.Eac;
using nMRTD.SmartCards;

namespace nMRTD.Cert;

/// <summary>
/// Port of <c>org.jmrtd.cert.CVCAuthorizationTemplate</c>: the Certificate Holder Authorization Template
/// (CHAT, tag <c>0x7F4C</c>) -- the role of the certificate holder (CVCA/DV/terminal) and, for terminal
/// certificates, the DG3/DG4 read-access rights it grants, per BSI TR-03110-3.
/// </summary>
public sealed class CVCAuthorizationTemplate : IEquatable<CVCAuthorizationTemplate>
{
    private const int ChatTag = 0x7F4C;
    private const int OidTag = 0x06;
    private const int AccessRightTag = 0x53;

    /// <summary>
    /// The authorization role, encoded in bits 7-6 of the CHAT discretionary-data byte. Values confirmed
    /// directly from JMRTD's own <c>CVCAuthorizationTemplate.Role</c> enum literals.
    /// </summary>
    public enum Role : byte
    {
        /// <summary>Certificate authority (CVCA).</summary>
        Cvca = 0xC0,

        /// <summary>Document verifier, domestic.</summary>
        DvDomestic = 0x80,

        /// <summary>Document verifier, foreign.</summary>
        DvForeign = 0x40,

        /// <summary>Inspection system (terminal).</summary>
        Is = 0x00,
    }

    /// <summary>
    /// The authorization permission (read-access rights), encoded in bits 1-0 of the CHAT
    /// discretionary-data byte. Values confirmed directly from JMRTD's own
    /// <c>CVCAuthorizationTemplate.Permission</c> enum literals.
    /// </summary>
    public enum Permission : byte
    {
        /// <summary>No read access.</summary>
        ReadAccessNone = 0x00,

        /// <summary>Read access to DG3.</summary>
        ReadAccessDg3 = 0x01,

        /// <summary>Read access to DG4.</summary>
        ReadAccessDg4 = 0x02,

        /// <summary>Read access to DG3 and DG4.</summary>
        ReadAccessDg3AndDg4 = 0x03,
    }

    /// <summary>
    /// The terminal-type OID for the CHAT's <c>0x06</c> element. JMRTD only ever produces/consumes
    /// Inspection System (id-IS) CHATs -- EAC-TA for ePassport DG3/DG4 access never uses id-AT/id-ST
    /// (those cover the unrelated eID authentication-terminal/signature-terminal applications). Derived
    /// from BouncyCastle's <see cref="EacObjectIdentifiers.bsi_de"/> root arc rather than a hand-typed OID
    /// string, per the porting spec's guidance to source OIDs from BouncyCastle where possible.
    /// </summary>
    public static readonly DerObjectIdentifier TerminalTypeOid = EacObjectIdentifiers.bsi_de.Branch("3.1.2.1");

    public Role AuthorizationRole { get; }

    public Permission AccessRight { get; }

    public CVCAuthorizationTemplate(Role role, Permission accessRight)
    {
        AuthorizationRole = role;
        AccessRight = accessRight;
    }

    public override string ToString() => AuthorizationRole.ToString() + AccessRight;

    public bool Equals(CVCAuthorizationTemplate? other)
    {
        if (other is null)
        {
            return false;
        }
        if (ReferenceEquals(other, this))
        {
            return true;
        }
        return AuthorizationRole == other.AuthorizationRole && AccessRight == other.AccessRight;
    }

    public override bool Equals(object? obj) => Equals(obj as CVCAuthorizationTemplate);

    public override int GetHashCode() => 2 * (byte)AuthorizationRole + 3 * (byte)AccessRight + 61;

    /// <summary>Combines role and access-right bits into the single CHAT discretionary-data byte.</summary>
    internal byte EncodeAccessRightByte() => (byte)((byte)AuthorizationRole | (byte)AccessRight);

    /// <summary>
    /// Decodes the discretionary-data byte defensively: role is masked as <c>byte &amp; 0xC0</c> and
    /// access rights as <c>byte &amp; 0x03</c>, rather than requiring an exact match against a known
    /// combination -- reserved bits 5-2 (never set by JMRTD itself, but not guaranteed zero in
    /// third-party-issued certificates) are simply ignored instead of causing a hard parse failure.
    /// </summary>
    internal static CVCAuthorizationTemplate DecodeAccessRightByte(byte value)
    {
        var role = (Role)(value & 0xC0);
        var permission = (Permission)(value & 0x03);
        return new CVCAuthorizationTemplate(role, permission);
    }

    /// <summary>Full <c>0x7F4C</c> TLV (tag + length + value) for this template.</summary>
    internal byte[] Encode()
    {
        byte[] oidTlv = TerminalTypeOid.GetDerEncoded();
        byte[] accessRightTlv = TlvUtil.TlvEncode(AccessRightTag, new[] { EncodeAccessRightByte() });
        byte[] value = new byte[oidTlv.Length + accessRightTlv.Length];
        Buffer.BlockCopy(oidTlv, 0, value, 0, oidTlv.Length);
        Buffer.BlockCopy(accessRightTlv, 0, value, oidTlv.Length, accessRightTlv.Length);
        return TlvUtil.TlvEncode(ChatTag, value);
    }

    /// <summary>Decodes the value octets of a <c>0x7F4C</c> element (terminal-type OID + <c>0x53</c> discretionary-data byte).</summary>
    internal static CVCAuthorizationTemplate Decode(byte[] chatValue)
    {
        ArgumentNullException.ThrowIfNull(chatValue);
        using var stream = new MemoryStream(chatValue, writable: false);
        using var tlvIn = new TlvInputStream(stream, leaveOpen: true);

        int oidTag = tlvIn.ReadTag();
        if (oidTag != OidTag)
        {
            throw new IOException($"Expected OID tag 0x{OidTag:X} in CHAT, found 0x{oidTag:X}.");
        }
        tlvIn.ReadLength();
        tlvIn.ReadValue(); // Terminal-type OID (id-IS/id-AT/id-ST): not needed to decode role/rights, which live entirely in the 0x53 byte.

        int accessRightTag = tlvIn.ReadTag();
        if (accessRightTag != AccessRightTag)
        {
            throw new IOException($"Expected discretionary data tag 0x{AccessRightTag:X} in CHAT, found 0x{accessRightTag:X}.");
        }
        tlvIn.ReadLength();
        byte[] data = tlvIn.ReadValue();
        if (data.Length != 1)
        {
            throw new IOException("CHAT discretionary data must be exactly 1 byte.");
        }
        return DecodeAccessRightByte(data[0]);
    }
}
