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

using System.Globalization;

using nMRTD.SmartCards;

namespace nMRTD;

/// <summary>Port of <c>org.jmrtd.PACEKeySpec</c>: a key for PACE, can be CAN, MRZ, PIN, or PUK.</summary>
public class PaceKeySpec : IAccessKeySpec
{
    private readonly byte[] _key;

    /// <summary>
    /// The type of key, valid values are <see cref="PassportService.MrzPaceKeyReference"/>,
    /// <see cref="PassportService.CanPaceKeyReference"/>, <see cref="PassportService.PinPaceKeyReference"/>,
    /// <see cref="PassportService.PukPaceKeyReference"/>.
    /// </summary>
    public byte KeyReference { get; }

    /// <summary>Constructs a PACE key from a string value.</summary>
    /// <param name="key">the string value containing CAN, PIN or PUK</param>
    /// <param name="keyReference">indicates the type of key</param>
    public PaceKeySpec(string key, byte keyReference)
        : this(Util.GetBytes(key), keyReference)
    {
    }

    /// <summary>Constructs a key.</summary>
    /// <param name="key">CAN, MRZ, PIN, PUK password bytes</param>
    /// <param name="keyReference">indicates the type of key</param>
    public PaceKeySpec(byte[] key, byte keyReference)
    {
        ArgumentNullException.ThrowIfNull(key);
        KeyReference = keyReference;
        _key = key;
    }

    /// <summary>Creates a PACE key from relevant details from a Machine Readable Zone.</summary>
    /// <param name="mrz">the details from the Machine Readable Zone</param>
    /// <returns>the PACE key</returns>
    public static PaceKeySpec CreateMrzKey(IBacKeySpec mrz) =>
        new(Protocol.PaceProtocol.ComputeKeySeedForPace(mrz), PassportService.MrzPaceKeyReference);

    /// <summary>Creates a PACE key from a Card Access Number.</summary>
    /// <param name="can">the Card Access Number</param>
    /// <returns>the PACE key</returns>
    public static PaceKeySpec CreateCanKey(string can) => new(can, PassportService.CanPaceKeyReference);

    /// <summary>Creates a PACE key from a PIN.</summary>
    /// <param name="pin">the PIN</param>
    /// <returns>the PACE key</returns>
    public static PaceKeySpec CreatePinKey(string pin) => new(pin, PassportService.PinPaceKeyReference);

    /// <summary>Creates a PACE key from a PUK.</summary>
    /// <param name="puk">the PUK</param>
    /// <returns>the PACE key</returns>
    public static PaceKeySpec CreatePukKey(string puk) => new(puk, PassportService.PukPaceKeyReference);

    /// <summary>Returns the algorithm: constant "PACE".</summary>
    /// <returns>the algorithm</returns>
    public string GetAlgorithm() => "PACE";

    /// <summary>Returns the key bytes.</summary>
    /// <returns>the key bytes</returns>
    public byte[] GetKey() => _key;

    public override int GetHashCode()
    {
        const int prime = 31;
        int result = 1;
        result = (prime * result) + JavaArrayHashCode(_key);
        result = (prime * result) + KeyReference;
        return result;
    }

    public override bool Equals(object? obj)
    {
        if (ReferenceEquals(this, obj))
        {
            return true;
        }

        if (obj is null || GetType() != obj.GetType())
        {
            return false;
        }

        PaceKeySpec other = (PaceKeySpec)obj;
        return _key.AsSpan().SequenceEqual(other._key) && KeyReference == other.KeyReference;
    }

    public override string ToString() =>
        $"PACEKeySpec [key: {Hex.BytesToHexString(_key)}, keyReference: {KeyReferenceToString(KeyReference)}]";

    /// <summary>Returns a textual representation of the given key reference parameter.</summary>
    /// <param name="keyReference">a key reference parameter</param>
    /// <returns>a textual representation of the key reference</returns>
    private static string KeyReferenceToString(byte keyReference) => keyReference switch
    {
        PassportService.MrzPaceKeyReference => "MRZ",
        PassportService.CanPaceKeyReference => "CAN",
        PassportService.PinPaceKeyReference => "PIN",
        PassportService.PukPaceKeyReference => "PUK",
        PassportService.NoPaceKeyReference => "NO",
        _ => keyReference.ToString(CultureInfo.InvariantCulture),
    };

    /// <summary>
    /// Replicates <c>java.util.Arrays.hashCode(byte[])</c>'s exact algorithm (Java's <c>byte</c> is
    /// signed, so each element is sign-extended before folding into the running hash).
    /// </summary>
    private static int JavaArrayHashCode(byte[] array)
    {
        int result = 1;
        foreach (byte b in array)
        {
            result = (31 * result) + (sbyte)b;
        }

        return result;
    }
}
