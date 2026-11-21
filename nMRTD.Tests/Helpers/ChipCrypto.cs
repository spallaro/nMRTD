using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

namespace nMRTD.Tests.Helpers;

/// <summary>
/// The cryptographic primitives of the simulated chip, written directly against BouncyCastle from ICAO Doc
/// 9303-11 and BSI TR-03110, without any nMRTD code, so the chip computes its values independently of the
/// terminal side under test.
/// </summary>
internal static class ChipCrypto
{
    private static readonly SecureRandom Random = new();

    public static byte[] RandomBytes(int length)
    {
        var bytes = new byte[length];
        Random.NextBytes(bytes);
        return bytes;
    }

    /// <summary>A random integer in [1, n - 1].</summary>
    public static BigInteger RandomScalar(BigInteger n)
    {
        BigInteger k;
        do
        {
            k = new BigInteger(n.BitLength, Random);
        }
        while (k.SignValue <= 0 || k.CompareTo(n) >= 0);
        return k;
    }

    // ---- Padding (ISO/IEC 9797-1 method 2) ----

    public static byte[] Pad(byte[] data, int blockSize)
    {
        int length = (data.Length / blockSize + 1) * blockSize;
        var padded = new byte[length];
        Array.Copy(data, padded, data.Length);
        padded[data.Length] = 0x80;
        return padded;
    }

    public static byte[] Unpad(byte[] padded)
    {
        int i = padded.Length - 1;
        while (i >= 0 && padded[i] == 0x00)
        {
            i--;
        }
        if (i < 0 || padded[i] != 0x80)
        {
            throw new InvalidOperationException("Bad padding");
        }
        return padded[..i];
    }

    // ---- Ciphers and MACs ----

    public static int BlockSize(bool aes) => aes ? 16 : 8;

    private static IBlockCipher Engine(bool aes) => aes ? new AesEngine() : new DesEdeEngine();

    /// <summary>CBC encryption or decryption without padding.</summary>
    public static byte[] Cbc(bool encrypt, bool aes, byte[] key, byte[] iv, byte[] data)
    {
        var cipher = new CbcBlockCipher(Engine(aes));
        cipher.Init(encrypt, new ParametersWithIV(new KeyParameter(key), iv));
        int blockSize = cipher.GetBlockSize();
        if (data.Length % blockSize != 0)
        {
            throw new InvalidOperationException("Data is not block aligned");
        }
        var output = new byte[data.Length];
        for (int offset = 0; offset < data.Length; offset += blockSize)
        {
            cipher.ProcessBlock(data, offset, output, offset);
        }
        return output;
    }

    /// <summary>A single-block ECB encryption.</summary>
    public static byte[] EncryptBlock(bool aes, byte[] key, byte[] block)
    {
        IBlockCipher engine = Engine(aes);
        engine.Init(true, new KeyParameter(key));
        var output = new byte[engine.GetBlockSize()];
        engine.ProcessBlock(block, 0, output, 0);
        return output;
    }

    /// <summary>
    /// The 8-byte MAC: ISO 9797-1 algorithm 3 (retail MAC) with DES for 3DES, AES-CMAC truncated to 8 bytes
    /// for AES. The 3DES variant expects data that is already padded; CMAC pads itself.
    /// </summary>
    public static byte[] Mac(bool aes, byte[] key, byte[] data)
    {
        IMac mac = aes ? new CMac(new AesEngine(), 128) : new ISO9797Alg3Mac(new DesEngine());
        mac.Init(new KeyParameter(key));
        mac.BlockUpdate(data, 0, data.Length);
        var output = new byte[mac.GetMacSize()];
        mac.DoFinal(output, 0);
        return output[..8];
    }

    // ---- Hashes and key derivation ----

    public static byte[] Digest(IDigest digest, byte[] data)
    {
        digest.BlockUpdate(data, 0, data.Length);
        var output = new byte[digest.GetDigestSize()];
        digest.DoFinal(output, 0);
        return output;
    }

    public static byte[] Sha1(byte[] data) => Digest(new Sha1Digest(), data);

    public const int KdfEnc = 1;
    public const int KdfMac = 2;
    public const int KdfPace = 3;

    /// <summary>
    /// KDF(K, c) of Doc 9303-11 9.7.1: SHA-1 for 3DES and AES-128, SHA-256 for AES-192/256, truncated to the
    /// key length (16 bytes for two-key 3DES).
    /// </summary>
    public static byte[] Kdf(byte[] secret, int counter, bool aes, int keyBits)
    {
        byte[] input = [.. secret, 0, 0, 0, (byte)counter];
        if (!aes)
        {
            return Sha1(input)[..16];
        }
        return keyBits == 128 ? Sha1(input)[..16] : Digest(new Sha256Digest(), input)[..(keyBits / 8)];
    }

    // ---- MRZ ----

    /// <summary>The 7-3-1 check digit of Doc 9303-3 4.9.</summary>
    public static char CheckDigit(string field)
    {
        int[] weights = [7, 3, 1];
        int sum = 0;
        for (int i = 0; i < field.Length; i++)
        {
            char c = field[i];
            int value = c switch
            {
                >= '0' and <= '9' => c - '0',
                >= 'A' and <= 'Z' => c - 'A' + 10,
                '<' => 0,
                _ => throw new ArgumentException($"Bad MRZ character {c}"),
            };
            sum += value * weights[i % 3];
        }
        return (char)('0' + sum % 10);
    }

    /// <summary>The MRZ information: document number, date of birth and date of expiry, each with its check digit.</summary>
    public static byte[] MrzInformation(string documentNumber, string dateOfBirth, string dateOfExpiry)
    {
        string number = documentNumber.PadRight(9, '<');
        string mrz = number + CheckDigit(number) + dateOfBirth + CheckDigit(dateOfBirth) + dateOfExpiry + CheckDigit(dateOfExpiry);
        return System.Text.Encoding.ASCII.GetBytes(mrz);
    }

    // ---- Domain parameters ----

    /// <summary>The standardized PACE domain parameters of Doc 9303-11 9.5.1, from BouncyCastle's named curves.</summary>
    public static object StandardizedDomainParameters(int parameterId)
    {
        if (parameterId == 0)
        {
            return TestData.DhWithQ; // RFC 5114 1024-bit MODP group with 160-bit prime order subgroup.
        }
        string name = parameterId switch
        {
            8 => "secp192r1",
            9 => "brainpoolP192r1",
            10 => "secp224r1",
            11 => "brainpoolP224r1",
            12 => "secp256r1",
            13 => "brainpoolP256r1",
            14 => "brainpoolP320r1",
            15 => "secp384r1",
            16 => "brainpoolP384r1",
            17 => "brainpoolP512r1",
            18 => "secp521r1",
            _ => throw new ArgumentException($"No standardized domain parameters with ID {parameterId}"),
        };
        X9ECParameters x9 = ECNamedCurveTable.GetByName(name);
        return new ECDomainParameters(x9.Curve, x9.G, x9.N, x9.H);
    }

    public static int FieldBytes(ECCurve curve) => (curve.FieldSize + 7) / 8;

    /// <summary>An unsigned big-endian encoding, left-padded to <paramref name="length"/> bytes.</summary>
    public static byte[] Fixed(BigInteger value, int length)
    {
        byte[] bytes = value.ToByteArrayUnsigned();
        if (bytes.Length > length)
        {
            throw new ArgumentException("Value too long");
        }
        var output = new byte[length];
        Array.Copy(bytes, 0, output, length - bytes.Length, bytes.Length);
        return output;
    }

    public static byte[] EncodePoint(ECPoint point) => point.Normalize().GetEncoded(false);

    public static ECPoint DecodePoint(ECCurve curve, byte[] encoded)
    {
        ECPoint point = curve.DecodePoint(encoded);
        if (!point.IsValid())
        {
            throw new InvalidOperationException("Invalid point");
        }
        return point;
    }

    // ---- Integrated Mapping (Doc 9303-11 4.4.3.3.2, TR-03110-3 A.3.4.2) ----

    private static readonly byte[] C0For128 = Convert.FromHexString("a668892a7c41e3ca739f40b057d85904");
    private static readonly byte[] C1For128 = Convert.FromHexString("a4e136ac725f738b01c1f60217c188ad");
    private static readonly byte[] C0For256 = Convert.FromHexString("d463d65234124ef7897054986dca0a174e28df758cbaa03f240616414d5a1676");
    private static readonly byte[] C1For256 = Convert.FromHexString("54bd7255f0aaf831bec3423fcf39d69b6cbf066677d0faae5aadd99df8e53517");

    /// <summary>
    /// The pseudo-random function R_p(s, t): the block cipher in CBC mode with a zero IV is keyed with t to
    /// encrypt s, and the result is expanded with the constants c0 and c1 until enough bits for p + 64 exist.
    /// </summary>
    public static BigInteger PseudoRandom(byte[] s, byte[] t, BigInteger p, bool aes)
    {
        int l = s.Length * 8;
        (byte[] c0, byte[] c1) = l == 128 ? (C0For128, C1For128) : (C0For256, C1For256);
        byte[] zeroIv = new byte[BlockSize(aes)];
        byte[] key = Cbc(true, aes, t, zeroIv, s)[..t.Length];
        var x = new List<byte>();
        for (int n = 0; n * l < p.BitLength + 64; n++)
        {
            byte[] next = Cbc(true, aes, key, zeroIv, c0)[..t.Length];
            x.AddRange(Cbc(true, aes, key, zeroIv, c1));
            key = next;
        }
        return new BigInteger(1, x.ToArray()).Mod(p);
    }

    /// <summary>Icart's point encoding f(t) for curves with p = 3 mod 4, followed by the cofactor multiplication.</summary>
    public static ECPoint PointEncode(BigInteger t, ECDomainParameters domain)
    {
        ECCurve curve = domain.Curve;
        BigInteger p = curve.Field.Characteristic;
        BigInteger a = curve.A.ToBigInteger();
        BigInteger b = curve.B.ToBigInteger();
        BigInteger Mod(BigInteger v) => v.Mod(p);

        BigInteger alpha = Mod(t.Multiply(t).Negate());
        BigInteger alphaPlusAlpha2 = Mod(alpha.Add(alpha.Multiply(alpha)));
        BigInteger x2 = Mod(b.Negate().Multiply(BigInteger.One.Add(alphaPlusAlpha2)).Multiply(a.Multiply(alphaPlusAlpha2).ModInverse(p)));
        BigInteger x3 = Mod(alpha.Multiply(x2));
        BigInteger h2 = Mod(x2.ModPow(BigInteger.Three, p).Add(a.Multiply(x2)).Add(b));
        BigInteger u = Mod(t.ModPow(BigInteger.Three, p).Multiply(h2));
        BigInteger exponent = p.Subtract(BigInteger.One).Subtract(p.Add(BigInteger.One).ShiftRight(2));
        BigInteger aa = h2.ModPow(exponent, p);
        ECPoint point = Mod(aa.Multiply(aa).Multiply(h2)).Equals(BigInteger.One)
            ? curve.CreatePoint(x2, Mod(aa.Multiply(h2)))
            : curve.CreatePoint(x3, Mod(aa.Multiply(u)));
        return point.Multiply(domain.H).Normalize();
    }

    // ---- Public key data objects (Doc 9303-11 9.4.4) ----

    /// <summary>The public key data object 7F49 with the protocol OID and the public value only.</summary>
    public static byte[] PublicKeyDataObject(string oid, AsymmetricKeyParameter publicKey)
    {
        byte[] oidBytes = new DerObjectIdentifier(oid).GetEncoded();
        byte[] value = publicKey switch
        {
            ECPublicKeyParameters ec => Tlv.Encode(0x86, EncodePoint(ec.Q)),
            DHPublicKeyParameters dh => Tlv.Encode(0x84, dh.Y.ToByteArrayUnsigned()),
            _ => throw new ArgumentException("Unsupported key"),
        };
        return Tlv.Encode(0x7F49, [.. oidBytes, .. value]);
    }

    /// <summary>Comp(PK) of Doc 9303-11 9.6: the x-coordinate for ECDH, SHA-1 of the public value for DH.</summary>
    public static byte[] Compress(AsymmetricKeyParameter publicKey) => publicKey switch
    {
        ECPublicKeyParameters ec => Fixed(ec.Q.Normalize().AffineXCoord.ToBigInteger(), FieldBytes(ec.Parameters.Curve)),
        DHPublicKeyParameters dh => Sha1(dh.Y.ToByteArrayUnsigned()),
        _ => throw new ArgumentException("Unsupported key"),
    };
}

/// <summary>A minimal BER-TLV codec for the simulated chip.</summary>
internal static class Tlv
{
    public static byte[] Encode(int tag, byte[] value)
    {
        var output = new List<byte>();
        if (tag > 0xFF)
        {
            output.Add((byte)(tag >> 8));
        }
        output.Add((byte)tag);
        output.AddRange(EncodeLength(value.Length));
        output.AddRange(value);
        return output.ToArray();
    }

    public static byte[] EncodeLength(int length) => length switch
    {
        < 0x80 => [(byte)length],
        < 0x100 => [0x81, (byte)length],
        < 0x10000 => [0x82, (byte)(length >> 8), (byte)length],
        _ => [0x83, (byte)(length >> 16), (byte)(length >> 8), (byte)length],
    };

    /// <summary>One parsed data object: its tag, value, and the whole encoding.</summary>
    public sealed record Item(int Tag, byte[] Value, byte[] Encoded);

    public static List<Item> Parse(byte[] data)
    {
        var items = new List<Item>();
        int pos = 0;
        while (pos < data.Length)
        {
            int start = pos;
            int tag = data[pos++];
            if ((tag & 0x1F) == 0x1F)
            {
                do
                {
                    tag = (tag << 8) | data[pos];
                }
                while ((data[pos++] & 0x80) != 0);
            }
            int length = data[pos++];
            if (length > 0x80)
            {
                int count = length & 0x7F;
                length = 0;
                for (int i = 0; i < count; i++)
                {
                    length = (length << 8) | data[pos++];
                }
            }
            else if (length == 0x80)
            {
                throw new InvalidOperationException("Indefinite length");
            }
            if (pos + length > data.Length)
            {
                throw new InvalidOperationException("Truncated data object");
            }
            items.Add(new Item(tag, data[pos..(pos + length)], data[start..(pos + length)]));
            pos += length;
        }
        return items;
    }

    public static byte[]? Find(List<Item> items, int tag) => items.FirstOrDefault(i => i.Tag == tag)?.Value;
}
