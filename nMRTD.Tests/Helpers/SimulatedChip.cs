using nMRTD.SmartCards;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using static nMRTD.Tests.Helpers.ChipCrypto;

namespace nMRTD.Tests.Helpers;

/// <summary>
/// A simulated eMRTD chip: the card side of ICAO Doc 9303-11 and BSI TR-03110 (applet selection, BAC,
/// PACE GM/IM/CAM, secure messaging, SELECT and READ BINARY, Chip Authentication, Terminal Authentication
/// and Active Authentication), so that <see cref="PassportService"/> can be driven end to end.
/// Every value the chip computes comes from <see cref="ChipCrypto"/> and BouncyCastle, never from nMRTD.
/// </summary>
internal sealed class SimulatedChip : CardService
{
    public static readonly byte[] Aid = [0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01];

    private const short Dg3 = 0x0103;
    private const short Dg4 = 0x0104;
    private const string TaEcdsaSha256 = "0.4.0.127.0.7.2.2.2.2.3";

    /// <summary>A PACE protocol the chip supports, as advertised in EF.CardAccess. With
    /// <paramref name="ExplicitParameters"/> (<see cref="ECDomainParameters"/> or <see cref="DHParameters"/>),
    /// <paramref name="ParameterId"/> is a proprietary id (32 and up) whose domain parameters EF.CardAccess
    /// carries in a PACEDomainParameterInfo.</summary>
    public sealed record PaceSupport(string Oid, int ParameterId, object? ExplicitParameters = null);

    /// <summary>A Chip Authentication key pair with its protocol and optional key ID.</summary>
    public sealed record CaKey(string Oid, AsymmetricCipherKeyPair KeyPair, int? KeyId = null);

    /// <summary>A READ BINARY the chip served: which file, where, and in which secure messaging session.</summary>
    public sealed record FileRead(short Fid, int Offset, int Length, int Session, byte Ins, bool BySfi);

    // ---- Personalization ----

    public string DocumentNumber { get; init; } = "";
    public string DateOfBirth { get; init; } = "";
    public string DateOfExpiry { get; init; } = "";
    public string? Can { get; init; }
    public bool BacEnabled { get; init; } = true;
    public List<PaceSupport> PaceProtocols { get; } = new();
    public List<CaKey> ChipAuthenticationKeys { get; } = new();
    public AsymmetricCipherKeyPair? ActiveAuthenticationKey { get; init; }

    /// <summary>With an RSA Active Authentication key: sign with SHA-256 and an explicit ISO/IEC 9796-2 trailer
    /// instead of SHA-1 with the implicit trailer.</summary>
    public bool ActiveAuthenticationRsaSha256 { get; set; }
    public string? CvcaReference { get; init; }
    public ECPublicKeyParameters? CvcaPublicKey { get; init; }

    /// <summary>Files of the master file, readable without access control (EF.CardAccess).</summary>
    public Dictionary<short, byte[]> MasterFiles { get; } = new();

    /// <summary>Files of the eMRTD application.</summary>
    public Dictionary<short, byte[]> ApplicationFiles { get; } = new();

    /// <summary>When false, extended length command APDUs are rejected with 6700 before any processing.</summary>
    public bool SupportsExtendedLength { get; init; } = true;

    /// <summary>With <see cref="SupportsExtendedLength"/> false: a protected extended length command is processed
    /// under secure messaging and answered with a protected 6700 (both send sequence counters move on), instead of
    /// a plain 6700 before any processing (Doc 9303-11, 9.8.3).</summary>
    public bool ProtectedWrongLength { get; init; }

    // ---- Fault injection ----

    /// <summary>Flips a bit in the MAC of the next protected response.</summary>
    public bool CorruptNextResponseMac { get; set; }

    /// <summary>Flips a bit in the MAC of the next protected command, as a man in the middle would.</summary>
    public bool CorruptNextCommandMac { get; set; }

    /// <summary>Makes the chip answer an authentication protocol wrongly, as an impostor chip would.</summary>
    public ChipFault Fault { get; set; }

    public enum ChipFault
    {
        None,

        /// <summary>The PACE authentication token T_PICC is wrong.</summary>
        PaceToken,

        /// <summary>The PACE step 4 response has no authentication token T_PICC (an empty 0x7C object).</summary>
        PaceNoToken,

        /// <summary>The PACE step 4 response has a truncated authentication token T_PICC.</summary>
        PaceTruncatedToken,

        /// <summary>The checksum M_IC of the BAC cryptogram is wrong.</summary>
        BacChecksum,

        /// <summary>The BAC cryptogram does not return RND.IFD.</summary>
        BacRandom,

        /// <summary>PACE generic mapping: the chip's mapping public key is not a valid key (an EC point
        /// off the curve, or the DH value 1).</summary>
        PaceInvalidMappingKey,

        /// <summary>PACE key agreement: the chip's ephemeral public key is not a valid key.</summary>
        PaceInvalidEphemeralKey,

        /// <summary>PACE key agreement: the chip returns the terminal's own ephemeral public key.</summary>
        PaceEchoedEphemeralKey,

        /// <summary>Active Authentication: the signature over the challenge is corrupted.</summary>
        ActiveAuthenticationSignature,
    }

    // ---- Observations ----

    /// <summary>Incremented each time a secure messaging session starts (BAC, PACE, CA).</summary>
    public int Session { get; private set; }

    public List<FileRead> Reads { get; } = new();
    public List<CommandApdu> Commands { get; } = new();
    public Exception? LastError { get; private set; }
    public bool TerminalAuthenticated => _taRights != 0;

    // ---- State ----

    private bool _isOpen;
    private bool _appletSelected;
    private short? _selectedEf;
    private SmSession? _sm;
    private bool _accessGranted;
    private byte[]? _challenge;
    private byte[]? _idPicc;
    private PaceState? _pace;
    private CaKey? _caSelected;
    private AsymmetricKeyParameter? _caTerminalKey;
    private ECPublicKeyParameters? _taVerificationKey;
    private int _taVerificationRights;
    private readonly Dictionary<string, (ECPublicKeyParameters Key, int Role, int Rights)> _certificates = new();
    private string? _taHolder;
    private int _taRights;

    public override void Open() => _isOpen = true;
    public override bool IsOpen => _isOpen;
    public override byte[] GetAtr() => [0x3B, 0x80, 0x80, 0x01, 0x01];
    public override bool IsConnectionLost(Exception e) => false;
    public override void Close() => _isOpen = false;

    public override ResponseApdu Transmit(CommandApdu apdu)
    {
        Commands.Add(apdu);
        if (!SupportsExtendedLength && (apdu.Ne > 256 || apdu.Nc > 255))
        {
            if (ProtectedWrongLength && (apdu.Cla & 0x0C) == 0x0C && _sm != null)
            {
                _sm.Unwrap(apdu, false);
                return new ResponseApdu(_sm.Wrap([], 0x6700, false, false));
            }
            return new ResponseApdu([0x67, 0x00]);
        }

        if ((apdu.Cla & 0x0C) == 0x0C)
        {
            SmSession? session = _sm;
            if (session == null)
            {
                return new ResponseApdu([0x69, 0x88]);
            }
            Command command;
            try
            {
                bool corrupt = CorruptNextCommandMac;
                CorruptNextCommandMac = false;
                command = session.Unwrap(apdu, corrupt);
            }
            catch (Exception e)
            {
                LastError = e;
                AbortSession();
                return new ResponseApdu([0x69, 0x88]);
            }
            (byte[] data, int sw) = Process(command);
            bool corruptResponse = CorruptNextResponseMac;
            CorruptNextResponseMac = false;
            return new ResponseApdu(session.Wrap(data, sw, (command.Ins & 1) == 1, corruptResponse));
        }

        if (_sm != null)
        {
            AbortSession(); // A plain command ends secure messaging.
        }
        (byte[] plainData, int plainSw) = Process(new Command(apdu.Cla, apdu.Ins, apdu.P1, apdu.P2, apdu.Data, apdu.Ne));
        return new ResponseApdu([.. plainData, (byte)(plainSw >> 8), (byte)plainSw]);
    }

    private void AbortSession()
    {
        _sm = null;
        _accessGranted = false;
        _taRights = 0;
    }

    private void StartSession(bool aes, byte[] encKey, byte[] macKey, long ssc)
    {
        _sm = new SmSession(aes, encKey, macKey, ssc);
        _accessGranted = true;
        Session++;
    }

    private (byte[] Data, int Sw) Process(Command c)
    {
        try
        {
            return c.Ins switch
            {
                0xA4 => Select(c),
                0xB0 => ReadBinary(c),
                0xB1 => ReadBinaryOdd(c),
                0x84 => GetChallenge(c),
                0x82 => _taHolder != null ? TerminalAuthenticate(c) : BacAuthenticate(c),
                0x22 => ManageSecurityEnvironment(c),
                0x86 => _pace != null ? PaceStep(c) : ChipAuthenticateAes(c),
                0x2A => VerifyCertificate(c),
                0x88 => InternalAuthenticate(c),
                _ => Status(0x6D00),
            };
        }
        catch (Exception e)
        {
            LastError = e;
            return Status(0x6A80);
        }
    }

    private static (byte[], int) Status(int sw) => ([], sw);

    private static (byte[], int) Ok(byte[] data) => (data, 0x9000);

    // ---- Files ----

    private Dictionary<short, byte[]> CurrentFiles => _appletSelected ? ApplicationFiles : MasterFiles;

    private (byte[], int) Select(Command c)
    {
        switch (c.P1)
        {
            case 0x04:
                if (!c.Data.AsSpan().SequenceEqual(Aid))
                {
                    return Status(0x6A82);
                }
                _appletSelected = true;
                _selectedEf = null;
                return Ok([]);
            case 0x00:
                _appletSelected = false;
                _selectedEf = null;
                return Ok([]);
            case 0x02:
                if (c.Data.Length != 2)
                {
                    return Status(0x6700);
                }
                short fid = (short)((c.Data[0] << 8) | c.Data[1]);
                if (!CurrentFiles.ContainsKey(fid))
                {
                    return Status(0x6A82);
                }
                _selectedEf = fid;
                return Ok([]);
            default:
                return Status(0x6A86);
        }
    }

    private bool MayRead(short fid)
    {
        if (!_appletSelected)
        {
            return true;
        }
        if (!_accessGranted)
        {
            return false;
        }
        return fid switch
        {
            Dg3 => (_taRights & 1) != 0,
            Dg4 => (_taRights & 2) != 0,
            _ => true,
        };
    }

    private (byte[], int) ReadBinary(Command c)
    {
        int offset;
        bool bySfi = (c.P1 & 0x80) != 0;
        if (bySfi)
        {
            if ((c.P1 & 0x60) != 0)
            {
                return Status(0x6A86);
            }
            int sfi = c.P1 & 0x1F;
            short? fid = CurrentFiles.Keys.Cast<short?>().FirstOrDefault(f => (f!.Value & 0xFF) == sfi);
            if (fid == null)
            {
                return Status(0x6A82);
            }
            _selectedEf = fid;
            offset = c.P2;
        }
        else
        {
            offset = (c.P1 << 8) | c.P2;
        }
        return Read(c, offset, c.Ne == 0 ? 256 : c.Ne, bySfi, wrapIn53: false);
    }

    private (byte[], int) ReadBinaryOdd(Command c)
    {
        if (c.P1 != 0 || c.P2 != 0)
        {
            return Status(0x6A86);
        }
        byte[]? offsetBytes = Tlv.Find(Tlv.Parse(c.Data), 0x54);
        if (offsetBytes == null)
        {
            return Status(0x6A80);
        }
        int offset = 0;
        foreach (byte b in offsetBytes)
        {
            offset = (offset << 8) | b;
        }
        int ne = c.Ne == 0 ? 256 : c.Ne;
        int max = ne - 2 < 0x80 ? ne - 2 : ne - 3 < 0x100 ? ne - 3 : ne - 4;
        return Read(c, offset, max, bySfi: false, wrapIn53: true);
    }

    private (byte[], int) Read(Command c, int offset, int max, bool bySfi, bool wrapIn53)
    {
        if (_selectedEf is not short fid)
        {
            return Status(0x6986);
        }
        if (!MayRead(fid))
        {
            return Status(0x6982);
        }
        byte[] file = CurrentFiles[fid];
        if (offset > file.Length)
        {
            return Status(0x6B00);
        }
        int length = Math.Min(max, file.Length - offset);
        byte[] chunk = file[offset..(offset + length)];
        Reads.Add(new FileRead(fid, offset, length, Session, (byte)c.Ins, bySfi));
        return Ok(wrapIn53 ? Tlv.Encode(0x53, chunk) : chunk);
    }

    private (byte[], int) GetChallenge(Command c)
    {
        _challenge = RandomBytes(8);
        return Ok(_challenge);
    }

    // ---- BAC (Doc 9303-11 4.3) ----

    private (byte[], int) BacAuthenticate(Command c)
    {
        if (!BacEnabled || _challenge == null)
        {
            return Status(0x6985);
        }
        byte[] rndIc = _challenge;
        _challenge = null;
        if (c.Data.Length != 40)
        {
            return Status(0x6700);
        }
        byte[] seed = Sha1(MrzInformation(DocumentNumber, DateOfBirth, DateOfExpiry))[..16];
        byte[] kEnc = Kdf(seed, KdfEnc, false, 128);
        byte[] kMac = Kdf(seed, KdfMac, false, 128);
        byte[] eIfd = c.Data[..32];
        if (!Mac(false, kMac, Pad(eIfd, 8)).AsSpan().SequenceEqual(c.Data.AsSpan(32, 8)))
        {
            return Status(0x6300);
        }
        byte[] s = Cbc(false, false, kEnc, new byte[8], eIfd);
        if (!s.AsSpan(8, 8).SequenceEqual(rndIc))
        {
            return Status(0x6300);
        }
        byte[] rndIfd = s[..8];
        byte[] kIfd = s[16..32];
        byte[] kIc = RandomBytes(16);
        byte[] returnedRndIfd = Fault == ChipFault.BacRandom ? rndIfd.Select(b => (byte)~b).ToArray() : rndIfd;
        byte[] eIc = Cbc(true, false, kEnc, new byte[8], [.. rndIc, .. returnedRndIfd, .. kIc]);
        byte[] mIc = Mac(false, kMac, Pad(eIc, 8));
        if (Fault == ChipFault.BacChecksum)
        {
            mIc[0] ^= 0x01;
        }

        byte[] sessionSeed = kIfd.Zip(kIc, (a, b) => (byte)(a ^ b)).ToArray();
        long ssc = 0;
        foreach (byte b in rndIc[4..].Concat(rndIfd[4..]))
        {
            ssc = (ssc << 8) | b;
        }
        StartSession(false, Kdf(sessionSeed, KdfEnc, false, 128), Kdf(sessionSeed, KdfMac, false, 128), ssc);
        string number = DocumentNumber.PadRight(9, '<');
        _idPicc = System.Text.Encoding.ASCII.GetBytes(number + CheckDigit(number));
        return Ok([.. eIc, .. mIc]);
    }

    // ---- Manage Security Environment ----

    private (byte[], int) ManageSecurityEnvironment(Command c)
    {
        List<Tlv.Item> items = Tlv.Parse(c.Data);
        switch ((c.P1 << 8) | c.P2)
        {
            case 0xC1A4:
                return PaceSetAt(items);
            case 0x41A4:
            {
                if (_sm == null)
                {
                    return Status(0x6982);
                }
                string oid = DecodeOid(Tlv.Find(items, 0x80)!);
                int? keyId = KeyId(items);
                _caSelected = ChipAuthenticationKeys.FirstOrDefault(k => k.Oid == oid && (keyId == null || k.KeyId == keyId));
                return _caSelected == null ? Status(0x6A88) : Ok([]);
            }
            case 0x41A6:
                return ChipAuthenticateDes(items);
            case 0x81B6:
            {
                string car = System.Text.Encoding.Latin1.GetString(Tlv.Find(items, 0x83)!);
                if (car == CvcaReference)
                {
                    _taVerificationKey = CvcaPublicKey;
                    _taVerificationRights = 3;
                }
                else if (_certificates.TryGetValue(car, out var known))
                {
                    _taVerificationKey = known.Key;
                    _taVerificationRights = known.Rights;
                }
                else
                {
                    _taVerificationKey = null;
                    return Status(0x6A88);
                }
                return Ok([]);
            }
            case 0x81A4:
            {
                string chr = System.Text.Encoding.Latin1.GetString(Tlv.Find(items, 0x83)!);
                if (!_certificates.TryGetValue(chr, out var holder) || holder.Role != 0 || _caTerminalKey == null)
                {
                    return Status(0x6A88);
                }
                _taHolder = chr;
                return Ok([]);
            }
            default:
                return Status(0x6A86);
        }
    }

    private static int? KeyId(List<Tlv.Item> items) =>
        Tlv.Find(items, 0x84) is byte[] id ? (int)new BigInteger(1, id).LongValue : null;

    private static string DecodeOid(byte[] contents) =>
        ((DerObjectIdentifier)Asn1Object.FromByteArray([0x06, (byte)contents.Length, .. contents])).Id;

    // ---- PACE (Doc 9303-11 4.4) ----

    private sealed class PaceState
    {
        public string Oid = "";
        public int Mapping; // 1 = DH-GM, 2 = ECDH-GM, 4 = ECDH-IM, 6 = ECDH-CAM
        public bool Aes;
        public int KeyBits;
        public object StaticParameters = null!;
        public byte[] PasswordKey = [];
        public int Step = 1;
        public byte[] Nonce = [];
        public BigInteger MappingPrivate = BigInteger.Zero;
        public object? EphemeralParameters;
        public BigInteger EphemeralPrivate = BigInteger.Zero;
        public AsymmetricKeyParameter? PiccPublic;
        public AsymmetricKeyParameter? PcdPublic;
        public byte[] EncKey = [];
        public byte[] MacKey = [];
    }

    private static (int Mapping, bool Aes, int KeyBits) ParsePaceOid(string oid)
    {
        const string prefix = "0.4.0.127.0.7.2.2.4.";
        if (!oid.StartsWith(prefix, StringComparison.Ordinal))
        {
            throw new ArgumentException($"Not a PACE OID: {oid}");
        }
        string[] parts = oid[prefix.Length..].Split('.');
        int cipher = int.Parse(parts[1], System.Globalization.CultureInfo.InvariantCulture);
        return (int.Parse(parts[0], System.Globalization.CultureInfo.InvariantCulture), cipher > 1, cipher switch { 1 => 112, 2 => 128, 3 => 192, _ => 256 });
    }

    private (byte[], int) PaceSetAt(List<Tlv.Item> items)
    {
        string oid = DecodeOid(Tlv.Find(items, 0x80)!);
        int? parameterId = KeyId(items);
        PaceSupport? support = PaceProtocols.FirstOrDefault(p => p.Oid == oid && (parameterId == null || p.ParameterId == parameterId));
        if (support == null)
        {
            return Status(0x6A80);
        }
        byte[] password = Tlv.Find(items, 0x83)![0] switch
        {
            0x01 => Sha1(MrzInformation(DocumentNumber, DateOfBirth, DateOfExpiry)),
            0x02 when Can != null => System.Text.Encoding.ASCII.GetBytes(Can),
            _ => throw new ArgumentException("Unsupported password"),
        };
        (int mapping, bool aes, int keyBits) = ParsePaceOid(oid);
        _pace = new PaceState
        {
            Oid = oid,
            Mapping = mapping,
            Aes = aes,
            KeyBits = keyBits,
            StaticParameters = support.ExplicitParameters ?? StandardizedDomainParameters(support.ParameterId),
            PasswordKey = Kdf(password, KdfPace, aes, keyBits),
        };
        return Ok([]);
    }

    private (byte[], int) PaceStep(Command c)
    {
        PaceState pace = _pace!;
        bool chained = (c.Cla & 0x10) != 0;
        if (chained != pace.Step < 4)
        {
            _pace = null;
            return Status(0x6883);
        }
        List<Tlv.Item> data = Tlv.Parse(Tlv.Find(Tlv.Parse(c.Data), 0x7C)!);
        switch (pace.Step++)
        {
            case 1:
                // Doc 9303-11, 4.4.3.3.2: the nonce s has l = 128 bits for 3DES and AES-128, 256 for AES-192 and AES-256.
                pace.Nonce = RandomBytes(pace.PasswordKey.Length <= 16 ? 16 : 32);
                return Ok(Tlv.Encode(0x7C, Tlv.Encode(0x80, Cbc(true, pace.Aes, pace.PasswordKey, new byte[BlockSize(pace.Aes)], pace.Nonce))));
            case 2:
                byte[] mapping = PaceMap(pace, Tlv.Find(data, 0x81)!);
                if (Fault == ChipFault.PaceInvalidMappingKey && pace.Mapping != 4)
                {
                    mapping = Tlv.Encode(0x82, InvalidPublicKey(pace.StaticParameters));
                }
                return Ok(Tlv.Encode(0x7C, mapping));
            case 3:
                byte[] pcdEphemeral = Tlv.Find(data, 0x83)!;
                byte[] piccEphemeral = PaceKeyAgreement(pace, pcdEphemeral);
                piccEphemeral = Fault switch
                {
                    ChipFault.PaceInvalidEphemeralKey => InvalidPublicKey(pace.EphemeralParameters!),
                    ChipFault.PaceEchoedEphemeralKey => pcdEphemeral,
                    _ => piccEphemeral,
                };
                return Ok(Tlv.Encode(0x7C, Tlv.Encode(0x84, piccEphemeral)));
            default:
                _pace = null;
                return PaceTokens(pace, Tlv.Find(data, 0x85)!);
        }
    }

    /// <summary>A public key encoding that no valid key has: an EC point with its y coordinate changed,
    /// so that it is off the curve, or the DH value 1.</summary>
    private static byte[] InvalidPublicKey(object parameters)
    {
        if (parameters is ECDomainParameters ec)
        {
            byte[] point = EncodePoint(ec.G);
            point[^1] ^= 0x01;
            return point;
        }
        return [0x01];
    }

    private static byte[] PaceMap(PaceState pace, byte[] mappingData)
    {
        BigInteger s = new(1, pace.Nonce);
        switch (pace.StaticParameters)
        {
            case ECDomainParameters ec when pace.Mapping == 4:
            {
                BigInteger p = ec.Curve.Field.Characteristic;
                ECPoint g = PointEncode(PseudoRandom(pace.Nonce, mappingData, p, pace.Aes), ec);
                pace.EphemeralParameters = new ECDomainParameters(ec.Curve, g, ec.N, ec.H);
                return Tlv.Encode(0x82, []);
            }
            case ECDomainParameters ec:
            {
                pace.MappingPrivate = RandomScalar(ec.N);
                ECPoint pcdMapping = DecodePoint(ec.Curve, mappingData);
                ECPoint h = pcdMapping.Multiply(pace.MappingPrivate);
                ECPoint g = ec.G.Multiply(s).Add(h).Normalize();
                pace.EphemeralParameters = new ECDomainParameters(ec.Curve, g, ec.N, ec.H);
                return Tlv.Encode(0x82, EncodePoint(ec.G.Multiply(pace.MappingPrivate)));
            }
            case DHParameters dh when pace.Mapping == 1:
            {
                pace.MappingPrivate = RandomScalar(dh.Q);
                BigInteger pcdMapping = new(1, mappingData);
                BigInteger h = pcdMapping.ModPow(pace.MappingPrivate, dh.P);
                BigInteger g = dh.G.ModPow(s, dh.P).Multiply(h).Mod(dh.P);
                pace.EphemeralParameters = new DHParameters(dh.P, g, dh.Q);
                return Tlv.Encode(0x82, dh.G.ModPow(pace.MappingPrivate, dh.P).ToByteArrayUnsigned());
            }
            default:
                throw new NotSupportedException("Unsupported mapping");
        }
    }

    private static byte[] PaceKeyAgreement(PaceState pace, byte[] pcdPublic)
    {
        byte[] shared;
        byte[] piccEncoded;
        switch (pace.EphemeralParameters)
        {
            case ECDomainParameters ec:
            {
                pace.EphemeralPrivate = RandomScalar(ec.N);
                ECPoint picc = ec.G.Multiply(pace.EphemeralPrivate).Normalize();
                ECPoint pcd = DecodePoint(ec.Curve, pcdPublic);
                if (pcd.Equals(picc))
                {
                    throw new InvalidOperationException("Equal ephemeral keys");
                }
                pace.PiccPublic = new ECPublicKeyParameters(picc, ec);
                pace.PcdPublic = new ECPublicKeyParameters(pcd, ec);
                shared = Fixed(pcd.Multiply(pace.EphemeralPrivate).Normalize().AffineXCoord.ToBigInteger(), FieldBytes(ec.Curve));
                piccEncoded = EncodePoint(picc);
                break;
            }
            case DHParameters dh:
            {
                pace.EphemeralPrivate = RandomScalar(dh.Q);
                BigInteger picc = dh.G.ModPow(pace.EphemeralPrivate, dh.P);
                BigInteger pcd = new(1, pcdPublic);
                if (pcd.CompareTo(BigInteger.One) <= 0 || pcd.CompareTo(dh.P.Subtract(BigInteger.One)) >= 0 || pcd.Equals(picc))
                {
                    throw new InvalidOperationException("Bad ephemeral key");
                }
                pace.PiccPublic = new DHPublicKeyParameters(picc, dh);
                pace.PcdPublic = new DHPublicKeyParameters(pcd, dh);
                shared = Fixed(pcd.ModPow(pace.EphemeralPrivate, dh.P), (dh.P.BitLength + 7) / 8);
                piccEncoded = picc.ToByteArrayUnsigned();
                break;
            }
            default:
                throw new NotSupportedException();
        }
        pace.EncKey = Kdf(shared, KdfEnc, pace.Aes, pace.KeyBits);
        pace.MacKey = Kdf(shared, KdfMac, pace.Aes, pace.KeyBits);
        return piccEncoded;
    }

    private static byte[] Token(bool aes, byte[] macKey, string oid, AsymmetricKeyParameter publicKey)
    {
        byte[] dataObject = PublicKeyDataObject(oid, publicKey);
        return Mac(aes, macKey, aes ? dataObject : Pad(dataObject, 8));
    }

    private (byte[], int) PaceTokens(PaceState pace, byte[] pcdToken)
    {
        if (!Token(pace.Aes, pace.MacKey, pace.Oid, pace.PiccPublic!).AsSpan().SequenceEqual(pcdToken))
        {
            return Status(0x6300);
        }
        byte[] piccToken = Token(pace.Aes, pace.MacKey, pace.Oid, pace.PcdPublic!);
        if (Fault == ChipFault.PaceToken)
        {
            piccToken[0] ^= 0x01;
        }
        byte[] response = Tlv.Encode(0x86, piccToken);
        if (Fault == ChipFault.PaceNoToken)
        {
            response = [];
        }
        else if (Fault == ChipFault.PaceTruncatedToken)
        {
            response = response[..4];
        }
        if (pace.Mapping == 6 && Fault is not (ChipFault.PaceNoToken or ChipFault.PaceTruncatedToken))
        {
            var ec = (ECDomainParameters)pace.StaticParameters;
            var staticKey = (ECPrivateKeyParameters)ChipAuthenticationKeys
                .First(k => k.KeyPair.Private is ECPrivateKeyParameters e && e.Parameters.Curve.Equals(ec.Curve)).KeyPair.Private;
            BigInteger caData = staticKey.D.ModInverse(ec.N).Multiply(pace.MappingPrivate).Mod(ec.N);
            byte[] iv = EncryptBlock(true, pace.EncKey, Enumerable.Repeat((byte)0xFF, 16).ToArray());
            byte[] encrypted = Cbc(true, true, pace.EncKey, iv, Pad(Fixed(caData, FieldBytes(ec.Curve)), 16));
            response = [.. response, .. Tlv.Encode(0x8A, encrypted)];
        }
        StartSession(pace.Aes, pace.EncKey, pace.MacKey, 0);
        _idPicc = Compress(pace.PiccPublic!);
        return Ok(Tlv.Encode(0x7C, response));
    }

    // ---- Chip Authentication (Doc 9303-11 6.2) ----

    private static (string Agreement, bool Aes, int KeyBits) ParseCaOid(string oid)
    {
        const string prefix = "0.4.0.127.0.7.2.2.3.";
        string[] parts = oid[prefix.Length..].Split('.');
        int cipher = int.Parse(parts[1], System.Globalization.CultureInfo.InvariantCulture);
        return (parts[0] == "1" ? "DH" : "ECDH", cipher > 1, cipher switch { 1 => 112, 2 => 128, 3 => 192, _ => 256 });
    }

    private (byte[], int) ChipAuthenticateDes(List<Tlv.Item> items)
    {
        if (_sm == null)
        {
            return Status(0x6982);
        }
        byte[] pcdPublic = Tlv.Find(items, 0x91)!;
        int? keyId = KeyId(items);
        CaKey? key = ChipAuthenticationKeys.FirstOrDefault(k => !ParseCaOid(k.Oid).Aes && (keyId == null || k.KeyId == keyId));
        if (key == null)
        {
            return Status(0x6A88);
        }
        ChipAuthenticate(key, pcdPublic);
        return Ok([]);
    }

    private (byte[], int) ChipAuthenticateAes(Command c)
    {
        CaKey? key = _caSelected;
        _caSelected = null;
        if (key == null || _sm == null)
        {
            return Status(0x6985);
        }
        byte[] pcdPublic = Tlv.Find(Tlv.Parse(Tlv.Find(Tlv.Parse(c.Data), 0x7C)!), 0x80)!;
        ChipAuthenticate(key, pcdPublic);
        return Ok([0x7C, 0x00]);
    }

    /// <summary>Computes the shared secret and starts a new session; the current response still uses the old keys.</summary>
    private void ChipAuthenticate(CaKey key, byte[] pcdPublic)
    {
        (_, bool aes, int keyBits) = ParseCaOid(key.Oid);
        byte[] shared;
        switch (key.KeyPair.Private)
        {
            case ECPrivateKeyParameters ec:
            {
                ECPoint pcd = DecodePoint(ec.Parameters.Curve, pcdPublic);
                shared = Fixed(pcd.Multiply(ec.D).Normalize().AffineXCoord.ToBigInteger(), FieldBytes(ec.Parameters.Curve));
                _caTerminalKey = new ECPublicKeyParameters(pcd, ec.Parameters);
                break;
            }
            case DHPrivateKeyParameters dh:
            {
                BigInteger pcd = new(1, pcdPublic);
                shared = Fixed(pcd.ModPow(dh.X, dh.Parameters.P), (dh.Parameters.P.BitLength + 7) / 8);
                _caTerminalKey = new DHPublicKeyParameters(pcd, dh.Parameters);
                break;
            }
            default:
                throw new NotSupportedException();
        }
        StartSession(aes, Kdf(shared, KdfEnc, aes, keyBits), Kdf(shared, KdfMac, aes, keyBits), 0);
    }

    // ---- Terminal Authentication (TR-03110 v1.11, Doc 9303-11 7.1) ----

    private static bool VerifyEcdsa(ECPublicKeyParameters key, byte[] data, byte[] signature)
    {
        int half = signature.Length / 2;
        var verifier = new ECDsaSigner();
        verifier.Init(false, key);
        return verifier.VerifySignature(Digest(new Sha256Digest(), data),
            new BigInteger(1, signature[..half]), new BigInteger(1, signature[half..]));
    }

    private (byte[], int) VerifyCertificate(Command c)
    {
        if (c.P1 != 0x00 || c.P2 != 0xBE)
        {
            return Status(0x6A86);
        }
        ECPublicKeyParameters? issuerKey = _taVerificationKey;
        if (issuerKey == null || _sm == null)
        {
            return Status(0x6985);
        }
        List<Tlv.Item> certificate = Tlv.Parse(c.Data);
        Tlv.Item body = certificate.First(i => i.Tag == 0x7F4E);
        byte[] signature = Tlv.Find(certificate, 0x5F37)!;
        List<Tlv.Item> fields = Tlv.Parse(body.Value);
        List<Tlv.Item> publicKey = Tlv.Parse(Tlv.Find(fields, 0x7F49)!);
        if (DecodeOid(publicKey[0].Value) != TaEcdsaSha256 || !VerifyEcdsa(issuerKey, body.Encoded, signature))
        {
            return Status(0x6300);
        }
        ECPoint point = DecodePoint(issuerKey.Parameters.Curve, Tlv.Find(publicKey, 0x86)!);
        string holder = System.Text.Encoding.Latin1.GetString(Tlv.Find(fields, 0x5F20)!);
        byte roleAndRights = Tlv.Find(Tlv.Parse(Tlv.Find(fields, 0x7F4C)!), 0x53)![^1];
        _certificates[holder] = (new ECPublicKeyParameters(point, issuerKey.Parameters), roleAndRights >> 6, roleAndRights & _taVerificationRights & 0x03);
        return Ok([]);
    }

    private (byte[], int) TerminalAuthenticate(Command c)
    {
        string holder = _taHolder!;
        _taHolder = null;
        byte[]? challenge = _challenge;
        _challenge = null;
        if (challenge == null || _idPicc == null || _caTerminalKey == null)
        {
            return Status(0x6985);
        }
        var certificate = _certificates[holder];
        byte[] signed = [.. _idPicc, .. challenge, .. Compress(_caTerminalKey)];
        if (!VerifyEcdsa(certificate.Key, signed, c.Data))
        {
            return Status(0x6300);
        }
        _taRights = certificate.Rights | 0x100; // non-zero marks success even without DG rights
        return Ok([]);
    }

    // ---- Active Authentication (Doc 9303-11 6.1) ----

    private (byte[], int) InternalAuthenticate(Command c)
    {
        if (ActiveAuthenticationKey == null || !_accessGranted)
        {
            return Status(0x6982);
        }
        if (c.Data.Length != 8)
        {
            return Status(0x6700);
        }
        switch (ActiveAuthenticationKey.Private)
        {
            case RsaKeyParameters rsa:
            {
                IDigest digest = ActiveAuthenticationRsaSha256 ? new Sha256Digest() : new Sha1Digest();
                var signer = new Iso9796d2Signer(new RsaEngine(), digest, !ActiveAuthenticationRsaSha256);
                signer.Init(true, rsa);
                int trailerLength = ActiveAuthenticationRsaSha256 ? 2 : 1;
                byte[] m1 = RandomBytes((rsa.Modulus.BitLength + 7) / 8 - digest.GetDigestSize() - trailerLength - 1);
                byte[] message = [.. m1, .. c.Data];
                signer.BlockUpdate(message, 0, message.Length);
                return Ok(CorruptIfFaulty(signer.GenerateSignature()));
            }
            case ECPrivateKeyParameters ec:
            {
                var signer = new ECDsaSigner();
                signer.Init(true, ec);
                BigInteger[] rs = signer.GenerateSignature(Digest(new Sha256Digest(), c.Data));
                int size = FieldBytes(ec.Parameters.Curve);
                return Ok(CorruptIfFaulty([.. Fixed(rs[0], size), .. Fixed(rs[1], size)]));
            }
            default:
                return Status(0x6A80);
        }
    }

    private byte[] CorruptIfFaulty(byte[] signature)
    {
        if (Fault == ChipFault.ActiveAuthenticationSignature)
        {
            signature[signature.Length / 2] ^= 0x01;
        }
        return signature;
    }

    // ---- Secure messaging (Doc 9303-11 9.8) ----

    private sealed record Command(int Cla, int Ins, int P1, int P2, byte[] Data, int Ne);

    private sealed class SmSession(bool aes, byte[] encKey, byte[] macKey, long ssc)
    {
        private long _ssc = ssc;
        private int BlockSize => ChipCrypto.BlockSize(aes);

        /// <summary>The SSC as an unsigned big-endian counter over the block size (a BAC SSC may use all 64 bits).</summary>
        private byte[] Ssc()
        {
            var encoded = new byte[BlockSize];
            for (int i = 0; i < 8; i++)
            {
                encoded[BlockSize - 1 - i] = (byte)(_ssc >> (8 * i));
            }
            return encoded;
        }

        private byte[] Iv() => aes ? EncryptBlock(true, encKey, Ssc()) : new byte[8];

        public Command Unwrap(CommandApdu apdu, bool corrupt)
        {
            _ssc++;
            List<Tlv.Item> items = Tlv.Parse(apdu.Data);
            int index = 0;
            Tlv.Item? cryptogram = index < items.Count && items[index].Tag is 0x85 or 0x87 ? items[index++] : null;
            Tlv.Item? le = index < items.Count && items[index].Tag == 0x97 ? items[index++] : null;
            if (index != items.Count - 1 || items[index].Tag != 0x8E || items[index].Value.Length != 8)
            {
                throw new InvalidOperationException("Bad secure messaging data objects");
            }
            byte[] header = [(byte)apdu.Cla, (byte)apdu.Ins, (byte)apdu.P1, (byte)apdu.P2];
            byte[] macInput = [.. Ssc(), .. Pad(header, BlockSize), .. cryptogram?.Encoded ?? [], .. le?.Encoded ?? []];
            byte[] mac = items[index].Value;
            if (corrupt)
            {
                mac[0] ^= 0x01;
            }
            if (!Mac(aes, macKey, Pad(macInput, BlockSize)).AsSpan().SequenceEqual(mac))
            {
                throw new InvalidOperationException("Bad command MAC");
            }

            byte[] data = [];
            if (cryptogram != null)
            {
                byte[] encrypted = cryptogram.Value;
                if (cryptogram.Tag == 0x87)
                {
                    if (encrypted[0] != 0x01)
                    {
                        throw new InvalidOperationException("Bad padding indicator");
                    }
                    encrypted = encrypted[1..];
                }
                data = Unpad(Cbc(false, aes, encKey, Iv(), encrypted));
            }
            int ne = 0;
            if (le != null)
            {
                int value = 0;
                foreach (byte b in le.Value)
                {
                    value = (value << 8) | b;
                }
                ne = value != 0 ? value : le.Value.Length == 1 ? 256 : 65536;
            }
            return new Command(apdu.Cla & ~0x0C, apdu.Ins, apdu.P1, apdu.P2, data, ne);
        }

        public byte[] Wrap(byte[] data, int sw, bool oddIns, bool corrupt)
        {
            _ssc++;
            byte[] cryptogram = [];
            if (data.Length > 0)
            {
                byte[] encrypted = Cbc(true, aes, encKey, Iv(), Pad(data, BlockSize));
                cryptogram = oddIns ? Tlv.Encode(0x85, encrypted) : Tlv.Encode(0x87, [0x01, .. encrypted]);
            }
            byte[] status = Tlv.Encode(0x99, [(byte)(sw >> 8), (byte)sw]);
            byte[] mac = Mac(aes, macKey, Pad([.. Ssc(), .. cryptogram, .. status], BlockSize));
            if (corrupt)
            {
                mac[0] ^= 0x01;
            }
            return [.. cryptogram, .. status, .. Tlv.Encode(0x8E, mac), (byte)(sw >> 8), (byte)sw];
        }
    }
}
