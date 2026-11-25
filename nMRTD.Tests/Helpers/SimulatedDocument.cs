using nMRTD.Cert;
using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.Lds.Iso39794;
using nMRTD.SmartCards;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using BigInteger = Org.BouncyCastle.Math.BigInteger;

namespace nMRTD.Tests.Helpers;

/// <summary>
/// Personalizes a <see cref="SimulatedChip"/> with a fictitious document: the LDS files are built with nMRTD's
/// own classes, the keys are generated per test run, and nothing comes from a real document.
/// </summary>
internal sealed class SimulatedDocument
{
    public const string DocumentNumber = "TST123456";
    public const string DateOfBirth = "800101";
    public const string DateOfExpiry = "351231";
    public const string Can = "123456";
    public const string CvcaReference = "UTCVCA00001";

    public static readonly MRZInfo Mrz = MRZInfo.CreateTD3MRZInfo(
        "P<", "UTO", "SPECIMEN", "TEST", DocumentNumber, "UTO", DateOfBirth, Gender.Female, DateOfExpiry, "");

    /// <summary>A face "image" longer than 32 KB, so that reading DG2 needs READ BINARY with an odd INS.</summary>
    public static readonly byte[] FaceImage = CreateFaceImage(40_000);

    /// <summary>DG3 content, readable only after Terminal Authentication.</summary>
    public static readonly byte[] Dg3 = Tlv.Encode(0x63, Enumerable.Range(0, 600).Select(i => (byte)(i * 7)).ToArray());

    private static readonly Lazy<AsymmetricCipherKeyPair> Rsa1024 = new(() => GenerateRsa(1024));
    private static readonly Lazy<AsymmetricCipherKeyPair> Rsa2048 = new(() => GenerateRsa(2048));

    public List<SimulatedChip.PaceSupport> Pace { get; } = new();
    public List<SimulatedChip.CaKey> ChipAuthenticationKeys { get; } = new();
    public AsymmetricCipherKeyPair? ActiveAuthenticationKey { get; set; }
    public AsymmetricCipherKeyPair? CvcaKey { get; set; }
    public bool BacEnabled { get; set; } = true;
    public bool SupportsExtendedLength { get; set; } = true;

    /// <summary>See <see cref="SimulatedChip.ProtectedWrongLength"/>.</summary>
    public bool ProtectedWrongLength { get; set; }

    /// <summary>The Document Signer that signs EF.SOD: by default the self-signed <see cref="SigningFixtures"/>.</summary>
    public AsymmetricKeyParameter DocumentSignerKey { get; set; } = SigningFixtures.KeyPair.Private;

    public Org.BouncyCastle.X509.X509Certificate DocumentSignerCertificate { get; set; } = SigningFixtures.Certificate;

    /// <summary>The EF.SOD signature algorithm, matching <see cref="DocumentSignerKey"/>.</summary>
    public string DocumentSignerAlgorithm { get; set; } = "SHA256withRSA";

    /// <summary>The application files, by file identifier, as personalized.</summary>
    public Dictionary<short, byte[]> Files { get; } = new();

    public static AsymmetricCipherKeyPair RsaKey1024 => Rsa1024.Value;
    public static AsymmetricCipherKeyPair RsaKey2048 => Rsa2048.Value;

    public static AsymmetricCipherKeyPair GenerateEc(int parameterId) =>
        GenerateEc((ECDomainParameters)ChipCrypto.StandardizedDomainParameters(parameterId));

    public static AsymmetricCipherKeyPair GenerateEc(ECDomainParameters domain)
    {
        var generator = new ECKeyPairGenerator();
        generator.Init(new ECKeyGenerationParameters(domain, new SecureRandom()));
        return generator.GenerateKeyPair();
    }

    public static AsymmetricCipherKeyPair GenerateDh()
    {
        var generator = new DHKeyPairGenerator();
        generator.Init(new DHKeyGenerationParameters(new SecureRandom(), TestData.DhWithQ));
        return generator.GenerateKeyPair();
    }

    private static AsymmetricCipherKeyPair GenerateRsa(int bits)
    {
        var generator = new RsaKeyPairGenerator();
        generator.Init(new KeyGenerationParameters(new SecureRandom(), bits));
        return generator.GenerateKeyPair();
    }

    private static byte[] CreateFaceImage(int length)
    {
        var image = new byte[length];
        new Random(42).NextBytes(image);
        byte[] header = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46];
        header.CopyTo(image, 0);
        return image;
    }

    public static IBacKeySpec BacKey => new BacKey(DocumentNumber, DateOfBirth, DateOfExpiry);

    public static byte[] Dg2Bytes()
    {
        var info = new FaceImageInformation2DBlock(
            FaceImageInformation2DBlock.ImageDataFormatCode.Jpeg,
            FaceImageInformation2DBlock.FaceImageKind2DCode.Mrtd,
            null, null, null, null, null, null, null, null, null);
        var representation = new FaceImageRepresentationBlock(BigInteger.One,
            new FaceImageRepresentation2DBlock(FaceImage, info, null), null, null, null, null, null, null, null, null);
        var block = new FaceImageDataBlock(new VersionBlock(3, 2019), new List<FaceImageRepresentationBlock> { representation }, null);
        return DG2File.CreateISO39794DG2File(new List<FaceImageDataBlock> { block }).GetEncoded()!;
    }

    public SimulatedChip Build()
    {
        Files.Clear();
        var dataGroups = new SortedDictionary<int, byte[]>
        {
            [1] = new DG1File(Mrz).GetEncoded()!,
            [2] = Dg2Bytes(),
            [3] = Dg3,
        };

        var securityInfos = new List<SecurityInfo>();
        foreach (SimulatedChip.CaKey key in ChipAuthenticationKeys)
        {
            BigInteger? keyId = key.KeyId is int id ? BigInteger.ValueOf(id) : null;
            securityInfos.Add(new ChipAuthenticationInfo(key.Oid, 1, keyId));
            securityInfos.Add(new ChipAuthenticationPublicKeyInfo(key.KeyPair.Public, keyId));
        }
        if (CvcaKey != null)
        {
            securityInfos.Add(new TerminalAuthenticationInfo());
        }
        if (ActiveAuthenticationKey?.Public is ECPublicKeyParameters)
        {
            securityInfos.Add(new ActiveAuthenticationInfo(ActiveAuthenticationInfo.ECDSA_PLAIN_SHA256_OID));
        }
        if (securityInfos.Count > 0)
        {
            dataGroups[14] = new DG14File(securityInfos).GetEncoded()!;
        }
        if (ActiveAuthenticationKey != null)
        {
            dataGroups[15] = new DG15File(ActiveAuthenticationKey.Public).GetEncoded()!;
        }

        var hashes = dataGroups.ToDictionary(e => e.Key, e => DigestUtilities.CalculateDigest("SHA-256", e.Value));
        int[] tags = dataGroups.Keys.Select(n => LDSFileUtil.LookupTagByDataGroupNumber(n)).ToArray();

        foreach ((int number, byte[] content) in dataGroups)
        {
            Files[(short)(0x0100 + number)] = content;
        }
        Files[PassportService.EF_COM] = new COMFile("1.7", "4.0.0", tags).GetEncoded()!;
        Files[PassportService.EF_SOD] = new SODFile("SHA-256", DocumentSignerAlgorithm, hashes,
            DocumentSignerKey, DocumentSignerCertificate).GetEncoded()!;
        if (CvcaKey != null)
        {
            Files[PassportService.EF_CVCA] = new CVCAFile(PassportService.EF_CVCA, CvcaReference).GetEncoded()!;
        }

        var chip = new SimulatedChip
        {
            DocumentNumber = DocumentNumber,
            DateOfBirth = DateOfBirth,
            DateOfExpiry = DateOfExpiry,
            Can = Can,
            BacEnabled = BacEnabled,
            ActiveAuthenticationKey = ActiveAuthenticationKey,
            CvcaReference = CvcaKey == null ? null : CvcaReference,
            CvcaPublicKey = CvcaKey?.Public as ECPublicKeyParameters,
            SupportsExtendedLength = SupportsExtendedLength,
            ProtectedWrongLength = ProtectedWrongLength,
        };
        chip.PaceProtocols.AddRange(Pace);
        chip.ChipAuthenticationKeys.AddRange(ChipAuthenticationKeys);
        foreach ((short fid, byte[] content) in Files)
        {
            chip.ApplicationFiles[fid] = content;
        }
        if (Pace.Count > 0)
        {
            var cardAccess = new List<SecurityInfo>();
            foreach (SimulatedChip.PaceSupport pace in Pace)
            {
                cardAccess.Add(new PACEInfo(pace.Oid, 2, pace.ParameterId));
                if (pace.ExplicitParameters != null)
                {
                    cardAccess.Add(new PACEDomainParameterInfo(DomainParameterProtocol(pace.Oid),
                        ExplicitDomainParameters(pace.ExplicitParameters), BigInteger.ValueOf(pace.ParameterId)));
                }
            }
            chip.MasterFiles[PassportService.EF_CARD_ACCESS] = new CardAccessFile(cardAccess).GetEncoded()!;
        }
        return chip;
    }

    /// <summary>The PACEDomainParameterInfo protocol for a PACEInfo protocol: id-PACE-ECDH-GM for
    /// id-PACE-ECDH-GM-AES-CBC-CMAC-128, and so on.</summary>
    private static string DomainParameterProtocol(string paceOid) => paceOid[..paceOid.LastIndexOf('.')];

    /// <summary>Explicit EC parameters (ecPublicKey) or X9.42 DH parameters (dhpublicnumber).</summary>
    private static Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier ExplicitDomainParameters(object parameters) => parameters switch
    {
        ECDomainParameters ec => new(new Org.BouncyCastle.Asn1.DerObjectIdentifier(PACEDomainParameterInfo.ID_EC_PUBLIC_KEY),
            new Org.BouncyCastle.Asn1.X9.X9ECParameters(ec.Curve, new Org.BouncyCastle.Asn1.X9.X9ECPoint(ec.G, false), ec.N, ec.H).ToAsn1Object()),
        DHParameters dh => new(new Org.BouncyCastle.Asn1.DerObjectIdentifier(PACEDomainParameterInfo.ID_DH_PUBLIC_NUMBER),
            new Org.BouncyCastle.Asn1.X9.DHDomainParameters(new Org.BouncyCastle.Asn1.DerInteger(dh.P), new Org.BouncyCastle.Asn1.DerInteger(dh.G),
                new Org.BouncyCastle.Asn1.DerInteger(dh.Q), null, null)),
        _ => throw new ArgumentException("Unsupported domain parameters", nameof(parameters)),
    };

    /// <summary>A CV certificate chain CVCA -> DV -> IS on the curve of <paramref name="cvca"/>.</summary>
    public static (CardVerifiableCertificate Dv, CardVerifiableCertificate Is, AsymmetricCipherKeyPair IsKey) CreateTerminalChain(
        AsymmetricCipherKeyPair cvca, CVCAuthorizationTemplate.Permission rights, AsymmetricKeyParameter? dvSigner = null)
    {
        var domain = ((ECPublicKeyParameters)cvca.Public).Parameters;
        AsymmetricCipherKeyPair dvKey = GenerateEc(domain);
        AsymmetricCipherKeyPair isKey = GenerateEc(domain);
        var cvcaRef = new CVCPrincipal("UT", "CVCA", "00001");
        var dvRef = new CVCPrincipal("UT", "DVTEST", "00001");
        var isRef = new CVCPrincipal("UT", "ISTEST", "00001");
        var from = new DateOnly(2026, 1, 1);
        var to = new DateOnly(2036, 1, 1);
        CardVerifiableCertificate dv = CVCertificateBuilder.CreateCertificate(dvKey.Public, cvca.Private, "SHA256withECDSA", cvcaRef, dvRef,
            new CVCAuthorizationTemplate(CVCAuthorizationTemplate.Role.DvDomestic, rights), from, to);
        CardVerifiableCertificate @is = CVCertificateBuilder.CreateCertificate(isKey.Public, dvSigner ?? dvKey.Private, "SHA256withECDSA", dvRef, isRef,
            new CVCAuthorizationTemplate(CVCAuthorizationTemplate.Role.Is, rights), from, to);
        return (dv, @is, isKey);
    }
}
