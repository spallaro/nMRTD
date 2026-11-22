using nMRTD.Lds;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using static nMRTD.Tests.EndToEnd.EndToEnd;
using static nMRTD.Tests.Helpers.TestData;

namespace nMRTD.Tests;

/// <summary><see cref="PaceParameters.Resolve"/>: standardized or explicit PACE domain parameters for a PACEInfo.</summary>
public class PaceParametersTests
{
    private static readonly ECDomainParameters Secp256k1 = Util.GetECDomainParameters("secp256k1");

    private static PACEDomainParameterInfo EcDomainInfo(string protocol, ECDomainParameters ec, int? parameterId) =>
        new(protocol,
            new AlgorithmIdentifier(new DerObjectIdentifier(PACEDomainParameterInfo.ID_EC_PUBLIC_KEY),
                new X9ECParameters(ec.Curve, new X9ECPoint(ec.G, false), ec.N, ec.H).ToAsn1Object()),
            parameterId == null ? null : BigInteger.ValueOf(parameterId.Value));

    private static PACEInfo Pace(string oid, int? parameterId) =>
        new(oid, 2, parameterId == null ? null : BigInteger.ValueOf(parameterId.Value));

    [Fact]
    public void StandardizedParameterId()
    {
        object parameters = PaceParameters.Resolve(Pace(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, 13), []);

        Assert.Same(PACEInfo.ToParameterSpec(13), parameters);
    }

    [Fact]
    public void UnknownStandardizedParameterIdIsRejected() =>
        Assert.Throws<ArgumentException>(() => PaceParameters.Resolve(Pace(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, 5), []));

    [Fact]
    public void ProprietaryParameterIdSelectsTheMatchingDomainParameterInfo()
    {
        SecurityInfo[] infos =
        [
            EcDomainInfo(SecurityInfo.ID_PACE_ECDH_GM, BrainpoolP256r1, 33),
            EcDomainInfo(SecurityInfo.ID_PACE_ECDH_GM, Secp256k1, 32),
        ];

        var parameters = Assert.IsType<ECDomainParameters>(PaceParameters.Resolve(Pace(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, 32), infos));

        Assert.Equal(Secp256k1.Curve, parameters.Curve);
        Assert.Equal(Secp256k1.G, parameters.G);
    }

    [Fact]
    public void NoParameterIdUsesTheOnlyDomainParameterInfo()
    {
        SecurityInfo[] infos = [EcDomainInfo(SecurityInfo.ID_PACE_ECDH_IM, Secp256k1, null)];

        var parameters = Assert.IsType<ECDomainParameters>(PaceParameters.Resolve(Pace(SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_256, null), infos));

        Assert.Equal(Secp256k1.N, parameters.N);
    }

    [Fact]
    public void NoParameterIdWithSeveralDomainParameterInfosIsRejected()
    {
        SecurityInfo[] infos =
        [
            EcDomainInfo(SecurityInfo.ID_PACE_ECDH_GM, BrainpoolP256r1, null),
            EcDomainInfo(SecurityInfo.ID_PACE_ECDH_GM, Secp256k1, null),
        ];

        Assert.Throws<ArgumentException>(() => PaceParameters.Resolve(Pace(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, null), infos));
    }

    [Fact]
    public void DomainParameterInfoOfAnotherProtocolIsIgnored()
    {
        // ECDH-IM parameters do not apply to an ECDH-GM PACEInfo.
        SecurityInfo[] infos = [EcDomainInfo(SecurityInfo.ID_PACE_ECDH_IM, Secp256k1, 32)];

        Assert.Throws<ArgumentException>(() => PaceParameters.Resolve(Pace(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, 32), infos));
    }

    [Fact]
    public void MissingDomainParameterInfoIsRejected() =>
        Assert.Throws<ArgumentException>(() => PaceParameters.Resolve(Pace(SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_128, 40), []));

    /// <summary>PACE end to end with domain parameters that are not standardized: EF.CardAccess advertises
    /// proprietary parameter id 32 and carries the parameters in a PACEDomainParameterInfo.</summary>
    [Theory]
    [InlineData(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, "secp256k1")]
    [InlineData(SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_128, "brainpoolP256r1")] // IM's point encoding needs a != 0, which secp256k1 lacks
    [InlineData(SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_128, "dh")]
    public void PaceWithExplicitDomainParameters(string oid, string group)
    {
        object explicitParameters = group switch
        {
            "dh" => DhWithQ,
            "secp256k1" => Secp256k1,
            _ => BrainpoolP256r1,
        };
        var document = new SimulatedDocument();
        document.Pace.Add(new SimulatedChip.PaceSupport(oid, 32, explicitParameters));
        SimulatedChip chip = document.Build();
        PassportService service = Open(chip);

        var cardAccess = new CardAccessFile(new MemoryStream(Read(service, PassportService.EF_CARD_ACCESS)));
        PACEInfo paceInfo = cardAccess.GetSecurityInfos().OfType<PACEInfo>().Single();
        object parameters = PaceParameters.Resolve(paceInfo, cardAccess.GetSecurityInfos());
        service.DoPace(PaceKeySpec.CreateCanKey(SimulatedDocument.Can), oid, parameters, paceInfo.GetParameterId());
        service.SendSelectApplet(true);

        Assert.Equal(1, chip.Session);
        Assert.Equal(SimulatedDocument.DocumentNumber, new Lds.Icao.DG1File(new MemoryStream(Read(service, PassportService.EF_DG1))).GetMRZInfo().GetDocumentNumber());
    }
}
