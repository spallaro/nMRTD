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

/// <summary>
/// <see cref="PACEDomainParameterInfo"/>: explicit PACE domain parameters in EF.CardAccess, for documents
/// that do not use one of the standardized parameter ids.
/// </summary>
public class PaceDomainParameterInfoTests
{
    private static readonly BigInteger ProprietaryParameterId = BigInteger.ValueOf(32);

    private static AlgorithmIdentifier ExplicitEcParameters(ECDomainParameters ec) =>
        new(new DerObjectIdentifier(PACEDomainParameterInfo.ID_EC_PUBLIC_KEY),
            new X9ECParameters(ec.Curve, new X9ECPoint(ec.G, false), ec.N, ec.H).ToAsn1Object());

    private static AlgorithmIdentifier X942DhParameters(DHParameters dh) =>
        new(new DerObjectIdentifier(PACEDomainParameterInfo.ID_DH_PUBLIC_NUMBER),
            new DHDomainParameters(new DerInteger(dh.P), new DerInteger(dh.G), new DerInteger(dh.Q), null, null));

    private static PACEDomainParameterInfo RoundTrip(PACEDomainParameterInfo info) =>
        Assert.IsType<PACEDomainParameterInfo>(SecurityInfo.GetInstance(Asn1Object.FromByteArray(info.GetEncoded()!)));

    [Fact]
    public void ExplicitEcParametersAreDecoded()
    {
        var info = RoundTrip(new PACEDomainParameterInfo(SecurityInfo.ID_PACE_ECDH_GM, ExplicitEcParameters(BrainpoolP256r1), ProprietaryParameterId));

        var parameters = Assert.IsType<ECDomainParameters>(info.GetParameters());
        Assert.Equal(BrainpoolP256r1.Curve, parameters.Curve);
        Assert.Equal(BrainpoolP256r1.G, parameters.G);
        Assert.Equal(BrainpoolP256r1.N, parameters.N);
        Assert.Equal(BrainpoolP256r1.H, parameters.H);
        Assert.Equal(ProprietaryParameterId, info.GetParameterId());
    }

    [Fact]
    public void X942DhParametersAreDecoded()
    {
        var info = RoundTrip(new PACEDomainParameterInfo(SecurityInfo.ID_PACE_DH_GM, X942DhParameters(DhWithQ)));

        var parameters = Assert.IsType<DHParameters>(info.GetParameters());
        Assert.Equal(DhP, parameters.P);
        Assert.Equal(DhG, parameters.G);
        Assert.Equal(DhQ, parameters.Q);
        Assert.Null(info.GetParameterId());
    }

    [Fact]
    public void UnknownAlgorithmIsRejected()
    {
        var info = new PACEDomainParameterInfo(SecurityInfo.ID_PACE_ECDH_GM,
            new AlgorithmIdentifier(new DerObjectIdentifier("1.2.3.4"), DerNull.Instance));

        Assert.Throws<InvalidOperationException>(() => info.GetParameters());
    }

    [Fact]
    public void ProtocolOtherThanPaceIsRejected() =>
        Assert.Throws<ArgumentException>(() => new PACEDomainParameterInfo(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128, ExplicitEcParameters(BrainpoolP256r1)));

    [Fact]
    public void EqualityAndText()
    {
        var info = new PACEDomainParameterInfo(SecurityInfo.ID_PACE_ECDH_GM, ExplicitEcParameters(BrainpoolP256r1), ProprietaryParameterId);
        var other = new PACEDomainParameterInfo(SecurityInfo.ID_PACE_DH_GM, X942DhParameters(DhWithQ), ProprietaryParameterId);

        Assert.Equal(info, RoundTrip(info));
        Assert.Equal(info.GetHashCode(), RoundTrip(info).GetHashCode());
        Assert.NotEqual(info, other);
        Assert.Equal("id-PACE-ECDH-GM", info.GetProtocolOIDString());
        Assert.Contains("id-PACE-ECDH-GM", info.ToString());
    }

    /// <summary>PACE with the parameters decoded from a <see cref="PACEDomainParameterInfo"/>: here the
    /// explicit form of brainpoolP256r1, which the simulated chip knows as standardized parameter id 13.</summary>
    [Fact]
    public void DecodedParametersWorkForPace()
    {
        var document = new SimulatedDocument();
        document.Pace.Add(new SimulatedChip.PaceSupport(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, 13));
        SimulatedChip chip = document.Build();
        PassportService service = Open(chip);
        var info = RoundTrip(new PACEDomainParameterInfo(SecurityInfo.ID_PACE_ECDH_GM, ExplicitEcParameters(BrainpoolP256r1), BigInteger.ValueOf(13)));

        service.DoPace(PaceKeySpec.CreateCanKey(SimulatedDocument.Can), SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128,
            info.GetParameters(), info.GetParameterId());

        Assert.Equal(1, chip.Session);
        Assert.NotNull(service.GetWrapper());
    }
}
