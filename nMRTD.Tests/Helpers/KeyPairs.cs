using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace nMRTD.Tests.Helpers;

/// <summary>Key pair generation, standing in for JCA's <c>KeyPairGenerator</c> in the ported JMRTD tests.</summary>
internal static class KeyPairs
{
    private static readonly SecureRandom Random = new();

    public static AsymmetricCipherKeyPair Rsa(int bits)
    {
        var generator = new RsaKeyPairGenerator();
        generator.Init(new KeyGenerationParameters(Random, bits));
        return generator.GenerateKeyPair();
    }

    public static AsymmetricCipherKeyPair EC(string curveName) => EC(Util.GetECDomainParameters(curveName));

    public static AsymmetricCipherKeyPair EC(ECDomainParameters domainParameters)
    {
        var generator = new ECKeyPairGenerator();
        generator.Init(new ECKeyGenerationParameters(domainParameters, Random));
        return generator.GenerateKeyPair();
    }

    public static AsymmetricCipherKeyPair DH(DHParameters parameters)
    {
        var generator = new DHKeyPairGenerator();
        generator.Init(new DHKeyGenerationParameters(Random, parameters));
        return generator.GenerateKeyPair();
    }
}
