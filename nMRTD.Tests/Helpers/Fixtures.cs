namespace nMRTD.Tests.Helpers;

/// <summary>Access to the test fixtures under <c>fixtures/</c>, ported from JMRTD's test resources.</summary>
internal static class Fixtures
{
    /// <summary>Reads a fixture, given its JMRTD resource path (for example <c>/lds/bsi2008/EF_COM.bin</c>).</summary>
    public static byte[] GetBytes(string resource) => File.ReadAllBytes(PathOf(resource));

    /// <summary>Opens a fixture, given its JMRTD resource path.</summary>
    public static Stream GetInputStream(string resource) => File.OpenRead(PathOf(resource));

    private static string PathOf(string resource) =>
        Path.Combine(AppContext.BaseDirectory, "fixtures", resource.TrimStart('/').Replace('/', Path.DirectorySeparatorChar));
}
