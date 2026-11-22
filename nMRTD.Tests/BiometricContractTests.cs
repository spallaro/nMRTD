using System.Collections;
using System.Reflection;
using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.Lds.Iso39794;
using nMRTD.Tests.Helpers;

namespace nMRTD.Tests;

/// <summary>
/// Every biometric fixture (ISO/IEC 19794 and 39794 face, finger and iris data) is decoded twice, and the
/// two object graphs are walked side by side through their public getters: each pair of nodes must be
/// equal, have the same hash code (the Equals and GetHashCode contract) and print without throwing.
/// </summary>
public class BiometricContractTests
{
    public static TheoryData<string> Fixtures => new()
    {
        "/lds/bsi2008/Datagroup2.bin",
        "/lds/bsi2008/Datagroup3.bin",
        "/lds/bsi2008/Datagroup4.bin",
        "/lds/loes2006/ef0102.bin",
        "/lds/dg2/dg2_silver_all_fields.bin",
        "/lds/dg2/dg2_silver_mandatory_fields.bin",
        "dg2:/lds/dg2/iso39794/sample-39794-5-ed-1-v1.der",
        "dg3:/lds/dg3/iso39794/sample-39794-4-ed-1-v1.der",
        "dg4:/lds/dg4/iso39794/sample-39794-6-ed-1-v1.der",
    };

    /// <summary>Decodes a data group file, or a bare ISO/IEC 39794 data block wrapped into one ("dgN:").</summary>
    private static object Decode(string fixture)
    {
        if (fixture.StartsWith("dg2:", StringComparison.Ordinal))
        {
            var block = new FaceImageDataBlock(Helpers.Fixtures.GetInputStream(fixture[4..]));
            return new DG2File(new MemoryStream(DG2File.CreateISO39794DG2File([block]).GetEncoded()!));
        }
        if (fixture.StartsWith("dg3:", StringComparison.Ordinal))
        {
            var block = new FingerImageDataBlock(Helpers.Fixtures.GetInputStream(fixture[4..]));
            return new DG3File(new MemoryStream(DG3File.CreateISO39794DG3File([block]).GetEncoded()!));
        }
        if (fixture.StartsWith("dg4:", StringComparison.Ordinal))
        {
            var block = new IrisImageDataBlock(Helpers.Fixtures.GetInputStream(fixture[4..]));
            return new DG4File(new MemoryStream(DG4File.CreateISO39794DG4File([block]).GetEncoded()!));
        }
        return LDSFileUtil.GetLDSFile(LDSFileUtil.LookupFIDByTag(Helpers.Fixtures.GetBytes(fixture)[0]), Helpers.Fixtures.GetInputStream(fixture));
    }

    [Theory]
    [MemberData(nameof(Fixtures))]
    public void DecodedObjectGraphsKeepTheEqualsAndHashCodeContract(string fixture)
    {
        var visited = new List<string>();
        var failures = new List<string>();
        Walk(Decode(fixture), Decode(fixture), fixture, visited, failures, depth: 0);
        Assert.True(visited.Count > 3, $"only {visited.Count} nodes visited");
        Assert.True(failures.Count == 0, string.Join(Environment.NewLine, failures));
    }

    private static readonly HashSet<string> SkippedGetters =
    [
        "GetType", "GetHashCode", "GetEncoded", "GetImageInputStream", "GetInputStream",
        "GetDecoder", "GetEncoder", // codecs, not values
        "GeImageData", // [Obsolete] alias
    ];

    private static void Walk(object? first, object? second, string path, List<string> visited, List<string> failures, int depth)
    {
        if (first == null || second == null)
        {
            if (first != null || second != null)
            {
                failures.Add($"{path}: only one side is null");
            }
            return;
        }
        Type type = first.GetType();
        if (first is Array && first is not byte[])
        {
            type = typeof(Array); // arrays have reference equality: compare them element by element below
        }
        if (depth > 12 || type.IsPrimitive || type.IsEnum || first is string or byte[] or Stream || type.Namespace?.StartsWith("nMRTD", StringComparison.Ordinal) != true)
        {
            if (first is IList firstList && second is IList secondList)
            {
                if (firstList.Count != secondList.Count)
                {
                    failures.Add($"{path}: lists of different length");
                    return;
                }
                for (int i = 0; i < firstList.Count; i++)
                {
                    Walk(firstList[i], secondList[i], $"{path}[{i}]", visited, failures, depth + 1);
                }
            }
            return;
        }

        visited.Add(path);
        if (!first.Equals(second))
        {
            failures.Add($"{path} ({type.Name}): Equals is false for two decodes of the same bytes");
        }
        else if (first.GetHashCode() != second.GetHashCode())
        {
            failures.Add($"{path} ({type.Name}): equal objects with different hash codes");
        }
        Assert.NotNull(first.ToString());

        foreach (MethodInfo getter in type.GetMethods(BindingFlags.Public | BindingFlags.Instance))
        {
            if (getter.GetParameters().Length != 0 || !getter.Name.StartsWith("Get", StringComparison.Ordinal)
                || getter.ReturnType == typeof(void) || SkippedGetters.Contains(getter.Name)
                || getter.IsDefined(typeof(ObsoleteAttribute)))
            {
                continue;
            }
            object? a, b;
            try
            {
                a = getter.Invoke(first, null);
                b = getter.Invoke(second, null);
            }
            catch (TargetInvocationException)
            {
                continue; // getters that are not meaningful for this instance (e.g. no header yet)
            }
            Walk(a, b, $"{path}.{getter.Name}", visited, failures, depth + 1);
        }
    }
}
