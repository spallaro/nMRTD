namespace nMRTD.Tests.Helpers;

/// <summary>
/// Test classes that decode DG2, DG3 or DG4 run one after the other. <c>DG2File</c>, <c>DG3File</c> and
/// <c>DG4File</c> share one static <c>ISO781611Decoder</c> each, which keeps the encoding type of the last
/// biometric data block it read in a field (as JMRTD's does), so concurrent decodes can interfere. JUnit
/// runs JMRTD's tests sequentially; xUnit runs test classes in parallel unless they share a collection.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class CbeffDataGroupCollection
{
    public const string Name = "CBEFF data groups";
}
