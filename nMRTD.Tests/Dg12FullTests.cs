using nMRTD.Lds.Icao;

namespace nMRTD.Tests;

/// <summary>DG12 (additional document details) with every field, including the images of the front and
/// the rear of the document, which the fixtures lack.</summary>
public class Dg12FullTests
{
    private static readonly byte[] Front = [0xFF, 0xD8, 0x01, 0x02];
    private static readonly byte[] Rear = [0xFF, 0xD8, 0x03, 0x04, 0x05];

    private static DG12File Full(string endorsements = "Valid for travel to Utopia only") => new(
        "Ministry of Utopia", "20260101", ["ERIKSSON<<NILS", "ERIKSSON<<KARIN"], endorsements,
        "No exit tax", Front, Rear, "20260102101112", "SN-0042");

    [Fact]
    public void EveryFieldSurvivesARoundTrip()
    {
        DG12File original = Full();

        var copy = new DG12File(new MemoryStream(original.GetEncoded()!));

        Assert.Equal(original, copy);
        Assert.Equal(original.GetHashCode(), copy.GetHashCode());
        Assert.Equal(original.GetTagPresenceList(), copy.GetTagPresenceList());
        Assert.Equal(9, copy.GetTagPresenceList().Count);
        Assert.Equal("Valid for travel to Utopia only", copy.GetEndorsementsAndObservations());
        Assert.Equal("No exit tax", copy.GetTaxOrExitRequirements());
        Assert.Equal(Front, copy.GetImageOfFront());
        Assert.Equal(Rear, copy.GetImageOfRear());
        Assert.Equal(["ERIKSSON<<NILS", "ERIKSSON<<KARIN"], copy.GetNamesOfOtherPersons()!);
        Assert.Equal("SN-0042", copy.GetPersonalizationSystemSerialNumber());
    }

    [Fact]
    public void EmptyFileHasNoFields()
    {
        var empty = new DG12File(null, (string?)null, null, null, null, null, null, (string?)null, null);

        var copy = new DG12File(new MemoryStream(empty.GetEncoded()!));

        Assert.Empty(copy.GetTagPresenceList());
        Assert.Equal(empty, copy);
        Assert.Null(copy.GetImageOfFront());
    }

    [Fact]
    public void DifferentFieldsAreNotEqual()
    {
        DG12File full = Full();

        Assert.NotEqual(full, Full("Other endorsement"));
        Assert.NotEqual(full, new DG12File("Ministry of Utopia", "20260101", ["ERIKSSON<<NILS", "ERIKSSON<<KARIN"],
            "Valid for travel to Utopia only", "No exit tax", Front, [0x00], "20260102101112", "SN-0042"));
        Assert.NotEqual(full, new DG12File("Ministry of Utopia", "20260101", ["ERIKSSON<<NILS"],
            "Valid for travel to Utopia only", "No exit tax", Front, Rear, "20260102101112", "SN-0042"));
        Assert.False(full.Equals(null));
        Assert.Contains("Ministry of Utopia", full.ToString());
    }
}
