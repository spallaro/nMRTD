using nMRTD.Io;
using static nMRTD.Io.FragmentBuffer;

namespace nMRTD.Tests;

/// <summary>
/// <see cref="FragmentBuffer"/>, which records the parts of a file already read from the chip: which part
/// of a requested range still has to be read, merging of fragments in every overlap case, and equality.
/// </summary>
public class FragmentBufferScenarioTests
{
    private static FragmentBuffer With(params (int Offset, int Length)[] fragments)
    {
        var buffer = new FragmentBuffer(64);
        foreach ((int offset, int length) in fragments)
        {
            buffer.AddFragment(offset, Enumerable.Repeat((byte)0xAB, length).ToArray());
        }
        return buffer;
    }

    /// <summary>The part of [offset, offset + length) that still has to be read. With two fragments they are
    /// added in both orders, since the fragments are kept in an unordered set.</summary>
    [Theory]
    [InlineData(5, 3, 0, 10, 0, 0, 0, 0)]      // inside a fragment: nothing to read
    [InlineData(5, 20, 0, 10, 0, 0, 10, 15)]   // starts inside a fragment: read the rest
    [InlineData(0, 25, 20, 10, 0, 0, 0, 20)]   // ends inside a fragment: read the start
    [InlineData(0, 50, 10, 10, 30, 10, 0, 50)] // fragments strictly inside: read it all in one go
    [InlineData(5, 35, 0, 10, 30, 20, 10, 20)] // starts and ends inside fragments: read the gap
    [InlineData(40, 5, 0, 10, 20, 10, 40, 5)]  // after every fragment: read it all
    public void SmallestUnbufferedFragment(int offset, int length, int o1, int l1, int o2, int l2, int expectedOffset, int expectedLength)
    {
        var fragments = new List<(int, int)> { (o1, l1) };
        if (l2 > 0)
        {
            fragments.Add((o2, l2));
        }

        foreach (List<(int, int)> order in new[] { fragments, Enumerable.Reverse(fragments).ToList() })
        {
            Fragment result = With([.. order]).GetSmallestUnbufferedFragment(offset, length);

            Assert.Equal(expectedLength, result.Length);
            if (expectedLength > 0)
            {
                Assert.Equal(expectedOffset, result.Offset);
            }
        }
    }

    [Theory]
    [InlineData(10, 10, 12, 4, 10, 10)] // new fragment inside an existing one
    [InlineData(10, 10, 15, 10, 10, 15)] // overlaps the end
    [InlineData(10, 10, 5, 10, 5, 15)] // overlaps the start
    [InlineData(10, 10, 5, 20, 5, 20)] // contains the existing one
    [InlineData(10, 10, 20, 5, 10, 15)] // adjacent after: merged
    [InlineData(10, 10, 5, 5, 5, 15)] // adjacent before: merged
    public void FragmentsMerge(int o1, int l1, int o2, int l2, int mergedOffset, int mergedLength)
    {
        FragmentBuffer buffer = With((o1, l1), (o2, l2));

        Fragment merged = Assert.Single(buffer.GetFragments());
        Assert.Equal(mergedOffset, merged.Offset);
        Assert.Equal(mergedLength, merged.Length);
        Assert.Equal(mergedLength, buffer.GetBytesBuffered());
        Assert.Equal(mergedOffset + mergedLength, buffer.GetPosition());
        Assert.Equal(mergedLength - 1, buffer.GetBufferedLength(mergedOffset + 1));
    }

    [Fact]
    public void BufferedLengthOutsideTheBufferIsZero()
    {
        FragmentBuffer buffer = With((0, 4));

        Assert.Equal(0, buffer.GetBufferedLength(1000));
        Assert.Equal(0, buffer.GetBufferedLength(10));
    }

    [Fact]
    public void DefaultBufferGrowsWhenNeeded()
    {
        var buffer = new FragmentBuffer();
        int length = buffer.GetLength();

        buffer.AddFragment(length + 10, 0x42);

        Assert.True(buffer.GetLength() > length + 10);
        Assert.Equal(0x42, buffer.GetBuffer()[length + 10]);
        Assert.True(buffer.IsCoveredByFragment(length + 10));
    }

    [Fact]
    public void EqualityFollowsContentAndFragments()
    {
        FragmentBuffer buffer = With((0, 4), (10, 2));

        Assert.Equal(buffer, With((10, 2), (0, 4)));
        Assert.Equal(buffer.GetHashCode(), With((10, 2), (0, 4)).GetHashCode());
        Assert.NotEqual(buffer, With((0, 4)));
        Assert.False(buffer.Equals(null));
        Assert.False(buffer.Equals("buffer"));
        Assert.Equal("FragmentBuffer [64, [", buffer.ToString()[..21]);
        Assert.Equal("[0 .. 3 (4)]", Fragment.GetInstance(0, 4).ToString());
        Assert.Equal(Fragment.GetInstance(0, 4), Fragment.GetInstance(0, 4));
        Assert.NotEqual(Fragment.GetInstance(0, 4), Fragment.GetInstance(0, 5));
        Assert.False(Fragment.GetInstance(0, 4).Equals(null));
    }
}
