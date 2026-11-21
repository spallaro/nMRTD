using nMRTD.Io;

namespace nMRTD.Tests.Jmrtd.Io;

/// <summary>Port of JMRTD's <c>org.jmrtd.io.FragmentBufferTest</c>.</summary>
public class FragmentBufferTest
{
    [Fact]
    public void testBasicAddAndCoverage()
    {
        var fb = new FragmentBuffer(50);
        Assert.Equal(50, fb.GetLength());
        Assert.Equal(0, fb.GetPosition());
        Assert.Equal(0, fb.GetBytesBuffered());

        fb.AddFragment(10, (byte)0xAA);
        Assert.True(fb.IsCoveredByFragment(10));
        Assert.False(fb.IsCoveredByFragment(9));
        Assert.False(fb.IsCoveredByFragment(11));
        Assert.Equal(11, fb.GetPosition());
        Assert.Equal(1, fb.GetBytesBuffered());
    }

    [Fact]
    public void testMultipleFragmentsAndMerging()
    {
        var fb = new FragmentBuffer(100);
        byte[] data1 = [1, 2, 3, 4, 5];
        byte[] data2 = [6, 7, 8, 9, 10];

        fb.AddFragment(10, data1);
        fb.AddFragment(15, data2);

        // [10..14] and [15..19] are contiguous, so they should cover [10..19]
        Assert.True(fb.IsCoveredByFragment(10, 10));
        Assert.Equal(20, fb.GetPosition());
        Assert.Equal(10, fb.GetBytesBuffered());
        Assert.Equal(10, fb.GetBufferedLength(10));
    }

    [Fact]
    public void testOverlapScenarios()
    {
        var fb = new FragmentBuffer(100);
        fb.AddFragment(10, [1, 2, 3, 4, 5]); // covers [10..14]

        // Add completely contained fragment
        fb.AddFragment(11, [99]);
        Assert.Equal(5, fb.GetBytesBuffered());

        // Add overlapping left fragment
        fb.AddFragment(8, [10, 11, 12, 13]); // covers [8..11]
        Assert.Equal(7, fb.GetBytesBuffered()); // [8..14]
        Assert.True(fb.IsCoveredByFragment(8, 7));
    }

    [Fact]
    public void testDynamicGrowth()
    {
        var fb = new FragmentBuffer(10);
        var data = new byte[20];
        fb.AddFragment(5, data);

        Assert.True(fb.GetLength() >= 25);
        Assert.True(fb.IsCoveredByFragment(5, 20));
        Assert.Equal(25, fb.GetPosition());
    }

    [Fact]
    public void testGetSmallestUnbufferedFragment()
    {
        var fb = new FragmentBuffer(100);
        fb.AddFragment(10, [1, 2, 3, 4, 5]); // covers [10..14]

        // Asking for a completely unbuffered section
        FragmentBuffer.Fragment unbuffered1 = fb.GetSmallestUnbufferedFragment(20, 10);
        Assert.NotNull(unbuffered1);
        Assert.Equal(20, unbuffered1.Offset);
        Assert.Equal(10, unbuffered1.Length);

        // Asking for a section that overlaps a buffered section at the start
        FragmentBuffer.Fragment unbuffered2 = fb.GetSmallestUnbufferedFragment(10, 10); // requested [10..19], [10..14] is covered
        Assert.NotNull(unbuffered2);
        Assert.Equal(15, unbuffered2.Offset);
        Assert.Equal(5, unbuffered2.Length);
    }

    [Fact]
    public void testUpdateFrom()
    {
        var fb1 = new FragmentBuffer(100);
        var fb2 = new FragmentBuffer(100);

        fb1.AddFragment(10, [1, 2, 3]);
        fb2.AddFragment(20, [4, 5, 6]);

        fb1.UpdateFrom(fb2);

        Assert.True(fb1.IsCoveredByFragment(10, 3));
        Assert.True(fb1.IsCoveredByFragment(20, 3));
        Assert.Equal(6, fb1.GetBytesBuffered());
    }
}
