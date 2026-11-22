using nMRTD.Cbeff;
using nMRTD.Lds.Icao;
using nMRTD.Tests.Helpers;

namespace nMRTD.Tests;

/// <summary>
/// DG2 files (and likewise DG3 and DG4) decoded at the same time on different threads keep their own encoding type.
/// JMRTD shares one static decoder per data group, which records the encoding type of the last block it
/// read; nMRTD creates a decoder per read.
/// </summary>
public class CbeffConcurrencyTests
{
    [Fact]
    public void ConcurrentDG2DecodesKeepTheirEncodingType()
    {
        byte[] iso19794 = Fixtures.GetBytes("/lds/bsi2008/Datagroup2.bin");
        byte[] iso39794 = Fixtures.GetBytes("/lds/dg2/dg2_silver_all_fields.bin");
        Assert.Equal(BiometricEncodingType.Iso19794, new DG2File(new MemoryStream(iso19794)).GetEncodingType());
        Assert.Equal(BiometricEncodingType.Iso39794, new DG2File(new MemoryStream(iso39794)).GetEncodingType());

        Parallel.For(0, 400, new ParallelOptions { MaxDegreeOfParallelism = 8 }, i =>
        {
            bool odd = (i & 1) == 1;
            var dg2 = new DG2File(new MemoryStream(odd ? iso39794 : iso19794));
            Assert.Equal(odd ? BiometricEncodingType.Iso39794 : BiometricEncodingType.Iso19794, dg2.GetEncodingType());
        });
    }

    [Fact]
    public void GetDecoderReturnsAFreshDecoder()
    {
        DG2File dg2 = new(new MemoryStream(Fixtures.GetBytes("/lds/dg2/dg2_silver_all_fields.bin")));
        Assert.NotSame(dg2.GetDecoder(), dg2.GetDecoder());
    }
}
