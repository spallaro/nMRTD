using System.Text;
using nMRTD.Cert;
using nMRTD.Lds;
using nMRTD.Lds.Icao;
using nMRTD.Lds.Iso19794;
using nMRTD.Protocol;
using nMRTD.SmartCards;
using Org.BouncyCastle.Math;

namespace nMRTD.Tests.Jmrtd;

/// <summary>
/// Port of JMRTD's <c>org.jmrtd.MalformedInputTest</c> (0.8.10 and 0.8.11): malformed chip data that used to make
/// a parser throw an unchecked exception, loop, or allocate too much. Each input is a file in
/// <c>fixtures/malformed/&lt;kind&gt;/</c>. Contract: parsing either succeeds (and what was parsed can be encoded
/// again), or fails with the checked exception of that parser: <see cref="IOException"/> or
/// <see cref="ArgumentException"/> (Java's <c>IllegalArgumentException</c>) for files and biometric records,
/// <see cref="IOException"/> (Java's <c>CertificateException</c>) for card verifiable certificates,
/// <see cref="CardServiceException"/> for PACE.
/// </summary>
public class MalformedInputTest
{
    /// <summary>For <c>lds-file</c>: the first byte of the input selects the file identifier, the rest is the file.</summary>
    private static readonly short[] LdsFids =
    [
        PassportService.EF_COM,
        PassportService.EF_SOD,
        PassportService.EF_DG1,
        PassportService.EF_DG2,
        PassportService.EF_DG3,
        PassportService.EF_DG4,
        PassportService.EF_DG5,
        PassportService.EF_DG6,
        PassportService.EF_DG7,
        PassportService.EF_DG11,
        PassportService.EF_DG12,
        PassportService.EF_DG14,
        PassportService.EF_DG15,
        PassportService.EF_CVCA,
    ];

    private static readonly BacKey PaceAccessKey = new("L898902C<", "690806", "940623");

    private static string Folder => Path.Combine(AppContext.BaseDirectory, "fixtures", "malformed");

    public static TheoryData<string, string> Inputs()
    {
        var data = new TheoryData<string, string>();
        foreach (string kind in Directory.GetDirectories(Folder).Select(d => Path.GetFileName(d)!).OrderBy(n => n, StringComparer.Ordinal))
        {
            foreach (string input in Directory.GetFiles(Path.Combine(Folder, kind)).Select(f => Path.GetFileName(f)!).OrderBy(n => n, StringComparer.Ordinal))
            {
                data.Add(kind, input);
            }
        }
        return data;
    }

    [Theory]
    [MemberData(nameof(Inputs))]
    public void malformedInputs(string kind, string input)
    {
        byte[] data = File.ReadAllBytes(Path.Combine(Folder, kind, input));
        switch (kind)
        {
            case "lds-file":
                CheckLdsFile(data);
                break;
            case "card-access-file":
                Expect(() => new CardAccessFile(new MemoryStream(data)).GetEncoded());
                break;
            case "card-security-file":
                Expect(() => new CardSecurityFile(new MemoryStream(data)).GetEncoded());
                break;
            case "face-info":
                Expect(() => new FaceInfo(new MemoryStream(data)).GetEncoded());
                break;
            case "finger-info":
                Expect(() => new FingerInfo(new MemoryStream(data)).GetEncoded());
                break;
            case "iris-info":
                Expect(() => new IrisInfo(new MemoryStream(data)).GetEncoded());
                break;
            case "mrz-text":
                CheckMrzText(data);
                break;
            case "cv-certificate":
                CheckCvCertificate(data);
                break;
            case "pace":
                CheckPace(Encoding.ASCII.GetString(data));
                break;
            default:
                throw new ArgumentException("Unknown kind of input: " + kind);
        }
    }

    /// <summary>Runs <paramref name="parse"/>; an <see cref="IOException"/> or <see cref="ArgumentException"/> is the
    /// expected outcome for malformed input, any other exception fails the test.</summary>
    private static void Expect(Action parse)
    {
        try
        {
            parse();
        }
        catch (Exception e) when (e is IOException or ArgumentException)
        {
            // Expected for malformed input.
        }
    }

    private static void CheckLdsFile(byte[] data)
    {
        if (data.Length < 1)
        {
            return;
        }
        short fid = LdsFids[data[0] % LdsFids.Length];
        Expect(() =>
        {
            AbstractLDSFile file = LDSFileUtil.GetLDSFile(fid, new MemoryStream(data, 1, data.Length - 1));
            file.GetEncoded();
            if (file is SODFile sod)
            {
                // The getters a verifier uses must not throw on a SOD that was read without an exception.
                sod.GetDataGroupHashes();
                sod.GetDigestAlgorithm();
                sod.GetLDSVersion();
                sod.GetUnicodeVersion();
            }
        });
    }

    /// <summary>MRZ text is rejected with an <see cref="ArgumentException"/>, or survives writing and reading again
    /// unchanged.</summary>
    private static void CheckMrzText(byte[] data)
    {
        MRZInfo mrzInfo;
        try
        {
            mrzInfo = new MRZInfo(Encoding.UTF8.GetString(data));
        }
        catch (ArgumentException)
        {
            return;
        }
        string once = mrzInfo.ToString();
        string twice = new MRZInfo(once).ToString();
        Assert.Equal(once, twice);
    }

    private static void CheckCvCertificate(byte[] data)
    {
        try
        {
            CardVerifiableCertificate certificate = CVCertificateFactorySpi.EngineGenerateCertificate(new MemoryStream(data));
            certificate.GetEncoded();
            _ = certificate.HolderReference;
            _ = certificate.AuthorityReference;
            _ = certificate.AuthorizationTemplate;
            _ = certificate.PublicKey;
            _ = certificate.NotBefore;
            _ = certificate.NotAfter;
        }
        catch (IOException)
        {
            // Expected for malformed input (Java: CertificateException).
        }
    }

    /// <summary>A PACE run against the chip responses in the input: lines "oid &lt;PACE OID&gt;", "param
    /// &lt;standardized domain parameter id&gt;" and "response &lt;hex&gt;", in order; when the responses run out,
    /// the chip is gone.</summary>
    private static void CheckPace(string script)
    {
        string? oid = null;
        int paramId = -1;
        var responses = new List<byte[]>();
        foreach (string line in script.Split('\n'))
        {
            string[] parts = line.Trim().Split(' ');
            switch (parts[0])
            {
                case "oid":
                    oid = parts[1];
                    break;
                case "param":
                    paramId = int.Parse(parts[1], System.Globalization.CultureInfo.InvariantCulture);
                    break;
                case "response":
                    responses.Add(Convert.FromHexString(parts[1]));
                    break;
            }
        }
        try
        {
            new PaceProtocol(new PACEAPDUSender(new ResponseScript(responses)), null, 256, true)
                .DoPace(PaceAccessKey, oid!, PACEInfo.ToParameterSpec(paramId), BigInteger.ValueOf(paramId));
        }
        catch (CardServiceException)
        {
            // Expected for malformed responses.
        }
    }

    private sealed class ResponseScript(List<byte[]> responses) : CardService
    {
        private int _index;

        public override ResponseApdu Transmit(CommandApdu commandApdu)
        {
            if (_index >= responses.Count)
            {
                throw new CardServiceException("No more responses");
            }
            return new ResponseApdu(responses[_index++]);
        }

        public override void Open()
        {
        }

        public override bool IsOpen => true;

        public override byte[] GetAtr() => [];

        public override bool IsConnectionLost(Exception exception) => false;

        public override void Close()
        {
        }
    }
}
