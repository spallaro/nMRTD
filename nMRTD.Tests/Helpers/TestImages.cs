namespace nMRTD.Tests.Helpers;

/// <summary>
/// Image bytes for the ported JMRTD tests. JMRTD encodes blank images of a given size with Java's
/// ImageIO; .NET has no built-in encoder, and the LDS classes treat the image as opaque bytes (width and
/// height are passed separately), so a fixed JPEG stands in for all of them.
/// </summary>
internal static class TestImages
{
    /// <summary>A minimal 1x1 baseline JPEG.</summary>
    private static readonly byte[] MinimalJpeg = Convert.FromBase64String(
        "/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////"
        + "wAALCAABAAEBAREA/8QAJgABAAAAAAAAAAAAAAAAAAAAAxABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQAAPwBH/9k=");

    /// <summary>
    /// A valid 1x1 JPEG padded with a comment segment to about the size of ImageIO's smallest output, as some
    /// JMRTD tests copy the first 256 bytes of an encoded data group.
    /// </summary>
    public static byte[] TrivialJpeg
    {
        get
        {
            const int commentLength = 512;
            var jpeg = new byte[MinimalJpeg.Length + 2 + commentLength];
            jpeg[0] = 0xFF; // SOI
            jpeg[1] = 0xD8;
            jpeg[2] = 0xFF; // COM
            jpeg[3] = 0xFE;
            jpeg[4] = (byte)(commentLength >> 8);
            jpeg[5] = (byte)(commentLength & 0xFF);
            for (int i = 6; i < 2 + 2 + commentLength; i++)
            {
                jpeg[i] = (byte)' ';
            }

            Array.Copy(MinimalJpeg, 2, jpeg, 2 + 2 + commentLength, MinimalJpeg.Length - 2);
            return jpeg;
        }
    }
}
