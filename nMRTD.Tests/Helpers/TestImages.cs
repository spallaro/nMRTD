namespace nMRTD.Tests.Helpers;

/// <summary>
/// Image bytes for the ported JMRTD tests. JMRTD encodes blank images of a given size with Java's
/// ImageIO; .NET has no built-in encoder, and the LDS classes treat the image as opaque bytes (width and
/// height are passed separately), so a fixed minimal JPEG stands in for all of them.
/// </summary>
internal static class TestImages
{
    /// <summary>A minimal 1x1 baseline JPEG.</summary>
    public static byte[] TrivialJpeg => Convert.FromBase64String(
        "/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////"
        + "wAALCAABAAEBAREA/8QAJgABAAAAAAAAAAAAAAAAAAAAAxABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQAAPwBH/9k=");
}
