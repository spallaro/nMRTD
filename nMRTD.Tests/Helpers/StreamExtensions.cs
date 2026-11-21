namespace nMRTD.Tests.Helpers;

/// <summary>Java stream idioms used by the ported JMRTD tests.</summary>
internal static class StreamExtensions
{
    /// <summary>Java's <c>DataInputStream.readFully</c>: fills <paramref name="buffer"/> or throws at end of stream.</summary>
    public static void ReadFully(this Stream stream, byte[] buffer)
    {
        int offset = 0;
        while (offset < buffer.Length)
        {
            int read = stream.Read(buffer, offset, buffer.Length - offset);
            if (read <= 0)
            {
                throw new EndOfStreamException();
            }

            offset += read;
        }
    }
}
