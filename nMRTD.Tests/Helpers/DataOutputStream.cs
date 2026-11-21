namespace nMRTD.Tests.Helpers;

/// <summary>Java's big-endian <c>DataOutputStream</c>, used by the ported JMRTD tests to build inputs.</summary>
internal sealed class DataOutputStream(Stream output) : IDisposable
{
    public void WriteInt(int value)
    {
        output.WriteByte((byte)(value >> 24));
        output.WriteByte((byte)(value >> 16));
        output.WriteByte((byte)(value >> 8));
        output.WriteByte((byte)value);
    }

    public void WriteShort(int value)
    {
        output.WriteByte((byte)(value >> 8));
        output.WriteByte((byte)value);
    }

    public void WriteByte(int value) => output.WriteByte((byte)value);

    public void WriteLong(long value)
    {
        WriteInt((int)(value >> 32));
        WriteInt((int)value);
    }

    public void Write(byte[] bytes) => output.Write(bytes, 0, bytes.Length);

    public void Flush() => output.Flush();

    public void Close() => output.Flush();

    public void Dispose() => Close();
}
