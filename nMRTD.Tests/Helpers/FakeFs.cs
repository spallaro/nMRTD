using nMRTD.SmartCards;

namespace nMRTD.Tests.Helpers;

/// <summary>An in-memory file system that can return empty blocks on demand.</summary>
internal sealed class FakeFs(Dictionary<short, byte[]> files) : IFileSystemStructured
{
    private short _selected;

    /// <summary>Offsets at which the next read returns an empty block (once each).</summary>
    public HashSet<int> EmptyReadsAt { get; init; } = new();

    /// <summary>When set, every read returns an empty block.</summary>
    public bool AlwaysEmpty { get; init; }

    public SmartCards.FileInfo[] GetSelectedPath() => [new FakeFileInfo(_selected, files[_selected].Length)];

    public void SelectFile(short fid) => _selected = fid;

    public byte[] ReadBinary(int offset, int length)
    {
        if (AlwaysEmpty || EmptyReadsAt.Remove(offset)) return [];
        return files[_selected].Skip(offset).Take(length).ToArray();
    }

    private sealed class FakeFileInfo(short fid, int length) : SmartCards.FileInfo
    {
        public override short Fid => fid;
        public override int FileLength => length;
    }
}
