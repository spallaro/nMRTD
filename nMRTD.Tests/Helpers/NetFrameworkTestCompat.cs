#if NETFRAMEWORK

using System.Text;

namespace nMRTD.Tests.Helpers
{
    /// <summary>
    /// The members of the .NET 6+ base library that the tests use and .NET Framework 4.6.2/4.7.2 lacks, as extension
    /// members with the same names (the library's own ones are in <c>nMRTD.Compat</c>). Only compiled for .NET
    /// Framework.
    /// </summary>
    internal static class NetFrameworkTestCompat
    {
        extension(Enum)
        {
            public static T Parse<T>(string value) where T : struct => (T)Enum.Parse(typeof(T), value);

            public static T[] GetValues<T>() where T : struct => (T[])Enum.GetValues(typeof(T));
        }

        extension(Convert)
        {
            public static string ToHexString(byte[] inArray, int offset, int length) =>
                Convert.ToHexString(inArray.AsSpan(offset, length).ToArray());
        }

#if !NET472_OR_GREATER
        /// <summary>Enumerable.ToHashSet exists from .NET Framework 4.7.2.</summary>
        public static HashSet<T> ToHashSet<T>(this IEnumerable<T> source) => new(source);
#endif

        public static TValue? GetValueOrDefault<TKey, TValue>(this Dictionary<TKey, TValue> dictionary, TKey key) where TKey : notnull =>
            dictionary.TryGetValue(key, out TValue? value) ? value : default;

        public static void Deconstruct<TKey, TValue>(this KeyValuePair<TKey, TValue> pair, out TKey key, out TValue value)
        {
            key = pair.Key;
            value = pair.Value;
        }

        public static void NextBytes(this Random random, Span<byte> buffer)
        {
            byte[] bytes = new byte[buffer.Length];
            random.NextBytes(bytes);
            bytes.CopyTo(buffer);
        }
    }
}

namespace System.Runtime.CompilerServices
{
    /// <summary>
    /// <c>RuntimeHelpers.GetSubArray</c> (.NET Core 3.0), which the compiler needs for a range of an array
    /// (<c>bytes[8..12]</c>) and .NET Framework lacks. Declared in the tests only: the library slices spans, not
    /// arrays. It hides the framework's own <c>RuntimeHelpers</c> in this assembly (warning CS0436, suppressed in the
    /// project file), which the tests do not use otherwise.
    /// </summary>
    internal static class RuntimeHelpers
    {
        public static T[] GetSubArray<T>(T[] array, Range range)
        {
            (int offset, int length) = range.GetOffsetAndLength(array.Length);
            T[] result = new T[length];
            Array.Copy(array, offset, result, 0, length);
            return result;
        }
    }
}

#endif
