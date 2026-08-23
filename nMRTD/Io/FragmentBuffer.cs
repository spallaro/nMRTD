/*
 * nMRTD - A .Net API for accessing Machine Readable Travel Documents.
 *
 * Copyright (C) Sebastiano Pallaro.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * This is a porting from jMRTD, Copyright (C) The jMRTD Team (https://jmrtd.org/).
 *
 * Distributed under the terms of GNU LGPL v3.
 * See LICENSE for more information.
 */

namespace nMRTD.Io;

/// <summary>
/// Port of <c>org.jmrtd.io.FragmentBuffer</c>. A buffer that can be partially filled; tracks which byte
/// ranges ("fragments") have actually been written so far, coalescing overlapping/adjacent fragments as
/// new ones are added.
/// </summary>
public class FragmentBuffer
{
    private const int DefaultSize = 2000;

    private readonly object _lock = new();

    /// <summary>Buffer with the actual bytes.</summary>
    private byte[] _buffer;

    /// <summary>Administration of which parts of buffer are filled.</summary>
    private readonly HashSet<Fragment> _fragments;

    /// <summary>Creates a fragment buffer with default size.</summary>
    public FragmentBuffer()
        : this(DefaultSize)
    {
    }

    /// <summary>Creates a fragment buffer.</summary>
    /// <param name="length">the length of the buffer</param>
    public FragmentBuffer(int length)
    {
        _buffer = new byte[length];
        _fragments = new HashSet<Fragment>();
    }

    /// <summary>Updates this buffer based on the given buffer.</summary>
    /// <param name="other">some other fragment buffer</param>
    public void UpdateFrom(FragmentBuffer other)
    {
        ArgumentNullException.ThrowIfNull(other);
        lock (_lock)
        {
            foreach (Fragment otherFragment in other._fragments)
            {
                AddFragment(otherFragment.Offset, other._buffer, otherFragment.Offset, otherFragment.Length);
            }
        }
    }

    /// <summary>Adds a fragment containing the given byte.</summary>
    /// <param name="offset">the offset</param>
    /// <param name="b">the byte to insert</param>
    public void AddFragment(int offset, byte b)
    {
        // NOTE: This can be done more efficiently for the common case resulting from InputStreamBuffer
        // reads: scan all fragments and extend a neighboring one.
        AddFragment(offset, new[] { b });
    }

    /// <summary>Adds a fragment of bytes at a specific offset to this file.</summary>
    /// <param name="offset">the fragment offset</param>
    /// <param name="bytes">the bytes from which fragment content will be copied</param>
    public void AddFragment(int offset, byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        AddFragment(offset, bytes, 0, bytes.Length);
    }

    /// <summary>Adds a fragment of bytes at a specific offset to this file.</summary>
    /// <param name="offset">the fragment offset</param>
    /// <param name="bytes">the bytes from which fragment contents will be copied</param>
    /// <param name="srcOffset">the offset within bytes where the contents of the fragment start</param>
    /// <param name="srcLength">the length of the fragment</param>
    public void AddFragment(int offset, byte[] bytes, int srcOffset, int srcLength)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        lock (_lock)
        {
            if (offset + srcLength > _buffer.Length)
            {
                SetLength(2 * Math.Max(offset + srcLength, _buffer.Length));
            }

            Array.Copy(bytes, srcOffset, _buffer, offset, srcLength);
            int thisOffset = offset;
            int thisLength = srcLength;
            List<Fragment> otherFragments = new(_fragments);
            foreach (Fragment other in otherFragments)
            {
                if (other.Offset <= thisOffset && thisOffset + thisLength <= other.Offset + other.Length)
                {
                    // [...other fragment.........]
                    //    [...this fragment...]
                    // This fragment is already contained in other. Don't add and return immediately.
                    return;
                }

                if (other.Offset <= thisOffset && thisOffset <= other.Offset + other.Length)
                {
                    // [...other fragment...]
                    //         [...this fragment...]
                    // This fragment is partially contained in other. Extend this fragment to size of other, remove other.
                    thisLength = thisOffset + thisLength - other.Offset;
                    thisOffset = other.Offset;
                    _fragments.Remove(other);
                }
                else if (thisOffset <= other.Offset && other.Offset + other.Length <= thisOffset + thisLength)
                {
                    //    [...other fragment...]
                    // [...this fragment...........]
                    // The other fragment is contained in this fragment. Remove other.
                    _fragments.Remove(other);
                }
                else if (thisOffset <= other.Offset && other.Offset <= thisOffset + thisLength)
                {
                    //        [...other fragment...]
                    // [...this fragment...]
                    // This fragment is partially contained in other. Extend this fragment to size of other, remove other.
                    thisLength = other.Offset + other.Length - thisOffset;
                    _fragments.Remove(other);
                }
            }

            _fragments.Add(Fragment.GetInstance(thisOffset, thisLength));
        }
    }

    /// <summary>
    /// Returns the position within the buffer. This is the upper limit of the farthest fragment read so far.
    /// </summary>
    /// <returns>the position within the buffer</returns>
    public int GetPosition()
    {
        lock (_lock)
        {
            int result = 0;
            for (int i = 0; i < _buffer.Length; i++)
            {
                if (IsCoveredByFragment(i))
                {
                    result = i + 1;
                }
            }

            return result;
        }
    }

    /// <summary>Returns the number of bytes currently buffered.</summary>
    /// <returns>the number of bytes currently buffered</returns>
    public int GetBytesBuffered()
    {
        lock (_lock)
        {
            int result = 0;
            for (int i = 0; i < _buffer.Length; i++)
            {
                if (IsCoveredByFragment(i))
                {
                    result++;
                }
            }

            return result;
        }
    }

    /// <summary>Checks whether the byte at the given offset is covered by a fragment.</summary>
    /// <param name="offset">the offset</param>
    /// <returns>a boolean indicating whether the byte at the given offset is covered</returns>
    public bool IsCoveredByFragment(int offset) => IsCoveredByFragment(offset, 1);

    /// <summary>Checks whether the segment specified by the given offset and length is completely covered by fragments.</summary>
    /// <param name="offset">the given offset</param>
    /// <param name="length">the given length</param>
    /// <returns>a boolean indicating whether the specified segment is fully covered</returns>
    public bool IsCoveredByFragment(int offset, int length)
    {
        lock (_lock)
        {
            foreach (Fragment fragment in _fragments)
            {
                int left = fragment.Offset;
                int right = fragment.Offset + fragment.Length;
                if (left <= offset && offset + length <= right)
                {
                    return true;
                }
            }

            return false;
        }
    }

    /// <summary>Calculates the number of bytes left in the buffer starting from the given index.</summary>
    /// <param name="index">the index</param>
    /// <returns>the number of bytes left in the buffer</returns>
    public int GetBufferedLength(int index)
    {
        lock (_lock)
        {
            int result = 0;
            if (index >= _buffer.Length)
            {
                return 0;
            }

            foreach (Fragment fragment in _fragments)
            {
                int left = fragment.Offset;
                int right = fragment.Offset + fragment.Length;
                if (left <= index && index < right)
                {
                    int newResult = right - index;
                    if (newResult > result)
                    {
                        result = newResult;
                    }
                }
            }

            return result;
        }
    }

    /// <summary>Returns the fragments of this buffer.</summary>
    /// <returns>the fragments</returns>
    public ICollection<Fragment> GetFragments() => _fragments;

    /// <summary>Returns the current buffer.</summary>
    /// <returns>the buffer</returns>
    public byte[] GetBuffer() => _buffer;

    /// <summary>Returns the buffer (the size of the underlying byte array).</summary>
    /// <returns>the size of the buffer</returns>
    public int GetLength()
    {
        lock (_lock)
        {
            return _buffer.Length;
        }
    }

    /// <summary>
    /// Returns the smallest fragment which, when added, makes the fragment buffer contain
    /// <c>offset</c> to <c>offset + length</c> that has <b>not</b> been buffered in this buffer.
    /// </summary>
    /// <param name="offset">the offset into the file</param>
    /// <param name="length">the length</param>
    /// <returns>the fragment that has not yet been buffered</returns>
    public Fragment GetSmallestUnbufferedFragment(int offset, int length)
    {
        lock (_lock)
        {
            int thisOffset = offset;
            int thisLength = length;
            foreach (Fragment other in _fragments)
            {
                if (other.Offset <= thisOffset && thisOffset + thisLength <= other.Offset + other.Length)
                {
                    // [...other fragment.........]
                    //    [...this fragment...]
                    // This fragment is already contained in other. Don't add and return immediately.
                    thisLength = 0; // NOTE: we don't care about offset
                    break;
                }

                if (other.Offset <= thisOffset && thisOffset < other.Offset + other.Length)
                {
                    // [...other fragment...]
                    //         [...this fragment...]
                    // This fragment is partially contained in other. Only fetch the trailing part of this fragment.
                    int newOffset = other.Offset + other.Length;
                    int newLength = thisOffset + thisLength - newOffset;
                    thisOffset = newOffset;
                    thisLength = newLength;
                }
                else if (thisOffset <= other.Offset && other.Offset + other.Length <= thisOffset + thisLength)
                {
                    //    [...other fragment...]
                    // [...this fragment...........]
                    // The other fragment is contained in this fragment. We send this fragment as is.
                    continue;
                }
                else if (offset <= other.Offset && other.Offset < thisOffset + thisLength)
                {
                    //        [...other fragment...]
                    // [...this fragment...]
                    // This fragment is partially contained in other. Only send the leading part of this fragment.
                    thisLength = other.Offset - thisOffset;
                }
            }

            return Fragment.GetInstance(thisOffset, thisLength);
        }
    }

    public override string ToString()
    {
        lock (_lock)
        {
            return $"FragmentBuffer [{_buffer.Length}, [{string.Join(", ", _fragments)}]]";
        }
    }

    public override bool Equals(object? otherObject)
    {
        lock (_lock)
        {
            if (otherObject is null)
            {
                return false;
            }

            if (ReferenceEquals(otherObject, this))
            {
                return true;
            }

            if (otherObject.GetType() != typeof(FragmentBuffer))
            {
                return false;
            }

            FragmentBuffer other = (FragmentBuffer)otherObject;
            return _buffer.AsSpan().SequenceEqual(other._buffer) && _fragments.SetEquals(other._fragments);
        }
    }

    public override int GetHashCode()
    {
        int arrayHashCode = 1;
        foreach (byte b in _buffer)
        {
            arrayHashCode = (31 * arrayHashCode) + (sbyte)b;
        }

        int fragmentsHashCode = 0;
        foreach (Fragment fragment in _fragments)
        {
            fragmentsHashCode += fragment.GetHashCode();
        }

        return (3 * arrayHashCode) + (2 * fragmentsHashCode) + 7;
    }

    /// <summary>
    /// Sets the capacity of the buffer. This has no effect for lengths smaller than the current buffer capacity.
    /// </summary>
    /// <param name="length">the proposed new capacity of the buffer</param>
    private void SetLength(int length)
    {
        lock (_lock)
        {
            if (length <= _buffer.Length)
            {
                return;
            }

            byte[] newBuffer = new byte[length];
            Array.Copy(_buffer, newBuffer, _buffer.Length);
            _buffer = newBuffer;
        }
    }

    /// <summary>Fragments encapsulate pairs of offset and length.</summary>
    public sealed class Fragment
    {
        /// <summary>Constructs a fragment.</summary>
        /// <param name="offset">the offset within the buffer</param>
        /// <param name="length">the length of the fragment</param>
        private Fragment(int offset, int length)
        {
            Offset = offset;
            Length = length;
        }

        /// <summary>Returns a fragment instance.</summary>
        /// <param name="offset">the offset within the buffer</param>
        /// <param name="length">the length of the fragment</param>
        /// <returns>the new fragment</returns>
        public static Fragment GetInstance(int offset, int length) => new(offset, length);

        /// <summary>This fragment's offset within the buffer.</summary>
        public int Offset { get; }

        /// <summary>The length of the fragment.</summary>
        public int Length { get; }

        public override string ToString() => $"[{Offset} .. {Offset + Length - 1} ({Length})]";

        public override bool Equals(object? otherObject)
        {
            if (otherObject is null)
            {
                return false;
            }

            if (ReferenceEquals(otherObject, this))
            {
                return true;
            }

            if (otherObject.GetType() != typeof(Fragment))
            {
                return false;
            }

            Fragment other = (Fragment)otherObject;
            return other.Offset == Offset && other.Length == Length;
        }

        public override int GetHashCode() => (2 * Offset) + (3 * Length) + 5;
    }
}
