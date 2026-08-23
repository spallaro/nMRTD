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

namespace nMRTD.SmartCards;

/// <summary>
/// Port of <c>net.sf.scuba.tlv.TLVOutputStream</c>: BER-TLV writer over a wrapped <see cref="Stream"/>,
/// with the incremental tag/length-backpatching state machine JMRTD relies on for LDS file generation:
/// <c>WriteTag</c> is followed by either one <c>WriteValue(byte[])</c> call, or any number of
/// <c>Write(byte[])</c> calls followed by one <c>WriteValueEnd()</c>. Because the underlying
/// <see cref="Stream"/> is not assumed to be seekable, each open tag buffers its value bytes into an
/// internal <see cref="MemoryStream"/> (a stack frame, so nesting works); on close (via
/// <c>WriteValue</c> or <c>WriteValueEnd</c>) the frame's length is computed from the buffered byte
/// count and tag+length+value is emitted -- to the parent frame's buffer if nested, otherwise straight
/// to the underlying stream.
/// </summary>
public sealed class TlvOutputStream : IDisposable
{
    private sealed class Frame
    {
        public Frame(int tag)
        {
            Tag = tag;
        }

        public int Tag { get; }

        public MemoryStream Buffer { get; } = new();
    }

    private readonly Stream _stream;
    private readonly bool _leaveOpen;
    private readonly Stack<Frame> _stack = new();

    public TlvOutputStream(Stream stream, bool leaveOpen = false)
    {
        _stream = stream ?? throw new ArgumentNullException(nameof(stream));
        _leaveOpen = leaveOpen;
    }

    public void WriteTag(int tag)
    {
        _stack.Push(new Frame(tag));
    }

    /// <summary>
    /// Rarely used directly by JMRTD (WriteValue normally computes/writes the length itself). This
    /// implementation always derives the BER-TLV length from the buffered value on frame close, so an
    /// explicit WriteLength is only a range check here, not an eager emission -- the buffered/backpatch
    /// design (see class remarks) produces correct output regardless of whether the caller pre-declares
    /// a length, and doing so avoids a second, non-buffered "known length" write mode.
    /// </summary>
    public void WriteLength(int length)
    {
        if (length < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(length));
        }
    }

    public void WriteValue(byte[] value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (_stack.Count == 0)
        {
            throw new InvalidOperationException("WriteTag() must be called before WriteValue().");
        }
        Frame frame = _stack.Peek();
        frame.Buffer.Write(value, 0, value.Length);
        CloseFrame();
    }

    /// <summary>Finalizes a TLV whose value was streamed incrementally via <see cref="Write(byte[])"/>.</summary>
    public void WriteValueEnd()
    {
        if (_stack.Count == 0)
        {
            throw new InvalidOperationException("No open TLV to end.");
        }
        CloseFrame();
    }

    /// <summary>
    /// Appends bytes to the value of the currently open tag (streaming mode). With no open tag, this is
    /// a raw passthrough write of already-encoded bytes straight to the underlying stream, matching
    /// scuba's <c>OutputStream</c> parity contract.
    /// </summary>
    public void Write(byte[] bytes) => Write(bytes, 0, bytes.Length);

    public void Write(byte[] bytes, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        if (_stack.Count == 0)
        {
            _stream.Write(bytes, offset, count);
            return;
        }
        _stack.Peek().Buffer.Write(bytes, offset, count);
    }

    public void Flush() => _stream.Flush();

    private void CloseFrame()
    {
        Frame frame = _stack.Pop();
        byte[] value = frame.Buffer.ToArray();
        byte[] encoded = TlvUtil.TlvEncode(frame.Tag, value);
        if (_stack.Count == 0)
        {
            _stream.Write(encoded, 0, encoded.Length);
        }
        else
        {
            _stack.Peek().Buffer.Write(encoded, 0, encoded.Length);
        }
    }

    public void Dispose()
    {
        // Any still-open frames indicate incomplete/misused writes; they were never meant to reach the
        // wire, so this is intentionally not a "flush what's pending" best-effort close.
        foreach (Frame frame in _stack)
        {
            frame.Buffer.Dispose();
        }
        if (!_leaveOpen)
        {
            _stream.Dispose();
        }
    }
}
