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

using PCSC;
using PCSC.Exceptions;

namespace nMRTD.SmartCards;

/// <summary>
/// New concrete <see cref="CardService"/> implementation (no JMRTD/scuba Java source to mirror) that
/// provides cross-platform (Windows/Linux/macOS) PC/SC smart-card access via the <c>PCSC</c> NuGet
/// package. Keeps this project's only reference to <c>PCSC.*</c> confined to this one file, per the
/// porting convention that the rest of the library only ever sees the <see cref="CardService"/>
/// abstraction.
///
/// Deliberately minimal: a synchronous establish-context -&gt; connect -&gt; transmit -&gt; disconnect flow.
/// Reader/card removal events and T=0 GET RESPONSE chaining are left as call sites' responsibility (the
/// higher <c>nMRTD</c> protocol layer already needs to handle GET RESPONSE chaining regardless of
/// transport, since JMRTD's own APDU senders do), not implemented as a transport-level feature here.
/// </summary>
public sealed class PcscCardService : CardService
{
    private readonly string? _readerName;

    private ISCardContext? _context;
    private ICardReader? _reader;
    private int _sequenceNumber;

    /// <param name="readerName">
    /// The PC/SC reader name to connect to, or <see langword="null"/> to use the first reader reported
    /// by the PC/SC resource manager at <see cref="Open"/> time. Use <see cref="GetReaderNames"/> to
    /// enumerate available readers up front.
    /// </param>
    public PcscCardService(string? readerName = null)
    {
        _readerName = readerName;
    }

    /// <summary>Enumerates the smart-card reader names currently known to the PC/SC resource manager.</summary>
    public static string[] GetReaderNames()
    {
        try
        {
            using ISCardContext context = ContextFactory.Instance.Establish(SCardScope.System);
            return context.GetReaders();
        }
        catch (PCSCException ex)
        {
            throw new CardServiceException("Failed to enumerate PC/SC readers: " + ex.Message, ex);
        }
    }

    public override bool IsOpen => _reader is { IsConnected: true };

    public override void Open()
    {
        if (IsOpen)
        {
            return;
        }

        try
        {
            _context = ContextFactory.Instance.Establish(SCardScope.System);
            string readerName = _readerName ?? SelectFirstReader(_context);
            // SCardProtocol.Any: accept whatever protocol (T=0 or T=1) the reader negotiates --
            // contactless readers commonly report T=1, but this should not be hardcoded.
            _reader = _context.ConnectReader(readerName, SCardShareMode.Shared, SCardProtocol.Any);
        }
        catch (PCSCException ex)
        {
            CloseInternal();
            throw new CardServiceException("Failed to open PC/SC connection: " + ex.Message, ex);
        }
    }

    private static string SelectFirstReader(ISCardContext context)
    {
        string[] readers = context.GetReaders();
        if (readers.Length == 0)
        {
            throw new CardServiceException("No PC/SC smart card readers are available.");
        }
        return readers[0];
    }

    public override ResponseApdu Transmit(CommandApdu commandApdu)
    {
        ArgumentNullException.ThrowIfNull(commandApdu);
        if (_reader is null)
        {
            throw new CardServiceException("Card service is not open.");
        }

        byte[] commandBytes = commandApdu.GetBytes();
        // Sized generously for the extended-length response (up to 65536 bytes of data + SW1 SW2) that
        // large LDS files (e.g. DG2 facial images) can require; PCSC.ICardReader.Transmit needs a
        // caller-sized receive buffer up front, it does not grow one for us.
        byte[] receiveBuffer = new byte[65538];
        int received;
        try
        {
            received = _reader.Transmit(commandBytes, receiveBuffer);
        }
        catch (PCSCException ex)
        {
            throw new CardServiceException("APDU transmit failed: " + ex.Message, ex);
        }

        byte[] responseBytes = new byte[received];
        Array.Copy(receiveBuffer, responseBytes, received);
        var responseApdu = new ResponseApdu(responseBytes);
        NotifyExchangedApdu(new ApduEvent(this, "RAW", _sequenceNumber++, commandApdu, responseApdu));
        return responseApdu;
    }

    public override byte[] GetAtr()
    {
        if (_reader is null)
        {
            throw new CardServiceException("Card service is not open.");
        }
        try
        {
            return _reader.GetStatus().GetAtr();
        }
        catch (PCSCException ex)
        {
            throw new CardServiceException("Failed to read ATR: " + ex.Message, ex);
        }
    }

    public override bool IsConnectionLost(Exception exception)
    {
        for (Exception? current = exception; current is not null; current = current.InnerException)
        {
            if (current is PCSCException pcscException)
            {
                return pcscException.SCardError switch
                {
                    SCardError.RemovedCard => true,
                    SCardError.ResetCard => true,
                    SCardError.NoSmartcard => true,
                    SCardError.UnpoweredCard => true,
                    SCardError.UnresponsiveCard => true,
                    SCardError.ReaderUnavailable => true,
                    SCardError.NoService => true,
                    SCardError.Shutdown => true,
                    SCardError.InvalidHandle => true,
                    _ => false,
                };
            }
        }
        return false;
    }

    public override void Close() => CloseInternal();

    private void CloseInternal()
    {
        if (_reader is not null)
        {
            try
            {
                _reader.Disconnect(SCardReaderDisposition.Reset);
            }
            catch (PCSCException)
            {
                // Best-effort: the card or reader may already be gone.
            }
            _reader.Dispose();
            _reader = null;
        }

        if (_context is not null)
        {
            _context.Dispose();
            _context = null;
        }
    }
}
