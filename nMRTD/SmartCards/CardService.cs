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
/// Port of <c>net.sf.scuba.smartcards.CardService</c> (abstract class, not an interface — confirmed by
/// JMRTD's own <c>FileSystemCardService</c>/<c>AbstractMRTDCardService</c>/<c>PassportService</c>
/// inheritance chain). <see cref="Transmit"/> is the single low-level I/O method; every concrete
/// implementation must call <see cref="NotifyExchangedApdu"/> after each raw transmit so that
/// listeners (e.g. JMRTD's own secure-messaging APDU sender) can observe the raw exchange.
/// </summary>
public abstract class CardService : IDisposable
{
    private readonly List<IApduListener> _apduListeners = new();

    public abstract void Open();

    public abstract bool IsOpen { get; }

    public abstract ResponseApdu Transmit(CommandApdu commandApdu);

    public abstract byte[] GetAtr();

    public abstract bool IsConnectionLost(Exception exception);

    public abstract void Close();

    public virtual void AddApduListener(IApduListener listener)
    {
        ArgumentNullException.ThrowIfNull(listener);
        lock (_apduListeners)
        {
            _apduListeners.Add(listener);
        }
    }

    public virtual void RemoveApduListener(IApduListener listener)
    {
        ArgumentNullException.ThrowIfNull(listener);
        lock (_apduListeners)
        {
            _apduListeners.Remove(listener);
        }
    }

    public virtual IReadOnlyCollection<IApduListener> ApduListeners
    {
        get
        {
            lock (_apduListeners)
            {
                return _apduListeners.ToArray();
            }
        }
    }

    /// <summary>
    /// Notifies listeners about an APDU event. <c>virtual</c> (unlike a plain <c>protected</c> helper)
    /// because <see cref="AbstractMRTDCardService"/>'s concrete subclass (<c>PassportService</c>) overrides
    /// the listener registry itself (delegating to a shared <c>SecureMessagingAPDUSender</c>, see
    /// <c>AddApduListener</c>/<c>RemoveApduListener</c>/<c>ApduListeners</c> above) and needs its override
    /// of this method to notify through that shared registry too, matching Java's own overridable
    /// <c>notifyExchangedAPDU</c> contract.
    /// </summary>
    protected virtual void NotifyExchangedApdu(ApduEvent apduEvent)
    {
        ArgumentNullException.ThrowIfNull(apduEvent);
        IApduListener[] snapshot;
        lock (_apduListeners)
        {
            snapshot = _apduListeners.ToArray();
        }
        foreach (IApduListener listener in snapshot)
        {
            listener.ExchangedApdu(apduEvent);
        }
    }

    public void Dispose()
    {
        Close();
        GC.SuppressFinalize(this);
    }
}
