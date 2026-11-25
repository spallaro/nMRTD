using nMRTD.Protocol;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;

namespace nMRTD.Tests.Jmrtd.Protocol;

/// <summary>
/// Port of JMRTD's <c>org.jmrtd.protocol.SecureMessagingAPDUSenderTest</c> (0.8.10, commit 6a0805b8): APDU
/// listeners only observe an exchange; a listener that throws must not change its outcome, which for instance
/// would prevent the fallback to short reads after a 6700.
/// </summary>
public class SecureMessagingAPDUSenderTest
{
    private static readonly CommandApdu Command = new(0x00, 0xB0, 0x00, 0x08, 256);

    private sealed class ThrowingListener : IApduListener
    {
        public void ExchangedApdu(ApduEvent apduEvent) => throw new NullReferenceException("listener failed");
    }

    private sealed class RecordingListener : IApduListener
    {
        public List<ApduEvent> Events { get; } = [];

        public void ExchangedApdu(ApduEvent apduEvent) => Events.Add(apduEvent);
    }

    [Fact]
    public void throwingListenerDoesNotHideWrongLengthUnderSecureMessaging()
    {
        var sender = new SecureMessagingAPDUSender(new ScriptedCardService(Response(Iso7816.SwWrongLength)));
        var events = new RecordingListener();
        sender.AddApduListener(new ThrowingListener());
        sender.AddApduListener(events);

        ResponseApdu response = sender.Transmit(SecureMessagingFixtures.NewWrapper(false), Command);

        Assert.Equal(Iso7816.SwWrongLength, (short)response.Sw);
        Assert.Single(events.Events);
        Assert.Null(((WrappedApduEvent)events.Events[0]).PlainTextResponseApdu);
    }

    [Fact]
    public void throwingListenerDoesNotHideCardServiceExceptionUnderSecureMessaging()
    {
        var sender = new SecureMessagingAPDUSender(new ScriptedCardService(Response(Iso7816.SwSecurityStatusNotSatisfied)));
        sender.AddApduListener(new ThrowingListener());

        var e = Assert.Throws<CardServiceException>(() => sender.Transmit(SecureMessagingFixtures.NewWrapper(false), Command));

        Assert.Equal(Iso7816.SwSecurityStatusNotSatisfied, (short)e.Sw);
    }

    [Fact]
    public void throwingListenerDoesNotHideResponseWithoutSecureMessaging()
    {
        var ok = new ResponseApdu([0x01, 0x02, 0x90, 0x00]);
        var sender = new SecureMessagingAPDUSender(new ScriptedCardService(ok));
        var events = new RecordingListener();
        sender.AddApduListener(new ThrowingListener());
        sender.AddApduListener(events);

        ResponseApdu response = sender.Transmit(null, Command);

        Assert.Same(ok, response);
        Assert.Single(events.Events);
    }

    private static ResponseApdu Response(short sw) => new([(byte)(sw >> 8), (byte)sw]);
}
