using nMRTD.SmartCards;

namespace nMRTD.Tests.Helpers;

/// <summary>A card service whose responses are computed by a function of the command APDU.</summary>
internal sealed class FakeCard(Func<CommandApdu, byte[]> respond) : CardService
{
    public override void Open() { }
    public override bool IsOpen => true;
    public override ResponseApdu Transmit(CommandApdu c) => new(respond(c));
    public override byte[] GetAtr() => [];
    public override bool IsConnectionLost(Exception e) => false;
    public override void Close() { }
}
