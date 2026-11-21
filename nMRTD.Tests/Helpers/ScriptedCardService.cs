using nMRTD.SmartCards;

namespace nMRTD.Tests.Helpers;

/// <summary>
/// Port of JMRTD's test helper <c>org.jmrtd.ScriptedCardService</c>: a card service that answers each
/// command with the next scripted response and records the commands it was sent.
/// </summary>
internal class ScriptedCardService(params ResponseApdu[] responses) : CardService
{
    private readonly List<ResponseApdu> _responses = [.. responses];
    private readonly List<CommandApdu> _commands = [];
    private int _responseIndex;
    private bool _open;

    public int OpenCount { get; private set; }

    public int CloseCount { get; private set; }

    public override void Open()
    {
        _open = true;
        OpenCount++;
    }

    public override bool IsOpen => _open;

    public override ResponseApdu Transmit(CommandApdu commandApdu)
    {
        _commands.Add(commandApdu);
        if (_responseIndex >= _responses.Count)
        {
            throw new CardServiceException("No scripted response for command " + _commands.Count);
        }

        return _responses[_responseIndex++];
    }

    public override byte[] GetAtr() => [0x3B, 0x00];

    public override bool IsConnectionLost(Exception e) => false;

    public override void Close()
    {
        _open = false;
        CloseCount++;
    }

    public List<CommandApdu> GetCommands() => [.. _commands];

    public int GetOpenCount() => OpenCount;

    public int GetCloseCount() => CloseCount;
}
