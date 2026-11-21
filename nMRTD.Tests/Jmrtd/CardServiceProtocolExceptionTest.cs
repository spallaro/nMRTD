using nMRTD.SmartCards;

namespace nMRTD.Tests.Jmrtd;

/// <summary>Port of JMRTD's <c>org.jmrtd.CardServiceProtocolExceptionTest</c>.</summary>
public class CardServiceProtocolExceptionTest
{
    [Fact]
    public void testMessageAndStepConstructor()
    {
        var exception = new CardServiceProtocolException("Something failed", 3);
        Assert.Equal(3, exception.Step);
        Assert.Equal("Something failed (step: 3)", exception.Message);
        Assert.Null(exception.InnerException);
    }

    [Fact]
    public void testMessageStepAndCauseConstructor()
    {
        Exception cause = new InvalidOperationException("root cause");
        var exception = new CardServiceProtocolException("Something failed", 2, cause);
        Assert.Equal(2, exception.Step);
        Assert.Equal("Something failed (step: 2)", exception.Message);
        Assert.Same(cause, exception.InnerException);
    }

    [Fact]
    public void testMessageStepAndStatusWordConstructor()
    {
        var exception = new CardServiceProtocolException("Something failed", 1, 0x6300);
        Assert.Equal(1, exception.Step);

        /*
         * CardServiceException.getMessage() itself already folds the status word into the
         * message; CardServiceProtocolException layers the step suffix on top of whatever that
         * produces, so only pin down that part here.
         */
        Assert.StartsWith("Something failed", exception.Message);
        Assert.EndsWith(" (step: 1)", exception.Message);
        Assert.Equal(0x6300, exception.Sw);
        Assert.Null(exception.InnerException);
    }

    [Fact]
    public void testMessageStepCauseAndStatusWordConstructor()
    {
        Exception cause = new InvalidOperationException("root cause");
        var exception = new CardServiceProtocolException("Something failed", 4, cause, 0x6A88);
        Assert.Equal(4, exception.Step);
        Assert.StartsWith("Something failed", exception.Message);
        Assert.EndsWith(" (step: 4)", exception.Message);
        Assert.Same(cause, exception.InnerException);
        Assert.Equal(0x6A88, exception.Sw);
    }

    [Fact]
    public void testIsCardServiceException()
    {
        var exception = new CardServiceProtocolException("msg", 0);
        Assert.IsAssignableFrom<CardServiceException>(exception);
    }

    [Fact]
    public void testDifferentStepsProduceDifferentMessages()
    {
        var step1 = new CardServiceProtocolException("Failed", 1);
        var step2 = new CardServiceProtocolException("Failed", 2);
        Assert.NotEqual(step1.Message, step2.Message);
    }
}
