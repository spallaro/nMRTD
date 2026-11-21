using nMRTD.Cert;
using nMRTD.Lds;
using nMRTD.Protocol;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace nMRTD.Tests.Jmrtd.Protocol;

/// <summary>Port of JMRTD's <c>org.jmrtd.protocol.BACResultTest</c>.</summary>
/**
  * Test cases for BACResult, the result of the BAC protocol.
  *
  * @author The JMRTD team (info@jmrtd.org)
  *
  * @version $Revision$
  *
  * @since 0.6.2
  */
public class BACResultTest
{

    [Fact]
    public void testBACResult()
    {
        BACResult bacResult = new BACResult(new BacKey("123456789", "700101", "171108"), new DESedeSecureMessagingWrapper(GetRandomDESedeKey(), GetRandomDESedeKey(), PassportService.NormalMaxTransceiveLength, true, 0L));
        IAccessKeySpec? bacKey = bacResult.BacKey;
        Assert.NotNull(bacKey);
        Assert.Equal(new BacKey("123456789", "700101", "171108"), bacKey);

        SecureMessagingWrapper wrapper = bacResult.Wrapper;
        Assert.NotNull(wrapper);

    }

    [Fact]
    public void testBACResultEquals()
    {
        KeyParameter encKey = GetRandomDESedeKey();
        KeyParameter macKey = GetRandomDESedeKey();
        BACResult bacResult = new BACResult(new BacKey("123456789", "700101", "171108"), new DESedeSecureMessagingWrapper(encKey, macKey, PassportService.NormalMaxTransceiveLength, true, 0L));
        BACResult anotherBACResult = new BACResult(new BacKey("123456789", "700101", "171108"), new DESedeSecureMessagingWrapper(encKey, macKey, PassportService.NormalMaxTransceiveLength, true, 0L));
        Assert.Equal(bacResult.GetHashCode(), anotherBACResult.GetHashCode());
        Assert.Equal(bacResult, anotherBACResult);
        Assert.Equal(bacResult.ToString(), anotherBACResult.ToString());
    }

    private static KeyParameter GetRandomDESedeKey()
    {
        return new KeyParameter(Org.BouncyCastle.Security.SecureRandom.GetNextBytes(new Org.BouncyCastle.Security.SecureRandom(), 24)); // Java: KeyGenerator "DESede"
    }
}
