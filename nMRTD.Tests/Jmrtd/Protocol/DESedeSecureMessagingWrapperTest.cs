using nMRTD.Cert;
using nMRTD.Lds;
using nMRTD.Protocol;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace nMRTD.Tests.Jmrtd.Protocol;

/// <summary>Port of JMRTD's <c>org.jmrtd.protocol.DESedeSecureMessagingWrapperTest</c>.</summary>
public class DESedeSecureMessagingWrapperTest
{

    [Fact]
    public void testDESedeSecureMessagingWrapper()
    {
        KeyParameter encKey = GetRandomDESedeKey();
        KeyParameter macKey = GetRandomDESedeKey();
        SecureMessagingWrapper wrapper = new DESedeSecureMessagingWrapper(encKey, macKey, PassportService.NormalMaxTransceiveLength, true, 0L);

        Assert.Equal(encKey, wrapper.EncryptionKey);
        Assert.Equal(macKey, wrapper.MacKey);
    }

    [Fact]
    public void testDESedeSecureMessagingWrapperEquals()
    {
        KeyParameter encKey = GetRandomDESedeKey();
        KeyParameter macKey = GetRandomDESedeKey();
        SecureMessagingWrapper wrapper = new DESedeSecureMessagingWrapper(encKey, macKey, PassportService.NormalMaxTransceiveLength, true, 0L);
        SecureMessagingWrapper anotherWrapper = new DESedeSecureMessagingWrapper(encKey, macKey, PassportService.NormalMaxTransceiveLength, true, 0L);
        Assert.Equal(wrapper.GetHashCode(), anotherWrapper.GetHashCode());
        Assert.Equal(wrapper, anotherWrapper);
        Assert.Equal(wrapper.ToString(), anotherWrapper.ToString());
    }

    [Fact]
    public void testDESedeSecureMessagingWrapperWrapUnwrap()
    {
        KeyParameter encKey = GetRandomDESedeKey();
        KeyParameter macKey = GetRandomDESedeKey();
        SecureMessagingWrapper wrapper = new DESedeSecureMessagingWrapper(encKey, macKey, PassportService.NormalMaxTransceiveLength, true, 0L);

        CommandApdu commandAPDU = new CommandApdu(0x00, 0xA4, 0x00, 0x00, new byte[] { 0x3F, 0x00 }, 0x00);
        CommandApdu wrappedCommandAPDU = wrapper.Wrap(commandAPDU);

        Assert.NotNull(wrappedCommandAPDU);
        Assert.Equal(0x0C, wrappedCommandAPDU.Cla);
        Assert.Equal(commandAPDU.Ins, wrappedCommandAPDU.Ins);
        Assert.Equal(commandAPDU.P1, wrappedCommandAPDU.P1);
        Assert.Equal(commandAPDU.P2, wrappedCommandAPDU.P2);
    }

    /*
      * See https://stackoverflow.com/q/47307716/27190.
      */
    [Fact]
    public void testStackOverflowTim()
    {
        KeyParameter encKey = new KeyParameter(TestData.Hex("3DE649F8AEA41C04FB6D4CD9043757AD"));

        KeyParameter macKey = new KeyParameter(TestData.Hex("8C34AD61974F68CEBA3E0EAEA1456476"));
        SecureMessagingWrapper wrapper = new DESedeSecureMessagingWrapper(encKey, macKey, unchecked((long)0xAB1D2F337FD997D6UL) /* Java: 0x00AB1D2F337FD997D6L */);

        CommandApdu protectedCommandAPDU = wrapper.Wrap(new CommandApdu(TestData.Hex("00 A4 02 0C 02 01 1E")));
        Assert.Equal("0CA4020C15870901FF0E241E2F94B5088E0822FF803EC310433600", Hex.BytesToHexString(protectedCommandAPDU.GetBytes()));

        CommandApdu protectedReadBinaryCommandAPDU = wrapper.Wrap(new CommandApdu(TestData.Hex("00 B0 00 00 04")));
        Assert.Equal("0CB000000D9701048E0868DD9FD88472834A00", Hex.BytesToHexString(protectedReadBinaryCommandAPDU.GetBytes()));
    }

    /**
      * Confirms that {@code wrap()} and {@code unwrap()} still work (no NPE from
      * lost transient cipher/mac fields) after a Java serialization round trip.
      */
    [Fact]
    public void testUnwrapValidProtectedResponse()
    {
        KeyParameter encKey = new KeyParameter(TestData.Hex("00112233445566778899AABBCCDDEEFF0011223344556677"));
        KeyParameter macKey = new KeyParameter(TestData.Hex("1032547698BADCFE0123456789ABCDEF1032547698BADCFE"));
        DESedeSecureMessagingWrapper wrapper =
                new DESedeSecureMessagingWrapper(encKey, macKey, 256, true, 0L);
        ResponseApdu protectedResponse =
                CreateProtectedResponse(encKey, macKey, 1L, new byte[] { 1, 2, 3 }, 0x9000);

        ResponseApdu response = wrapper.Unwrap(protectedResponse);

        Assert.Equal(new byte[] { 1, 2, 3 }, response.Data);
        Assert.Equal(0x9000, response.Sw);
        Assert.Equal(1L, wrapper.SendSequenceCounter);
    }

    [Fact]
    public void testUnwrapRejectsTamperedMac()
    {
        KeyParameter encKey = new KeyParameter(TestData.Hex("00112233445566778899AABBCCDDEEFF0011223344556677"));
        KeyParameter macKey = new KeyParameter(TestData.Hex("1032547698BADCFE0123456789ABCDEF1032547698BADCFE"));
        DESedeSecureMessagingWrapper wrapper =
                new DESedeSecureMessagingWrapper(encKey, macKey, 256, true, 0L);
        byte[] bytes = CreateProtectedResponse(
                encKey, macKey, 1L, new byte[] { 1, 2, 3 }, 0x9000).GetBytes();
        bytes[bytes.Length - 3] ^= 0x01;
        ResponseApdu tamperedResponse = new ResponseApdu(bytes);

        Assert.ThrowsAny<InvalidOperationException>(() => wrapper.Unwrap(tamperedResponse));
    }

    /*
      * A DO'87 with an unsupported or negative long-form length is rejected like any other malformed response
      * (it was a NegativeArraySizeException, or an OutOfMemoryError for a huge length).
      */
    [Fact]
    public void testUnwrapRejectsBadDO87Length()
    {
        KeyParameter encKey = new KeyParameter(TestData.Hex("00112233445566778899AABBCCDDEEFF0011223344556677"));
        KeyParameter macKey = new KeyParameter(TestData.Hex("1032547698BADCFE0123456789ABCDEF1032547698BADCFE"));
        DESedeSecureMessagingWrapper wrapper =
                new DESedeSecureMessagingWrapper(encKey, macKey, 256, true, 0L);

        /* 0x80: no length bytes, so length 0, minus the 0x01 marker is -1. */
        ResponseApdu noLengthBytes = new ResponseApdu(TestData.Hex("87 80 01 90 00"));
        Assert.ThrowsAny<InvalidOperationException>(() => wrapper.Unwrap(noLengthBytes));

        /* Four length bytes FFFFFFFF, a negative length. */
        ResponseApdu negativeLength = new ResponseApdu(TestData.Hex("87 84 FF FF FF FF 01 90 00"));
        Assert.ThrowsAny<InvalidOperationException>(() => wrapper.Unwrap(negativeLength));

        /* Four length bytes 7FFFFFFF, a huge length. */
        ResponseApdu hugeLength = new ResponseApdu(TestData.Hex("87 84 7F FF FF FF 01 90 00"));
        Assert.ThrowsAny<InvalidOperationException>(() => wrapper.Unwrap(hugeLength));
    }

    /*
      * A tampered ciphertext fails on the MAC, before decryption (it used to be decrypted first,
      * so a padding error was reported instead of the MAC error).
      */
    [Fact]
    public void testUnwrapChecksMacBeforeDecrypting()
    {
        KeyParameter encKey = new KeyParameter(TestData.Hex("00112233445566778899AABBCCDDEEFF0011223344556677"));
        KeyParameter macKey = new KeyParameter(TestData.Hex("1032547698BADCFE0123456789ABCDEF1032547698BADCFE"));
        DESedeSecureMessagingWrapper wrapper =
                new DESedeSecureMessagingWrapper(encKey, macKey, 256, true, 0L);
        byte[] bytes = CreateProtectedResponse(
                encKey, macKey, 1L, new byte[] { 1, 2, 3 }, 0x9000).GetBytes();
        bytes[3 + 7] ^= 0x01; /* Last byte of the (single block) ciphertext, after 87 09 01. */
        ResponseApdu tamperedResponse = new ResponseApdu(bytes);

        InvalidOperationException e = Assert.ThrowsAny<InvalidOperationException>(() => wrapper.Unwrap(tamperedResponse));
        Assert.Equal("Invalid MAC", e.Message);
    }

    /*
      * An unknown data object is skipped as a whole (its value used to be parsed as data objects).
      */
    [Fact]
    public void testUnwrapSkipsUnknownDataObject()
    {
        KeyParameter encKey = new KeyParameter(TestData.Hex("00112233445566778899AABBCCDDEEFF0011223344556677"));
        KeyParameter macKey = new KeyParameter(TestData.Hex("1032547698BADCFE0123456789ABCDEF1032547698BADCFE"));
        DESedeSecureMessagingWrapper wrapper =
                new DESedeSecureMessagingWrapper(encKey, macKey, 256, true, 0L);
        /* The value of the unknown data object looks like a DO'8E (a bogus MAC). */
        ResponseApdu protectedResponse = CreateProtectedResponse(
                encKey, macKey, 1L, new byte[] { 1, 2, 3 }, TestData.Hex("AA 0A 8E 08 00 00 00 00 00 00 00 00"), 0x9000);

        ResponseApdu response = wrapper.Unwrap(protectedResponse);

        Assert.Equal(new byte[] { 1, 2, 3 }, response.Data);
        Assert.Equal(0x9000, response.Sw);
    }

    /*
      * DO'8E is the last data object: the MAC covers everything before it.
      */
    [Fact]
    public void testUnwrapRejectsDataAfterMac()
    {
        KeyParameter encKey = new KeyParameter(TestData.Hex("00112233445566778899AABBCCDDEEFF0011223344556677"));
        KeyParameter macKey = new KeyParameter(TestData.Hex("1032547698BADCFE0123456789ABCDEF1032547698BADCFE"));
        DESedeSecureMessagingWrapper wrapper =
                new DESedeSecureMessagingWrapper(encKey, macKey, 256, true, 0L);
        byte[] bytes = CreateProtectedResponse(
                encKey, macKey, 1L, new byte[] { 1, 2, 3 }, 0x9000).GetBytes();
        byte[] extended = new byte[bytes.Length + 2];
        Array.Copy(bytes, 0, extended, 0, bytes.Length - 2);
        extended[bytes.Length - 2] = (byte)0x99; /* Unauthenticated data after DO'8E... */
        extended[bytes.Length - 1] = 0x00;
        extended[extended.Length - 2] = (byte)0x90; /* ...then the status word. */
        ResponseApdu response = new ResponseApdu(extended);

        Assert.ThrowsAny<InvalidOperationException>(() => wrapper.Unwrap(response));
    }

    private static ResponseApdu CreateProtectedResponse(KeyParameter encKey, KeyParameter macKey,
            long ssc, byte[] data, int sw)
            {
        return CreateProtectedResponse(encKey, macKey, ssc, data, new byte[0], sw);
    }

    /*
      * As above, with extraDataObjects (covered by the MAC) between DO'87 and DO'99.
      */
    private static ResponseApdu CreateProtectedResponse(KeyParameter encKey, KeyParameter macKey,
            long ssc, byte[] data, byte[] extraDataObjects, int sw)
            {
        return ProtectedResponses.Create(false, encKey, macKey, ssc, data, extraDataObjects, 8, sw);
    }

    private static KeyParameter GetRandomDESedeKey()
    {
        return new KeyParameter(Org.BouncyCastle.Security.SecureRandom.GetNextBytes(new Org.BouncyCastle.Security.SecureRandom(), 24)); // Java: KeyGenerator "DESede"
    }
}
