using nMRTD.Cert;
using nMRTD.Lds;
using nMRTD.Protocol;
using nMRTD.SmartCards;
using nMRTD.Tests.Helpers;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace nMRTD.Tests.Jmrtd.Protocol;

/// <summary>Port of JMRTD's <c>org.jmrtd.protocol.AESSecureMessagingWrapperTest</c>.</summary>
public class AESSecureMessagingWrapperTest
{

    [Fact]
    public void testAESSecureMessagingWrapper()
    {
        KeyParameter encKey = GetRandomAESKey();
        KeyParameter macKey = GetRandomAESKey();
        SecureMessagingWrapper wrapper = new AESSecureMessagingWrapper(encKey, macKey, 256, true, 0L);

        Assert.Equal(encKey, wrapper.EncryptionKey);
        Assert.Equal(macKey, wrapper.MacKey);
    }

    [Fact]
    public void testAESSecureMessagingWrapperEquals()
    {
        KeyParameter encKey = GetRandomAESKey();
        KeyParameter macKey = GetRandomAESKey();
        SecureMessagingWrapper wrapper = new AESSecureMessagingWrapper(encKey, macKey, 256, true, 0L);
        SecureMessagingWrapper anotherWrapper = new AESSecureMessagingWrapper(encKey, macKey, 0L);
        Assert.Equal(wrapper.GetHashCode(), anotherWrapper.GetHashCode());
        Assert.Equal(wrapper, anotherWrapper);
        Assert.Equal(wrapper.ToString(), anotherWrapper.ToString());
    }

    [Fact]
    public void testAESSecureMessagingWrapperWrapUnwrap()
    {
        KeyParameter encKey = GetRandomAESKey();
        KeyParameter macKey = GetRandomAESKey();
        SecureMessagingWrapper wrapper = new AESSecureMessagingWrapper(encKey, macKey, 256, true, 0L);

        CommandApdu commandAPDU = new CommandApdu(0x00, 0xA4, 0x00, 0x00, new byte[] { 0x3F, 0x00 }, 0x00);
        CommandApdu wrappedCommandAPDU = wrapper.Wrap(commandAPDU);

        Assert.NotNull(wrappedCommandAPDU);
        Assert.Equal(0x0C, wrappedCommandAPDU.Cla);
        Assert.Equal(commandAPDU.Ins, wrappedCommandAPDU.Ins);
        Assert.Equal(commandAPDU.P1, wrappedCommandAPDU.P1);
        Assert.Equal(commandAPDU.P2, wrappedCommandAPDU.P2);
    }

    /**
      * Confirms that {@code wrap()} and {@code unwrap()} still work (no NPE from
      * lost transient cipher/mac/sscIVCipher fields) after a Java serialization
      * round trip.
      */
    [Fact]
    public void testUnwrapValidProtectedResponse()
    {
        KeyParameter encKey = new KeyParameter(TestData.Hex("00112233445566778899AABBCCDDEEFF"));
        KeyParameter macKey = new KeyParameter(TestData.Hex("1032547698BADCFE0123456789ABCDEF"));
        AESSecureMessagingWrapper wrapper =
                new AESSecureMessagingWrapper(encKey, macKey, 256, true, 0L);
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
        KeyParameter encKey = new KeyParameter(TestData.Hex("00112233445566778899AABBCCDDEEFF"));
        KeyParameter macKey = new KeyParameter(TestData.Hex("1032547698BADCFE0123456789ABCDEF"));
        AESSecureMessagingWrapper wrapper =
                new AESSecureMessagingWrapper(encKey, macKey, 256, true, 0L);
        byte[] bytes = CreateProtectedResponse(
                encKey, macKey, 1L, new byte[] { 1, 2, 3 }, 0x9000).GetBytes();
        bytes[bytes.Length - 3] ^= 0x01;
        ResponseApdu tamperedResponse = new ResponseApdu(bytes);

        Assert.ThrowsAny<InvalidOperationException>(() => wrapper.Unwrap(tamperedResponse));
    }

    /*
      * A DO'87 with an unsupported or negative long-form length is rejected like any other malformed response.
      */
    [Fact]
    public void testUnwrapRejectsBadDO87Length()
    {
        KeyParameter encKey = new KeyParameter(TestData.Hex("00112233445566778899AABBCCDDEEFF"));
        KeyParameter macKey = new KeyParameter(TestData.Hex("1032547698BADCFE0123456789ABCDEF"));
        AESSecureMessagingWrapper wrapper =
                new AESSecureMessagingWrapper(encKey, macKey, 256, true, 0L);

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
      * A tampered ciphertext fails on the MAC, before decryption (not with a padding error).
      */
    [Fact]
    public void testUnwrapChecksMacBeforeDecrypting()
    {
        KeyParameter encKey = new KeyParameter(TestData.Hex("00112233445566778899AABBCCDDEEFF"));
        KeyParameter macKey = new KeyParameter(TestData.Hex("1032547698BADCFE0123456789ABCDEF"));
        AESSecureMessagingWrapper wrapper =
                new AESSecureMessagingWrapper(encKey, macKey, 256, true, 0L);
        byte[] bytes = CreateProtectedResponse(
                encKey, macKey, 1L, new byte[] { 1, 2, 3 }, 0x9000).GetBytes();
        bytes[3 + 15] ^= 0x01; /* Last byte of the (single block) ciphertext, after 87 11 01. */
        ResponseApdu tamperedResponse = new ResponseApdu(bytes);

        InvalidOperationException e = Assert.ThrowsAny<InvalidOperationException>(() => wrapper.Unwrap(tamperedResponse));
        Assert.Equal("Invalid MAC", e.Message);
    }

    /*
      * An unknown data object is skipped as a whole (its value is not parsed as data objects).
      */
    [Fact]
    public void testUnwrapSkipsUnknownDataObject()
    {
        KeyParameter encKey = new KeyParameter(TestData.Hex("00112233445566778899AABBCCDDEEFF"));
        KeyParameter macKey = new KeyParameter(TestData.Hex("1032547698BADCFE0123456789ABCDEF"));
        AESSecureMessagingWrapper wrapper =
                new AESSecureMessagingWrapper(encKey, macKey, 256, true, 0L);
        /* The value of the unknown data object looks like a DO'8E (a bogus MAC). */
        ResponseApdu protectedResponse = CreateProtectedResponse(
                encKey, macKey, 1L, new byte[] { 1, 2, 3 }, TestData.Hex("AA 0A 8E 08 00 00 00 00 00 00 00 00"), 8, 0x9000);

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
        KeyParameter encKey = new KeyParameter(TestData.Hex("00112233445566778899AABBCCDDEEFF"));
        KeyParameter macKey = new KeyParameter(TestData.Hex("1032547698BADCFE0123456789ABCDEF"));
        AESSecureMessagingWrapper wrapper =
                new AESSecureMessagingWrapper(encKey, macKey, 256, true, 0L);
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

    /*
      * The full (untruncated) 16 byte AES-CMAC in DO'8E is accepted, and the MAC input
      * ends before DO'8E (offset from the actual MAC length, not from 8).
      */
    [Fact]
    public void testUnwrapAcceptsFullLengthMac()
    {
        KeyParameter encKey = new KeyParameter(TestData.Hex("00112233445566778899AABBCCDDEEFF"));
        KeyParameter macKey = new KeyParameter(TestData.Hex("1032547698BADCFE0123456789ABCDEF"));
        AESSecureMessagingWrapper wrapper =
                new AESSecureMessagingWrapper(encKey, macKey, 256, true, 0L);
        ResponseApdu protectedResponse = CreateProtectedResponse(
                encKey, macKey, 1L, new byte[] { 1, 2, 3 }, new byte[0], 16, 0x9000);

        ResponseApdu response = wrapper.Unwrap(protectedResponse);

        Assert.Equal(new byte[] { 1, 2, 3 }, response.Data);
        Assert.Equal(0x9000, response.Sw);
    }

    [Fact]
    public void testUnwrapRejectsTamperedFullLengthMac()
    {
        KeyParameter encKey = new KeyParameter(TestData.Hex("00112233445566778899AABBCCDDEEFF"));
        KeyParameter macKey = new KeyParameter(TestData.Hex("1032547698BADCFE0123456789ABCDEF"));
        AESSecureMessagingWrapper wrapper =
                new AESSecureMessagingWrapper(encKey, macKey, 256, true, 0L);
        byte[] bytes = CreateProtectedResponse(
                encKey, macKey, 1L, new byte[] { 1, 2, 3 }, new byte[0], 16, 0x9000).GetBytes();
        bytes[bytes.Length - 3] ^= 0x01; /* Last byte of the MAC, beyond the 8 byte truncation. */
        ResponseApdu tamperedResponse = new ResponseApdu(bytes);

        Assert.ThrowsAny<InvalidOperationException>(() => wrapper.Unwrap(tamperedResponse));
    }

    /*
      * The SSC is part of the MAC input (and of the IV), so a response replayed
      * after the counter moved on is rejected.
      */
    [Fact]
    public void testUnwrapRejectsReplayedResponse()
    {
        KeyParameter encKey = new KeyParameter(TestData.Hex("00112233445566778899AABBCCDDEEFF"));
        KeyParameter macKey = new KeyParameter(TestData.Hex("1032547698BADCFE0123456789ABCDEF"));
        AESSecureMessagingWrapper wrapper =
                new AESSecureMessagingWrapper(encKey, macKey, 256, true, 0L);
        ResponseApdu protectedResponse =
                CreateProtectedResponse(encKey, macKey, 1L, new byte[] { 1, 2, 3 }, 0x9000);

        wrapper.Unwrap(protectedResponse);
        Assert.ThrowsAny<InvalidOperationException>(() => wrapper.Unwrap(protectedResponse));
    }

    /*
      * A response protected for a later SSC (e.g. a skipped command) is rejected.
      */
    [Fact]
    public void testUnwrapRejectsResponseForWrongSendSequenceCounter()
    {
        KeyParameter encKey = new KeyParameter(TestData.Hex("00112233445566778899AABBCCDDEEFF"));
        KeyParameter macKey = new KeyParameter(TestData.Hex("1032547698BADCFE0123456789ABCDEF"));
        AESSecureMessagingWrapper wrapper =
                new AESSecureMessagingWrapper(encKey, macKey, 256, true, 0L);
        ResponseApdu protectedResponse =
                CreateProtectedResponse(encKey, macKey, 2L, new byte[] { 1, 2, 3 }, 0x9000);

        InvalidOperationException e = Assert.ThrowsAny<InvalidOperationException>(() => wrapper.Unwrap(protectedResponse));
        Assert.Equal("Invalid MAC", e.Message);
    }

    /*
      * Builds a TR-SAC style protected response APDU (DO'87, DO'99, DO'8E) for
      * the given send sequence counter, mirroring what AESSecureMessagingWrapper
      * itself computes: the IV is E(K_Enc, SSC), see ICAO SAC TR Section 4.6.3.
      */
    private static ResponseApdu CreateProtectedResponse(KeyParameter encKey, KeyParameter macKey,
            long ssc, byte[] data, int sw)
            {
        return CreateProtectedResponse(encKey, macKey, ssc, data, new byte[0], 8, sw);
    }

    /*
      * As above, with extraDataObjects (covered by the MAC) between DO'87 and DO'99,
      * and the first macLength bytes of the CMAC in DO'8E.
      */
    private static ResponseApdu CreateProtectedResponse(KeyParameter encKey, KeyParameter macKey,
            long ssc, byte[] data, byte[] extraDataObjects, int macLength, int sw)
            {
        return ProtectedResponses.Create(true, encKey, macKey, ssc, data, extraDataObjects, macLength, sw);
    }


    private static KeyParameter GetRandomAESKey()
    {
        return new KeyParameter(Org.BouncyCastle.Security.SecureRandom.GetNextBytes(new Org.BouncyCastle.Security.SecureRandom(), 16)); // Java: KeyGenerator "AES"
    }
}

