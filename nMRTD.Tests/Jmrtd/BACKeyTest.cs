namespace nMRTD.Tests.Jmrtd;

/// <summary>Port of JMRTD's <c>org.jmrtd.BACKeyTest</c>.</summary>
public class BACKeyTest
{
    [Fact]
    public void testBACKey()
    {
        string documentNumber = "123456789";
        string dateOfBirthString = "710121";
        string dateOfExpiryString = "310309";
        var bacKey = new BacKey(documentNumber, dateOfBirthString, dateOfExpiryString);
        Assert.Equal("BAC", bacKey.GetAlgorithm());
        Assert.Equal(documentNumber, bacKey.GetDocumentNumber());
        Assert.Equal(dateOfBirthString, bacKey.GetDateOfBirth());
        Assert.Equal(dateOfExpiryString, bacKey.GetDateOfExpiry());
    }

    [Fact]
    public void testBACKeyNoNull()
    {
        string documentNumber = "123456789";
        string dateOfBirthString = "710121";
        string dateOfExpiryString = "310309";

        // Cannot use null for document number
        Assert.ThrowsAny<Exception>(() => new BacKey(null!, dateOfBirthString, dateOfExpiryString));

        // Cannot use null for date of birth
        Assert.ThrowsAny<Exception>(() => new BacKey(documentNumber, null!, dateOfExpiryString));

        // Cannot use null for date of expiry
        Assert.ThrowsAny<Exception>(() => new BacKey(documentNumber, dateOfBirthString, null!));
    }

    [Fact]
    public void testBACKeyEquals()
    {
        string documentNumber = "123456789";
        string dateOfBirthString = "710121";
        string dateOfExpiryString = "310309";
        var bacKey = new BacKey(documentNumber, dateOfBirthString, dateOfExpiryString);
        var anotherBACKey = new BacKey(documentNumber, dateOfBirthString, dateOfExpiryString);
        Assert.Equal(bacKey.GetHashCode(), anotherBACKey.GetHashCode());
        Assert.Equal(bacKey, anotherBACKey);
        Assert.Equal(bacKey.ToString(), anotherBACKey.ToString());
    }

    [Fact]
    public void testBACKeyDates()
    {
        var bacKey = new BacKey("123456789", new DateTime(1971, 1, 21), new DateTime(2031, 3, 9));
        Assert.Equal("710121", bacKey.GetDateOfBirth());
        Assert.Equal("310309", bacKey.GetDateOfExpiry());
    }

    [Fact]
    public void testBACKeyShortDocumentNumber()
    {
        string dateOfBirthString = "710121";
        string dateOfExpiryString = "310309";
        Assert.Equal("123456789", new BacKey("123456789", dateOfBirthString, dateOfExpiryString).GetDocumentNumber());
        Assert.Equal("12345678<", new BacKey("12345678", dateOfBirthString, dateOfExpiryString).GetDocumentNumber());
        Assert.Equal("1234567<<", new BacKey("1234567", dateOfBirthString, dateOfExpiryString).GetDocumentNumber());
        Assert.Equal("123456<<<", new BacKey("123456", dateOfBirthString, dateOfExpiryString).GetDocumentNumber());
        Assert.Equal("12345<<<<", new BacKey("12345", dateOfBirthString, dateOfExpiryString).GetDocumentNumber());
        Assert.Equal("1234<<<<<", new BacKey("1234", dateOfBirthString, dateOfExpiryString).GetDocumentNumber());
        Assert.Equal("123<<<<<<", new BacKey("123", dateOfBirthString, dateOfExpiryString).GetDocumentNumber());
        Assert.Equal("12<<<<<<<", new BacKey("12", dateOfBirthString, dateOfExpiryString).GetDocumentNumber());
        Assert.Equal("1<<<<<<<<", new BacKey("1", dateOfBirthString, dateOfExpiryString).GetDocumentNumber());
        Assert.Equal("<<<<<<<<<", new BacKey("", dateOfBirthString, dateOfExpiryString).GetDocumentNumber());

        Assert.Equal("123456789", new BacKey("123456789", dateOfBirthString, dateOfExpiryString).GetDocumentNumber());
        Assert.Equal("12345678<", new BacKey("12345678<", dateOfBirthString, dateOfExpiryString).GetDocumentNumber());
        Assert.Equal("1234567<<", new BacKey("1234567<<", dateOfBirthString, dateOfExpiryString).GetDocumentNumber());
        Assert.Equal("123456<<<", new BacKey("123456<<<", dateOfBirthString, dateOfExpiryString).GetDocumentNumber());
        Assert.Equal("12345<<<<", new BacKey("12345<<<<", dateOfBirthString, dateOfExpiryString).GetDocumentNumber());
        Assert.Equal("1234<<<<<", new BacKey("1234<<<<<", dateOfBirthString, dateOfExpiryString).GetDocumentNumber());
        Assert.Equal("123<<<<<<", new BacKey("123<<<<<<", dateOfBirthString, dateOfExpiryString).GetDocumentNumber());
        Assert.Equal("12<<<<<<<", new BacKey("12<<<<<<<", dateOfBirthString, dateOfExpiryString).GetDocumentNumber());
        Assert.Equal("1<<<<<<<<", new BacKey("1<<<<<<<<", dateOfBirthString, dateOfExpiryString).GetDocumentNumber());
        Assert.Equal("<<<<<<<<<", new BacKey("<<<<<<<<<", dateOfBirthString, dateOfExpiryString).GetDocumentNumber());
    }

    [Fact]
    public void testBACKeyLongDocumentNumber()
    {
        string dateOfBirthString = "710121";
        string dateOfExpiryString = "310309";
        Assert.Equal("1234567890", new BacKey("1234567890", dateOfBirthString, dateOfExpiryString).GetDocumentNumber());
    }
}
