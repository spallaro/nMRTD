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

using Org.BouncyCastle.Asn1;

namespace nMRTD.Lds.Iso39794;

//  DateTimeBlock ::= SEQUENCE {
//    year          [0] Year,
//    month         [1] Month          OPTIONAL,
//    day           [2] Day            OPTIONAL,
//    hour          [3] Hour           OPTIONAL,
//    minute        [4] Minute         OPTIONAL,
//    second        [5] Second         OPTIONAL,
//    millisecond   [6] Millisecond    OPTIONAL
//  }

//  Year ::= INTEGER (0..9999)
//
//  Month ::= INTEGER (1..12)
//
//  Day ::= INTEGER (1..31)
//
//  Hour ::= INTEGER (0..23)
//
//  Minute ::= INTEGER (0..59)
//
//  Second ::= INTEGER (0..59)
//
//  Millisecond ::= INTEGER (0..999)

/// <summary>
/// Port of <c>org.jmrtd.lds.iso39794.DateTimeBlock</c>. Java's <c>Serializable</c> marker is dropped (no
/// reflection-based serialization is needed in this port).
///
/// NOTE: matching Java exactly, the OPTIONAL fields (everything but <see cref="GetYear"/>) use a
/// primitive-<c>int</c>-with-<c>-1</c>-sentinel convention rather than <c>int?</c>, since Java's own
/// accessors return primitive <c>int</c> (not <c>Integer</c>) here -- kept as-is for a faithful 1:1 port
/// of this public API surface.
/// </summary>
public class DateTimeBlock : Block
{
    private readonly int _year;
    private readonly int _month;
    private readonly int _day;
    private readonly int _hour;
    private readonly int _minute;
    private readonly int _second;
    private readonly int _millisecond;

    public DateTimeBlock(int year, int month, int day, int hour, int minute, int second, int millisecond)
    {
        _year = year;
        _month = month;
        _day = day;
        _hour = hour;
        _minute = minute;
        _second = second;
        _millisecond = millisecond;
    }

    internal DateTimeBlock(Asn1Encodable asn1Encodable)
    {
        Dictionary<int, Asn1Encodable> taggedObjects = ASN1Util.DecodeTaggedObjects(asn1Encodable);
        _year = ASN1Util.DecodeInt(taggedObjects[0]);
        _month = taggedObjects.TryGetValue(1, out Asn1Encodable? month) ? ASN1Util.DecodeInt(month) : -1;
        _day = taggedObjects.TryGetValue(2, out Asn1Encodable? day) ? ASN1Util.DecodeInt(day) : -1;
        _hour = taggedObjects.TryGetValue(3, out Asn1Encodable? hour) ? ASN1Util.DecodeInt(hour) : -1;
        _minute = taggedObjects.TryGetValue(4, out Asn1Encodable? minute) ? ASN1Util.DecodeInt(minute) : -1;
        _second = taggedObjects.TryGetValue(5, out Asn1Encodable? second) ? ASN1Util.DecodeInt(second) : -1;
        _millisecond = taggedObjects.TryGetValue(6, out Asn1Encodable? millisecond) ? ASN1Util.DecodeInt(millisecond) : -1;
    }

    public int GetYear() => _year;

    public int GetMonth() => _month;

    public int GetDay() => _day;

    public int GetHour() => _hour;

    public int GetMinute() => _minute;

    public int GetSecond() => _second;

    public int GetMillisecond() => _millisecond;

    public override int GetHashCode() => HashCode.Combine(_day, _hour, _millisecond, _minute, _month, _second, _year);

    public override bool Equals(object? other)
    {
        if (ReferenceEquals(this, other))
        {
            return true;
        }
        if (other == null || GetType() != other.GetType())
        {
            return false;
        }

        var otherBlock = (DateTimeBlock)other;
        return _year == otherBlock._year
            && _month == otherBlock._month
            && _day == otherBlock._day
            && _hour == otherBlock._hour
            && _minute == otherBlock._minute
            && _second == otherBlock._second
            && _millisecond == otherBlock._millisecond;
    }

    public override string ToString() =>
        "DateTimeBlock ["
        + $"year: {_year}"
        + $", month: {_month}"
        + $", day: {_day}"
        + $", hour: {_hour}"
        + $", minute: {_minute}"
        + $", second: {_second}"
        + $", millisecond: {_millisecond}"
        + "]";

    /* PACKAGE */

    internal override Asn1Encodable GetAsn1Object()
    {
        var taggedObjects = new Dictionary<int, Asn1Encodable>
        {
            [0] = ASN1Util.EncodeInt(_year),
        };
        if (_month >= 0)
        {
            taggedObjects[1] = ASN1Util.EncodeInt(_month);
        }
        if (_day >= 0)
        {
            taggedObjects[2] = ASN1Util.EncodeInt(_day);
        }
        if (_hour >= 0)
        {
            taggedObjects[3] = ASN1Util.EncodeInt(_hour);
        }
        if (_minute >= 0)
        {
            taggedObjects[4] = ASN1Util.EncodeInt(_minute);
        }
        if (_second >= 0)
        {
            taggedObjects[5] = ASN1Util.EncodeInt(_second);
        }
        if (_millisecond >= 0)
        {
            taggedObjects[6] = ASN1Util.EncodeInt(_millisecond);
        }
        return ASN1Util.EncodeTaggedObjects(taggedObjects)!;
    }
}
