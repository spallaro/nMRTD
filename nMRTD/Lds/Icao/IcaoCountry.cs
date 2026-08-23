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

using nMRTD.SmartCards;

namespace nMRTD.Lds.Icao;

/// <summary>
/// Port of <c>org.jmrtd.lds.icao.ICAOCountry</c>: special ICAO countries not covered in
/// <c>net.sf.scuba.data.ISOCountry</c> / <see cref="nMRTD.SmartCards.Country"/>. Contributed by
/// Aleksandar Kamburov (wise_guybg).
///
/// The Java source subclasses <c>net.sf.scuba.data.Country</c> directly, overriding
/// <c>valueOf()</c>/<c>getName()</c>/<c>getNationality()</c>/<c>toAlpha2Code()</c>/<c>toAlpha3Code()</c>.
/// Phase 1's <see cref="nMRTD.SmartCards.Country"/> is a non-abstract <c>sealed class</c> (not designed
/// for subclassing -- see its own doc comment), so this is ported as a separate static lookup helper
/// that layers the ICAO-special-code table on top of <see cref="nMRTD.SmartCards.Country.GetInstance"/>
/// as a fallback, producing genuine <see cref="nMRTD.SmartCards.Country"/> instances for the special
/// codes too (via the <c>Country.Create</c> factory added to Phase 1 for this purpose). Lookup priority
/// is preserved exactly: ICAO-specific codes are scanned first, then the base ISO-3166-1 table.
/// </summary>
public static class IcaoCountry
{
    /// <summary>Germany's legacy MRZ code (pre-unification / older documents).</summary>
    public static readonly Country DE = Country.Create("DE", "D<<", -1, "Germany", "German");

    public static readonly Country RKS = Country.Create("KS", "RKS", -1, "Republic of Kosovo", "Kosovar");

    public static readonly Country GBD = Country.Create("GB", "GBD", -1, "British Dependent territories citizen");
    public static readonly Country GBN = Country.Create("GB", "GBN", -1, "British National (Overseas)");
    public static readonly Country GBO = Country.Create("GB", "GBO", -1, "British Overseas citizen");
    public static readonly Country GBP = Country.Create("GB", "GBP", -1, "British Protected person");
    public static readonly Country GBS = Country.Create("GB", "GBS", -1, "British Subject");

    public static readonly Country XXA = Country.Create("XX", "XXA", -1, "Stateless person", "Stateless");
    public static readonly Country XXB = Country.Create("XX", "XXB", -1, "Refugee", "Refugee");
    public static readonly Country XXC = Country.Create("XX", "XXC", -1, "Refugee (other)", "Refugee (other)");
    public static readonly Country XXX = Country.Create("XX", "XXX", -1, "Unspecified", "Unspecified");

    /// <summary>Part B: Europe.</summary>
    public static readonly Country EUE = Country.Create("EU", "EUE", -1, "Europe", "European");

    /// <summary>Part C: Codes for Use in United Nations Travel Documents.</summary>
    public static readonly Country UNO = Country.Create("UN", "UNO", -1, "United Nations Organization");
    public static readonly Country UNA = Country.Create("UN", "UNA", -1, "United Nations Agency");
    public static readonly Country UNK = Country.Create("UN", "UNK", -1, "United Nations Interim Administration Mission in Kosovo");

    /// <summary>Part D: Other issuing authorities.</summary>
    public static readonly Country XBA = Country.Create("XX", "XBA", -1, "African Development Bank (ADB)");
    public static readonly Country XIM = Country.Create("XX", "XIM", -1, "African Export-Import Bank (AFREXIM bank)");
    public static readonly Country XCC = Country.Create("XC", "XCC", -1, "Carribean Community or one of its emissaries (CARICOM)");
    public static readonly Country XCE = Country.Create("XX", "XCE", -1, "Council of Europe");
    public static readonly Country XCO = Country.Create("XX", "XCO", -1, "Common Market for Eastern an Southern Africa (COMESA)");
    public static readonly Country XEC = Country.Create("XX", "XEC", -1, "Economic Community of West African States (ECOWAS)");
    public static readonly Country XPO = Country.Create("XP", "XPO", -1, "International Criminal Police Organization (INTERPOL)");
    public static readonly Country XES = Country.Create("XX", "XES", -1, "Organization of Eastern Caribbean States (OECS)");
    public static readonly Country XMP = Country.Create("XX", "XMP", -1, "Parliamentary Assembly of the Mediterranean (PAM)");
    public static readonly Country XOM = Country.Create("XO", "XOM", -1, "Sovereign Military Order of Malta or one of its emissaries");
    public static readonly Country XDC = Country.Create("XX", "XDC", -1, "Southern African Development Community");

    /// <summary>
    /// NOTE: this mirrors JMRTD's own <c>VALUES</c> array exactly, including its omission of
    /// <see cref="XES"/>, <see cref="XMP"/>, and <see cref="XDC"/> from the lookup table below (those
    /// three fields exist in the Java source but are -- apparently by oversight -- never added to
    /// <c>VALUES</c>, so <c>ICAOCountry.getInstance("XES")</c> etc. fall through to the base ISO table
    /// and throw in upstream JMRTD too). Ported as-is for behavioral fidelity, not "fixed".
    /// </summary>
    private static readonly Country[] Values =
    [
        DE, RKS,
        GBD, GBN, GBO, GBP, GBS,
        XXA, XXB, XXC, XXX,
        EUE,
        UNO, UNA, UNK,
        XBA, XIM, XCC, XCO, XEC, XPO, XOM,
    ];

    /// <summary>Returns an ICAO country instance.</summary>
    /// <param name="alpha3Code">a three-digit ICAO country code</param>
    /// <exception cref="ArgumentException">if the code is not a recognized ICAO or ISO 3166-1 alpha-3 code</exception>
    public static Country GetInstance(string alpha3Code)
    {
        foreach (Country country in Values)
        {
            if (country.Alpha3Code == alpha3Code)
            {
                return country;
            }
        }

        try
        {
            return Country.GetInstance(alpha3Code);
        }
        catch (ArgumentException)
        {
            /* NOTE: ignore this exception if it's not a legal 3 digit code. */
        }

        throw new ArgumentException("Illegal ICAO country alpha 3 code " + alpha3Code);
    }
}
