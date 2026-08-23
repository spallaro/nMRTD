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

namespace nMRTD.SmartCards;

/// <summary>
/// Port of <c>net.sf.scuba.data.Country</c>: the standard ISO 3166-1 country table (alpha-2, alpha-3,
/// numeric-3, English short name), looked up by alpha-3 code exactly as JMRTD's own
/// <c>ICAOCountry.getInstance</c> falls back to it for every code that isn't one of ICAO's ~29 special
/// MRZ codes (D&lt;&lt;, XXA, EUE, RKS, ...). This is the base ISO-3166-1 table only -- those ICAO-specific
/// extra codes are layered on top by a separate type during the later <c>lds/icao</c> porting phase, not
/// implemented here.
///
/// Modelled as a single non-abstract sealed class (no need to mirror Java's abstract-subclass split),
/// backed by one static readonly table built once at type-init time (no reflection, no per-call
/// allocation) -- fully AOT-safe.
/// </summary>
public sealed class Country
{
    public string Alpha2Code { get; }

    public string Alpha3Code { get; }

    public int NumericCode { get; }

    public string Name { get; }

    private readonly string? _nationality;

    /// <summary>
    /// Judgment call: mechanically deriving an English nationality/demonym adjective from ~249 country
    /// names is unreliable (irregular forms like "Dutch", "Batswana", "Emirati" cannot be produced by a
    /// simple suffix rule, and a wrong guess reads as silly). Per the porting spec's own guidance,
    /// falling back to the country name itself is the correct, simple choice here rather than a
    /// large hand-typed table of adjectives that risks being wrong.
    ///
    /// The one exception is the ICAO-specific extra codes layered on top by <c>nMRTD.Lds.Icao.IcaoCountry</c>
    /// (Germany's legacy "D&lt;&lt;", stateless/refugee codes, etc.) -- those come with an explicit
    /// nationality string from ICAO Doc 9303 itself (via <see cref="Create"/>), not a guess, so it is
    /// used verbatim instead of falling back to <see cref="Name"/>.
    /// </summary>
    public string Nationality => _nationality ?? Name;

    private Country(string alpha2Code, string alpha3Code, int numericCode, string name, string? nationality = null)
    {
        Alpha2Code = alpha2Code;
        Alpha3Code = alpha3Code;
        NumericCode = numericCode;
        Name = name;
        _nationality = nationality;
    }

    /// <summary>
    /// Factory for country instances outside the base ISO-3166-1 table -- used by
    /// <c>nMRTD.Lds.Icao.IcaoCountry</c> to construct its ~29 ICAO-specific extra codes (Germany's legacy
    /// "D&lt;&lt;", Kosovo, UK sub-nationalities, stateless/refugee codes, EU, UN bodies, international
    /// organizations). Mirrors JMRTD's <c>ICAOCountry</c> private constructor plus its
    /// <c>valueOf()</c> override (always -1 for these, per JMRTD): pass <paramref name="numericCode"/> as
    /// -1 for such synthetic codes since they have no real ISO 3166-1 numeric-3 assignment.
    /// </summary>
    public static Country Create(string alpha2Code, string alpha3Code, int numericCode, string name, string? nationality = null)
    {
        ArgumentNullException.ThrowIfNull(alpha2Code);
        ArgumentNullException.ThrowIfNull(alpha3Code);
        ArgumentNullException.ThrowIfNull(name);
        return new Country(alpha2Code, alpha3Code, numericCode, name, nationality);
    }

    /// <summary>ICAOCountry.valueOf() (JMRTD's extra-codes subclass) always returns -1; the base ISO
    /// table has real ISO 3166-1 numeric-3 codes, returned here.</summary>
    public int ValueOf() => NumericCode;

    public string ToAlpha2Code() => Alpha2Code;

    public string ToAlpha3Code() => Alpha3Code;

    public override string ToString() => Alpha3Code;

    /// <summary>Throws <see cref="ArgumentException"/> on an unknown code (JMRTD's ICAOCountry.getInstance wraps and re-throws similarly).</summary>
    public static Country GetInstance(string alpha3Code)
    {
        ArgumentNullException.ThrowIfNull(alpha3Code);
        if (ByAlpha3.TryGetValue(alpha3Code, out Country? country))
        {
            return country;
        }
        throw new ArgumentException($"Unknown ISO 3166-1 alpha-3 country code: \"{alpha3Code}\".", nameof(alpha3Code));
    }

    /// <summary>
    /// Alpha-2 counterpart of <see cref="GetInstance"/>, needed by <c>nMRTD.Cert.CVCPrincipal</c> (CV
    /// certificate CAR/CHR reference fields are 2-letter country codes, unlike MRZ data which is alpha-3)
    /// -- mirrors <c>net.sf.scuba.data.Country.getInstance</c> being called with a 2-character code at that
    /// call site. Throws <see cref="ArgumentException"/> on an unknown code, same contract as <see cref="GetInstance"/>.
    /// </summary>
    public static Country GetInstanceByAlpha2(string alpha2Code)
    {
        ArgumentNullException.ThrowIfNull(alpha2Code);
        if (ByAlpha2.TryGetValue(alpha2Code, out Country? country))
        {
            return country;
        }
        throw new ArgumentException($"Unknown ISO 3166-1 alpha-2 country code: \"{alpha2Code}\".", nameof(alpha2Code));
    }

    /// <summary>
    /// Placeholder for an unrecognized country code, mirroring <c>CVCPrincipal.getCountry()</c>'s
    /// catch-and-substitute anonymous <c>Country</c> subclass in JMRTD (valueOf() -1, name/nationality
    /// "Unknown", alpha-2 the original unrecognized code, alpha-3 "XXX"). Not registered in the lookup
    /// tables -- it exists only to be returned directly to the caller.
    /// </summary>
    public static Country CreateUnknown(string alpha2Code)
    {
        ArgumentNullException.ThrowIfNull(alpha2Code);
        return new Country(alpha2Code, "XXX", -1, "Unknown");
    }

    private static readonly Country[] All = BuildTable();

    private static readonly Dictionary<string, Country> ByAlpha3 = BuildAlpha3Index(All);

    private static readonly Dictionary<string, Country> ByAlpha2 = BuildAlpha2Index(All);

    private static Dictionary<string, Country> BuildAlpha3Index(Country[] all)
    {
        var index = new Dictionary<string, Country>(all.Length, StringComparer.Ordinal);
        foreach (Country country in all)
        {
            index[country.Alpha3Code] = country;
        }
        return index;
    }

    private static Dictionary<string, Country> BuildAlpha2Index(Country[] all)
    {
        var index = new Dictionary<string, Country>(all.Length, StringComparer.Ordinal);
        foreach (Country country in all)
        {
            index[country.Alpha2Code] = country;
        }
        return index;
    }

    private static Country[] BuildTable() => new[]
    {
        new Country("AD", "AND", 20, "Andorra"),
        new Country("AE", "ARE", 784, "United Arab Emirates"),
        new Country("AF", "AFG", 4, "Afghanistan"),
        new Country("AG", "ATG", 28, "Antigua and Barbuda"),
        new Country("AI", "AIA", 660, "Anguilla"),
        new Country("AL", "ALB", 8, "Albania"),
        new Country("AM", "ARM", 51, "Armenia"),
        new Country("AO", "AGO", 24, "Angola"),
        new Country("AQ", "ATA", 10, "Antarctica"),
        new Country("AR", "ARG", 32, "Argentina"),
        new Country("AS", "ASM", 16, "American Samoa"),
        new Country("AT", "AUT", 40, "Austria"),
        new Country("AU", "AUS", 36, "Australia"),
        new Country("AW", "ABW", 533, "Aruba"),
        new Country("AX", "ALA", 248, "Åland Islands"),
        new Country("AZ", "AZE", 31, "Azerbaijan"),
        new Country("BA", "BIH", 70, "Bosnia and Herzegovina"),
        new Country("BB", "BRB", 52, "Barbados"),
        new Country("BD", "BGD", 50, "Bangladesh"),
        new Country("BE", "BEL", 56, "Belgium"),
        new Country("BF", "BFA", 854, "Burkina Faso"),
        new Country("BG", "BGR", 100, "Bulgaria"),
        new Country("BH", "BHR", 48, "Bahrain"),
        new Country("BI", "BDI", 108, "Burundi"),
        new Country("BJ", "BEN", 204, "Benin"),
        new Country("BL", "BLM", 652, "Saint Barthélemy"),
        new Country("BM", "BMU", 60, "Bermuda"),
        new Country("BN", "BRN", 96, "Brunei Darussalam"),
        new Country("BO", "BOL", 68, "Bolivia (Plurinational State of)"),
        new Country("BQ", "BES", 535, "Bonaire, Sint Eustatius and Saba"),
        new Country("BR", "BRA", 76, "Brazil"),
        new Country("BS", "BHS", 44, "Bahamas"),
        new Country("BT", "BTN", 64, "Bhutan"),
        new Country("BV", "BVT", 74, "Bouvet Island"),
        new Country("BW", "BWA", 72, "Botswana"),
        new Country("BY", "BLR", 112, "Belarus"),
        new Country("BZ", "BLZ", 84, "Belize"),
        new Country("CA", "CAN", 124, "Canada"),
        new Country("CC", "CCK", 166, "Cocos (Keeling) Islands"),
        new Country("CD", "COD", 180, "Congo, Democratic Republic of the"),
        new Country("CF", "CAF", 140, "Central African Republic"),
        new Country("CG", "COG", 178, "Congo"),
        new Country("CH", "CHE", 756, "Switzerland"),
        new Country("CI", "CIV", 384, "Côte d'Ivoire"),
        new Country("CK", "COK", 184, "Cook Islands"),
        new Country("CL", "CHL", 152, "Chile"),
        new Country("CM", "CMR", 120, "Cameroon"),
        new Country("CN", "CHN", 156, "China"),
        new Country("CO", "COL", 170, "Colombia"),
        new Country("CR", "CRI", 188, "Costa Rica"),
        new Country("CU", "CUB", 192, "Cuba"),
        new Country("CV", "CPV", 132, "Cabo Verde"),
        new Country("CW", "CUW", 531, "Curaçao"),
        new Country("CX", "CXR", 162, "Christmas Island"),
        new Country("CY", "CYP", 196, "Cyprus"),
        new Country("CZ", "CZE", 203, "Czechia"),
        new Country("DE", "DEU", 276, "Germany"),
        new Country("DJ", "DJI", 262, "Djibouti"),
        new Country("DK", "DNK", 208, "Denmark"),
        new Country("DM", "DMA", 212, "Dominica"),
        new Country("DO", "DOM", 214, "Dominican Republic"),
        new Country("DZ", "DZA", 12, "Algeria"),
        new Country("EC", "ECU", 218, "Ecuador"),
        new Country("EE", "EST", 233, "Estonia"),
        new Country("EG", "EGY", 818, "Egypt"),
        new Country("EH", "ESH", 732, "Western Sahara"),
        new Country("ER", "ERI", 232, "Eritrea"),
        new Country("ES", "ESP", 724, "Spain"),
        new Country("ET", "ETH", 231, "Ethiopia"),
        new Country("FI", "FIN", 246, "Finland"),
        new Country("FJ", "FJI", 242, "Fiji"),
        new Country("FK", "FLK", 238, "Falkland Islands (Malvinas)"),
        new Country("FM", "FSM", 583, "Micronesia (Federated States of)"),
        new Country("FO", "FRO", 234, "Faroe Islands"),
        new Country("FR", "FRA", 250, "France"),
        new Country("GA", "GAB", 266, "Gabon"),
        new Country("GB", "GBR", 826, "United Kingdom of Great Britain and Northern Ireland"),
        new Country("GD", "GRD", 308, "Grenada"),
        new Country("GE", "GEO", 268, "Georgia"),
        new Country("GF", "GUF", 254, "French Guiana"),
        new Country("GG", "GGY", 831, "Guernsey"),
        new Country("GH", "GHA", 288, "Ghana"),
        new Country("GI", "GIB", 292, "Gibraltar"),
        new Country("GL", "GRL", 304, "Greenland"),
        new Country("GM", "GMB", 270, "Gambia"),
        new Country("GN", "GIN", 324, "Guinea"),
        new Country("GP", "GLP", 312, "Guadeloupe"),
        new Country("GQ", "GNQ", 226, "Equatorial Guinea"),
        new Country("GR", "GRC", 300, "Greece"),
        new Country("GS", "SGS", 239, "South Georgia and the South Sandwich Islands"),
        new Country("GT", "GTM", 320, "Guatemala"),
        new Country("GU", "GUM", 316, "Guam"),
        new Country("GW", "GNB", 624, "Guinea-Bissau"),
        new Country("GY", "GUY", 328, "Guyana"),
        new Country("HK", "HKG", 344, "Hong Kong"),
        new Country("HM", "HMD", 334, "Heard Island and McDonald Islands"),
        new Country("HN", "HND", 340, "Honduras"),
        new Country("HR", "HRV", 191, "Croatia"),
        new Country("HT", "HTI", 332, "Haiti"),
        new Country("HU", "HUN", 348, "Hungary"),
        new Country("ID", "IDN", 360, "Indonesia"),
        new Country("IE", "IRL", 372, "Ireland"),
        new Country("IL", "ISR", 376, "Israel"),
        new Country("IM", "IMN", 833, "Isle of Man"),
        new Country("IN", "IND", 356, "India"),
        new Country("IO", "IOT", 86, "British Indian Ocean Territory"),
        new Country("IQ", "IRQ", 368, "Iraq"),
        new Country("IR", "IRN", 364, "Iran (Islamic Republic of)"),
        new Country("IS", "ISL", 352, "Iceland"),
        new Country("IT", "ITA", 380, "Italy"),
        new Country("JE", "JEY", 832, "Jersey"),
        new Country("JM", "JAM", 388, "Jamaica"),
        new Country("JO", "JOR", 400, "Jordan"),
        new Country("JP", "JPN", 392, "Japan"),
        new Country("KE", "KEN", 404, "Kenya"),
        new Country("KG", "KGZ", 417, "Kyrgyzstan"),
        new Country("KH", "KHM", 116, "Cambodia"),
        new Country("KI", "KIR", 296, "Kiribati"),
        new Country("KM", "COM", 174, "Comoros"),
        new Country("KN", "KNA", 659, "Saint Kitts and Nevis"),
        new Country("KP", "PRK", 408, "Korea (Democratic People's Republic of)"),
        new Country("KR", "KOR", 410, "Korea, Republic of"),
        new Country("KW", "KWT", 414, "Kuwait"),
        new Country("KY", "CYM", 136, "Cayman Islands"),
        new Country("KZ", "KAZ", 398, "Kazakhstan"),
        new Country("LA", "LAO", 418, "Lao People's Democratic Republic"),
        new Country("LB", "LBN", 422, "Lebanon"),
        new Country("LC", "LCA", 662, "Saint Lucia"),
        new Country("LI", "LIE", 438, "Liechtenstein"),
        new Country("LK", "LKA", 144, "Sri Lanka"),
        new Country("LR", "LBR", 430, "Liberia"),
        new Country("LS", "LSO", 426, "Lesotho"),
        new Country("LT", "LTU", 440, "Lithuania"),
        new Country("LU", "LUX", 442, "Luxembourg"),
        new Country("LV", "LVA", 428, "Latvia"),
        new Country("LY", "LBY", 434, "Libya"),
        new Country("MA", "MAR", 504, "Morocco"),
        new Country("MC", "MCO", 492, "Monaco"),
        new Country("MD", "MDA", 498, "Moldova, Republic of"),
        new Country("ME", "MNE", 499, "Montenegro"),
        new Country("MF", "MAF", 663, "Saint Martin (French part)"),
        new Country("MG", "MDG", 450, "Madagascar"),
        new Country("MH", "MHL", 584, "Marshall Islands"),
        new Country("MK", "MKD", 807, "North Macedonia"),
        new Country("ML", "MLI", 466, "Mali"),
        new Country("MM", "MMR", 104, "Myanmar"),
        new Country("MN", "MNG", 496, "Mongolia"),
        new Country("MO", "MAC", 446, "Macao"),
        new Country("MP", "MNP", 580, "Northern Mariana Islands"),
        new Country("MQ", "MTQ", 474, "Martinique"),
        new Country("MR", "MRT", 478, "Mauritania"),
        new Country("MS", "MSR", 500, "Montserrat"),
        new Country("MT", "MLT", 470, "Malta"),
        new Country("MU", "MUS", 480, "Mauritius"),
        new Country("MV", "MDV", 462, "Maldives"),
        new Country("MW", "MWI", 454, "Malawi"),
        new Country("MX", "MEX", 484, "Mexico"),
        new Country("MY", "MYS", 458, "Malaysia"),
        new Country("MZ", "MOZ", 508, "Mozambique"),
        new Country("NA", "NAM", 516, "Namibia"),
        new Country("NC", "NCL", 540, "New Caledonia"),
        new Country("NE", "NER", 562, "Niger"),
        new Country("NF", "NFK", 574, "Norfolk Island"),
        new Country("NG", "NGA", 566, "Nigeria"),
        new Country("NI", "NIC", 558, "Nicaragua"),
        new Country("NL", "NLD", 528, "Netherlands, Kingdom of the"),
        new Country("NO", "NOR", 578, "Norway"),
        new Country("NP", "NPL", 524, "Nepal"),
        new Country("NR", "NRU", 520, "Nauru"),
        new Country("NU", "NIU", 570, "Niue"),
        new Country("NZ", "NZL", 554, "New Zealand"),
        new Country("OM", "OMN", 512, "Oman"),
        new Country("PA", "PAN", 591, "Panama"),
        new Country("PE", "PER", 604, "Peru"),
        new Country("PF", "PYF", 258, "French Polynesia"),
        new Country("PG", "PNG", 598, "Papua New Guinea"),
        new Country("PH", "PHL", 608, "Philippines"),
        new Country("PK", "PAK", 586, "Pakistan"),
        new Country("PL", "POL", 616, "Poland"),
        new Country("PM", "SPM", 666, "Saint Pierre and Miquelon"),
        new Country("PN", "PCN", 612, "Pitcairn"),
        new Country("PR", "PRI", 630, "Puerto Rico"),
        new Country("PS", "PSE", 275, "Palestine, State of"),
        new Country("PT", "PRT", 620, "Portugal"),
        new Country("PW", "PLW", 585, "Palau"),
        new Country("PY", "PRY", 600, "Paraguay"),
        new Country("QA", "QAT", 634, "Qatar"),
        new Country("RE", "REU", 638, "Réunion"),
        new Country("RO", "ROU", 642, "Romania"),
        new Country("RS", "SRB", 688, "Serbia"),
        new Country("RU", "RUS", 643, "Russian Federation"),
        new Country("RW", "RWA", 646, "Rwanda"),
        new Country("SA", "SAU", 682, "Saudi Arabia"),
        new Country("SB", "SLB", 90, "Solomon Islands"),
        new Country("SC", "SYC", 690, "Seychelles"),
        new Country("SD", "SDN", 729, "Sudan"),
        new Country("SE", "SWE", 752, "Sweden"),
        new Country("SG", "SGP", 702, "Singapore"),
        new Country("SH", "SHN", 654, "Saint Helena, Ascension and Tristan da Cunha"),
        new Country("SI", "SVN", 705, "Slovenia"),
        new Country("SJ", "SJM", 744, "Svalbard and Jan Mayen"),
        new Country("SK", "SVK", 703, "Slovakia"),
        new Country("SL", "SLE", 694, "Sierra Leone"),
        new Country("SM", "SMR", 674, "San Marino"),
        new Country("SN", "SEN", 686, "Senegal"),
        new Country("SO", "SOM", 706, "Somalia"),
        new Country("SR", "SUR", 740, "Suriname"),
        new Country("SS", "SSD", 728, "South Sudan"),
        new Country("ST", "STP", 678, "Sao Tome and Principe"),
        new Country("SV", "SLV", 222, "El Salvador"),
        new Country("SX", "SXM", 534, "Sint Maarten (Dutch part)"),
        new Country("SY", "SYR", 760, "Syrian Arab Republic"),
        new Country("SZ", "SWZ", 748, "Eswatini"),
        new Country("TC", "TCA", 796, "Turks and Caicos Islands"),
        new Country("TD", "TCD", 148, "Chad"),
        new Country("TF", "ATF", 260, "French Southern Territories"),
        new Country("TG", "TGO", 768, "Togo"),
        new Country("TH", "THA", 764, "Thailand"),
        new Country("TJ", "TJK", 762, "Tajikistan"),
        new Country("TK", "TKL", 772, "Tokelau"),
        new Country("TL", "TLS", 626, "Timor-Leste"),
        new Country("TM", "TKM", 795, "Turkmenistan"),
        new Country("TN", "TUN", 788, "Tunisia"),
        new Country("TO", "TON", 776, "Tonga"),
        new Country("TR", "TUR", 792, "Türkiye"),
        new Country("TT", "TTO", 780, "Trinidad and Tobago"),
        new Country("TV", "TUV", 798, "Tuvalu"),
        new Country("TW", "TWN", 158, "Taiwan, Province of China"),
        new Country("TZ", "TZA", 834, "Tanzania, United Republic of"),
        new Country("UA", "UKR", 804, "Ukraine"),
        new Country("UG", "UGA", 800, "Uganda"),
        new Country("UM", "UMI", 581, "United States Minor Outlying Islands"),
        new Country("US", "USA", 840, "United States of America"),
        new Country("UY", "URY", 858, "Uruguay"),
        new Country("UZ", "UZB", 860, "Uzbekistan"),
        new Country("VA", "VAT", 336, "Holy See"),
        new Country("VC", "VCT", 670, "Saint Vincent and the Grenadines"),
        new Country("VE", "VEN", 862, "Venezuela (Bolivarian Republic of)"),
        new Country("VG", "VGB", 92, "Virgin Islands (British)"),
        new Country("VI", "VIR", 850, "Virgin Islands (U.S.)"),
        new Country("VN", "VNM", 704, "Viet Nam"),
        new Country("VU", "VUT", 548, "Vanuatu"),
        new Country("WF", "WLF", 876, "Wallis and Futuna"),
        new Country("WS", "WSM", 882, "Samoa"),
        new Country("YE", "YEM", 887, "Yemen"),
        new Country("YT", "MYT", 175, "Mayotte"),
        new Country("ZA", "ZAF", 710, "South Africa"),
        new Country("ZM", "ZMB", 894, "Zambia"),
        new Country("ZW", "ZWE", 716, "Zimbabwe"),
    };
}
