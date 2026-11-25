# Test fixtures

These files come from the unit tests of [JMRTD](https://jmrtd.org/)
(`jmrtd/src/test/resources` in `https://git.code.sf.net/p/jmrtd/jmrtd`, commit `2c08440a`; `malformed`
from commit `bb62243e`),
which is distributed under the GNU Lesser General Public License. They are test documents and
sample data only; none of them describes a real person.

| Folder | Content |
|---|---|
| `lds/bsi2008` | LDS files (EF.COM, EF.SOD, DG1–DG4, DG14, DG15) of the BSI 2008 test passport |
| `lds/loes2006` | LDS files (EF.COM, EF.SOD, DG1, DG2, DG15) of the "Loes" 2006 Dutch test document |
| `lds/dg2` | ISO/IEC 19794-5 DG2 files with mandatory and with all fields |
| `lds/dg2/iso39794`, `lds/dg3/iso39794`, `lds/dg4/iso39794` | ISO/IEC 39794-5, -4 and -6 sample DG2, DG3 and DG4 |
| `lds/wsq` | WSQ fingerprint images |
| `dg2` | A JPEG 2000 face image |
| `efcardsecurity` | An EF.CardSecurity dump |
| `malformed` | Malformed chip data (LDS files, EF.CardAccess, EF.CardSecurity, biometric records, MRZ text, card verifiable certificates, PACE responses) for `MalformedInputTest`; the file names are JMRTD's (hashes of the content) |

The tests that use them are ports of JMRTD's own unit tests and keep their names and expected values.
