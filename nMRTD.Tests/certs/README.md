# Test certificates

Card verifiable certificates (CVCA, link CVCA, DV and IS) from JMRTD's
`abandoned/passporthostapi-test/certs` folder. The `orig` set is the original Dutch test
passport chain; the `new` set adds a new trust point (CVCA 00002, linked from 00001).
They are used to check that real CV certificates parse, re-encode identically and verify.
