# security-lab04

## Environment

Python was chosen for the laboratory work. [numpy.random.default_rng](https://numpy.org/doc/stable/reference/random/generator.html#numpy.random.default_rng)
was chosen to select items from a set, generate pseudo-random numbers on intervals, and shuffling the password array.
It is based on [PCG-64](https://en.wikipedia.org/wiki/Permuted_congruential_generator) generator, which provides
excellent statistical performance with fast code and small state size.

To create salts and seeds was used according to [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
[secrets module](https://docs.python.org/3/library/secrets.html#module-secrets). Module for random numbers generation
uses the highest quality sources provided by the operating system.

## Common passwords source

Frequently used passwords were taken from [SecLists](https://github.com/danielmiessler/SecLists) repository. Two lists
were used to generate passwords: [top-100](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100.txt),
[top-1000000](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt).
List [top-1000000](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt)
includes [top-100](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100.txt).

## Password generation

Passwords are generated in proportions of 5 top-100 passwords, 80 top-1000000 passwords, 5 random passwords,
10 passwords generated according to the rules. After generation, passwords are mixed and hashed.

### Generation of top 100 passwords

A password is randomly selected from the list [top-100](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100.txt).

### Generation of top 1000000 passwords 

A password is randomly selected from the list [top-1000000](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt).

### Generation of random passwords

A random password is generated with a length in the interval (7;32), randomly choosing characters from
[ascii_letters](https://docs.python.org/3/library/string.html#string.ascii_letters),
[digits](https://docs.python.org/3/library/string.html#string.digits) and
[punctuation](https://docs.python.org/3/library/string.html#string.punctuation).

### Generation of passwords by the rule engine

A rule-based approach was used to generate passwords in this way. The rules were chosen from [list](https://hashcat.net/wiki/doku.php?id=rule_based_attack)
compatible with hashcat, John the Ripper, and PasswordsPro. Selected rules:
  
    * Lowercase
    * Uppercase
    * Capitalize
    * Invert Capitalize
    * Toggle Case
    * Toggle @
    * Reverse
    * Duplicate
    * Reflect
    * Rotate Left
    * Rotate Right
    * Append Character
    * Prepend Character
    * Replace
    * Duplicate all

To generate a password, passwords are first taken from [top-1000000](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt)
as follows: 1 password is taken with probability `1`, then 1 more password is taken with probability
`1 - delta` (delta = 0.3), then 1 more password is taken with probability `1 - 2 * delta`, etc. The selected passwords
are concatenated. In the same way, rules are selected from the list above, with only 0.2 deltas, and applied to the
generated password. Passwords and rules can be repeated. If the rule requires you to select a symbol, they are randomly
selected from the same alphabet as in the Generation of random passwords.
