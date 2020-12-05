## Environment

JavaScript was chosen for the laboratory work. [Math.random](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Math/random)
was chosen to select items from a set, generate pseudo-random numbers on intervals, and shuffling the password array.
[crypto.radnomBytes](https://nodejs.org/dist/latest-v10.x/docs/api/crypto.html#crypto_crypto_randombytes_size_callback) was chosen to generate salts.

## Common passwords source

Frequently used passwords were taken from [SecLists](https://github.com/danielmiessler/SecLists) repository. Two lists
were used to generate passwords: [top-100](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100.txt),
[top-1000000](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt).
List [top-1000000](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt)
includes [top-100](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100.txt).

## Password generation

Passwords are generated in proportions of 10 top-100 passwords, 80 top-1000000 passwords, 4 random passwords,
6 passwords generated according to the rules. After generation, passwords are mixed and hashed.

### Generation of top 100 passwords

A password is randomly selected from the list [top-100](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100.txt).

### Generation of top 1000000 passwords 

A password is randomly selected from the list [top-1000000](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt).

### Generation of random passwords

A random password is generated with a length in the interval (8;16), randomly choosing characters from ASCII letters (a-z, A-Z),
digits (0-9) and special characters (!@#$_).

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

A password is randomly selected from [top-1000000](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt) 
then rule is randomly selected from rules list and then rule is applied to a password. 
If the rule requires you to select a symbol, they are randomly selected from the same alphabet as in the Generation of random passwords.
