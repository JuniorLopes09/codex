# Codex
 A python tool for automated cipher decryption by **Cleonor Junior**

## How to use
`python3 codex.py cipher_input [options] `
##### Examples
* `python3 codex.py 48656C6C6F -c hexadecimal` or `python3 codex.py 48656C6C6F -c hex`

* `python3 codex.py "9‡‡*(5("`

* `python3 codex.py TJVGKJP -c vigenere -k synth `

* `python3 codex.py Qfcpjmai -c caesar -r 24`

* `python3 codex.py IJWDIY3LMIYHS=== -q -o output_file`


#### Options
flags | description
------------ | -------------
-A, --ascii | Use ASCII table instead of alphabet on Caesar Cipher
-b, --bruteforce | Caesar bruteforce mode (Starts from 1 and increment the rotation until the specified rotation)
-c, --cipher | Specifies the cipher method to decode
-f, --file | Read input from file
-F, --force | Force the decoder to print non-printable characters
-k, --key | Specifies the key for Vigenère decoder
-l, --less | Return only the decoded text
-L, --list | Show all available ciphers
-n, --num, | Return the numeric value instead of ASCII
-o, --output | Write the result in a file
-q, --quiet | Do not print the result on screen
-r, --rotation | Specifies Caesar Cipher rotation
-s, --separator | Specifies a custom separator
-v, --verbose | Return even the failed tries

#### Ciphers 
* Binary
* Octal
* Decimal
* Hexadecimal
* Base 32
* Base 58
* Base 64
* Base 85
* Morse 
* AtBash
* A1Z26
* ROT 13
* ROT 47
* T9
* MultiTap
* TomTom
* Nato
* Dvorak
* Alt Code
* Baconian
* Baconian 26
* Gold Bug
* Caesar cipher
* Vigenère


