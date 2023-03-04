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
* A1Z26
* Alt Code
* AtBash     
* Baconian
* Baconian26
* Base32     
* Base45
* Base58
* Base62
* Base64
* Base85
* Base91
* Binary     
* Brainfuck
* Caesar Cipher
* Decimal    
* Dvorak
* GoldBug
* Hexadecimal
* Morse
* MultiTap
* Nato
* Octal      
* Ook!
* ROT13
* ROT47
* ROT8000
* T9
* Tom Tom
* Vigenère


