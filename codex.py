#!/bin/python3
# -*- coding: UTF-8 -*-
# Author: Cleonor Junior

import argparse
import base64 as b64

BLUE = '\033[94m'
GREEN = '\033[32m'
WHITE = '\033[97m'
RED = '\033[31m'
ENDC = '\033[0m'
BOLD = '\033[1m'


class MyParser(argparse.ArgumentParser):
    help_message = '''usage: Codex.py ciphered_input [OPTIONS] 

    required arguments:
      ciphered_input           The ciphered text or file to be decoded

    optional arguments:
      -A, --ascii          		    Use ascii table instead of alphabet on Caesar Cipher

      -b, --bruteforce      	    Caesar bruteforce mode

      -c, --cipher                  CIPHER   The cipher method to decode

      -f, --file                    Read input from file

      -F, --force                   Force the decoder to print non-printable characters

      -h, --help                	show this help message and exit

      -k, --key KEY     	    	Specifies a key for vigenere

      -l, --less            	    Show only the decoded text

      -L, --list                    Show all available ciphers

      -n, --num                 	Show the numeric value instead of ASCII

      -o, --output OUTPUT   	    Write the result in a file

      -q, --quiet           	    Do not display the result on screen

      -r, --rotation ROTATION       Specifies Caesar Cipher rotation

      -s, --separator SEPARATOR 	Specifies the separator

      -v, --verbose			        Return even the failed tries

      -w, --wordlist WORDLIST	    Read a wordlist as key for vigenere


    specific ciphers options:
      Binary, Octal, Decimal, Hexadecimal [-n]
      Base32
      Base64
      T9
      A1Z26, MultiTap [-s]
      Morse
      GoldBug
      Caesar [-r, -b, -A]
      Vigenere {-k | -w}

      '''

    def format_help(self):
        return self.help_message


class Cipher:

    def __init__(self, identifier: str, formated_name: str, decoder: callable, decoder_params: list = []):
        self.identifier = identifier
        self.decoder = decoder
        self.formated_name = formated_name
        self.decoder_params = decoder_params

    def decode(self, cipher_text):
        if self.decoder_params:
            return self.decoder(cipher_text, *self.decoder_params)

        return self.decoder(cipher_text)


parser = MyParser(usage='codex.py cipher_text [OPTIONS]')
group = parser.add_mutually_exclusive_group()
parser.add_argument("cipher_text", help="The ciphered text or file to be decoded", type=str)
parser.add_argument("-v", "--verbose", action='store_true')
parser.add_argument("-s", "--separator", help='Specifies the separator', default=' ', type=str)
parser.add_argument("-n", "--num", help="Show the numeric value instead of ASCII", action='store_true')
parser.add_argument("-o", "--output", help="Write the result in a file")
parser.add_argument("-f", "--file", help="Read input from file", action='store_true')
parser.add_argument("-F", "--force", help="Force the decoder to print non-printable characters ", action='store_true')
group.add_argument("-l", "--less", help="Show only the decoded text", action='store_true')
group.add_argument("-L", "--list", help="List all available ciphers", action='store_true')
group.add_argument("-q", "--quiet", help="Do not display the result on screen", action='store_true')
parser.add_argument("-c", "--cipher", help="Specifies The cipher method to decode", type=str)
parser.add_argument("-b", "--bruteforce", help='Caesar bruteforce method', action='store_true')
parser.add_argument("-r", "--rotation", help='Specifies Caesar Cipher rotation', type=int, default=25)
parser.add_argument('-A', '--ascii', help='Use ascii table instead of alphabet on Caesar Cipher', action='store_true')
parser.add_argument('-w', '--wordlist', help='Read a wordlist as key for vigenere')
parser.add_argument('-k', '--key', help='Specifies a key for vigenere', default='', type=str)
args = parser.parse_args()

alphabet = [chr(i + 97) for i in range(26)]

baconian_table = {'AAAAA': 'A', 'ABAAA': 'I', 'BAAAA': 'R', 'AAAAB': 'B', 'ABAAB': 'K', 'BAAAB': 'S', 'AAABA': 'C',
            'ABABA': 'L', 'BAABA': 'T', 'AAABB': 'D', 'ABABB': 'M', 'BAABB': 'V', 'AABAA': 'E', 'ABBAA': 'N',
            'BABAA': 'W', 'AABAB': 'F', 'ABBAB': 'O', 'BABAB': 'X', 'AABBA': 'G', 'ABBBA': 'P', 'BABBA': 'Y',
            'AABBB': 'H', 'ABBBB': 'Q', 'BABBB': 'Z'}

baconian26_table = {"AAAAA": "A", "AAAAB": "B", "AAABA": "C", "AAABB": "D", "AABAA": "E", "AABAB": "F", "AABBA": "G",
                    "AABBB": "H", "ABAAA": "I", "ABAAB": "J", "ABABA": "K", "ABABB": "L", "ABBAA": "M", "ABBAB": "N",
                    "ABBBA": "O", "ABBBB": "P", "BAAAA": "Q", "BAAAB": "R", "BAABA": "S", "BAABB": "T", "BABAA": "U",
                    "BABAB": "V", "BABBA": "W", "BABBB": "X", "BBAAA": "Y", "BBAAB": "Z"}

atbash_table = {'A': 'Z', 'B': 'Y', 'C': 'X', 'D': 'W', 'E': 'V', 'F': 'U', 'G': 'T', 'H': 'S', 'I': 'R', 'J': 'Q',
          'K': 'P', 'L': 'O', 'M': 'N', 'N': 'M', 'O': 'L', 'P': 'K', 'Q': 'J', 'R': 'I', 'S': 'H', 'T': 'G',
          'U': 'F', 'V': 'E', 'W': 'D', 'X': 'C', 'Y': 'B', 'Z': 'A'}

morse_table = {'.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F', '--.': 'G', '....': 'H',
               '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P',
               '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
               '-.--': 'Y', '--..': 'Z', '.----': '1', '..---': '2', '...--': '3', '....-': '4', '.....': '5',
               '-....': '6', '--...': '7', '---..': '8', '----.': '9', '-----': '0', '--..--': ', ', '.-.-.-': '.',
               '..--..': '?', '-..-.': '/', '-....-': '-', '-.--.': '(', '-.--.-': ')', '/': ' '}

goldbug_table = {'5': 'A', '2': 'B', '-': 'C', '†': 'D', '8': 'E', '1': 'F', '3': 'G', '4': 'H',  '6': 'I',  ',': 'J',
                 '7': 'K', '0': 'L', '9': 'M', '*': 'N', '‡': 'O', '.': 'P', '$': 'Q', '(': 'R', ')': 'S', ';': 'T',
                 '?': 'U', '¶': 'V', ']': 'W', '¢': 'X', ':': 'Y', '[': 'Z'}

a1z26_table = {'1': 'A', '2': 'B', '3': 'C', '4': 'D', '5': 'E', '6': 'F', '7': 'G', '8': 'H', '9': 'I', '10': 'J',
               '11': 'K', '12': 'L', '13': 'M', '14': 'N', '15': 'O', '16': 'P', '17': 'Q', '18': 'R', '19': 'S',
               '20': 'T', '21': 'U', '22': 'V', '23': 'W', '24': 'X', '25': 'Y', '26': 'Z'}

rot13_table = {'N': 'A', 'O': 'B', 'P': 'C', 'Q': 'D', 'R': 'E', 'S': 'F', 'T': 'G', 'U': 'H', 'V': 'I', 'W': 'J',
               'X': 'K', 'Y': 'L', 'Z': 'M', 'A': 'N', 'B': 'O', 'C': 'P', 'D': 'Q', 'E': 'R', 'F': 'S', 'G': 'T',
               'H': 'U', 'I': 'V', 'J': 'W', 'K': 'X', 'L': 'Y', 'M': 'Z'}

t9_table = {'0': ' ', '21': 'A', '22': 'B', '23': 'C', '31': 'D', '32': 'E', '33': 'F', '41': 'G', '42': 'H', '43': 'I',
            '51': 'J', '52': 'K', '53': 'L', '61': 'M', '62': 'N', '63': 'O', '71': 'P', '72': 'Q', '73': 'R',
            '74': 'S', '81': 'T', '82': 'U', '83': 'V', '91': 'W', '92': 'X', '93': 'Y', '94': 'Z'}

multitap_table = {'222': 'C', '22': 'B', '2': 'A', '333': 'F', '33': 'E', '3': 'D', '444': 'I', '44': 'H', '4': 'G',
                  '555': 'L', '55': 'K', '5': 'J', '666': 'O', '66': 'N', '6': 'M', '7777': 'S', '777': 'R', '77': 'Q',
                  '7': 'P', '888': 'V', '88': 'U', '8': 'T', '9999': 'Z', '999': 'W', '99': 'X', '9': 'Y', '0': ' '}

tomtom_table = {"/": "A", "//": "B", "///": "C", "////": "D", "/\\": "E", "//\\": "F", "///\\": "G", "/\\\\": "H",
                "/\\\\\\": "I", "\\/": "J", "\\\\/": "K", "\\\\\\/": "L", "\\//": "M", "\\///": "N", "/\\/": "O",
                "//\\/": "P", "/\\\\/": "Q", "/\\//": "R", "\\/\\": "S", "\\\\/\\": "T", "\\//\\": "U", "\\/\\\\": "V",
                "//\\\\": "W", "\\\\//": "X", "\\/\\/": "Y", "/\\/\\": "Z"}

nato_table = {"ALPHA": "A", "BRAVO": "B", "CHARLIE": "C", "DELTA": "D", "ECHO": "E", "FOXTROT": "F", "GOLF": "G",
              "HOTEL": "H", "INDIA": "I", "JULIETT": "J", "KILO": "K", "LIMA": "L", "MIKE": "M", "NOVEMBER": "N",
              "OSCAR": "O", "PAPA": "P", "QUEBEC": "Q", "ROMEO": "R", "SIERRA": "S", "TANGO": "T", "UNIFORM": "U",
              "VICTOR": "V", "WHISKEY": "W", "YANKEE": "Y", "ZULU": "Z"}

alt_code_table = {"☺": "1", "☻": "2", "♥": "3", "♦": "4", "♣": "5", "♠": "6", "•": "7", "◘": "8", "○": "9",
                  "◙": "10", "♂": "11", "♀": "12", "♪": "13", "♫": "14", "☼": "15", "►": "16", "◄": "17",
                  "↕": "18", "‼": "19", "¶": "20", "§": "21", "▬": "22", "↨": "23", "↑": "24", "↓": "25",
                  "→": "26", "←": "27", "∟": "28", "↔": "29", "▲": "30", "▼": "31", "⌂": "255"}

punctuation = [' ', '!', "#", '&', '$', '@', '%', '(', ')', '[', ']', '{', '}', '=', '-', ':', ';', '>', '<', '?', '.',
               ',', '_', '"', "'", '\\', '/', '^', '~', '|']

def style(text: str, is_found: bool, cipher: Cipher, less: bool = False, verbose: bool = False):
    if less and is_found:
        return f"{WHITE}{text}{ENDC}"
    elif is_found:
        if cipher in [caesar, vigenere] and args.wordlist or args.bruteforce:
            return f"{BLUE}[{WHITE}{cipher.formated_name}{BLUE}]{WHITE}: {text} {ENDC}"
        return f"{GREEN}[{WHITE}+{GREEN}]{WHITE} {cipher.formated_name}: {text} {ENDC}"
    elif verbose:
        return f"{RED}[{WHITE}-{RED}]{WHITE} {cipher.formated_name}: {text} {ENDC}"
    else:
        return text


def cut(string: str, size: int):
    string_cutted = ''
    cutted = []
    for i in range(len(string)):
        if i % size == 0:
            cutted.append(string_cutted)
            string_cutted = ''
        string_cutted += string[i]
        if i == len(string) - 1:
            cutted.append(string_cutted)
    return cutted[1:]


def to_num(char: str):
    return alphabet.index(char.lower())


def to_char(num: int):
    return alphabet[num % 26]


def substitution_cipher(text: str, cipher_dict: dict, split: bool = False, min_distinct: int = 0):
    sub_decoded = ''
    string = ''

    if split:
        text = text.split(args.separator)

    for letter in text:
        if letter not in punctuation or letter in cipher_dict:
            sub_decoded += cipher_dict[(letter.upper())] if letter.isupper() else cipher_dict[letter.upper()].lower()
            string += letter
        else:
            sub_decoded += letter
    if string and (len(set(sub_decoded)) > min_distinct or args.cipher):
        return sub_decoded
    else:
        raise ValueError


def dvorak_decode(text: str):
    qwerty = r''' !"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}'''
    dvorak = r''' !_#$%&-()*}w[vz0123456789SsW]VZ@AXJE>UIDCHTNMBRL"POYGK<QF:/\=^{`axje.uidchtnmbrl'poygk,qf;?|+'''

    string = ''

    for letter in text:
        if letter not in punctuation or letter in dvorak:
            string += qwerty[dvorak.index(letter)]
        else:
            string += letter

    return string


def base_decode(text: str, base: int, stream_size: int):
    base_decoded = ""
    if ' ' in text:
        string = text.split(' ')
    else:
        string = cut(text, stream_size)
    for i in string:
        if args.num:
            base_decoded += str(int(i, base))
        else:
            base_decoded += chr(int(i, base))
    return base_decoded


def base32_decode(text: str):
    return b64.b32decode(text).decode('UTF-8')


def base58_decode(text: str):
    base58_alphabet = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

    text = text.rstrip().encode('ascii')

    origlen = len(text)
    text = text.lstrip(base58_alphabet[0:1])
    newlen = len(text)

    if b' ' not in base58_alphabet:
        text = text.rstrip()

    _map = {char: index for index, char in enumerate(base58_alphabet)}

    decimal = 0
    _base = len(base58_alphabet)

    for char in text:
        decimal = decimal * _base + _map[char]

    acc = decimal

    result = []
    while acc > 0:
        acc, mod = divmod(acc, 256)
        result.append(mod)

    return (b'\0' * (origlen - newlen) + bytes(reversed(result))).decode('UTF-8')


def base64_decode(text: str):
    return b64.b64decode(text + "==").decode('UTF-8')


def base85_decode(text: str):
    return b64.a85decode(text).decode('UTF-8')


def t9_decode(text: str):
    t9_decoded = ''
    if ' ' in text:
        for i in text.split():
            t9_decoded += t9_decode(i)
            t9_decoded += ' '
    else:
        cutted_txt = cut(text, 2)
        for i in cutted_txt:
            t9_decoded += t9_table[i]
    return t9_decoded


def morse_decode(text: str):
    decoded_morse = ''
    for word in text.split('/'):
        for char in word.split():
            decoded_morse += morse_table[char]
        decoded_morse += ' '
    return decoded_morse


def multitap_decode(text: str, sep: str = " "):
    multitap_decoded = ''
    invalid_char = False
    for char in text:
        if char not in '023456789 ' + sep:
            invalid_char = True
            break
    if not invalid_char:
        if sep in text:
            for word in text.split():
                for char in word.split(sep):
                    multitap_decoded += multitap_table[char]
                multitap_decoded += ' '
        else:
            for i in multitap_table:
                text = text.replace(i, multitap_table[i])
            multitap_decoded = text
    return multitap_decoded


def caesar_decode(text: str, rot: int, ascii_mode: bool = False):
    decoded_caesar = ''
    if ascii_mode:
        for i in range(len(text)):
            if int(ord(text[i]) - rot) < 0:
                decoded_caesar += 'Impossible to print all characteres'
                break
            decoded_caesar += chr(int(ord(text[i])) - rot)
    else:
        for i in range(len(text)):
            if text[i].lower() in alphabet:
                decoded_caesar += to_char(to_num(text[i]) - rot).upper() if text[i].isupper() \
                    else to_char(to_num(text[i]) - rot)
            else:
                decoded_caesar += text[i]

    return decoded_caesar


def vigenere_decode(text: str, key: str):
    decoded_viginere = ''
    n_key = [to_num(i) for i in key]
    limit = len(key)
    for i, char in enumerate(text):
        if char.lower() in alphabet:
            new_char = to_char(to_num(char) - n_key[i % limit])
            decoded_viginere += new_char.upper() if char.isupper() else new_char.lower()
        else:
            decoded_viginere += char

    return decoded_viginere


def rot47_decode(text: str):
    decode = []
    for i in range(len(text)):
        encoded = ord(text[i])
        if 33 <= encoded <= 126:
            decode.append(chr(33 + ((encoded + 14) % 94)))
        else:
            decode.append(text[i])
    return ''.join(decode)


def remove_color(text: str):
    return text.replace(GREEN, '').replace(WHITE, '').replace(RED, '').replace(BLUE, '').replace(BOLD, '')


# Ciphers definition
binary = Cipher("binary", "Binary", base_decode, [2, 8])
octal = Cipher("octal", "Octal", base_decode, [8, 3])
decimal = Cipher("decimal", "Decimal", base_decode, [10, 3])
hexadecimal = Cipher("hexadecimal", "Hexadecimal", base_decode, [16, 2])
base32 = Cipher("base32", "Base32", base32_decode)
base58 = Cipher("base58", "Base58", base58_decode)
base64 = Cipher("base64", "Base64", base64_decode)
base85 = Cipher("base85", "Base85", base85_decode)
a1z26 = Cipher("a1z26", "A1Z26", substitution_cipher, [a1z26_table, True])
morse = Cipher("morse", "Morse", morse_decode)
goldbug = Cipher("goldbug", "GoldBug", substitution_cipher, [goldbug_table, False, 11])
baconian = Cipher("baconian", "Baconian", substitution_cipher, [baconian_table, True])
baconian26 = Cipher("baconian26", "Baconian26", substitution_cipher, [baconian26_table, True])
atbash = Cipher("atbash", "AtBash", substitution_cipher, [atbash_table, False, 9])
rot13 = Cipher("rot13", "ROT13", substitution_cipher, [rot13_table, False, 9])
rot47 = Cipher("rot47", "ROT47", rot47_decode)
caesar = Cipher("caesar", f"Caesar +{args.rotation}", caesar_decode, [args.rotation, args.ascii])
vigenere = Cipher("vigenere", f"Vigenère ({args.key})", vigenere_decode, [args.key])
multitap = Cipher("multitap", "MultiTap", multitap_decode)
t9 = Cipher("t9", "T9", t9_decode)
tomtom = Cipher("tomtom", "Tom Tom", substitution_cipher, [tomtom_table, True])
nato = Cipher("nato", "Nato", substitution_cipher, [nato_table, True])
dvorak = Cipher("dvorak", "Dvorak", dvorak_decode)
altcode = Cipher("altcode", "Alt Code", substitution_cipher, [alt_code_table])

ciphers = [caesar, vigenere, binary, octal, decimal, hexadecimal, base32, base58, base64, base85, a1z26, morse, goldbug,
           baconian, baconian26, atbash, rot13, tomtom, multitap, t9, nato, dvorak, altcode, rot47]
# Exclude these ciphers from automated tentative
all_exclude = ['caesar', 'vigenere', 'dvorak', 'rot47']


def list_ciphers():
    for cipher in ciphers:
        print(cipher.formated_name)


def caesar_bruteforce():
    for rot in range(1, 26):
        caesar.decoder_params = [rot, args.ascii]
        caesar.formated_name = f"Rotation {rot}"
        main()


def vigenere_wordlist():
    with open(args.wordlist, 'r') as wordlist:
        keys = [key.strip() for key in wordlist.readlines()]

    for key in keys:
        vigenere.decoder_params = [key]
        vigenere.formated_name = key
        main()


def main():

    file_out = ''
    unknown_cipher = True
    for cipher in ciphers:
        if (not args.cipher and cipher.identifier not in all_exclude) or (args.cipher and args.cipher in cipher.identifier):
            unknown_cipher = False
            decoded = ''
            out = ''
            found = True
            try:
                decoded = cipher.decode(args.cipher_text)

            except (ValueError, IndexError, KeyError) as e:
                found = False

            except Exception as e:
                print(e)

            decoded = decoded.replace("\n", "§§\\n§§").replace("\t", "§§\\t§§")
            if decoded.strip() and (decoded.isprintable() or args.force):
                decoded = decoded.replace("§§\\n§§", "\n").replace("§§\\t§§", "\t")
                out = style(decoded, found, cipher, less=args.less, verbose=args.verbose)

            if out:
                if not args.quiet:
                    print(out)
                if args.output:
                    file_out += out

            if args.cipher:
                break

    if unknown_cipher:
        error_msg = "Unknown Cipher"
        print(style(error_msg, False, args.cipher, verbose=True))

    if args.output:
        with open(f"{args.output}", "w") as file:
            file.write(remove_color(file_out))


if __name__ == "__main__":
    if args.file:
        with open(args.cipher_text, encoding='UTF-8') as f:
            args.cipher_text = f.read().strip()
    if args.list:
        list_ciphers()
    elif args.cipher and args.cipher in caesar.identifier and args.bruteforce:
        caesar_bruteforce()
    elif args.cipher and args.cipher in vigenere.identifier and args.wordlist:
        vigenere_wordlist()
    else:
        main()
