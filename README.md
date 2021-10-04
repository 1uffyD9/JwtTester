# JwtTester

Simple Script to check JWTs

## `JwtTester` Help
```bash
usage: jwttester.py [-h] -m {decode,encode,brute} [-t TOKEN] [--header HEADER] [-p PAYLOAD] [-k KEY] [--no-sig] [--no-color] [--no-space]

Simple Script to make JWT related testing easier

optional arguments:
  -h, --help            show this help message and exit
  -m {decode,encode,brute}, --method {decode,encode,brute}
                        specify the method: (decode, encode, brute)
  -t TOKEN, --token TOKEN
                        specify the JWT token as a string or a file
  --header HEADER       specify the header string or the file containg the header string
  -p PAYLOAD, --payload PAYLOAD
                        specify the payload string or the file containg the header string
  -k KEY, --key KEY     specify the secret key or the file containg the key that use to sign. 
                        If the method is brute, only file will accept and each line in the file will take as a single key
  --no-sig              Do not print signature
  --no-color            Print in plain text
  --no-space            Ignore tailing spaces of each lines in the wordlist
```

## Installation
```bash
$ git clone https://github.com/1uffyD9/JwtTester.git
$ cd JwtTester
$ chmod +x jwttester.py
$ sudo ln -sf `pwd`/jwttester.py /usr/local/bin/jwttester`
```

## Examples
Passing the token as a command line argment
```bash
$ jwttester -m decode -t "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

{
  "alg": "HS256",
  "typ": "JWT"
}

{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022
}

Signature is : SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```
Passing the token as a file
```bash
$ jwttester -m decode -t token.txt

{
  "alg": "HS256",
  "typ": "JWT"
}

{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022
}

Signature is : SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

```
Get only header & the payload without the signature
```bash
$ jwttester -m decode -t token.txt --no-sig

{
  "alg": "HS256",
  "typ": "JWT"
}

{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022
}
```
Piping the output to [jq](https://stedolan.github.io/jq/)
```bash
$ jwttester -m decode -t token.txt --no-sig --no-color | jq -c
{"alg":"HS256","typ":"JWT"}
{"sub":"1234567890","name":"John Doe","iat":1516239022}
```
## Todo

- [ ] Signing for other algorithms 
