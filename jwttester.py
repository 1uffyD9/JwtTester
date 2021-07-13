#!/usr/bin/env python3

import sys
import math
import json
import hmac
import hashlib
from os import path
import base64 as b64
import argparse, textwrap
from urllib.parse import unquote

class JwtTester:
    
    # https://pkg.go.dev/github.com/whitedevops/colors
    # 0-red, 1-purple, 2-blue, 3-normal, 4-green, 5-yellow
    color_code = ['\033[31m', '\033[35m', '\033[34m', '\033[39m', '\033[32m', '\033[33m']

    def __init__(self):

        args = self.get_args()

        # making url decoded bytes like objects in this function
        # handling files : getting the content
        if args.token and path.isfile(args.token):
            # token is provided and it is a file
            with open(args.token, 'rb') as token: args.token = token.read().strip()

        if args.header and path.isfile(args.header):
            # header is provided and it is a file
            with open(args.header, 'rb') as header: args.header = header.read().strip()

        if args.payload and path.isfile(args.payload):
            # payload is provided and it is a file
            with open(args.payload, 'rb') as payload: args.payload = payload.read().strip()

        # decode URL encoded values of the token and split
        if args.token : args.token = unquote(args.token).split('.')

        # check if the provided header and payload have valid json string or not
        if args.header:
            try: 
                json.loads(args.header)
            except:
                sys.exit("{}[!]{} Header doesn't have a valid json string! (Valid JSON Ex : {{\"alg\":\"None\"}}). Please try again.".format(self.color_code[0], self.color_code[3]))
        
        if args.payload:
            try:
                json.loads(args.payload)
            except:
                sys.exit("{}[!]{} Payload doesn't have a valid json string! (Valid JSON Ex : {{\"name\":null}}). Please try again.".format(self.color_code[0], self.color_code[3]))

        # sys.exit(args.token)
        if args.method == 'decode':
            if args.token is not None:
                # file, string or invalid
                try:
                    self.print_decoded_jwt(self.jwt_decode(args.token), args.no_sig, args.no_color)
                except:
                    sys.exit("{}[!]{} Invalid string detected! Check the token string and try again.".format(self.color_code[0], self.color_code[3]))

            else:
                sys.exit("{}[!]{} Token is missing in order to use decode method!".format(self.color_code[0], self.color_code[3]))
        
        elif args.method == 'brute':
            # to do : brute with default 10 threads

            if args.token and args.key:
                if path.isfile(args.key):
                    with open(args.key, 'rb') as wordlist:
                        if args.no_space: 
                            args.key = filter(None, (line.rstrip() for line in wordlist))
                        else:
                            args.key = filter(None, (line.replace(b'\n',b'') for line in wordlist))
                        
                        # bruteforce the key
                        try:
                            self.jwt_brute(args.token, args.key, args.no_color)
                        except KeyboardInterrupt:
                            sys.exit("{}[!]{} Keyboard Interruption occured! Exiting the program.".format(self.color_code[0], self.color_code[3]))  
                        
                        # print(args.token, args.key)

                else:
                    sys.exit("{}[!]{} Cannot find the wordlist! Please try again.".format(self.color_code[0], self.color_code[3]))
                
            else:
                sys.exit("{}[!]{} Following option(s) are missing : -t/--token, -k/--key".format(self.color_code[0], self.color_code[3])) 
        
        else:
            if args.key and path.isfile(args.key):
                # key is provided and it is a file
                with open(args.key, 'rb') as key: 
                    if args.no_space:
                        # remove tailing spaces at the end of the file
                        args.key = key.read().strip()
                    else:
                        args.key = key.read()

            # Encoding process
            if args.token and (args.header and args.payload):
                sys.exit("{}[!]{} You have provided three options.  You can only provide 2 options out of following options: --header, -p/--payload, -t/--token".format(self.color_code[0], self.color_code[3]))

            elif args.header and args.payload:
                # jwt token creation
                self.jwt_create(args.header, args.payload, args.key, args.no_color)

            elif args.token and (args.header or args.payload):
                # sys.exit("to be implemented")
                if args.header:
                    # header is provided
                    # get the payload from the token and encode
                    self.jwt_create(args.header, self.jwt_decode(args.token)[1], args.key, args.no_color)

                else:
                    # payload is provided
                    # get the header from the token and encode
                    self.jwt_create(self.jwt_decode(args.token)[0], args.payload, args.key, args.no_color)

            else:
                sys.exit("{}[!]{} Following option(s) are missing : --header, -p/--payload, -t/--token".format(self.color_code[0], self.color_code[3]))


    def get_args(self):
        parser = argparse.ArgumentParser(description="Simple Script to make JWT related testing easier", formatter_class=argparse.RawTextHelpFormatter)
        parser.add_argument('-m', '--method', type=str, help="specify the method: (decode, encode, brute)", choices=['decode', 'encode', 'brute'], required=True)
        parser.add_argument('-t', '--token', type=str, help="specify the JWT token as a string or a file")
        parser.add_argument('--header', type=str, help="specify the header string or the file containg the header string")
        parser.add_argument('-p', '--payload', type=str, help="specify the payload string or the file containg the header string")
        parser.add_argument('-k', '--key', type=str, help='''specify the secret key or the file containg the key that use to sign. \nIf the method is brute, only file will accept and each line in the file will take as a single key''')
        parser.add_argument('--no-sig',  action='store_true', help="Do not print signature")
        parser.add_argument('--no-color',  action='store_true', help="Print in plain text")
        parser.add_argument('--no-space',  action='store_true', help="Ignore tailing spaces of each lines in the wordlist")

        return parser.parse_args()

    
    def jwt_decode(self, jwt_token):
        """This will decode JWT token's header, payload, [signature] provided as strings in a list"""

        for i in range(len(jwt_token)):
            if i != 2:
                # handling others except the signature
                if jwt_token[i][-2:] == 'fQ' :
                    jwt_token[i] = b64.decodebytes(jwt_token[i][:-2].encode('ascii')) + b'}'
                else:
                    # resolving base64 padding issue : https://gist.github.com/perrygeo/ee7c65bb1541ff6ac770#gistcomment-3253616
                    # base64.urlsafe_b64decode(s + '=' * (4 - len(s) % 4)) url : https://stackoverflow.com/questions/3302946/how-to-decode-base64-url-in-python
                    jwt_token[i] = jwt_token[i].ljust((int)(math.ceil(len(jwt_token[i]) / 4)) * 4, '=')
                    jwt_token[i] = b64.decodebytes(jwt_token[i].encode('ascii'))

        return jwt_token


    def print_decoded_jwt(self, jwt_token, no_sig=False, no_color=False):

        for i in range(len(jwt_token)):
            if i == 2:
                if not no_sig:
                    # ok to print signature if it's there
                    if not no_color:
                        # ok to print color
                        print(u"\n{}Signature is : {}{}".format(self.color_code[3], self.color_code[i], jwt_token[i]))
                    else:
                        print(u"\nSignature is : {}".format(jwt_token[i]))
            else:
                if not no_color:
                    # ok to print color
                    print(u"{}\n{}".format(self.color_code[i], json.dumps(json.loads(jwt_token[i]), indent=2)))
                else:
                    print(u"\n{}".format(json.dumps(json.loads(jwt_token[i]), indent=2)))


    def invoke_jhmac(self, value, key):
        """Creating signature HS256 signature"""

        # only accepting bytes
        # returning bytes string
        return (b64.urlsafe_b64encode(hmac.new(key, value, hashlib.sha256).digest())).replace(b'=', b'')


    def jwt_create(self, header, payload, key, no_color=False):
        """Creating the JWT token. will accept header and payload as sring / bytes"""
        # key is a single string 
        # convertine all to bytes 
        try:
            # if header not provided as a file
            header = header.encode('utf-8')
        except:
            pass

        try:
            # if payload is not provided as a file
            payload = payload.encode('utf-8')
        except:
            pass

        try:
            # if key is not provided as a file
            key = key.encode('utf-8')
        except:
            pass

        try:
            alg = json.loads(header)['alg']
        except:
            sys.exit("{}[!]{} Invalid header is found! Please try again.".format(self.color_code[0], self.color_code[3]))

        # create base64UrlEncoded header
        # strip out the equal sign
        header = (b64.urlsafe_b64encode(header)).replace(b'=', b'')

        # create base64UrlEncoded payload
        # strip out the equal sign
        payload = (b64.urlsafe_b64encode(payload)).replace(b'=', b'')

        # creating the signature
        value = b'%s.%s' % (header, payload)
        signature = b''

        print(alg)
        if alg == 'HS256':
            # if the key is provided
            signature = self.invoke_jhmac(value, key)

        if not no_color:
            # ok to print color 
            print("{}[*]{} JWT : {}{}{}.{}{}{}.{}{}{}".format(self.color_code[4], self.color_code[3],
                                                                self.color_code[0], header.decode('utf-8'), self.color_code[3],
                                                                self.color_code[1], payload.decode('utf-8'), self.color_code[3],
                                                                self.color_code[2], signature.decode('utf-8'), self.color_code[3]))
        else:
            print("[*] JWT : {}.{}.{}".format(header.decode('utf-8'), payload.decode('utf-8'), signature.decode('utf-8')))

    def jwt_brute(self, jwt_token, keys, no_color=False):
        """Bruteforcing the secret key or public key to find a valid key"""
        
        # Note : keys is a list contains the keys in bytes
        #        token is a list contains the parts of JWT

        # check if signature is not provided
        if len(jwt_token) == 3:
            if not jwt_token[2]:
                print("{}[!]{} Empty signature detected. Continuing..".format(self.color_code[5], self.color_code[3]))

            try:
                # check if the invalid string in jwt_token while getting alg 
                # jwt_token is pass by value. Otherwise alteration made by other function will be affecting everywhere in the current context
                alg = json.loads(self.jwt_decode(jwt_token.copy())[0])['alg']
                key_found = False

                # to do : 
                #   threading
                #   progress bar
                if alg == 'HS256':
                    # if the alg is SHA256
                    count = 1
                    for key in keys:
                        # handline non-ascii chars in wordlist files
                        try:
                            print("[{}] Trying : {}".format(count, key.decode('utf-8')[:50].ljust(50)), end='\r', flush=True)
                            if self.invoke_jhmac('.'.join(jwt_token[:2]).encode('utf-8'), key).decode('utf-8') == jwt_token[2]:
                                key_found = True
                                sys.exit("{}[*]{} Found the password : {}{}{}".format(self.color_code[4], self.color_code[3], self.color_code[4], key.decode('utf-8'), self.color_code[3]))
                            count += 1
                        except UnicodeDecodeError:
                            # https://stackoverflow.com/questions/19699367/for-line-in-results-in-unicodedecodeerror-utf-8-codec-cant-decode-byte

                            print("[{}] Trying : {}".format(count, key[:50].ljust(50)), end='\r', flush=True)
                            if self.invoke_jhmac('.'.join(jwt_token[:2]).encode('utf-8'), key).decode('utf-8') == jwt_token[2]:
                                key_found = True
                                sys.exit("{}[*]{} Found the password : {}{}{}".format(self.color_code[4], self.color_code[3], self.color_code[4], key.decode('ISO-8859-1'), self.color_code[3]))
                            count += 1
                
                if not key_found: 
                    sys.exit("{}[!]{} Key not found! Try again with a different wordlist. or try again with/without ---no-space flag".format(self.color_code[0], self.color_code[3]))

            except Exception:
                sys.exit("{}[!]{} Invalid string detected! Check the token string and try again. {}".format(self.color_code[0], self.color_code[3]))

        else:
            sys.exit("{}[!]{} Signature not detected in the token! Check the token string and try again.".format(self.color_code[0], self.color_code[3]))
  


if __name__ == '__main__':
    JwtTester()

