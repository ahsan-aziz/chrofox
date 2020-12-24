import os
import sys
import sqlite3
import requests
import json
import platform
import argparse
import hmac
import secretstorage
from colorama import init, Fore, Back, Style
from Crypto.Cipher import DES3
from Crypto.Cipher import AES
from Crypto.Protocol import KDF
from pyasn1.codec.der.decoder import decode as der_decode
from base64 import b64decode, b64encode
from hashlib import sha1
from importlib import import_module
from pathlib import Path

operatingSystem = str(sys.platform)
dirFirefox, dirChrome = "",""

if "win" in operatingSystem or "Win" in operatingSystem:
    operatingSystem = "Windows"
            

def printNicely(title, credentialsList=[]):
    if (operatingSystem == "Windows"):
        init(convert=True)
    cr = '\r\n'
    section_break = cr +  "=" * 100 + cr
    text = cr + Fore.RED + title + Style.RESET_ALL 
    print(text)
    if credentialsList != []:   
        print (section_break)
        for item in credentialsList:
            for key in item.keys():
                print(Fore.GREEN + key +":"+ Style.RESET_ALL + item[key])
            print(cr)
        print (section_break)



def getChromeCredentials(directory, credentialsType):

    cookieList,passwordList = [],[]
    
    if (operatingSystem == "Windows"):

        '''
        Chrome uses the so-called Data Protection API (DPAPI), which is in Windows from NT 5.0 (i.e. Windows 2000) onwards, which nowadays uses AES-256 to encrypt the passwords. 
        We can use  CryptUnprotectData from win32crypt python module to decrypt it. 
        See: https://digital-forensics.sans.org/summit-archives/dfirprague14/Give_Me_the_Password_and_Ill_Rule_the_World_Francesco_Picasso.pdf
        '''
        import win32crypt

        if (credentialsType == "cookies" or credentialsType == "all"):

            value = queryDatabase(directory, 'Cookies', 'SELECT * FROM cookies')
            for data in value:
                try:
                    decryptedCookie = win32crypt.CryptUnprotectData(data[12], None, None, None, 0)[1]
                    cookieList.append({
                       'hostname': data[1],
                        'cookieName': data[2],
                        'cookie': str(decryptedCookie)
                    
                    })
                except:
                    pass
                
      
            

        if(credentialsType == "passwords" or credentialsType == "all"):
            value = queryDatabase(directory, 'Login Data','SELECT action_url, username_value, password_value FROM logins')

            try:
                for origin_url, username, password in value:
                    decryptedPassword = win32crypt.CryptUnprotectData(password, None, None, None, 0)[1]
                    passwordList.append({
                        'origin_url': origin_url,
                        'username': username,
                        'password': str(decryptedPassword)
                })
            except:
                pass
     
           
        
    else:

        '''
        In linux, the cookies (stored in sqlite file "Cookies") and passwords (stored in "Login Data") are encryted with AES CBC mode. To decrypt the data we need:
        (1) KEY. The key is derived using key derivation function PBKDF2, PBKDF2 requires 4 parameters:
              (i) Secret password. This is "Chrome Safe Storage" password stored in the keychain. 
		  We can use secretstorage which uses D-Bus Secret Service API that is supported by GNOME Keyring.
	      (ii) Salt. Most probably the salt would be "saltysalt"
              (iii) Lengh. The cumulative length of the desired keys. Default is 16 bytes, suitable for instance for Crypto.Cipher.AES.
              (iv) Count. An integer for no. of interations.
        (2) AES Mode. Which is CBC.
        (3) Initialization Vector (IV), which is 16 bytes of empty string.
           
        '''
        connection = secretstorage.dbus_init()
        collection = secretstorage.get_default_collection(connection)
        chromePassword = 'peanuts'.encode('utf8') #it used to be peanuts, but it's deprecated since early 2011
        for secret in collection.get_all_items():
            if secret.get_label() == 'Chrome Safe Storage':
                chromePassword = secret.get_secret()
                break

        
        salt = b'saltysalt'
        length = 16
        count = 1
        aesKey = KDF.PBKDF2(chromePassword, salt, length, count)
        IV = b' ' * 16

        if (credentialsType == "cookies" or credentialsType == "all"):

            value = queryDatabase(directory, 'Cookies', 'SELECT * FROM cookies')
            try: 
                for data in value:
                    encryptedCookie = data[12][3:] #cookies start with three extra characters (v11)
                    cipher = AES.new(aesKey, AES.MODE_CBC, IV)
                    decrypted = cipher.decrypt(encryptedCookie) 
                    decryptedCookie = decrypted.strip().decode('utf8')

                    cookieList.append({
                        'hostname': data[1],
                        'cookieName': data[2],
                        'cookie': str(decryptedCookie)
                    })
            except:
                pass


        if (credentialsType == "passwords" or credentialsType == "all"):
            value = queryDatabase(directory, 'Login Data','SELECT action_url, username_value, password_value FROM logins')
            try:
                for origin_url, username, password in value:
                    encryptedPassword = password[3:]
                    cipher = AES.new(aesKey, AES.MODE_CBC, IV)
                    decrypted = cipher.decrypt(encryptedPassword)
                    decryptedPassword = decrypted.strip().decode('utf8')

                    passwordList.append({
                        'origin_url': origin_url,
                        'username': username,
                        'password': str(decryptedPassword)
                    })
            except:
                pass
    

    return cookieList, passwordList
   

def queryDatabase(directory, database, query):
    try:
        connection = sqlite3.connect(directory + database)
        cursor = connection.cursor()
        v = cursor.execute(query)
        value = v.fetchall()
        return (value)
    except:
        printNicely("(-) Something's wrong with the sqlite database file. Make sure Google chrome / Firefox is not running while you run this script")
        exit()



def getDirectory():
    if (operatingSystem == "Windows"):
        dirChrome = str(os.environ['USERPROFILE'])+'\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\'
        for root, dirs, files in os.walk(str(os.environ['USERPROFILE'])+'\\AppData\\Roaming\\Mozilla\\\Firefox\\Profiles\\'):
            if "key4.db" in files:
                dirFirefox = os.path.join(root)+'\\'

    else:
        dirChrome = str(Path.home())+'/.config/google-chrome/Default/'
        for root, dirs, files in os.walk(str(Path.home())+'/.mozilla/firefox/'):
            if "key4.db" in files:
                dirFirefox = os.path.join(root)+'/'
    return dirChrome, dirFirefox
    


   
def getFirefoxCredentials(directory, masterPassword, credentialsType):

    passwordList,cookieList = [],[]

    '''Cookies are not encrypted in Firefox'''

    if (credentialsType == "cookies" or credentialsType == "all"):
           
        value = queryDatabase(directory, "cookies.sqlite", "SELECT * FROM moz_cookies")
        for data in value:
            cookieList.append({
                'hostname': data[4],
                'cookieName': data[2],
                'cookie': data[3]
            })
       


    if(credentialsType == "passwords" or credentialsType == "all"):
    
        '''
        The passwords in firefox are stored in logins.json file. Passwords are encrypted three times:
        (1) With Triple DES (DES3). Python module DES3 from Crypto.Cipher can be used to decrypt data.It requires KEY, DES3 Mode (it's CBC) and IV (can be extrated from encrypted data).
            The KEY is also encrypted with DES3. It requires three parameters to decrypt the KEY. 
            (i) key. key is generated from entrySalt (stored in key4.db), globalSalt (stored in key4.db) and masterPassword (user needs to provide this, default value is ""). 
                See decryptTripleDes function for detailed algorithm.  
            (ii) DES3 Mode. Which is CBC.
            (iii) Initialization Vector(IV). Same as key, IV can also be extracted from key4.db.  
        (2) ANS1 DER Encoding. It doesn't need a key. Python module pyasn1.codec.der.decoder can be used to decode. 
        (3) Base64 Encoding. It doesn't need a key. Python module b64decode can be used to to decode.
        '''     
        
        value = queryDatabase(directory, "key4.db", 'SELECT item1,item2 FROM metadata WHERE id = "password"')
        
        '''Item1 is global salt. That's all we need from this metadata table'''
        globalSalt = value[0][0]
   
   
        value = queryDatabase(directory, "key4.db", 'SELECT a11,a102 FROM nssPrivate where a11 is not null;')

        for item in value:          
            if item[1] == b"\xf8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01":
                derEncodedData = item[0]
                break
            else:
                printNicely("(-) Wait! Something's wrong with firfox key4.db file. Try Re-running the program and set master password with -p parameter")
                exit()

        try: 
            derDecodedData, someData = der_decode(derEncodedData)
            entrySalt = derDecodedData[0][1][0].asOctets()
            encryptedKey = derDecodedData[1].asOctets()
            key = decryptTripleDES(globalSalt, masterPassword, entrySalt, encryptedKey)
            key=key[:24]

            with open(directory+"logins.json", "r") as loginData:
                jsonLogins = json.load(loginData)

        
            if "logins" not in jsonLogins:
                printNicely("No logins found in logins.json")
                exit()

            for item in jsonLogins["logins"]:
                passwordList.append(
                    {
                        "URL": item["hostname"],
                        "username" : decodeLoginData(key, item["encryptedUsername"]),
                        "password" : decodeLoginData(key, item["encryptedPassword"]),
                    }
                )
            return cookieList,passwordList
        
        except:
            pass
    return cookieList,passwordList
    

def decryptTripleDES(globalSalt, masterPassword, entrySalt, encryptedData):
    hashedPassword = sha1(globalSalt + masterPassword.encode()).digest()
    paddedEntrySalt = entrySalt + b"\x00" * (20 - len(entrySalt))
    combinedHashedPassword = sha1(hashedPassword + entrySalt).digest()
    k1 = hmac.new(combinedHashedPassword, paddedEntrySalt + entrySalt, sha1).digest()
    tk = hmac.new(combinedHashedPassword, paddedEntrySalt, sha1).digest()
    k2 = hmac.new(combinedHashedPassword, tk + entrySalt, sha1).digest()
    k = k1 + k2
    iv = k[-8:]
    key = k[:24]
    return DES3.new(key, DES3.MODE_CBC, iv).decrypt(encryptedData)



def decodeLoginData(key, data):
    base64DecodedData = b64decode(data)
    derDecodedData, someData = der_decode(base64DecodedData)
    iv = derDecodedData[1][1].asOctets()
    desCiphertext = derDecodedData[2].asOctets()
    des = DES3.new(key, DES3.MODE_CBC, iv)
    desDecrypted = des.decrypt(desCiphertext)
    '''PKCS7 unpadding'''
    unpaddedDesDecrypted =  desDecrypted[: -desDecrypted[-1]]
    return unpaddedDesDecrypted.decode()



def exit():
    try:
        sys.exit(0)
    except SystemExit:
        os._exit(0)


def main():
    parser = argparse.ArgumentParser(
					prog=None, 
					usage='python3 passwords.py -c cookies -b firefox',
					description = 'Extract the saved-password from Firefox and Chrome.')

    parser.add_argument('-c', '--credentials',
			default = "all",  
			choices=["passwords", "cookies", "all"], 
			help = 'Specify the credentials you want to extract, "passwords" or "cookies" or "all"')

    parser.add_argument('-b', '--browser', 
			default = "all", 
			choices=["firefox", "chrome", "all"], 
			help = 'Specify the broswer, "firefox" or "chrome" or "all"')

    parser.add_argument('-p', '--password', 
			default = "", 
			help = 'Specify the Master Password for firefox, if you have never set the master password, do not set this parameter.')

    args = parser.parse_args()

    dirChrome, dirFirefox = getDirectory()

    if not os.path.isdir(dirChrome) and not os.path.isdir(dirFirefox):
        printNicely('(-) Error! the chrome and firefox database files are not found.')
        exit()
    else:
        if not os.path.isdir(dirChrome):
            printNicely('(-) The chrome database file is not found!')
        if not os.path.isdir(dirFirefox):   
            printNicely('(-) The firefox database file is not found!')
        
        if os.path.isdir(dirFirefox) and (args.browser == "firefox" or args.browser == "all"):        
            cookieList,passwordList = getFirefoxCredentials(dirFirefox, args.password, args.credentials)
            if cookieList:
                printNicely("(+) Firefox Cookies:", cookieList)
            if not cookieList and args.credentials == "cookies":
                printNicely("(-) Couldn't decrypt firefox cookies")
            if passwordList:
                printNicely("(+) Firefox Passwords:", passwordList)
            if not passwordList and args.credentials == "passwords":
                printNicely("(-) Couldn't decrypt firefox passwords")
        if os.path.isdir(dirChrome) and (args.browser == "chrome" or args.browser == "all"):
            cookieList,passwordList = getChromeCredentials(dirChrome, args.credentials)
            if cookieList:
                printNicely("(+) Chrome Cookies:", cookieList)
            if not cookieList and args.credentials == "cookies":
                printNicely("(-) Couldn't decrypt chrome cookies")
            if passwordList:
                printNicely("(+) Chrome Passwords:", passwordList)
            if not passwordList and args.credentials == "passwords":
                printNicely("(-) Couldn't decrypt chrome passwords")
        exit()




if __name__== '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Exiting')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)

