# chrofire

Have you ever used "save password" option in chrome or firefox? wonder where does the browser save these credentials and how secure is it? Bad news is it's not very secure, if your computer catches a malware or someone gets few second access of your computer (e.g. you were on free public wifi and an adversary got access of your system by compromising an application which you never updated), it will only take a script like **chrofire.py** to get all your saved credentials/cookies. It is also possible to get other saved data (credit card numbers, name, address, bookmarks, history, anything which you have saved in browser). So how to secure it? avoid saving data in browsers or at-least secure your passwords; if you're using firefox, enable Master Password, in this case all the username/passwords would get encrypted using Master Password; chrome doesn't have any feature like this, best option would be to use a password manager e.g. [lastPass](https://www.lastpass.com/).

**chrofire.py** can extract username-passwords and cookies from chrome and firefox. **You need python3 to run the script**. Here is the usage:

Windows:
```
pip install -r requirements-windows.txt
python chrofire.py         //this will only get chrome credentials
python chrofire.py -h      //help
python chrofire.py -b firefox -d C:\Users\%username%\AppData\Roaming\Mozilla\Firefox\Profiles\***.default\    //get credentials from firefox, look for file key4.db for firefox direcotry
python chrofire.py -b chrome -c cookies    //get only cookies from chrome
python chrofire.py -b firefox -c passwords -d C:\Users\%username%\AppData\Roaming\Mozilla\Firefox\Profiles\***.default\    //get passwords from firefox
```
Linux:
```
pip install -r requirements-linux.txt
python chrofire.py         //this will only get chrome credentials
python chrofire.py -h      //help
python chrofire.py -b firefox -d /%username%/.mozilla/firefox/***.default/    //get credentials from firefox (run "locat key4.db" to get the directory)
python chrofire.py -b chrome -c cookies    //get only cookies from chrome
python chrofire.py -b firefox -c passwords -d /%username%/.mozilla/firefox/***.default/    //get passwords from firefox
```

## Chrome and Firefox password encryption algorithms

Below is a high level explanation of encryption algorithms used by chrome and firefox to save passwords.

Chrome save passwords in Windows and Linux differently. 

**Chrome in Windows:**

Chrome uses the so-called Data Protection API (DPAPI), which is in Windows from NT 5.0 (i.e. Windows 2000) onwards, which nowadays uses AES-256 to encrypt the passwords and cookies. We can use  CryptUnprotectData from win32crypt python module to decrypt it. See [this](https://digital-forensics.sans.org/summit-archives/dfirprague14/Give_Me_the_Password_and_Ill_Rule_the_World_Francesco_Picasso.pdf) for DPAPI explanation.


**Chrome in Linux:**

In linux, the cookies (stored in sqlite file "Cookies") and passwords (stored in "Login Data") are encryted with AES CBC mode. To decrypt the data we need:
        
        1. KEY. The key is derived using key derivation function PBKDF2, the PBKDF2 requires 4 parameters:
        
            i. Secret password. This is "Chrome Safe Storage" password stored in the keychain. We can use secretstorage which uses D-Bus. Secret Service API that is supported by GNOME Keyring.
            ii. Salt. Most probably the salt would be "saltysalt"
            iii. Lengh. The cumulative length of the desired keys. Default is 16 bytes, suitable for instance for Crypto.Cipher.AES.
            iv. Count. An integer for no. of interations.
            
         2. AES Mode. Which is CBC.
         3. Initialization Vector (IV), which is 16 bytes of empty string.
         
         
Below is a visual description of algorithm used in linux for chrome credentials:


![chrome-linux](https://github.com/spaceintotime/chrofire/raw/master/chrome-linux.jpg)


**Firefox in Linux and Windows**
Firefox deos not encrypt cookies. The encryption algorithm for username-password is same for Windows and Linux. 

 The passwords in firefox are stored in logins.json file. Passwords are encrypted three times:
 
        1. With Triple DES (DES3). Python module DES3 from Crypto.Cipher can be used to decrypt data.It requires KEY, DES3 Mode (it's CBC) and IV (can be extrated from encrypted data).
           The KEY is also encrypted with DES3. It requires three parameters to decrypt the KEY. 
             i. key. key is generated from entrySalt (stored in key4.db), globalSalt (stored in key4.db) and masterPassword (user needs to provide this, default value is ""). 
                See decryptTripleDes function for detailed algorithm.  
             ii. DES3 Mode. Which is CBC.
             iii. Initialization Vector(IV). Same as key, IV can also be extracted from key4.db.
            
        2. ANS1 DER Encoding. It doesn't need a key. Python module pyasn1.codec.der.decoder can be used to decode. 
        3. Base64 Encoding. It doesn't need a key. Python module b64decode can be used to to decode.
        


Below is a visual descripton of the algorithm:


![fireforx-algo](https://github.com/spaceintotime/chrofire/raw/master/firefox-algo.jpg)
