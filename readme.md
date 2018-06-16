# ps.testPassword
Powershell Module to Test the Password Strength 

##### Background
- 22/Feb/2018 Troy Hunt published his [pwned passwords v2](<https://www.troyhunt.com/ive-just-launched-pwned-passwords-version-2/>) with [Cloudflare's help](<https://blog.cloudflare.com/validating-leaked-passwords-with-k-anonymity/>)
- His post has triggered the password research yet again 
- My favorite sources in this regard were Jeff Atwood's [post](<https://blog.codinghorror.com/hacker-hack-thyself/>) from about year ago and a bit outdated ["Estimating Password Cracking Times"](<https://www.betterbuys.com/estimating-password-cracking-times/>)  
- Jeff pointed to Jeremi M Gosney's [Github gists](<https://gist.github.com/epixoip>) with hashcat benchmarks running on various hardware configurations  
- The most interesting was the [8 x Nvidia GTX 1080 Ti Hashcat Benchmarks](<https://gist.github.com/epixoip/ace60d09981be09544fdd35005051505>)
- The list of other handful resources I have used:
  - [Introducing 306 Million Freely Downloadable Pwned Passwords](<https://www.troyhunt.com/introducing-306-million-freely-downloadable-pwned-passwords/>)
  - [How Long Does It Take to Crack Your Password?](<https://blog.elcomsoft.com/2017/04/how-long-does-it-take-to-crack-your-password/>)
  - [How to Break 30 Per Cent of Passwords in Seconds](<https://blog.elcomsoft.com/2017/02/how-to-break-30-per-cent-of-passwords-in-seconds/>)
  - [Today I Am Releasing Ten Million Passwords](<https://xato.net/today-i-am-releasing-ten-million-passwords-b6278bbe7495>)
  - [Password strength calculator](<https://projects.lambry.com/elpassword/>)
  - [Calculate Passwords](<https://asecuritysite.com/encryption/passes>)
- I'm sure there are much more...

### What module does
- Tests the password strength
- Queries Troy's [HIBP](<https://haveibeenpwned.com/Passwords>) password database
- Prints benchmark table based on Jeremi's [8 x Nvidia GTX 1080 Ti Hashcat Benchmarks](<https://gist.github.com/epixoip/ace60d09981be09544fdd35005051505>)  

### Prerequisits
- Module PCSX 
```powershell
Install-Module pscx -AllowClobber
```

### Installation from Github
```powershell
cd $env:Userprofile\Documents\WindowsPowerShell\Modules\
git clone https://github.com/yubu/ps.testPassword.git
Import-Module ps.passwordTest
``` 
or
```powershell
cd c:\temp
git clone https://github.com/yubu/ps.testPassword.git
Import-Module c:\temp\ps.passwordTest\ps.passwordTest.psm1
```

### Installation from Powershell Gallery
```powershell
Install-Module ps.testPassword
```

### Getting Started
##### Use powershell help to get commands and examples
```powershell
gcm -module ps.testPassword
help -ex Test-Password
```

##### Examples
```powershell
Test-Password qwerty                # Test "qwerty" password strength
Test-Password qwerty -HIBP          # Test "qwerty" password strength and query the HIBP DB
Test-Password qwerty -HIBP | ? Hashtype -match Office | sort SecToCrack | ft -a
Test-Password qwerty -HIBP | ? Hashtype -match PBKDF2 | sort SecToCrack | ft -a
gc c:\passlist.txt | ? {$_} | tpass -HIBP | ? Hashtype -match pbkdf2 | sort SecToCrack,Pass | ft -a
```

##### Result
```powershell
Test-Password qwerty -HIBP | ? Hashtype -match PBKDF2 | sort SecToCrack | ft -a

Password: qwerty
Password length is only 6 characters long. Longer is better!
OK. Lower case: 6
BAD! No Upper case
BAD! No Numbers
BAD! No NonAlphanumeric
Total password complexity: 26
Total password variants for brute force: 308915776

 Variants Speed.Dev         Speed SecToCrack Hashtype                                                   CountInHIBP Pass   PassSHA1
 -------- ---------         ----- ---------- --------                                                   ----------- ----   --------
308915776    126.5 MH/s 126500000          2  MS-AzureSync PBKDF2-HMAC-SHA256                               3599486 qwerty B1B3773A05C0ED0176787A4F1574FF0075F7521E
308915776  88169.0 kH/s  88169000          4  PBKDF2-HMAC-MD5                                               3599486 qwerty B1B3773A05C0ED0176787A4F1574FF0075F7521E
308915776  39996.7 kH/s  39996699          8  PBKDF2-HMAC-SHA1                                              3599486 qwerty B1B3773A05C0ED0176787A4F1574FF0075F7521E
308915776  15187.1 kH/s  15187100         20  PBKDF2-HMAC-SHA256                                            3599486 qwerty B1B3773A05C0ED0176787A4F1574FF0075F7521E
308915776   5451.3 kH/s   5451300         57  PBKDF2-HMAC-SHA512                                            3599486 qwerty B1B3773A05C0ED0176787A4F1574FF0075F7521E
308915776    775.4 kH/s    775400        398  Cisco-IOS $8$ (PBKDF2-SHA256)                                 3599486 qwerty B1B3773A05C0ED0176787A4F1574FF0075F7521E
308915776    775.5 kH/s    775500        398  Django (PBKDF2-SHA256)                                        3599486 qwerty B1B3773A05C0ED0176787A4F1574FF0075F7521E
308915776    382.0 kH/s    382000        809  TrueCrypt PBKDF2-HMAC-RIPEMD160 + XTS 512 bit + boot-mode     3599486 qwerty B1B3773A05C0ED0176787A4F1574FF0075F7521E
308915776    356.6 kH/s    356600        866  TrueCrypt PBKDF2-HMAC-SHA512 + XTS 512 bit                    3599486 qwerty B1B3773A05C0ED0176787A4F1574FF0075F7521E
308915776    232.6 kH/s    232600       1328  TrueCrypt PBKDF2-HMAC-Whirlpool + XTS 512 bit                 3599486 qwerty B1B3773A05C0ED0176787A4F1574FF0075F7521E
308915776    197.3 kH/s    197300       1566  TrueCrypt PBKDF2-HMAC-RIPEMD160 + XTS 512 bit                 3599486 qwerty B1B3773A05C0ED0176787A4F1574FF0075F7521E
308915776    156.2 kH/s    156200       1978  OSX v10.8+ (PBKDF2-SHA512)                                    3599486 qwerty B1B3773A05C0ED0176787A4F1574FF0075F7521E
308915776      2375 H/s      2375     130070  VeraCrypt PBKDF2-HMAC-SHA256 + XTS 512 bit + boot-mode        3599486 qwerty B1B3773A05C0ED0176787A4F1574FF0075F7521E
308915776      1500 H/s      1500     205944  VeraCrypt PBKDF2-HMAC-RIPEMD160 + XTS 512 bit + boot-mode     3599486 qwerty B1B3773A05C0ED0176787A4F1574FF0075F7521E
308915776       969 H/s       969     318799  VeraCrypt PBKDF2-HMAC-SHA256 + XTS 512 bit                    3599486 qwerty B1B3773A05C0ED0176787A4F1574FF0075F7521E
308915776       781 H/s       781     395539  VeraCrypt PBKDF2-HMAC-SHA512 + XTS 512 bit                    3599486 qwerty B1B3773A05C0ED0176787A4F1574FF0075F7521E
308915776       562 H/s       562     549672  VeraCrypt PBKDF2-HMAC-RIPEMD160 + XTS 512 bit                 3599486 qwerty B1B3773A05C0ED0176787A4F1574FF0075F7521E
308915776       500 H/s       500     617832  VeraCrypt PBKDF2-HMAC-Whirlpool + XTS 512 bit                 3599486 qwerty B1B3773A05C0ED0176787A4F1574FF0075F7521E
```

### What is the good password in the end?
- The longer is better. I would start from 12 characters long
- Max complexity is must
- Don't reuse 
- Even those below are better, than one good reusable. But, till somebody will figure out your pattern. Then you're busted 
  - qwerty111Googl!@#
  - qwerty111Insta!@#
  - qwerty111Yahoo!@#
  - qwerty111Faceb!@# 
- To brute force 'qwerty111Googl!@#' hashed by weakest algorithm (MySQL323, crack rate 601.2 GH/s) will take 6.95476258698434E+21 seconds == 220534074929742 years
- When your pattern is known, will take about 45 seconds, when hashed with most modern BKDF2-HMAC-SHA256 algorithm
- Be creative

### Funny part 
- In the HIBP password messi counts 8631 times and ronaldo 112121 times
- qwerty 3599486 times
- usa 2841 times
- america 127330 times
- canada 103770 times
- england 50919 times
- scotland 45182 times
- china 12028 times
- japan 11273 times
- russia 46390 times
- france 55101 times
- italy 7271 times
- holland 28535 times
- turkey 33186 times
- brasil 34675 times
- australia 58356 times
- africa 35838 times
- mozart 43641 times
- bach 2107 times
- beethoven 16103 times
- ...

