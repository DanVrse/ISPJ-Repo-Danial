import pyotp

# TOTP
timedOTP = pyotp.TOTP('base32secret3232')
print(timedOTP.now())
print(timedOTP.verify('495790'))
print('')
hOTP = pyotp.HOTP('base32secret3232')
print(hOTP.at(0))
print(hOTP.at(1))
print(hOTP.at(1401))

# verifying HOTP codes with PyOTP
print(hOTP.verify("316439", 1401))
print(hOTP.verify("316439", 1402))
