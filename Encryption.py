# from Crypto.PublicKey import RSA
# from Crypto.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from OpenSSL import crypto, SSL
# from Crypto.Cipher import AES
# from Crypto.Random import get_random_bytes
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
# from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding,  rsa
from cryptography import x509
import os
from datetime import datetime, timedelta
import json
from cryptography.fernet import Fernet

import shutil
import pyminizip

#
def generate_keypair(keysize):
    return RSA.generate(keysize)
# def write_private_key(keypair, private_keyfile):
#     private_key = keypair.export_key()
#     private_out = open(private_keyfile, "wb")
#     private_out.write(private_key)
#     private_out.close()
#     return
# def read_private_key(private_keyfile):
#     return RSA.import_key(open(private_keyfile).read())
# def write_public_key(keypair, public_keyfile):
#     public_key = keypair.publickey().export_key()
#     public_out = open(public_keyfile, "wb")
#     public_out.write(public_key)
#     public_out.close()
#     return
# def read_public_key(public_keyfile):
#     return RSA.import_key(open(public_keyfile).read())
# def encrypt(public_key, plaintext_utf8):
#     rsa = PKCS1_OAEP.new(public_key)
#     ciphertext_utf8 = rsa.encrypt(plaintext_utf8)
#     return ciphertext_utf8
# def decrypt(private_key, ciphertext_utf8):
#     rsa = PKCS1_OAEP.new(private_key)
#     decryptedtext_utf8 = rsa.decrypt(ciphertext_utf8)
#     return decryptedtext_utf8
# def generate_the_keys():
#     keypair = generate_keypair(2048)
#     write_private_key(keypair, "credentialkey_private.pem")
#     write_public_key(keypair, "credentialkey_public.pem")

def generate_my_keys():
    keypair = generate_keypair(2048)
    public_out = open("./Testkeys/thehey.pem", "wb")
    public_out.write(keypair.export_key())

    public_out.close()

    # write_private_key(keypair, "mykey_private.pem")
    # write_public_key(keypair, "mykey_public.pem")


def cert_gen(

    owner = "SimpleBoard2",

    serialNumber=0,
    validityStartInSeconds=0,
    validityEndInSeconds=10*365*24*60*60,
    KEY_FILE = "./Testkeys/SimpleboardprivateKey.pem",
    KEY_FILE2 = "./Testkeys/SimpleboardpublicKey.pem",
    CERT_FILE="./Testkeys/Simpleboardcert.crt"):
    #can look at generated file using openssl:
    #openssl x509 -inform pem -in selfsigned.crt -noout -text
    # create a key pair
    # k = read_private_key("thehey.pem")

    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 4096)
    # create a self-signed cert
    cert = crypto.X509()

    cert.get_subject().O = owner
    cert.set_serial_number(serialNumber)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(validityEndInSeconds)
    cert.set_issuer(cert.get_subject())

    cert.set_pubkey(k)
    cert.sign(k, 'sha512')
    with open(CERT_FILE, "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert.to_cryptography()).decode("utf-8"))
    with open(KEY_FILE, "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))
    with open(KEY_FILE2, "wt") as f:
        f.write(crypto.dump_publickey(crypto.FILETYPE_PEM, k).decode("utf-8"))


# cert_gen()
# certfile = open("selfsigned.crt", "r")
# certcontent =certfile.read()
# cert = crypto.load_certificate(crypto.FILETYPE_PEM, certcontent.encode("utf-8"))
# thekey = cert.get_pubkey()
# print(cert.X509Req.verify(cert.get_pubkey()))

# with open("MypublicKey.pem", "r") as publickey:
#     issuer_public_key = load_pem_public_key(publickey.read().encode("utf-8"))



def gen_key_test():
    private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
)
    pem = private_key.private_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PrivateFormat.TraditionalOpenSSL,
   encryption_algorithm=serialization.NoEncryption()
)
    with open("./Testkeys/testkey.pem", "wt") as f:
        f.write(pem.decode("utf-8"))

def cert_gen_user(

    owner, filename,password,path,key,

    serialNumber=0,
    validityStartInSeconds=0,
    validityEndInSeconds=10*365*24*60*60,
):
    #can look at generated file using openssl:
    #openssl x509 -inform pem -in selfsigned.crt -noout -text
    # create a key pair
    # k = read_private_key("thehey.pem")




    KEY_FILE = f"./tempfiles/{filename}/{filename}.pem"
    #
    # CERT_FILE=f"./Testkeys/Simpleboardcert.crt"
    # KEY_FILE = f"./Testkeys/testkey.pem"

    CERT_FILE=f"{path}/cert.crt"
    dir = f"./tempfiles/{filename}"
    os.mkdir(dir)
    ROOT_KEY_FILE = "./Testkeys/SimpleboardprivateKey.pem"

    ROOT_CERT_FILE="./Testkeys/Simpleboardcert.crt"
    ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(ROOT_CERT_FILE).read().encode("utf-8"))

    ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM,open(ROOT_KEY_FILE).read().encode("utf-8"))
#     private_key = rsa.generate_private_key(
#     public_exponent=65537,
#     key_size=4096,
# )
#     pem = private_key.private_bytes(
#     encoding=serialization.Encoding.PEM,
#     format=serialization.PrivateFormat.TraditionalOpenSSL,
#     encryption_algorithm=serialization.NoEncryption()
# )
#     public_key = private_key.public_key()
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 4096)
    # kp = crypto.PKey()
    # kp.from_cryptography_key(public_key)
    # k.generate_key(crypto.TYPE_RSA, 4096)
    # create a self-signed cert
    cert = crypto.X509()

    cert.get_subject().O = owner
    cert.set_serial_number(serialNumber)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(validityEndInSeconds)
    cert.set_issuer(ca_cert.get_subject())

    cert.set_pubkey(k)
    cert.sign(ca_key, 'sha512')
    with open(CERT_FILE, "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert.to_cryptography()).decode("utf-8"))
    with open(KEY_FILE, "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))
    #
    # certdate = json.load(open("./ISPJ uploads/certdates.json"))
    # expire = datetime.now() + timedelta(hours=24)
    # certdate[filename] = expire
    # zippy = ZipFile(f"./tempfiles/{filename}.zip", "x" )
    #
    # zippy.setpassword(bytes(password, 'utf-8'))
    # zippy.close()
    # zippy = ZipFile(f"./tempfiles/{filename}.zip", "w" )
    # zippy.write(KEY_FILE)
    # zippy.write(CERT_FILE)
    encryptaesfile(key,  f"{path}/access.json")
    encryptfile(CERT_FILE, key, f"{path}/keys.txt")

    keycert = KEY_FILE
    # input file path

    # output zip file path
    oupt = f"./tempfiles/{filename}.zip"

    # set password value

    # compress level
    com_lvl = 5


    # compressing file
    pyminizip.compress(keycert, None, oupt,
                       password, com_lvl)
    shutil.rmtree(dir)
    # with open("./Testkeys/testkeyC.pem", "wt") as f:
    #
    #     f.write(pem.decode("utf-8"))

    # with open(KEY_FILE2, "wt") as f:
    #     f.write(crypto.dump_publickey(crypto.FILETYPE_PEM, k).decode("utf-8"))






def verify_certificate(cert_path, trusted_certs):
    # Download the certificate from the url and load the certificate
    cert_path="./Testkeys/Simpleboardcert.crt"
    cert_file = open(cert_path, 'r')
    cert_data = cert_file.read().encode("utf-8")
    certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)

    #Create a certificate store and add your trusted certs
    try:
        store = crypto.X509Store()
        store.add_cert(certificate)
        # Assuming the certificates are in PEM format in a trusted_certs list
        with open(trusted_certs, "r") as cert_file:
            cert_data = cert_file.read().encode("utf-8")
            client_certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)


        # Create a certificate context using the store and the downloaded certificate
        store_ctx = crypto.X509StoreContext(store, client_certificate)

        # Verify the certificate, returns None if it can validate the certificate
        store_ctx.verify_certificate()

        return True

    except Exception as e:
        print(e)
        return False


def verify_cert():
    with open("./Testkeys/selfsigned.crt", "r") as certi:
        cert_to_check = x509.load_pem_x509_certificate(certi.read().encode("utf-8"))
        issuer_public_key = cert_to_check.public_key()
    print(issuer_public_key.verify(
        cert_to_check.signature,
        cert_to_check.tbs_certificate_bytes,
        # Depends on the algorithm used to create the certificate
        padding.PKCS1v15(),
        cert_to_check.signature_hash_algorithm,
    ))

#
# def encrypt(message):
#     with open("./Testkeys/testkeyC.pem", "r") as private:
#         privatekey = crypto.load_privatekey(crypto.FILETYPE_PEM, private.read())
#     ciphertext = privatekey.encrypt(
#     message,
#     padding.OAEP(
#         mgf=padding.MGF1(algorithm=hashes.SHA256()),
#         algorithm=hashes.SHA256(),
#         label=None
#     )
# )
#
#     return ciphertext

def encrypt(certfile, plaintext_utf8,file):
    if file =='yes':
        cert_to_check = x509.load_pem_x509_certificate(certfile.read())
        issuer_public_key = cert_to_check.public_key()
    else:
        with open(certfile, "r") as certi:
            cert_to_check = x509.load_pem_x509_certificate(certi.read().encode("utf-8"))
            issuer_public_key = cert_to_check.public_key()
        # print(issuer_public_key)
    # rsa = PKCS1_OAEP.new(public_key)
    # decryptedtext_utf8 = rsa.decrypt(ciphertext_utf8)
    # return decryptedtext_utf8
    pem = issuer_public_key.public_bytes( encoding=serialization.Encoding.PEM,
                                          format=serialization.PublicFormat.SubjectPublicKeyInfo)
    # print(pem.decode("utf-8"))
#     ciphertext_utf8 = public_key.encrypt(
#     plaintext_utf8.encode(),padding.OAEP(
#         mgf=padding.MGF1(algorithm=hashes.SHA256()),
#         algorithm=hashes.SHA256(),
#         label=None
#     )
#
# )

    privatekey = RSA.importKey(pem.decode("utf-8"))

    rsa = PKCS1_OAEP.new(privatekey)
    if file == 'yes':
        ciphertext_utf8 = rsa.encrypt(str(plaintext_utf8).encode())
    else:
        ciphertext_utf8 = rsa.encrypt(plaintext_utf8)
    return ciphertext_utf8

def decrypt(keyfile, ciphertext_utf8, Yes="no"):
    # with open("./Testkeys/samuel@gmail.com.pem", "r") as f
    if Yes=="yes":
            private_key = crypto.load_privatekey(crypto.FILETYPE_PEM,keyfile).to_cryptography_key()
    else:
        keyfile.seek(0)
        private_key = crypto.load_privatekey(crypto.FILETYPE_PEM,keyfile.read()).to_cryptography_key()

    print("IRWOR")
    pem = private_key.private_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PrivateFormat.PKCS8,
   encryption_algorithm=serialization.NoEncryption())


    publickey = RSA.importKey(pem.decode("utf-8"))

    rsa = PKCS1_OAEP.new(publickey)

    plaintext_utf8 = rsa.decrypt(ciphertext_utf8)
    return plaintext_utf8
# cert_gen("happy")
# cert_gen()
# verify_cert()
# cert_gen_user("gmail", "gmail")
# cert_gen()
# print(verify_certificate("./Testkeys/Simpleboardcert.crt", "./Testkeys/testcert.crt"))
def encryptfile(certfile,key, filepath,file="no"):

    text = encrypt(certfile,key, file)
        # print("cipher: ",text)
        # print("plain: ",decrypt(8, textc))

    with open(filepath,"wb") as access:
        access.write(text)

#
#
# # print(text)
# # gen_key_test()
# # generate_my_keys()
def decryptfile(keyfile, filepath, Yes = 'no'):
    with open(filepath,"rb") as access:
        texta = decrypt(keyfile, access.read(), Yes)

        return texta

        # print("cipher: ", access.read())
        # print(type(textc), type(access.read()))
        # print(len(textc), len(access.read()))
        # access.seek(0, os.SEEK_END)
        # ln = access.tell()
        # access.seek(0)
        # print(len(textc), ln)
        # if textc == access.read():
        #     access.seek(0)
        #     print("MATCH")
#
# print(decryptfile("C:/Users/User/Desktop/lel@gmail.com.pem","./ISPJ uploads/user/lel@gmail.com!$%()gg/access.json"))
# cert_gen()
def encryptaes(key, plaintext_utf8, ciphertext_file):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext_utf8, AES.block_size))
    file_out = open(ciphertext_file, "wb")
    [file_out.write(x) for x in (cipher.iv, ciphertext)]
    file_out.close()
    return

def decryptaes(key, ciphertext_file):
    file_in = open(ciphertext_file, "rb")
    iv, ciphertext = [file_in.read(x) for x in (16, -1)]
    file_in.close()

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decryptedtext_utf = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decryptedtext_utf.decode("ISO-8859-1")

def generateaeskey():
    key = get_random_bytes(32)
    return key

def encryptaesfile(key, filepath,file="no"):
    with open(filepath,"rb") as access:
        encryptaes(key,access.read(),filepath)
        # print("cipher: ",text)
        # print("plain: ",decrypt(8, textc))


def decryptaesfile(key, filepath, Yes = 'no'):
    print(key)
    texta = decryptaes(key, filepath)
    print(texta)
    texta = texta.replace("'", '"')
    # if Yes == "yes":
    #     textt = json.loads(texta)
    textt = json.loads(texta)
    return textt


#
# with open("./Testkeys/keys.txt", "rb") as keys:
#     encryptaesfile(keys.read(), "./Testkeys/access.json")
# with open("./Testkeys/keys.txt", "rb") as keys:
#     decryptaesfile(keys.read(), "./Testkeys/access.json")