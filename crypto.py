from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os
import sys

class crypto:
    def __init__(self):
        self.backend = default_backend()

    #For creating RSA key pair
    def rsa_key_pair(self):
        private_key = rsa.generate_private_key(public_exponent=65537,
                                           key_size=2048,backend=self.backend)
        public_key = private_key.public_key()
        return public_key, private_key




    #For loading RSA keys for usage
    def public_key_load(self, public_key_pem):
        public_key = serialization.load_pem_public_key(public_key_pem.read(),
                                                        backend=self.backend)
        return public_key

    def private_key_load(self, private_key_pem):
        private_key = serialization.load_pem_public_key(private_key_pem.read(),
                                                        backend=self.backend)
        return private_key





    #Need to pass peer public key for key generation
    def diffie_hellman(self, peer_public_key):

        parameters = dh.generate_parameters(generator=2, key_size=2048,backend=default_backend())


        # A new private key for each exchange
        priv_key_DH=parameters.generate_private_key()

        #Pass the public of the peer
        session_key= priv_key_DH.exchange(peer_public_key)
        derived_key = HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=b'handshake',backend=default_backend()).derive(session_key)



    # Encrypt the message using the public key of the destination
    def rsa_encryption(self,public_key,message):
        ciphertext = public_key.encrypt(message,padding.OAEP(mgf = padding.MGF1(algorithm=hashes.SHA256()),
                                                             algorithm = hashes.SHA256(),label = None))
        return ciphertext

    # Decrypt the message using the private key of the receiver
    def rsa_decryption(self,private_key,ciphertext):
        plaintext = private_key.decrypt(ciphertext,padding.OAEP(mgf = padding.MGF1(algorithm=hashes.SHA256()),
                                                                algorithm = hashes.SHA256(),label = None))
        return plaintext


    # AES Symmetric encryption
    def symmetric_encryption(self, sym_key, iv, payload, ad):
        ciphers = Cipher(algorithms.AES(sym_key), mode=modes.GCM(iv),
                                   backend=self.backend).encryptor()
        encryptor=ciphers.encryptor
        encryptor.authenticate_additional_data(ad)
        ciphertext = encryptor.update(payload) + encryptor.finalize()
        return encryptor.tag, ciphertext


    # AES Symmetric encryption
    def symmetric_decryption(self, sym_key, iv, payload, tag, ad):
        ciphers = Cipher(algorithms.AES(sym_key),mode= modes.GCM(iv, tag),
                                backend=self.backend).decryptor()

        decryptor=ciphers.decryptor
        decryptor.authenticate_additional_data(ad)
        plain_text = decryptor.update(payload) + decryptor.finalize()
        return plain_text


    #function to serialize private key
    def private_key(self,key_file):
     try:
           private_key_serial = serialization.load_pem_private_key(key_file.read(),password=None, backend=default_backend())


     except:
                   print "Key format not supported,(My developer is lazy)"
                   print "Supported key format: PEM"
                   sys.exit(1)

     return private_key_serial


    #function to serialize public key
    def public_key(self,key_file):

      try:
         public_key_serial = serialization.load_pem_public_key(key_file.read(), backend=default_backend())


      except:
         try:
          print "Key format not supported, (My developer is lazy)"
          print "Supported key formats: PEM"
          sys.exit(1)

         except:

          return public_key_serial


    def sign(self,private_key_sender,message): #pass the private key of the sender
        signature = private_key_sender.sign(message,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                                       salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())

        return signature

    #Pass the public key and signature of the sender
    #  Check if the signature tag is required
    def verify(self,public_key_receiver,signature):
        public_key_receiver.verify(signature,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                             salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())

