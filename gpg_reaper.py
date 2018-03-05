# GPG Reaper
# 
# MIT License
#
# Copyright (c) 2018 Kacper Szurek
# https://security.szurek.pl/
from pgpy.packet.fields import MPI, RSAPriv
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
from pgpy import PGPKey
from pgpy.packet.packets import PrivKeyV4
import json
import codecs
import sys
import os

begin_block = '--START_GPG_REAPER--'
end_block = '--END_GPG_REAPER--'

if len(sys.argv) != 2:
    print "Usage: " + __file__ + " output.txt"
    os._exit(0)

file_path = sys.argv[1]

if not os.path.isfile(file_path):
    print "[-] File not exist"
    os._exit(0)

try:
    def detect_by_bom(path,default=None):
        with open(path, 'rb') as f:
            raw = f.read(4)
        for enc,boms in \
                ('utf-8-sig',(codecs.BOM_UTF8,)),\
                ('utf-16',(codecs.BOM_UTF16_LE,codecs.BOM_UTF16_BE)),\
                ('utf-32',(codecs.BOM_UTF32_LE,codecs.BOM_UTF32_BE)):
            if any(raw.startswith(bom) for bom in boms): return enc
        return default

    file_encoding = detect_by_bom(file_path)
    content = open(file_path).read()

    if file_encoding:
        content = content.decode(file_encoding)

    begin_find = content.find(begin_block)
    end_find = content.find(end_block)
    if begin_find != -1 and end_find != -1:
        data = json.loads(content[begin_find+len(begin_block):end_find])    
        if type(data) is not list:
            data = [data]
        for gpg in data:
            try:
                rsa_priv = RSAPriv()
                rsa_priv.e = MPI(int(gpg['e'], 16))
                rsa_priv.n = MPI(int(gpg['n'], 16))
                rsa_priv.d = MPI(int(gpg['d'], 16))
                rsa_priv.p = MPI(int(gpg['p'], 16))
                rsa_priv.q = MPI(int(gpg['q'], 16))
                rsa_priv.u = MPI(int(gpg['u'], 16))
                rsa_priv._compute_chksum()

                restored_priv_key = PrivKeyV4()
                restored_priv_key.pkalg = PubKeyAlgorithm.RSAEncryptOrSign
                restored_priv_key.keymaterial = rsa_priv
                restored_priv_key.update_hlen()

                pgp_key = PGPKey()
                pgp_key._key = restored_priv_key 

                public_key, _ = PGPKey.from_blob(gpg['public'])
                # fingerprint contains cration date so we need explicit copy this one
                pgp_key._key.created = public_key._key.created

                pgp_key.add_uid(
                  public_key.userids[0],
                  usage={
                    KeyFlags.Sign,
                    KeyFlags.EncryptCommunications,
                    KeyFlags.EncryptStorage
                    },
                  hashes=[
                    HashAlgorithm.SHA256,
                    HashAlgorithm.SHA384,
                    HashAlgorithm.SHA512,
                    HashAlgorithm.SHA224],
                  ciphers=[
                    SymmetricKeyAlgorithm.AES256,
                    SymmetricKeyAlgorithm.AES192,
                    SymmetricKeyAlgorithm.AES128],
                  compression=[
                    CompressionAlgorithm.ZLIB,
                    CompressionAlgorithm.BZ2,
                    CompressionAlgorithm.ZIP,
                    CompressionAlgorithm.Uncompressed])

                # print pgp_key
                key_fingeprint = pgp_key.fingerprint.replace(" ", "")
                print "[+] Dump {} - {}".format(key_fingeprint, public_key.userids[0])
                open(key_fingeprint+".key", "w").write(str(pgp_key))
            except Exception as e:
                print "[-] Error: "+str(e)
    else:
        print "[-] No info"
except Exception as e:
    print "[-] Error: "+str(e)