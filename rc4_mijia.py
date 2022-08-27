import base64
import hashlib
import zlib
import os
from Crypto.Cipher import ARC4

@staticmethod
def uncryptText(_nonce, ssecurity, data):
    hash_object = hashlib.sha256(base64.b64decode(ssecurity) + base64.b64decode(_nonce))
    rcPassword = base64.b64encode(hash_object.digest()).decode('utf-8')

    r = ARC4.new(base64.b64decode(rcPassword))
    r.encrypt(bytes(1024))
    decoded = r.encrypt(base64.b64decode(data))

    try:
        decodedText = decoded.decode("utf-8")
    except Exception:
        try:
            decodedGzip = zlib.decompress(decoded, 16+zlib.MAX_WBITS)
        except Exception: 
            return -1
        decodedText = decodedGzip.decode("utf-8")
    
    if(len(decodedText) <= 0):
        return -1
    else:
        return decodedText

@staticmethod
def encryptText(_nonce, ssecurity, data):
    hash_object = hashlib.sha256(base64.b64decode(ssecurity) + base64.b64decode(_nonce))
    rcPassword = base64.b64encode(hash_object.digest()).decode('utf-8')

    r = ARC4.new(base64.b64decode(rcPassword))
    r.encrypt(bytes(1024))
    encoded = r.encrypt(data.encode('utf-8'))

    encoded = base64.b64encode(encoded)
    encoded = encoded.decode('utf-8')

    return encoded

@staticmethod
def encryptRC4(password, payload):
    r = ARC4.new(base64.b64decode(password))
    r.encrypt(bytes(1024))
    return base64.b64encode(r.encrypt(payload.encode())).decode()

@staticmethod
def mkNonce(millis):
    nonce_bytes = os.urandom(8) + (int(millis / 60000)).to_bytes(4, byteorder='big')
    return base64.b64encode(nonce_bytes).decode()

@staticmethod
def mkSignedNonce(nonce, ssecurity):
    hash_object = hashlib.sha256(base64.b64decode(ssecurity) + base64.b64decode(nonce))
    return base64.b64encode(hash_object.digest()).decode('utf-8')

@staticmethod
def mkEncSignature(url, reqType, signed_nonce, data):
    signature_params = [str(reqType).upper(), url.split("com")[1].replace("/app/", "/")]
    for k, v in data.items():
        signature_params.append(f"{k}={v}")
    signature_params.append(signed_nonce)
    signature_string = "&".join(signature_params)
    return base64.b64encode(hashlib.sha1(signature_string.encode('utf-8')).digest()).decode()

@staticmethod
def mkEncData(url, reqType, signed_nonce, nonce, ssecurity, data):
    data['rc4_hash__'] = mkEncSignature(url, reqType, signed_nonce, data)
    for k, v in data.items():
        data[k] = encryptRC4(signed_nonce, v)
    data.update({
        'signature': mkEncSignature(url, reqType, signed_nonce, data),
        'ssecurity': ssecurity,
        '_nonce': nonce,
    })
    return data
