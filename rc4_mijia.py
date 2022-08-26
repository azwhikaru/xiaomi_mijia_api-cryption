import base64
import hashlib
import zlib
from Crypto.Cipher import ARC4

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

def encryptText(_nonce, ssecurity, data):
    hash_object = hashlib.sha256(base64.b64decode(ssecurity) + base64.b64decode(_nonce))
    rcPassword = base64.b64encode(hash_object.digest()).decode('utf-8')

    r = ARC4.new(base64.b64decode(rcPassword))
    r.encrypt(bytes(1024))
    encoded = r.encrypt(data.encode('utf-8'))

    encoded = base64.b64encode(encoded)
    encoded = encoded.decode('utf-8')

    return encoded

print(uncryptText("6HaPJt5Hqg8BpoZp","G8XyxCKqCQvCeAr+IkNUDw==","f1BZF4uBRiSK3Rek+wzs/lVmAzvVibw3vj9nFIjgth1pOEoj7CbSfWWTPqkTiwB6afegmlCro0d4Ozo2bCE+v+eh9G5Kjo87ORU+dHcruMpqBlCtAN62c9Nq4ltAOCZ+CYecGKrUZtwHRQa1LIPJO39F7d0="))
print(encryptText("6HaPJt5Hqg8BpoZp","G8XyxCKqCQvCeAr+IkNUDw==",'{"method":"GET","params":{"routerID":"779d7b08-5c8e-6838-cc5c-851ff6c14c50","locale":"zh_TW","v":"2","refresh":"1"}}'))
