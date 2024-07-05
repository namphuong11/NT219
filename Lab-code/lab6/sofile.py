import ctypes
import sys
import os

# .so path
sopath = os.path.join(os.getcwd(), "digital_signature.so")

# load the shared library
signature = ctypes.CDLL(sopath,winmode=ctypes.DEFAULT_MODE)

# Set up the prototype of the function
# All of them are strings (char*)
sign = signature.signPdf # call hashes funtion from shas.so;
sign.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
sign.restype = bool  # The function returns void

verify = signature.verifySignature # call hashes funtion from shas.so;
verify.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
verify.restype = bool  # The function returns void
 
# Wrapped funtions
def call_sign( prvKey, pdfFile, output):
    # Convert Python strings to bytes, as ctypes works with bytes
    prvKey = prvKey.encode('utf-8')
    pdfFile = pdfFile.encode('utf-8')
    output = output.encode('utf-8')
   
    # Call the C function
    return sign(prvKey, pdfFile, output)

def call_verify( pbKey, pdfFile, output):
    # Convert Python strings to bytes, as ctypes works with bytes
    pbKey = pbKey.encode('utf-8')
    pdfFile = pdfFile.encode('utf-8')
    output = output.encode('utf-8')
   
    # Call the C function
    return verify(pbKey, pdfFile, output)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <sign|verify> <parameters>\n")
        sys.exit(1)
    
    if (sys.argv[1]  =='sign'):
        if len(sys.argv) != 5:
            print(f"Usage: python {sys.argv[0]} sign <privateKey> <pdfFile> <output>\n")
            sys.exit(1)
        if (call_sign(sys.argv[2],sys.argv[3],sys.argv[4])):
            print("Sign successed")
        else:
            print("Sign failed")

    if (sys.argv[1]  =='verify'):
        if len(sys.argv) != 5:
            print(f"Usage: python {sys.argv[0]} verify <publicKey> <pdfFile> <output>\n")
            sys.exit(1)
        if (call_verify(sys.argv[2],sys.argv[3],sys.argv[4])):
            print("Verify successed")
        else:
            print("Verify failed")


    