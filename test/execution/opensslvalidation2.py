import datetime

import OpenSSL
from six import u, b, binary_type, PY3

root_cert_pem = b("""-----BEGIN CERTIFICATE-----
MIIC7TCCAlagAwIBAgIIPQzE4MbeufQwDQYJKoZIhvcNAQEFBQAwWDELMAkGA1UE
BhMCVVMxCzAJBgNVBAgTAklMMRAwDgYDVQQHEwdDaGljYWdvMRAwDgYDVQQKEwdU
ZXN0aW5nMRgwFgYDVQQDEw9UZXN0aW5nIFJvb3QgQ0EwIhgPMjAwOTAzMjUxMjM2
NThaGA8yMDE3MDYxMTEyMzY1OFowWDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAklM
MRAwDgYDVQQHEwdDaGljYWdvMRAwDgYDVQQKEwdUZXN0aW5nMRgwFgYDVQQDEw9U
ZXN0aW5nIFJvb3QgQ0EwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAPmaQumL
urpE527uSEHdL1pqcDRmWzu+98Y6YHzT/J7KWEamyMCNZ6fRW1JCR782UQ8a07fy
2xXsKy4WdKaxyG8CcatwmXvpvRQ44dSANMihHELpANTdyVp6DCysED6wkQFurHlF
1dshEaJw8b/ypDhmbVIo6Ci1xvCJqivbLFnbAgMBAAGjgbswgbgwHQYDVR0OBBYE
FINVdy1eIfFJDAkk51QJEo3IfgSuMIGIBgNVHSMEgYAwfoAUg1V3LV4h8UkMCSTn
VAkSjch+BK6hXKRaMFgxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJJTDEQMA4GA1UE
BxMHQ2hpY2FnbzEQMA4GA1UEChMHVGVzdGluZzEYMBYGA1UEAxMPVGVzdGluZyBS
b290IENBggg9DMTgxt659DAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4GB
AGGCDazMJGoWNBpc03u6+smc95dEead2KlZXBATOdFT1VesY3+nUOqZhEhTGlDMi
hkgaZnzoIq/Uamidegk4hirsCT/R+6vsKAAxNTcBjUeZjlykCJWy5ojShGftXIKY
w/njVbKMXrvc83qmTdGl3TAM0fxQIpqgcglFLveEBgzn
-----END CERTIFICATE-----
""")
intermediate_cert_pem = b("""-----BEGIN CERTIFICATE-----
MIICVzCCAcCgAwIBAgIRAMPzhm6//0Y/g2pmnHR2C4cwDQYJKoZIhvcNAQENBQAw
WDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAklMMRAwDgYDVQQHEwdDaGljYWdvMRAw
DgYDVQQKEwdUZXN0aW5nMRgwFgYDVQQDEw9UZXN0aW5nIFJvb3QgQ0EwHhcNMTQw
ODI4MDIwNDA4WhcNMjQwODI1MDIwNDA4WjBmMRUwEwYDVQQDEwxpbnRlcm1lZGlh
dGUxDDAKBgNVBAoTA29yZzERMA8GA1UECxMIb3JnLXVuaXQxCzAJBgNVBAYTAlVT
MQswCQYDVQQIEwJDQTESMBAGA1UEBxMJU2FuIERpZWdvMIGfMA0GCSqGSIb3DQEB
AQUAA4GNADCBiQKBgQDYcEQw5lfbEQRjr5Yy4yxAHGV0b9Al+Lmu7wLHMkZ/ZMmK
FGIbljbviiD1Nz97Oh2cpB91YwOXOTN2vXHq26S+A5xe8z/QJbBsyghMur88CjdT
21H2qwMa+r5dCQwEhuGIiZ3KbzB/n4DTMYI5zy4IYPv0pjxShZn4aZTCCK2IUwID
AQABoxMwETAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBDQUAA4GBAPIWSkLX
QRMApOjjyC+tMxumT5e2pMqChHmxobQK4NMdrf2VCx+cRT6EmY8sK3/Xl/X8UBQ+
9n5zXb1ZwhW/sTWgUvmOceJ4/XVs9FkdWOOn1J0XBch9ZIiFe/s5ASIgG7fUdcUF
9mAWS6FK2ca3xIh5kIupCXOFa0dPvlw/YUFT
-----END CERTIFICATE-----
""")
untrusted_cert_pem = b("""-----BEGIN CERTIFICATE-----
MIICWDCCAcGgAwIBAgIRAPQFY9jfskSihdiNSNdt6GswDQYJKoZIhvcNAQENBQAw
ZjEVMBMGA1UEAxMMaW50ZXJtZWRpYXRlMQwwCgYDVQQKEwNvcmcxETAPBgNVBAsT
CG9yZy11bml0MQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExEjAQBgNVBAcTCVNh
biBEaWVnbzAeFw0xNDA4MjgwMjEwNDhaFw0yNDA4MjUwMjEwNDhaMG4xHTAbBgNV
BAMTFGludGVybWVkaWF0ZS1zZXJ2aWNlMQwwCgYDVQQKEwNvcmcxETAPBgNVBAsT
CG9yZy11bml0MQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExEjAQBgNVBAcTCVNh
biBEaWVnbzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAqpJZygd+w1faLOr1
iOAmbBhx5SZWcTCZ/ZjHQTJM7GuPT624QkqsixFghRKdDROwpwnAP7gMRukLqiy4
+kRuGT5OfyGggL95i2xqA+zehjj08lSTlvGHpePJgCyTavIy5+Ljsj4DKnKyuhxm
biXTRrH83NDgixVkObTEmh/OVK0CAwEAATANBgkqhkiG9w0BAQ0FAAOBgQBa0Npw
UkzjaYEo1OUE1sTI6Mm4riTIHMak4/nswKh9hYup//WVOlr/RBSBtZ7Q/BwbjobN
3bfAtV7eSAqBsfxYXyof7G1ALANQERkq3+oyLP1iVt08W1WOUlIMPhdCF/QuCwy6
x9MJLhUCGLJPM+O2rAPWVD9wCmvq10ALsiH3yA==
-----END CERTIFICATE-----
""")

# load certificates
root_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, root_cert_pem)
intermediate_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, intermediate_cert_pem)
untrusted_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, untrusted_cert_pem)

# Trust the root certificate
#flags = X509StoreFlags

store = OpenSSL.crypto.X509Store()
store.add_cert(root_cert)
# Set time to reuse certs from example above
validation_date = datetime.datetime.strptime("2016-01-01", "%Y-%m-%d")
store.set_time(validation_date)

# only add intermediate if it can be verified by the root
# store_ctx = OpenSSL.crypto.X509StoreContext(store, intermediate_cert)
# print(store_ctx.verify_certificate())
# store.add_cert(intermediate_cert)


# now that root and intermediate are trused, you can verify the end certificate using the store
store_ctx = OpenSSL.crypto.X509StoreContext(store, untrusted_cert, [intermediate_cert])
print("Untrusted chain example")
try:
    store_ctx.verify_certificate()
    print("Verify - OK")
except OpenSSL.crypto.X509StoreContextError:
    print("Verify failed - bad")
