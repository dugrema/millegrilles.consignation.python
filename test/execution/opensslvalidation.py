import OpenSSL
from six import u, b, binary_type, PY3

# https://stackoverflow.com/questions/30700348/how-to-validate-verify-an-x509-certificate-chain-of-trust-in-python
# https://duo.com/labs/research/chain-of-fools

# Dependance
# apt install python3-openssl

root_cert_pem = b("""
-----BEGIN CERTIFICATE-----
MIIBUzCCAQWgAwIBAgIUbl3363S2J56H0agwMXf0a94C9RgwBQYDK2VwMBcxFTAT
BgNVBAMMDG1pbGxlZ3JpbGxlczAeFw0yMjAxMDkxMTM1NTVaFw00MjAxMDQxMTM1
NTVaMBcxFTATBgNVBAMMDG1pbGxlZ3JpbGxlczAqMAUGAytlcAMhAGQZ8QkmNIZQ
tqJS2Tcu0g7rIpprCOKz5gZUvzFVjsI4o2MwYTAPBgNVHRMBAf8EBTADAQH/MB0G
A1UdDgQWBBQJRu4NOqtYiAxQbbZNpgNQZ2vvczAfBgNVHSMEGDAWgBQJRu4NOqtY
iAxQbbZNpgNQZ2vvczAOBgNVHQ8BAf8EBAMCAaYwBQYDK2VwA0EA8yDLg6Mlx+L1
e/v99BfqbVQEqaNJpBCc9Eueoj45cFf1gVuM9h3FWFUb9TiP1+P0lQY4u+j8HnWE
72+IybWLBw==
-----END CERTIFICATE-----
""")

intermediate_cert_pem = b("""
-----BEGIN CERTIFICATE-----
MIIBazCCAR2gAwIBAgIUSP9S8t+chJ0C2uBZphMckbHP484wBQYDK2VwMBcxFTAT
BgNVBAMMDG1pbGxlZ3JpbGxlczAeFw0yMjAxMDkwNjEzMzhaFw0yMjAxMTIwNjE1
MzhaMDUxETAPBgNVBAoMCGFiY2QxMjM0MRAwDgYDVQQLDAdtb25pdG9yMQ4wDAYD
VQQDDAVkdW1teTAqMAUGAytlcAMhAGIxZN7WlDgNb3jI8cVb2izT0El0hwqs+l2g
qoTx1Scyo10wWzAdBgNVHQ4EFgQUhRMsUNbw8DP2glUu4x/Fe3Px4m0wHwYDVR0j
BBgwFoAU9vygId7u4iGzprKuQE1Q1miGJ/IwDAYDVR0TAQH/BAIwADALBgNVHQ8E
BAMCBPAwBQYDK2VwA0EAOO028NIWqWjarRlA+L64lm3qKZEkd5iMMAahDqXPt3pb
eiE1LR1xvM82cFN+45MGbtBbU3CBwMV7AheprPg8DA==
-----END CERTIFICATE-----
""")

untrusted_cert_pem = b("""
-----BEGIN CERTIFICATE-----
MIIBtTCCAWegAwIBAgIBAjAFBgMrZXAwFzEVMBMGA1UEAwwMbWlsbGVncmlsbGVz
MB4XDTIyMDEwOTE1NDYzN1oXDTIyMDIwODE1NDYzN1owETEPMA0GA1UEAwwGY2xp
ZW50MCowBQYDK2VwAyEA2M5mh6tMiqhr5GTKn7BZxu3MgvJ1IGsVXY8wPRUtXWuj
gd0wgdowCQYDVR0TBAIwADALBgNVHQ8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUH
AwEGCCsGAQUFBwMCMGEGA1UdEQRaMFiHBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAGH
BMCoAsOCGW1nLWRldjUubWFwbGUubWFjZXJvYy5jb22CBW1vbmdvgglsb2NhbGhv
c3SCB21nLWRldjWCAm1xMB0GA1UdDgQWBBQwV0dTxyc523FkZBo8kWQPP6JYRjAf
BgNVHSMEGDAWgBQJRu4NOqtYiAxQbbZNpgNQZ2vvczAFBgMrZXADQQDLZU8StSuB
GG09Q7sCfmrIkbyoU41h8eYKuZff2FJofP6APlzNi0m5WcejM401LpDbcYgWL+12
+TcxIOXH27sM
-----END CERTIFICATE-----
""")

bad_cert_pem = b("""
-----BEGIN CERTIFICATE-----
MIIBazCCAR2gAwIBAgIUSP9S8t+chJ0C2uBZphMckbHP484wBQYDK2VwMBcxFTAT
BgNVBAMMDG1pbGxlZ3JpbGxlczAeFw0yMjAxMDkwNjEzMzhaFw0yMjAxMTIwNjE1
MzhaMDUxETAPBgNVBAoMCGFiY2QxMjM0MRAwDgYDVQQLDAdtb25pdG9yMQ4wDAYD
VQQDDAVkdW1teTAqMAUGAytlcAMhAGIxZN7WlDgNb3jI8cVb2izT0El0hwqs+l2g
qoTx1Scyo10wWzAdBgNVHQ4EFgQUhRMsUNbw8DP2glUu4x/Fe3Px4m0wHwYDVR0j
BBgwFoAU9vygId7u4iGzprKuQE1Q1miGJ/IwDAYDVR0TAQH/BAIwADALBgNVHQ8E
BAMCBPAwBQYDK2VwA0EAOO028NIWqWjarRlA+L64lm3qKZEkd5iMMAahDqXPt3pb
eiE1LR1xvM82cFN+45MGbtBbU3CBwMV7AheprPg8DA==
-----END CERTIFICATE-----
""")

# load certificates
root_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, root_cert_pem)
#intermediate_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, intermediate_cert_pem)
untrusted_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, untrusted_cert_pem)

# Trust the root certificate
store = OpenSSL.crypto.X509Store()
store.add_cert(root_cert)

# only add intermediate if it can be verified by the root
#store_ctx = OpenSSL.crypto.X509StoreContext(store, intermediate_cert)
#print(store_ctx.verify_certificate())
#store.add_cert(intermediate_cert)

# now that root and intermediate are trusted, you can verify the end certificate using the store
store_ctx = OpenSSL.crypto.X509StoreContext(store, untrusted_cert)
verification = store_ctx.verify_certificate()
if verification is None:
    print("Verification OK")

bad_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, bad_cert_pem)
try:
    store_ctx = OpenSSL.crypto.X509StoreContext(store, bad_cert)
    verification = store_ctx.verify_certificate()
    print("Erreur, bad cert considere valide")
except OpenSSL.crypto.X509StoreContextError:
    print("BAD cert echec (OK!)")
