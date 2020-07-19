import tarfile
import io

with open('/tmp/acme_certs.0.tar', 'rb') as fichier:
    tar_bytes = fichier.read()
    io_buffer = io.BytesIO(tar_bytes)

with tarfile.open(fileobj=io_buffer) as tar_content:
    member_key = tar_content.getmember('mg-dev4.maple.maceroc.com/mg-dev4.maple.maceroc.com.key')
    fichier = tar_content.extractfile(member_key)
    contenu_fichier = fichier.read()

    pass