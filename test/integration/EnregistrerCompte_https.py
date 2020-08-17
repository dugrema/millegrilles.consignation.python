import requests

path_certificat = '/home/mathieu/mgdev/certs/pki.monitor.cert'
path_millegrille = '/home/mathieu/mgdev/certs/pki.millegrille.cert'

class ConnecterCertificat:

    def poster_certificat(self):
        reponse = requests.post(
            'https://mg-dev3.maple.maceroc.com/administration',
            # cert=path_certificat,
            verify=False  # path_millegrille
        )
        print(reponse.content)


def main():
    connecter = ConnecterCertificat()
    connecter.poster_certificat()


if __name__ == '__main__':
    main()