import requests
import logging
import json
import gzip

from base64 import b64encode

from millegrilles.util.BaseTestMessages import DomaineTest


SAMPLE_DATA_1 = {
  "_certificat": [
    "-----BEGIN CERTIFICATE-----\nMIICqTCCAlugAwIBAgIUNazLYqI/8SQbOnIaUXG+MyCiJVUwBQYDK2VwMHIxLTAr\nBgNVBAMTJDI1YTk5YmUxLWJmYmQtNDc3OS1iOTJkLTFhN2RmZTJjNTAwODFBMD8G\nA1UEChM4emVZbmNScUVxWjZlVEVtVVo4d2hKRnVIRzc5NmVTdkNUV0U0TTQzMml6\nWHJwMjJiQXR3R203SmYwHhcNMjIwMjIzMTU0MzAxWhcNMjIwMzE2MTU0NTAxWjCB\nhzFBMD8GA1UECgw4emVZbmNScUVxWjZlVEVtVVo4d2hKRnVIRzc5NmVTdkNUV0U0\nTTQzMml6WHJwMjJiQXR3R203SmYxEzARBgNVBAsMCm1lc3NhZ2VyaWUxLTArBgNV\nBAMMJDI1YTk5YmUxLWJmYmQtNDc3OS1iOTJkLTFhN2RmZTJjNTAwODAqMAUGAytl\ncAMhAPIzCw4wyDcn79ffu5W+519VGKKTH2B2xeA8WrnnjAHfo4HsMIHpMB0GA1Ud\nDgQWBBRoVYav2HOWLwR7X/FG9k4lqARD6jAfBgNVHSMEGDAWgBRkv0ubKhyaFvfm\nkZChsGh5Tm18/TAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIE8DAQBgQqAwQABAg0\nLnNlY3VyZTASBgQqAwQBBAptZXNzYWdlcmllMBIGBCoDBAIECk1lc3NhZ2VyaWUw\nUgYDVR0RBEswSYIkMjVhOTliZTEtYmZiZC00Nzc5LWI5MmQtMWE3ZGZlMmM1MDA4\ngglsb2NhbGhvc3SHBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAEwBQYDK2VwA0EAZheW\nb/mlCqCHhWimOSGaaaQPXl0/V11JEQwiBW1elHGTUk8PH1PuFJ0FVRGsWk/hNp7H\n9E2ra+JugVcI0pztCw==\n-----END CERTIFICATE-----\n",
    "-----BEGIN CERTIFICATE-----\nMIIBozCCAVWgAwIBAgIKEHAXiYV2UgCGGDAFBgMrZXAwFjEUMBIGA1UEAxMLTWls\nbGVHcmlsbGUwHhcNMjIwMjIzMTUzNDU4WhcNMjMwOTA0MTUzNDU4WjByMS0wKwYD\nVQQDEyQyNWE5OWJlMS1iZmJkLTQ3NzktYjkyZC0xYTdkZmUyYzUwMDgxQTA/BgNV\nBAoTOHplWW5jUnFFcVo2ZVRFbVVaOHdoSkZ1SEc3OTZlU3ZDVFdFNE00MzJpelhy\ncDIyYkF0d0dtN0pmMCowBQYDK2VwAyEAMp0+f8uH17qEHVwXqm1CCcCavVUvJ0in\nIb08uoxipY+jYzBhMBIGA1UdEwEB/wQIMAYBAf8CAQAwCwYDVR0PBAQDAgEGMB0G\nA1UdDgQWBBRkv0ubKhyaFvfmkZChsGh5Tm18/TAfBgNVHSMEGDAWgBTTiP/MFw4D\nDwXqQ/J2LLYPRUkkETAFBgMrZXADQQAyfzc4Vb/lzRDFt63jMUMAk4Qr7yipQ0RZ\n2fRiBX7h808eAX5ThKjM1nnnqmFhQuVdIxh6usn4JQI6vTWYALsH\n-----END CERTIFICATE-----\n"
  ],
  "_signature": "mAmmiUQqf8uMqgVKY9sCMkn6SzLSYUGiU+hisKFkMl5RiKJCFZbEwq+A90y+hFU7dKisjvh/GmjqCfLWqxyv/1gs",
  "cle_info": {
    "domaine": "Messagerie",
    "format": "mgs3",
    "hachage_bytes": "zSEfXUD16zhzViiUuZt9PVLDXC6FeXUYnetnu1rVbkJdnqbZWJwHNDUekdqJqusT2D3yvfdDe3cy3bhdoWmKdsYCnYUNLx",
    "identificateurs_document": {
      "message": "true"
    },
    "iv": "msib8pC725LbXnXKj",
    "tag": "mzdgV+iZVHrxiFlNY/aw+iw"
  },
  "destinations": [
    {
      "cles": {
        "z2i3XjxJgyzgMSwpJ5E3xiy1wmPJF2W1moQxYnuTA1NYMrgg38N": "mqynb5PfQGSGVWy1642c4rTTGxAoye8ieNUKKK8gNIh+2DDW2sdxwLqU5pgmXZY7KC+MwGmLgpOC5mxlCFcetaQVWqJeDufjHol1YG/pqFMo"
      },
      "destinataires": [
        "@proprietaire/mg-dev4.maple.maceroc.com"
      ],
      "fiche": {
        "adresses": [
          "mg-dev4.maple.maceroc.com"
        ],
        "application": [
          {
            "application": "messagerie",
            "url": "https://mg-dev4.maple.maceroc.com/messagerie",
            "version": "2022.1.1"
          }
        ],
        "ca": "-----BEGIN CERTIFICATE-----\r\nMIIBQzCB9qADAgECAgoScllGKAmVUxVJMAUGAytlcDAWMRQwEgYDVQQDEwtNaWxs\r\nZUdyaWxsZTAeFw0yMjAyMjIxOTMyMDJaFw00MjAyMjIxOTMyMDJaMBYxFDASBgNV\r\nBAMTC01pbGxlR3JpbGxlMCowBQYDK2VwAyEAFqZkyS5fIsgPtMbH6SdqwiDprNus\r\nC49y0+wFJP7kseijYDBeMA8GA1UdEwEB/wQFMAMBAf8wCwYDVR0PBAQDAgLkMB0G\r\nA1UdDgQWBBRCvJfvqQx9OMkUhnAER0AFMZo+OjAfBgNVHSMEGDAWgBRCvJfvqQx9\r\nOMkUhnAER0AFMZo+OjAFBgMrZXADQQCVN8Al7Fut34+QafudyqSTen+Eu7OcXb7C\r\n6oEy8XPbyoModAQSMbL6qHsG/8UIhRRnU9zz4AhEf0EvN9+70R0K\r\n-----END CERTIFICATE-----",
        "chiffrage": [
          [
            "-----BEGIN CERTIFICATE-----\nMIICIzCCAdWgAwIBAgIUaKICHCiD3hOPlJGdGbUm2dascI0wBQYDK2VwMHIxLTAr\nBgNVBAMTJDVkMGNjMjY5LTczN2ItNDMwMi1iOTkwLTQ0MTZkYjE3YTE3ODFBMD8G\nA1UEChM4elhiVXdFNWgyeE1KUnBVd2VKZDRGcThnUll1amNQZmp4Q2JBM3ZwMUxC\ndkVCMVpNaWlFMURoVzgwHhcNMjIwMjI0MjMzMjIxWhcNMjIwMzE3MjMzNDIxWjBq\nMUEwPwYDVQQKDDh6WGJVd0U1aDJ4TUpScFV3ZUpkNEZxOGdSWXVqY1BmanhDYkEz\ndnAxTEJ2RUIxWk1paUUxRGhXODETMBEGA1UECwwKbWFpdHJlY2xlczEQMA4GA1UE\nAwwHbWctZGV2NDAqMAUGAytlcAMhAHYh3WHaq9VIMbM1yWEKauW1syo2dR0CKQ5T\nexSFt27+o4GEMIGBMB0GA1UdDgQWBBR52RhyX4RZgVE58cRHf9cTQR1v9TAfBgNV\nHSMEGDAWgBS4URNE124X+xlaS4e0Kim2DGmQ3jAMBgNVHRMBAf8EAjAAMAsGA1Ud\nDwQEAwIE8DAQBgQqAwQABAg0LnNlY3VyZTASBgQqAwQBBAptYWl0cmVjbGVzMAUG\nAytlcANBAEo4eqOd1F9KT8XJjC2NzhzEWgu1k3Qd6RGH7v4MyDOQHemSTQ2Y1cl4\nKINuFTvHpLidY48IFR9jGu2SmEpfmQw=\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nMIIBozCCAVWgAwIBAgIKEJM5h1AmNSZzmTAFBgMrZXAwFjEUMBIGA1UEAxMLTWls\nbGVHcmlsbGUwHhcNMjIwMjI0MjMyNjE1WhcNMjMwOTA1MjMyNjE1WjByMS0wKwYD\nVQQDEyQ1ZDBjYzI2OS03MzdiLTQzMDItYjk5MC00NDE2ZGIxN2ExNzgxQTA/BgNV\nBAoTOHpYYlV3RTVoMnhNSlJwVXdlSmQ0RnE4Z1JZdWpjUGZqeENiQTN2cDFMQnZF\nQjFaTWlpRTFEaFc4MCowBQYDK2VwAyEAlx720FI8kFGx8iXjbvrNjuMP2VdxEVpL\njdj5iHEUANSjYzBhMBIGA1UdEwEB/wQIMAYBAf8CAQAwCwYDVR0PBAQDAgEGMB0G\nA1UdDgQWBBS4URNE124X+xlaS4e0Kim2DGmQ3jAfBgNVHSMEGDAWgBRCvJfvqQx9\nOMkUhnAER0AFMZo+OjAFBgMrZXADQQBYgurEBub28pEJRjgD8tx93K65t6xvWuNt\n9Rt8fmdxjgt2Hau20k7CGON6rDozniTggLdwLwpcGbksmAqkYdMI\n-----END CERTIFICATE-----\n"
          ]
        ],
        "idmg": "zXbUwE5h2xMJRpUweJd4Fq8gRYujcPfjxCbA3vp1LBvEB1ZMiiE1DhW8"
      },
      "idmg": "zXbUwE5h2xMJRpUweJd4Fq8gRYujcPfjxCbA3vp1LBvEB1ZMiiE1DhW8",
      "mapping": {
        "dns": [
          "mg-dev4.maple.maceroc.com"
        ],
        "retry": 0
      }
    }
  ],
  "en-tete": {
    "action": "poster",
    "domaine": "postmaster",
    "estampille": 1646176559,
    "fingerprint_certificat": "z2i3Xjx88iAKh8bfkm6uyoeM3kUkDhXhqJ2U5vCx79MMZAreiPp",
    "hachage_contenu": "mEiBwU/i0tS3mGj4dItZC7AqboKFEQn63vgwiPBz7KO/upQ",
    "idmg": "zeYncRqEqZ6eTEmUZ8whJFuHG796eSvCTWE4M432izXrp22bAtwGm7Jf",
    "uuid_transaction": "299d3607-b286-43bc-b9fe-4866a1ac4a3b",
    "version": 1
  },
  "message": {
    "_signature": "mAm2MLxM9jxoqiJcpdJEzz0hex5p1XwbDVLf9XS6M2A6J1HrCRmMcGfHrHe9UnN2cNeGqJ8ow20nSxMOp+kljRQg",
    "en-tete": {
      "domaine": "Messagerie",
      "estampille": 1646176558,
      "fingerprint_certificat": "z2i3Xjx5vJJW4j8gcSwXcxiJPAqM4r9Q9L34C2W2SxeELBPmRmq",
      "hachage_contenu": "m4OQCIPKGbA31ldY3uxAK9JT5uRQCyPPXW6S8Wz93TqgLln+G",
      "idmg": "zeYncRqEqZ6eTEmUZ8whJFuHG796eSvCTWE4M432izXrp22bAtwGm7Jf",
      "uuid_transaction": "5947f38e-a0e4-4bee-bcdb-498ee7071888",
      "version": 1
    },
    "fingerprint_certificat": "z2i3Xjx5vJJW4j8gcSwXcxiJPAqM4r9Q9L34C2W2SxeELBPmRmq",
    "hachage_bytes": "zSEfXUD16zhzViiUuZt9PVLDXC6FeXUYnetnu1rVbkJdnqbZWJwHNDUekdqJqusT2D3yvfdDe3cy3bhdoWmKdsYCnYUNLx",
    "message_chiffre": "mJc4cl7luYx747Ij9G8i1wMgRByu2/KpUYuzE4+LAexE6owX0XstD42wZD/2feiEhAcEkCE/PP/q0YJK5/MY5Wnw3kSvReCp05AxI68xHJwbOehvtOQGPzjZGEso6x/YtR1HX2gzM3p97rGgK3ed/ULAcurrrhh9PIgssVbofC7KcJTC4M3ubbbien/nrzHWjOA4TwsWfgUBq5aM0VyWWJ810wBRGp1sivRu/9XTpspfZk7GGBsF7x2X5ZXbdnk5m/Ncf5KSbTchWsaZijv1po/6GeQ0IxVRZHZELSYDCEL4aritzpMGVYjW/Vsj4ntQYcFYZawFJYkIbaw8nIAa3GTgtJhuBrSwijeCjCJEqfSt8RRKKxEBiADNc/aPQuple6fQ4+bo69SiNP01A8wQF6IDb64Y0wEE4lD4kXkuABdQ2lVOvGX2GnyYVtKgSek6K6nNNv3R3ok7klNTjp1ef7o89EDzut+25GCCfgBfh9j3TtJGlKFcYw7QTZqLpt3bGptgS22qgeyQkj0B1N9MsI3lARRjQKxb2w6Cwutz1lnZCnZRJ662ADe+gnS7C7MHpcVTcMvAjxv0MUDoSFRj9xAYiIg/1q2axyC1TDcr5er7f8vS5"
  }
}


class PosterTest(DomaineTest):

    def __init__(self):
        super().__init__()
        self.__logger = logging.getLogger(self.__class__.__name__)

        self.url_poster = 'https://mg-dev4.maple.maceroc.com/messagerie/poster'
        self.certfile = self.configuration.pki_certfile
        self.keyfile = self.configuration.pki_keyfile
        with open(self.configuration.pki_cafile, 'r') as fichier:
            self.capem = fichier.read()

    def poster_message(self, url_poster, data: dict):
        # Signer data
        generateur = self.generateur
        data_enveloppe = generateur.preparer_enveloppe(data, version=1, ajouter_certificats=True)
        data_enveloppe['_millegrille'] = self.capem

        data_bytes = json.dumps(data_enveloppe).encode('utf-8')

        additional_headers = dict()
        # additional_headers['content-encoding'] = 'gzip'
        additional_headers['Content-Type'] = 'application/json'
        additional_headers['Content-Encoding'] = 'gzip'
        data_gzip = gzip.compress(data_bytes, 9)
        self.__logger.debug("Data size : brut: %d, compresse %d" % (len(data_bytes), len(data_gzip)))

        r = requests.post(
            url_poster,
            data=data_gzip,
            # files=files,
            # verify=self._contexte.configuration.mq_cafile,
            verify=False,
            # cert=(self.certfile, self.keyfile)
            headers=additional_headers
        )

        if r.status_code == 429:
            self.__logger.warning("Erreur poster throttle en cours (429)")
        elif r.status_code != 200:
            self.__logger.error("Erreur poster (%d)" % (r.status_code))
        else:
            resultat = r.json()
            self.__logger.info("Poster OK, resultat:\n%s" % json.dumps(resultat, indent=2))

        return r

    def poster(self):
        messages = list()
        for destination in SAMPLE_DATA_1['destinations']:
            message = SAMPLE_DATA_1['message']
            cle_info = SAMPLE_DATA_1['cle_info']

            cle = cle_info.copy()
            cle['cles'] = destination['cles']
            fiche = destination['fiche']
            applications = fiche['application']
            idmg = destination['idmg']

            contenu = {
                'message': message,
                'chiffrage': cle,
                'destinataires': destination['destinataires']
            }

            for app in applications:
                url = app['url']
                url_poster = url + '/poster'
                self.poster_message(url_poster, contenu)


        return messages

    def executer(self):
        self.__logger.debug("Executer")
        try:
            self.poster()
        except:
            self.__logger.exception("Erreur")
        finally:
            self.event_recu.set()

# --- MAIN ---
if __name__ == '__main__':
    logging.basicConfig()
    logging.getLogger('millegrilles').setLevel(logging.DEBUG)
    logging.getLogger('PosterTest').setLevel(logging.DEBUG)
    # test = PutCommands()
    test = PosterTest()
    # TEST

    # FIN TEST
    test.event_recu.wait(120)
    test.deconnecter()

