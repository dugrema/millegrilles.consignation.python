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
  "_signature": "mAu0fxjxITiHCazhJaJXqTQmh0VO/Dkfczg1eB/4QabQ54Z2TMQb0etymRsM/8LddZro04B44C1Q2T8EDmHgcPA0",
  "certificat_message": [
    "-----BEGIN CERTIFICATE-----\nMIICVzCCAgmgAwIBAgIUQrZjXTAIXBn4dVnfB2kP1UYKZgMwBQYDK2VwMHIxLTAr\nBgNVBAMTJDI1YTk5YmUxLWJmYmQtNDc3OS1iOTJkLTFhN2RmZTJjNTAwODFBMD8G\nA1UEChM4emVZbmNScUVxWjZlVEVtVVo4d2hKRnVIRzc5NmVTdkNUV0U0TTQzMml6\nWHJwMjJiQXR3R203SmYwHhcNMjIwMjI2MTc1NTI4WhcNMjIwMzE5MTc1NzI4WjBm\nMUEwPwYDVQQKDDh6ZVluY1JxRXFaNmVURW1VWjh3aEpGdUhHNzk2ZVN2Q1RXRTRN\nNDMyaXpYcnAyMmJBdHdHbTdKZjEPMA0GA1UECwwGVXNhZ2VyMRAwDgYDVQQDDAdt\nYXRoaWV1MCowBQYDK2VwAyEA/KNDChHzRde0mLqV0rWw15qTWG1V5clsLx2kMNa9\nq2mjgbwwgbkwHQYDVR0OBBYEFH8W/TpHOLqPD6X3WiKclpxYf3KfMB8GA1UdIwQY\nMBaAFGS/S5sqHJoW9+aRkKGwaHlObXz9MAwGA1UdEwEB/wQCMAAwCwYDVR0PBAQD\nAgTwMB8GBCoDBAEEF25hdmlnYXRldXIsY29tcHRlX3ByaXZlMDsGBCoDBAMEM3oy\naTNYanhCZ0NwMW5VN3h3a0tuOUplTWpVOENBd25tb1JZUkpEZ2FNQ2NhZEw1NkhW\ndzAFBgMrZXADQQALJ5yls3GKUWrg5KtyeDODYn4Hk3qA98Gi33I8Ps2cwOBpOYbH\nwiW5B5BBsgFuueBkO1AAWTrgXEbdoyW0ZbMA\n-----END CERTIFICATE-----\n",
    "-----BEGIN CERTIFICATE-----\nMIIBozCCAVWgAwIBAgIKEHAXiYV2UgCGGDAFBgMrZXAwFjEUMBIGA1UEAxMLTWls\nbGVHcmlsbGUwHhcNMjIwMjIzMTUzNDU4WhcNMjMwOTA0MTUzNDU4WjByMS0wKwYD\nVQQDEyQyNWE5OWJlMS1iZmJkLTQ3NzktYjkyZC0xYTdkZmUyYzUwMDgxQTA/BgNV\nBAoTOHplWW5jUnFFcVo2ZVRFbVVaOHdoSkZ1SEc3OTZlU3ZDVFdFNE00MzJpelhy\ncDIyYkF0d0dtN0pmMCowBQYDK2VwAyEAMp0+f8uH17qEHVwXqm1CCcCavVUvJ0in\nIb08uoxipY+jYzBhMBIGA1UdEwEB/wQIMAYBAf8CAQAwCwYDVR0PBAQDAgEGMB0G\nA1UdDgQWBBRkv0ubKhyaFvfmkZChsGh5Tm18/TAfBgNVHSMEGDAWgBTTiP/MFw4D\nDwXqQ/J2LLYPRUkkETAFBgMrZXADQQAyfzc4Vb/lzRDFt63jMUMAk4Qr7yipQ0RZ\n2fRiBX7h808eAX5ThKjM1nnnqmFhQuVdIxh6usn4JQI6vTWYALsH\n-----END CERTIFICATE-----\n"
  ],
  "certificat_millegrille": "-----BEGIN CERTIFICATE-----\r\nMIIBQzCB9qADAgECAgoHBykXJoaCCWAAMAUGAytlcDAWMRQwEgYDVQQDEwtNaWxs\r\nZUdyaWxsZTAeFw0yMjAxMTMyMjQ3NDBaFw00MjAxMTMyMjQ3NDBaMBYxFDASBgNV\r\nBAMTC01pbGxlR3JpbGxlMCowBQYDK2VwAyEAnnixameVCZAzfx4dO+L63DOk/34I\r\n/TC4fIA1Rxn19+KjYDBeMA8GA1UdEwEB/wQFMAMBAf8wCwYDVR0PBAQDAgLkMB0G\r\nA1UdDgQWBBTTiP/MFw4DDwXqQ/J2LLYPRUkkETAfBgNVHSMEGDAWgBTTiP/MFw4D\r\nDwXqQ/J2LLYPRUkkETAFBgMrZXADQQBSb0vXhw3pw25qrWoMjqROjawe7/kMlu7p\r\nMJyb/Ppa2C6PraSVPgJGWKl+/5S5tBr58KFNg+0H94CH4d1VCPwI\r\n-----END CERTIFICATE-----",
  "cle_info": {
    "domaine": "Messagerie",
    "format": "mgs3",
    "hachage_bytes": "zSEfXUAMzsh3NXfTVWyvVSjTXJZb1sP7KKsXzPj75sFN5sfHxZ8XMFULmaz7efWWBH5ug5bCb8xtNfzBbPtGNZmu2Tsxy2",
    "identificateurs_document": {
      "message": "true"
    },
    "iv": "mVaCt/BUg/7rt+KOj",
    "tag": "mU9yIV1lKTIXDRmeHOYe8eQ"
  },
  "destinations": [
    {
      "cles": {
        "z2i3XjxGvXgnU9b9ZbtZY3FQmw9hchsCt4WhWch1un9uRs5fnhe": "mNt7IiOUhqDNVxKqrjtuvZpGXBFwTs/mEvK4g9GYU4E425qW3jdDlv3yo+O7iHAIcnTMuT/H/RJYWospNnGnaxynl+w36SHe42smmNmrQBno",
        "z2i3XjxJgyzgMSwpJ5E3xiy1wmPJF2W1moQxYnuTA1NYMrgg38N": "mTjOn6eL2wLPdvbtkRmqL7W22KCiqQpM8i9CHaOJ5ikSKmJWH/ISqIUQ3ah1n9dpH1Tu424NLFsMWlQF/k7beewHVHvayc+R1W5oy5yPjQXI"
      },
      "destinataires": [
        "@proprietaire/mg-dev5.maple.maceroc.com"
      ],
      "fiche": {
        "adresses": [
          "mg-dev5.maple.maceroc.com"
        ],
        "application": [
          {
            "application": "messagerie",
            "url": "https://mg-dev5.maple.maceroc.com/messagerie",
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
          "mg-dev5.maple.maceroc.com"
        ],
        "retry": 0
      }
    }
  ],
  "en-tete": {
    "action": "poster",
    "domaine": "postmaster",
    "estampille": 1646241377,
    "fingerprint_certificat": "z2i3Xjx88iAKh8bfkm6uyoeM3kUkDhXhqJ2U5vCx79MMZAreiPp",
    "hachage_contenu": "mEiBs9c2RUfbHLWTJOTvglmQzKfVC7BF2AktL03vDhLX8xQ",
    "idmg": "zeYncRqEqZ6eTEmUZ8whJFuHG796eSvCTWE4M432izXrp22bAtwGm7Jf",
    "uuid_transaction": "454d869b-d526-4917-a195-41d3edc218ce",
    "version": 1
  },
  "message": {
    "_signature": "mAknKBcarKvC5aPB8o0VwUmgg1T6GyjSN3nGK0e77VZ7FE32dVkabm6+rN5Iudmo8YMwQgA5If3YM7ruICB6t9gg",
    "en-tete": {
      "domaine": "Messagerie",
      "estampille": 1646241377,
      "fingerprint_certificat": "z2i3Xjx5vJJW4j8gcSwXcxiJPAqM4r9Q9L34C2W2SxeELBPmRmq",
      "hachage_contenu": "m4OQCIKFfHkwuY9N23xi+mgEhJqd9Xumq//sZtvwameCJV8Cn",
      "idmg": "zeYncRqEqZ6eTEmUZ8whJFuHG796eSvCTWE4M432izXrp22bAtwGm7Jf",
      "uuid_transaction": "5a73eab5-41c1-4524-841a-04e5292c3cdb",
      "version": 1
    },
    "fingerprint_certificat": "z2i3Xjx5vJJW4j8gcSwXcxiJPAqM4r9Q9L34C2W2SxeELBPmRmq",
    "hachage_bytes": "zSEfXUAMzsh3NXfTVWyvVSjTXJZb1sP7KKsXzPj75sFN5sfHxZ8XMFULmaz7efWWBH5ug5bCb8xtNfzBbPtGNZmu2Tsxy2",
    "message_chiffre": "mIhTw6AG+9nvYgovRWZKUxVMq6hcSVUwfeyttHfTkOcYMDvRpQc2TuGF0+GmekzBrip3dZRU55ZwcyX+cwPH/PgBXaff0Rf9FObl/IwObstShyBY/r1eZ47TM48m6qmQjvPurv1iWUd8UTSIaTyZr4BIARGMqMCJdZrXjsv9I40lt3m+vmHMnKCSuRV4c1lxQkIrcRuaIS/eIIooF/diIud/kYCR5ibpac83tUQRNnkixZ2+7/Fd+UqVbJRhE4bfiHnN5FYgwFJFkLAQcjSGgkYXx1KY+IYPuVJ+cZ2Bq4Fb1Hn5+2mBaS+OeZjlGaWLneyYSJnVa1nclkJ9cUny9uJRN5cpsvprB9/P+1ISyfB3g7Pqac+TOkIdzHID0oVFtSzssDgbRwdu824Jq3oD8/ODhJaDsroBDVfG/5vVieOWzpX/oy4N68ejxJbwLp9r45xzq4o2fHheTE79drZ75Xkp+TxEGpDwU8vvDjhG5E8DtxvbVXEJUPsG04SdCYZG7cyT0hePumGXWqvRYMyZobgbd/8gaESfQj0aCUFPypoTNdR0ojqMMr8gbTptsF33W+bvZ1qSQCZPepqhl+c4l0g8+NJR90naAqx7zNFAIPsyPdGYjQQ"
  }
}


class PosterTest(DomaineTest):

    def __init__(self):
        super().__init__()
        self.__logger = logging.getLogger(self.__class__.__name__)

        self.url_poster = 'https://mg-dev5.maple.maceroc.com/messagerie/poster'
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

        # Injecter _certificat/_millegrille dans le message
        message = SAMPLE_DATA_1['message'].copy()
        message['_certificat'] = SAMPLE_DATA_1['certificat_message']
        message['_millegrille'] = SAMPLE_DATA_1['certificat_millegrille']

        for destination in SAMPLE_DATA_1['destinations']:
            cle_info = SAMPLE_DATA_1['cle_info']
            cle = cle_info.copy()
            cle['cles'] = destination['cles']
            fiche = destination['fiche']
            applications = fiche['application']

            contenu = {
                'message': message,
                'chiffrage': cle,
                'destinataires': destination['destinataires'],
            }

            for app in applications:
                url = app['url']
                url_poster = url + '/poster'
                # self.poster_message(url_poster, contenu)
                self.poster_attachment(url_poster, 'zabcd1234')

        return messages

    def poster_attachment(self, url_poster: str, fuuid: str):
        # Signer data
        data_bytes = b"abcd1234"

        additional_headers = dict()
        # additional_headers['content-encoding'] = 'gzip'
        additional_headers['Content-Type'] = 'application/stream'
        self.__logger.debug("Attachment data size : brut: %d" % len(data_bytes))

        fichier = open('/var/opt/millegrilles/consignation/grosfichiers/zSEfX/UA/zSEfXUAYsb3HjbUpYSLPgvNQRhUbyXCG9ZHCp7wQKpk2KyQ2WCgbkGCJHuN2oMF64m6VpDPmN8GD3ARHg5zHMKJBeFc42C.mgs3.old', 'rb')

        url_poster_attachment = url_poster + '/zSEfXUAYsb3HjbUpYSLPgvNQRhUbyXCG9ZHCp7wQKpk2KyQ2WCgbkGCJHuN2oMF64m6VpDPmN8GD3ARHg5zHMKJBeFc42C'
        r = requests.put(
            url_poster_attachment,
            data=fichier,
            # files=files,
            verify=False,
            headers=additional_headers,
            timeout=1,
        )

        if r.status_code == 429:
            self.__logger.warning("Erreur poster throttle en cours (429)")
        elif r.status_code in [200, 201, 202]:
            self.__logger.debug("Poster attachment status %s \n%s" % (r.status_code, json.dumps(r.json(), indent=2)))
        else:
            self.__logger.error("Erreur poster (%d)" % (r.status_code))
            try:
                contenu_json = r.json()
                self.__logger.debug("Data erreur recu\n%s" % json.dumps(contenu_json, indent=2))
            except json.decoder.JSONDecodeError:
                pass

        return r

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
