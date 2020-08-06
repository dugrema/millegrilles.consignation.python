import socket


def get_local_ips() -> dict:
    hostname = socket.gethostname()
    adresses = dict()

    try:
        ip = get_ip(hostname)
        if ip:
            adresses['ipv4'] = ip
    except Exception:
        pass

    try:
        ip6 = get_ip6()
        if ip6:
            adresses['ipv6'] = ip6
    except Exception:
        pass

    return adresses


def get_ip(hostname):

    adresse_ip = socket.gethostbyname(hostname)
    if adresse_ip.startswith('127.') or adresse_ip.startswith('172.'):
        # On n'a pas trouve l'adresse, essayer d'ouvrir un socket pour laisser
        # la table de routage trouver la destination.

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Si on est sur le meme hote (hostname == localhost == 127.0.0.1), essayer de connecter a "l'exterieur"
            # Noter que l'adresse est dummy
            s.connect(('10.255.255.255', 1))
            adresse_ip = s.getsockname()[0]

            if adresse_ip.startswith('127') or adresse_ip.startswith('172'):
                # On n'a toujours pas l'adresse, pas bon signe.
                # Derniere chance, revient presque au meme que le 1er test.
                s.close()
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect((hostname, 1))
                adresse_ip = s.getsockname()[0]

        except Exception:
            adresse_ip = None
        finally:
            s.close()
    return adresse_ip


def get_ip6():
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.connect(('2001:db8::1', 1))  # Utilisation block dummy pour tenter routage externe
    adresse_ip = s.getsockname()[0]
    return adresse_ip
