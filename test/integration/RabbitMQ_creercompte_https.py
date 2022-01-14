import requests
from millegrilles.util.RabbitMQManagement import RabbitMQAPI

SERVEUR = 'mg-dev5'
MOTDEPASSE = 'o1UtREOepPqQhNjsBvpi2tNCEwzl4I2qFEho7BQwzkU'

path_certificat = '/home/mathieu/mgdev/certs/pki.monitor.cert'
path_cle = '/home/mathieu/mgdev/certs/pki.monitor.key'

path_millegrille = '/home/mathieu/mgdev/certs/pki.millegrille.cert'

admin_api = RabbitMQAPI(SERVEUR, MOTDEPASSE, path_millegrille)  # , guest=True)


class ConnecterCertificat:

    def healthcheck(self):
        admin_api.healthchecks()


def main():
    connecter = ConnecterCertificat()
    connecter.healthcheck()


if __name__ == '__main__':
    main()


# NGINX
#
# modules_include.conf
# ssl_client_certificate/etc/nginx/conf.d/modules/pki.millegrille.cert;
# ssl_verify_client optional;
# ssl_verify_depth 1;
#
# include / etc / nginx / conf.d / server.include;

# locations.include
#             location /administration {
#                 include /etc/nginx/conf.d/modules/proxypass_installation.include;
#                 include /etc/nginx/conf.d/component_base.include;
#
# #                ssl_client_certificate /etc/nginx/conf.d/modules/pki.millegrille.cert;
# #                ssl_verify_client optional;
#
#                 proxy_set_header VERIFIED $ssl_client_verify;
# #                proxy_set_header X-Client-Cert-esc $ssl_client_escaped_cert;
# #                proxy_set_header X-Client-Cert $ssl_client_cert;
#                 proxy_set_header X-Client-Issuer-DN $ssl_client_i_dn;
#                 proxy_set_header X-Client-Cert-RAW $ssl_client_raw_cert;
#                 proxy_set_header DN $ssl_client_s_dn;
#             }
