import docker
import logging

from docker.client import DockerClient

logger = logging.getLogger('__main__')


def init_docker_client() -> DockerClient:
    return docker.from_env()
    # return docker.DockerClient('unix:///run/docker.sock')


def get_onionize_container(docker_client: DockerClient):
    filtre = {'name': 'onionize'}
    list_containers = docker_client.containers.list(filters=filtre)
    try:
        container = list_containers[0]
        return container
    except IndexError:
        pass


def get_nginx_hostname(container):
    resultat = container.exec_run('cat /var/lib/tor/onion_services/nginx/hostname')
    output_resultat = resultat.output.decode('utf-8').strip()
    logger.debug("Resultat : %s" % output_resultat)
    pass


def main():
    logging.basicConfig()
    logging.getLogger('__main__').setLevel(logging.DEBUG)

    logger.debug("Charger docker")

    docker_client = init_docker_client()
    container = get_onionize_container(docker_client)

    if container is not None:
        logger.debug("get nginx hostname from container id %s" % container.id)
        get_nginx_hostname(container)


if __name__ == '__main__':
    main()
