import docker

from os import path
from docker.types import Mount


class DockerContainerRun:

    def __init__(self):
        self.__docker = docker.from_env()

    def run_container(self):

        nom_app = 'redmine_mariadb'

        volumes = ['redmine_files']
        mounts = list()
        mounts.append(Mount(type='bind', source=path.join('/var/opt/millegrilles/consignation/backup_app_work', nom_app), target='/backup'))
        cmd = ''
        for v in volumes:
            path_target = path.join('/', v)
            m = Mount(type='volume', target=path_target, source=v, read_only=True)
            mounts.append(m)

            cmd = cmd + 'cp -ru %s /backup; ' % path_target

        self.__docker.containers.run('alpine', cmd, auto_remove=True, mounts=mounts, name='test_docker')


def main():
    runner = DockerContainerRun()
    runner.run_container()


if __name__ == '__main__':
    main()
