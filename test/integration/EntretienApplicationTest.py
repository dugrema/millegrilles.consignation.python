from millegrilles.util.EntretienApplication import BackupApplication


class BackupApplicationTest:

    def __init__(self):
        self.backup_application = BackupApplication()

    def executer(self):
        self.backup_application.configurer_parser()
        self.backup_application.parse()
        self.backup_application.initialiser()

        # Preparer env, mais ne fera pas le backup (manque --backup_upload)
        self.backup_application.executer()

        # Executer le backup
        self.backup_application.executer_backup()


def main():
    test = BackupApplicationTest()
    test.executer()


if __name__ == '__main__':
    main()
