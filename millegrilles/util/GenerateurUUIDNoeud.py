from uuid import uuid1
import binascii

class GenerateurUUIDNoeud:

    def __init__(self):
        pass

    def generer_uuid_pournoeud(self):
        uuid_noeud = uuid1()
        print(str(uuid_noeud))

        columns = 16
        column = 0
        line_content = list()
        for val in uuid_noeud.bytes:
            if column >= columns:
                print(', '.join(line_content))
                line_content = list()
                column = 0

            line_content.append(hex(val))
            column = column + 1

        print(', '.join(line_content))  # Derniere ligne


if __name__ == '__main__':
    generateur = GenerateurUUIDNoeud()
    generateur.generer_uuid_pournoeud()
