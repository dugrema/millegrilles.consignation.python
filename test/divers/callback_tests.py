callbacks = list()


class Commande:

    def __init__(self, print_me_text):
        self.print_me_text = print_me_text

    def run(self, compteur):
        print('%d: %s' % (compteur, self.print_me_text))


def callback_generator(print_me_text):
    callback = Commande(print_me_text).run
    callbacks.append(callback)


callback_generator("Du texte")
callback_generator("Plus de texte")
callback_generator("Encore plus de text")


compteur = 0
for callback in callbacks:
    callback(compteur)
    compteur = compteur + 1
