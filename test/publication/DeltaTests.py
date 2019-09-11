from delta import html


class TestDelta:

    def __init__(self):
        self.delta_1 = {'ops':
            [
                { "insert":"Quill\nEditor\n\n" },
                { "insert": "bold",
                  "attributes": {"bold": True}},
                { "insert":" and the " },
                { "insert":"italic",
                  "attributes": { "italic": True }},
                { "insert":"\n\nNormal\n" },
            ]
        }

    def render(self, delta):
        resultat = html.render(delta['ops'])
        print(resultat)


# ========= MAIN ==========

test = TestDelta()
test.render(test.delta_1)

