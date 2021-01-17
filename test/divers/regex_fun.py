import re

strings = [
    'pki.maitrecles.key.20210117172839',
    'pki.maitrecles.key.20210117172840',
    'pki.domaines.key.20210117172839',
    'pki.domaines.key.20210117172840',
    'pki.nginx.key.20210117172839',
]

def test_1():

    p = re.compile(r'^pki.maitrecles.key.([0-9]+)$')
    for s in strings:
        r = p.match(s)
        print('%s = %s' % (s, r))
        try:
            groups = r.groups()
            for i in range(0, len(groups)):
                # for g in r.groups():
                g = groups[i]
                print('%d = %s' % (i, g))
        except AttributeError:
            pass  # OK


def test_replace():
    string = 'M1  m2 M1 M1 M11'
    rep = string.replace('M1', 'AA')
    print(rep)


if __name__ == '__main__':
    test_1()
    # test_replace()
