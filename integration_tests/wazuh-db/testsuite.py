# July 19, 2019

def get_directory():
    with open('/etc/ossec-init.conf') as f:
        for line in f:
            key, value = line.rstrip("\n").split("=")

            if key == "DIRECTORY":
                return value.replace("\"","")

    raise Exception("No such directory configuration in the init file")

class TestSuite:
    def __init__(self, autoprint=True):
        self.tests = []
        self.autoprint = autoprint

    def append(self, title, result, expected=True):
        self.tests.append((title, result, expected))

        if self.autoprint:
            print('{0} - {1}{2}'.format('ok' if result else 'not ok', title, '' if expected else ' # TODO'))

    def __str__(self):
        output = '1..{0}'.format(len(self.tests))

        if not self.autoprint:
            for t in self.tests:
                output += '\n{0} - {1}{2}'.format('ok' if t[1] else 'not ok', t[0], '' if t[2] else ' # TODO')

        return output
