import subprocess

class Recorder:

    def __init__(self, device):
        self.popen = subprocess.Popen(["tshark", "-i", device, "-T", "json"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.start = True
        self.lines = ""

    def __iter__(self):
        'Returns itself as an iterator object'
        return self

    def __next__(self):
        self.lines = ""
        if self.start:
            self.start = False

        while True:
            line = self.popen.stdout.readline()
            line = line.decode("utf-8")
            line = line.rstrip()
            if line == "  }":
                self.lines = self.lines + line
                break
            elif line == "  ,":
                pass
            else:
                self.lines = self.lines + line

        try:
            return self.lines 
        except:
            return ""

    def terminate(self):
        self.popen.terminate()

if __name__ == "__main__":
    r = Recorder("eth0")
    for value in r:
        print(value)
