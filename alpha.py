import argparse
import sys
import re
from cmd2 import Cmd, Settable, cmd2


class AlphaAnalyzer(Cmd):
    input = None
    inputListed = None
    resultStep1 = None
    resultStep2concurrent = list()
    resultStep2causal = list()
    resultStep4Transitions = None
    andSplitPattern = set()
    andJoinPattern = set()
    xorSplitPattern = set()
    xorJoinPattern = set()
    resultStep6 = set()
    resultStep5 = set()
    blacklistXOR = set()
    resultStep8 = list()
    cache = list()

    def prepareData(self):
        self.input = re.sub('[!@#()/$]', '', self.input).upper()
        self.inputListed = self.input.split(",")
        self.resultStep1 = None
        self.resultStep2concurrent = list()
        self.resultStep2causal = list()
        self.x = list()

    def step1Alpha(self):
        buffer = list()
        for string in self.inputListed:
            for i in range(0, len(string)-1):
                buffer.append(string[i]+string[i+1])
        self.resultStep1 = buffer

    def step2Alpha(self):
        buffer = list(dict.fromkeys(self.resultStep1))
        buffer = sorted(buffer, key=lambda element: (element[0], element[1]))
        for t in buffer:
            reverse = t[1]+t[0]
            if (reverse in buffer):
                self.resultStep2concurrent.append(t[0]+"||"+t[1])
            elif ((reverse not in buffer) and (t[0] + "->" + t[1]) not in self.resultStep2causal):
                self.resultStep2causal.append(t[0] + "->" + t[1])
            else:
                pass

    def step3Alpha(self):
        buffer = self.resultStep4Transitions
        sBuild = ""
        for c in buffer:
            sBuild += "  "
            sBuild += c
        print(sBuild) #prints headlines of columns
        for c in buffer:
            sbuild = ["   "] * (buffer.__len__()+1)
            sbuild[0] =  c.upper()
            for s in self.resultStep2causal:
                if( s.startswith(c)):
                    ch = s[3]
                    num = (ord(ch)-64)
                    sbuild[num] = "-> "
            for s in self.resultStep2concurrent:
                if( s.startswith(c)):
                    ch = s[3]
                    num = (ord(ch)-64)
                    sbuild[num] = "|| "
            new_line = "".join(sbuild)
            print(new_line)



    def step4Alpha(self):
        self.resultStep4Inputs = set()
        self.resultStep4Outputs = set()
        buffer = self.input.replace(",", "")
        self.resultStep4Transitions = ''.join(sorted(set(buffer), key=buffer.index))
        for s in self.inputListed:
            self.resultStep4Inputs.add(s[0])
            self.resultStep4Outputs.add(s[-1])
        self.x += self.resultStep2causal
        self.xorSplit()

    def xorSplit(self):
        buffer = self.resultStep2causal
        self.andSplitPattern = set()
        self.andJoinPattern = set()
        self.xorSplitPattern = set()
        self.xorJoinPattern = set()

        for x in buffer:
            for y in buffer:
                if x == y:
                    pass
                elif x[0] == y[0]:
                    if (x[3]+"||"+y[3]) in self.resultStep2concurrent:
                        self.andSplitPattern.add(x[0] + x[3])
                    elif ((x[3]+"||"+y[3]) not in self.resultStep2concurrent and
                          (x[3]+"->"+y[3]) not in self.resultStep2causal) and \
                            ((x[0] + "->(" + y[3] + "#" + x[3] + ")") not in self.xorSplitPattern):
                        self.xorSplitPattern.add(x[0] + "->(" + x[3] + "#" + y[3] + ")")
                        self.blacklistXOR.add(x)
                        self.blacklistXOR.add(y)
                elif x[3]  == y[3]:
                    if (x[0]+"||"+y[0]) in self.resultStep2concurrent:
                        self.andJoinPattern.add(x[0] + x[3])
                    elif ((x[0]+"||"+y[0]) not in self.resultStep2concurrent and
                          ((y[0]+"->"+x[0]) not in self.resultStep2causal)and \
                            ("("+ y[0] + "#" + x[0] + ")->"+x[3] not in self.xorJoinPattern)):
                        self.xorJoinPattern.add("(" + x[0] + "#" + y[0] + ")->"+x[3])
                        self.blacklistXOR.add(x)
                        self.blacklistXOR.add(y)
    def step5Alpha(self):
        buffer = list(set(self.resultStep2causal).difference(self.blacklistXOR))
        self.resultStep5 = buffer
        for e in self.xorJoinPattern:
            self.resultStep5.append(e)
        for e in self.xorSplitPattern:
            self.resultStep5.append(e)

    def step6Alpha(self):
        self.resultStep6 = self.resultStep5
        for e in self.resultStep4Inputs:
            self.resultStep6.append("(i,"+e+")")
            self.resultStep8.append("(i,"+e+")")
        for e in self.resultStep4Outputs:
            self.resultStep6.append("(o," + e+")")
            self.resultStep8.append("(o,"+e+")")

    def step8Alpha(self):
        cache =  list(set(self.resultStep2causal).difference(self.blacklistXOR))

        for elem in cache:
            self.resultStep8.append("("+elem[0]+","+elem+")")
        for elem in cache:
            self.resultStep8.append("(" + elem +","+ elem[3] +")")

        cache = self.xorSplitPattern
        for elem in cache:
            self.resultStep8.append("("+elem[0]+","+elem+")")
        for elem in cache:
            self.resultStep8.append("(" + elem +","+ elem[4] +")")
        for elem in cache:
            self.resultStep8.append("(" + elem +","+ elem[6] +")")

        cache = self.xorJoinPattern
        for elem in cache:
            self.resultStep8.append("("+elem[1]+","+elem+")")
        for elem in cache:
            self.resultStep8.append("("+elem[3]+","+elem+")")
        for elem in cache:
            self.resultStep8.append("(" + elem +","+ elem[7] +")")

    def __init__(self):
        super().__init__()
        # Make maxrepeats settable at runtime
        self.resultStep4Outputs = set()
        self.resultStep4Inputs = set()
        self.maxrepeats = 3
        self.add_settable(Settable('maxrepeats', int, 'max repetitions for speak command'))

    parser2 = argparse.ArgumentParser(
        description='The IoT Network Analyzer: to load a pcap file which shall be analyzed')
    parser2.add_argument('-f', help="filename of PCAP file")
    args = parser2.parse_args()

    parser = argparse.ArgumentParser(description='The IoT Network Analyzer: to load a pcap file which shall be analyzed')

    @cmd2.with_argparser(parser2)
    def do_load(self, args):
        if args.f:
            self.input= args.f  # holds a object with all information for a research
            self.prepareData()
            self.resultStep8 = list()
            print("loaded:", self.input)
            self.step1Alpha()
            print("Directly-follows: ", str(self.resultStep1))
            self.step2Alpha()
            print("Causal relations: ", str(self.resultStep2causal))
            print("Concurrent relations: ", str(self.resultStep2concurrent))
            self.step4Alpha()
            self.step3Alpha()
            new_line = "".join(self.resultStep4Transitions)
            print("1.) Transitions: ", re.sub(r'([A-Z])(?!$)', r'\1,', new_line))
            new_line = "".join(self.resultStep4Inputs)
            print("2.) Transition Inputs: ", re.sub(r'([A-Z])(?!$)', r'\1,', new_line))
            new_line = "".join(self.resultStep4Outputs)
            print("3.) Transition Outputs: ", re.sub(r'([A-Z])(?!$)', r'\1,', new_line))
            print("4.1) X= ", str(self.resultStep2causal))
            new_line = "".join(self.andSplitPattern)
            print("AND Split Pattern: "+', '.join(new_line[i:i + 2] for i in range(0, len(new_line), 2)) )
            new_line = "".join(self.andJoinPattern)
            print("AND Join Pattern: "+', '.join(new_line[i:i + 2] for i in range(0, len(new_line), 2)) )
            new_line = "".join(self.xorJoinPattern)
            print("4.2) XOR Join Pattern: "+ new_line)
            new_line = "".join(self.xorSplitPattern)
            print("4.3) XOR Split Pattern: ", new_line)
            self.step5Alpha()
            new_line = ', '.join([str(x) for x in self.blacklistXOR])
            new_line2 = ', '.join([str(x) for x in self.resultStep5])
            print("5) Y = X -", "(" +new_line+")"+" = "+new_line2)
            self.step6Alpha()
            print("6) P = ",self.resultStep6)
            self.step8Alpha()
            print("8) \u03B1(F) = ", self.resultStep8)
def main():
    print("Alpha Algorithm analyzer")
    app = AlphaAnalyzer()
    sys.exit(app.cmdloop())

if __name__ == '__main__':
    main()