# !/usr/bin/env python3


import subprocess
import threading
import time
from ctypes import *
from queue import Queue
from statistics import mean, stdev





class Flow():
    def __init__(self, bufferSize):
        self.bufferSize = bufferSize
        self.buffer = []
        self.read = 0
        self.write = 0
        self.staticCount = 20
        self.flowStaticData = {}

        self.buffer_lock = threading.Lock()
        #self.con=0

        

    def runTshark(self):
        cmd = ['python3','/home/sofiane007/Dynamic_CCA_Selection/get_socket_data.py']
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)

        while True:
            try:
                lawline = proc.stdout.readline()
                line = str(lawline, encoding="utf-8")
                line = line.strip()

                if not line:
                    None
                else:
                    with self.buffer_lock:
                        if self.write < self.bufferSize:
                            self.buffer.append(line)
                            self.write += 1
                        else:
                            index = self.write % self.bufferSize
                            self.buffer[index] = line
                            self.write += 1
            except Exception as e:
                print("run shell error" + str(e))


    def readPacketData(self):
        

        #self.key = ( self.saddr, self.lport, self.daddr, self.dport)
        while True:
            with self.buffer_lock:
                if self.read >= self.write:
                    continue #exit the with block
                line = self.buffer[self.read % self.bufferSize]
                readData = self.getData(line)
                #print("readData: " + str(readData))
                key = (readData['saddr'], readData['lport'], readData['daddr'], readData['dport'])
                #print("key: " + str(key))
                self.read += 1
                if key not in self.flowStaticData:
                    # self.con+=1
                    # print("new connection: " + str(self.con), flush=True)
                    proc = Connection(
                        readData['saddr'], readData['daddr'],
                        readData['lport'], readData['dport'],
                        staticCount=self.staticCount,
                    )
                    self.flowStaticData[key] = proc

                self.flowStaticData[key].feed(readData)

    def getData(self, line):
        data = {}
        param = line.split(";")
        #print ("param: " + str(param))
        data['daddr'] = param[3]
        data['saddr'] = param[1]
        data['time'] = int(param[0])
        data['delivered'] = param[18]
        data['rtt'] = int(param[5])
        data['mdevRtt'] = int(param[6])
        data['minRtt'] = int(param[7])
        data['bytes_in_flight'] = int(param[8])
        data['dport'] = param[4]
        data['lost'] = int(param[9])
        data['retrans'] = int(param[10])
        data['rcv_buf'] = param[11]
        data['snd_buf'] = int(param[12])
        data['snd_cwnd'] = int(param[13])
        data['status'] = param[14]
        data['pacing_rate'] = param[16]

        data['lport'] = param[2]


        return data


class Connection(threading.Thread):
    def __init__(self, saddr, daddr, lport, dport, staticCount):
        super().__init__(daemon=True, name=f"Connection - {daddr} : {dport}")
        self.queue = Queue()
        self.saddr = saddr
        self.daddr = daddr
        self.lport = lport
        self.dport = dport
        self.staticCount = staticCount

        self.state = {
            'delivered': [], 'rcvBuf': [], 'sndBuf': [], 'sndCwnd': [],
            'rtt': [], 'bytesInFlight': [], 
            'max_pacing_rate': 0, 'number': 0,
            'beginTime': int(round(time.time() * 1000))
        }

        self.start()

    def feed(self, readData):
        """Quick enqueue into the queue—no processing done here."""
        self.queue.put(readData)

    def run(self):
        """Single loop of the thread: it retrieves and processes each readData."""
        while True:
            readData = self.queue.get()
            if readData is None:
                break

            s = self.state
            s['delivered'].append(int(readData['delivered']))
            s['rcvBuf'].append(int(readData['rcv_buf']))
            s['sndBuf'].append(int(readData['snd_buf']))
            s['sndCwnd'].append(int(readData['snd_cwnd']))
            s['rtt'].append(int(readData['rtt']))
            s['bytesInFlight'].append(int(readData['bytes_in_flight']))
            s['lost'] = readData['lost']
            s['retrans'] = readData['retrans']
            s['pacing_rate'] = s.get('pacing_rate', []) + [int(readData['pacing_rate'])]
            s['max_pacing_rate'] = max(s['max_pacing_rate'], int(readData['pacing_rate']))
            s['number'] += 1

            #print(s['rtt'], flush=True)
            #print("state:", s, flush=True)
            feat = self.extract_features(s)
            s['conn_type'] = self.classify_conn(feat)
            print(f"==> {self.name} classified : {s['conn_type']}", flush=True)

                
                
                

    def extract_features(self, s):
        rtts = s['rtt']
        if not rtts:
            return None
        mean_rtt = mean(rtts)
        std_rtt  = stdev(rtts) if len(rtts)>1 else 0
        delivered = sum(s['delivered'])  
        lost      = s.get('lost', 0)
        loss_rate = lost / (delivered + lost) if (delivered+lost)>0 else 0
        avg_rate  = mean(s.get('pacing_rate', [0]))
        return {
            'mean_rtt': mean_rtt,
            'jitter':   std_rtt,
            'loss':     loss_rate,
            'throughput': avg_rate,
            'max_rate': s['max_pacing_rate'],
        }
    
    def classify_conn(self,feat):
        rtt = feat['mean_rtt']
        jit = feat['jitter']
        tp  = feat['throughput']
        if rtt < 30 and jit < 10 and tp > 100_000_000:
            return 'filaire'
        if rtt > 100 and jit > 20 and tp < 20_000_000:
            return 'mobile'
        return 'wifi'

    # def stop(self):
    #     """To stop properly the thread"""
    #     self.queue.put(None)
    #     self.join()
        
  

class tSharkThread(threading.Thread):
    def __init__(self, object):
        threading.Thread.__init__(self, name='tshark')
        self.object = object

    def run(self):
        self.object.runTshark()


class readThread(threading.Thread):
    def __init__(self, object):
        threading.Thread.__init__(self, name='read')
        self.object = object

    def run(self):
        self.object.readPacketData()





# Main
flow = Flow(200)
tshark = tSharkThread(flow)
read = readThread(flow)
tshark.start()
read.start()
tshark.join()
read.join()