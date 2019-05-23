#coding=utf-8
from db_utils import *
from KafkaProducer import *
import json
import random

ip_to_number = lambda x:sum([256**j*int(i) for j,i in enumerate(x.split('.')[::-1])])
number_to_ip =  lambda x: '.'.join([str(x/(256**i)%256) for i in range(3,-1,-1)])

class AssetThreatItem(object):
    def __init__(self, ip, asset_type, event_count=0, asset_name='For test', region='for test', severity=0, business_count=0, label=''):
        self.ip = ip
        self.asset_type = asset_type
        self.asset_name = asset_name
        self.region = region
        self.severity = severity
        self.business_count = business_count
        self.label = label

    def getIp(self):
        return self.ip

    def getAssetType(self):
        return self.asset_type

    def toDict(self):
        #convert object to a dict
        d = {}
        #d['__class__'] = obj.__class__.__name__
        #d['__module__'] = obj.__module__
        d.update(self.__dict__)
        return d

class Threat(object):
    def __init__(self, srcIp, srcType, dstIp, dstType, severity=1 ,secType=0, title="For test", needShow=True):
        self.srcIp = srcIp
        self.srcType = srcType
        self.dstIp = dstIp
        self.dstType = dstType
        self.severity = severity
        self.secType = secType
        self.title = title
        self.needShow = needShow

    def toDict(self):
        #convert object to a dict
        d = {}
        #d['__class__'] = obj.__class__.__name__
        #d['__module__'] = obj.__module__
        d.update(self.__dict__)
        return d

    def toJson(self):
        jsonStr = json.dumps(self.toDict())
        #print jsonStr
        return jsonStr
    
def gen_random_ip():
    def gen_random_ip_digit():
        for i in range(4):
            yield random.randint(0,255)
    return '.'.join(map(lambda x : str(x), gen_random_ip_digit()))

def gen_random_ip_range(begin, end):
    begin_num = ip_to_number(begin)
    end_num = ip_to_number(end)
    rndIp = random.randint(begin_num, end_num)
    ipStr = number_to_ip(rndIp)
    #print ipStr
    return ipStr
    
def gen_random_int_list(maxLen, begin, end):
    length = random.randint(1, maxLen)
    ret = []
    while len(ret) < length:
        tmp = random.randint(begin, end)
        if tmp in ret:
            continue
        ret.append(tmp)
    return ret



def gen_random_asset_threat_item():
    rand_ip = gen_random_ip()
    rand_type = random.randint(1, 2)
    return AssetThreatItem(rand_ip, rand_type)

def gen_random_asset_threat_item(begin, end):
    rand_ip = gen_random_ip_range(begin, end)
    rand_type = random.randint(1, 2)
    return AssetThreatItem(rand_ip, rand_type)

def gen_random_threat_with_src(ip, type):
    threat = Threat(srcIp=ip, srcType=type, dstIp = gen_random_ip(), dstType=random.randint(0,2), secType=gen_random_int_list(10, 0, 41), severity=random.randint(1,4))
    return threat

def gen_random_threat_with_dst(ip, type):
    threat = Threat(dstIp=ip, dstType=type, srcIp = gen_random_ip(), srcType=random.randint(0,2), secType=gen_random_int_list(10, 0, 41), severity=random.randint(1,4))
    return threat

def prepareAssetThreatTbl(assetCnt, eventCnt):
    db = Mydb(host='10.180.171.233', user_name='xxx', passwd='hIllstoneBdap4Ever', db_name='bdap')
    db.delete('asset_threat_tbl')
    producer = MyProducer()
    topic = 'threat-event'
    asset = gen_random_asset_threat_item('192.0.0.0', '192.255.255.255')
    asset1 = gen_random_asset_threat_item('192.0.0.0', '192.255.255.255')
    threat1 = gen_random_threat_with_src(asset.getIp(), asset.getAssetType())
    threat2 = gen_random_threat_with_dst(asset.getIp(), asset.getAssetType())
    threat3 = gen_random_threat_with_src(asset.getIp(), asset.getAssetType())
    threat4 = gen_random_threat_with_src(asset1.getIp(), asset1.getAssetType())
    threat5 = gen_random_threat_with_dst(asset1.getIp(), asset1.getAssetType())
    producer.send(topic, threat1.toJson())
    producer.send(topic, threat2.toJson())
    producer.send(topic, threat3.toJson())
    producer.send(topic, threat4.toJson())
    producer.send(topic, threat5.toJson())
        
    producer.close()
    db.close()


def parepareDatas(cnt):
    db = Mydb(host='10.180.171.233', user_name='hillstone', passwd='hIllstoneBdap4Ever', db_name='bdap')
    db.delete('asset_threat_tbl')
    producer = MyProducer()
    topic = 'threat-event'
    for i in range(cnt):
        asset = gen_random_asset_threat_item('192.0.0.0', '192.255.255.255')
        if random.randint(0,1) == 1:
            threat = gen_random_threat_with_src(asset.getIp(), asset.getAssetType())
        else:
            threat = gen_random_threat_with_dst(asset.getIp(), asset.getAssetType())
        if i%1000 == 999:
            print i + 1
        producer.send(topic, threat.toJson())
    producer.close()
    db.close()
    



def get_host_ip():
    import socket
    hostname = socket.gethostname()
    ip = socket.gethostbyname(hostname)
    return ip

            
if __name__ == '__main__':
    set_db_debug(True)
    parepareDatas(1000000)
