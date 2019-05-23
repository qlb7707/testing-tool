#coding=utf-8
from kafka import KafkaProducer

class MyProducer(object):
    def __init__(self, **properties):
        self.server = properties.get('bootstrap_servers', 'bdap-master.hillstone:9092')
        self.producer = KafkaProducer(bootstrap_servers=self.server)
    
    def send(self, topic, msg):
        assert(isinstance(topic, str) and isinstance(msg, str))
        self.producer.send(topic, msg)


    def close(self):
        self.producer.close()
