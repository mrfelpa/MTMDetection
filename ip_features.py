from scapy.all import IP

def extract_ip_features(pkt):
    if pkt.haslayer(IP):
        ip_layer = pkt[IP]
        features = [
            ip_layer.version, 
            ip_layer.ihl,  
            ip_layer.tos,  
            ip_layer.id,  
            ip_layer.flags,  
            ip_layer.frag,  
            ip_layer.ttl,  
            ip_layer.proto,  
            ip_layer.chksum,  
            ip_layer.src,  
            ip_layer.dst  
        ]
        return features
    else:
        return []  