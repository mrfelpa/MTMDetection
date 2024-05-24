from scapy.all import ICMP

def extract_icmp_features(pkt):
    if pkt.haslayer(ICMP):
        icmp_layer = pkt[ICMP]
        features = [
            icmp_layer.type,  
            icmp_layer.code,  
            icmp_layer.chksum,  
            icmp_layer.id,  
            icmp_layer.seq  
        ]
        return features
    else:
        return []  