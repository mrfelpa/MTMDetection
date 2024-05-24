from scapy.all import UDP

def extract_udp_features(pkt):
    if pkt.haslayer(UDP):
        udp_layer = pkt[UDP]
        features = [
            udp_layer.sport,  
            udp_layer.dport,  
            udp_layer.len,  
            udp_layer.chksum  
        ]
        return features
    else:
        return []  