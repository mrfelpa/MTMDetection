def extract_tcp_features(pkt):
    features = [
        pkt.sport,  
        pkt.dport,  
        pkt.seq,  
        pkt.ack,  
        pkt.window,  
    ]
    return features