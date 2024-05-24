def extract_arp_features(pkt):
    features = [
        pkt.op,  
        len(pkt.hwsrc),  
        len(pkt.psrc), 
        len(pkt.hwdst),  
        len(pkt.pdst),  
    ]
    return features