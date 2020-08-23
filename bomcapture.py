#!/usr/bin/env python3
import sys
import redis
import ujson
from trecord import Recorder
from pprint import pprint

rdb = redis.Redis()


# The redis schema.
# dnsqueue: This queue holds only DNS queries, to be used by the web application
# rawpackets: This queue will be used by ajit tool, and data will be saved into database as required
# `ip:iv4`: These keys stores Domain names as sets in redis. Directly gets updates from TLS SNI values.
# Later ajit will also updatge from DNS responses.

def process_packet(p):
    """
    Recives a packet as dict, and the processes it.
    It pushes the data into proper queues in Redis for further analysis.
    """
    layers = p["_source"]["layers"]
    if not "ip" in layers:
        return
    ipl = layers["ip"]
    try:
        if "ssl" in layers:
            ssl = layers["ssl"]
            if "ssl.record" in ssl:
                sslrecords = ssl["ssl.record"]
                if "ssl.handshake" in sslrecords:
                    handshake = sslrecords["ssl.handshake"]
                    if type(handshake) != dict:
                        return
                    keys = sslrecords["ssl.handshake"].keys()
                    for k in keys:
                        if k.startswith("Extension: server_name "):
                            try:
                                sni = sslrecords["ssl.handshake"][k]["Server Name Indication extension"]
                            except:
                                # example of the ssl records
                                # {'ssl.handshake.extension.type': '0', 'ssl.handshake.extension.len': '0'}
                                continue
                            server_name = sni["ssl.handshake.extensions_server_name"]
                            rdb.sadd(f"ip:{ipl['ip.dst']}", server_name)
                            # print(f"ip.src {ipl['ip.src']} ip.dst {ipl['ip.dst']} Server: {server_name}")
                            return
        rawpacket = {"is_dns": False, "src": ipl["ip.src"], "dst": ipl["ip.dst"]}
        if "tcp" in layers:
            tcp = layers["tcp"]
            rawpacket["ptype"] = "tcp"
            rawpacket["srcport"] = tcp["tcp.srcport"]
            rawpacket["dstport"] = tcp["tcp.dstport"]
            # print(f"TCP ip.src {ipl['ip.src']}:{srcport} ip.dst {ipl['ip.dst']}:{dstport}")
        elif "udp" in layers:
            udp = layers["udp"]
            rawpacket["ptype"] = "udp"
            rawpacket["srcport"] = udp["udp.srcport"]
            rawpacket["dstport"] = udp["udp.dstport"]
            # print(f"UDP ip.src {ipl['ip.src']}:{srcport} ip.dst {ipl['ip.dst']}:{dstport}")
        if "dns" in layers:
            dns = layers["dns"]
            rawpacket["is_dns"] = True
            flags = dns.get("dns.flags_tree", None)
            if flags:
                if "Queries" in dns:
                    qlist = []
                    queries = dns["Queries"]
                    for q in queries.values():
                        qname = q["dns.qry.name"]
                        # print(f"DNS query: {qname}")
                        qlist.append(qname)
                    rawpacket["qlist"] = qlist
                if flags["dns.flags.response"] == "0":
                    # This is a query
                    rawpacket["qtype"] = 0
                # There are times when we have a response but no Answers in it
                elif flags["dns.flags.response"] == "1" and "Answers" in dns:
                    # This is a DNS response
                    answers = dns["Answers"]
                    ansd = []
                    for ans in answers.values():
                        if "dns.a" in ans:
                            ansd.append((ans["dns.resp.name"], "A", ans["dns.a"]))
                        elif "dns.cname" in ans:
                            ansd.append((ans["dns.resp.name"], "CNAME", ans["dns.cname"]))
                    # print(f"DNS Response: {ansd}")
                    rawpacket["qtype"] = 1
                    rawpacket["qresponse"] = ansd
                    # Now also get the query details
                else:  # We got nxdomain as response, no such domain
                    rawpacket["qtype"] = 1
                    rawpacket["qresponse"] = []


        # Convert to JSON
        data = ujson.dumps(rawpacket)
        if rawpacket["is_dns"]:
            # For web DNS view
            rdb.rpush("dnsqueue", data)
        # The following queue will be consumed by ajit
        rdb.rpush("rawpackets", data)
    except Exception as err:
        breakpoint()


def main():
    if len(sys.argv) > 1:
        device = sys.argv[1]
    else:
        device = "wg0"
    rec = Recorder(device)
    print(f"Started capturing packets on {device}")
    for record in rec:
        try:
            if record.startswith("["):
                record = record[1:]
            data = ujson.loads(record)
        except:
            print(record)
            continue
        process_packet(data)


if __name__ == "__main__":
    main()


