from scapy.all import sniff
import geoip2.database

try:
     reader = geoip2.database.Reader("GeoLite2-Country.mmdb")
except:
     reader = None
     print("файла с бд стран не найден")

def get_country(ip):
    if ip.startswith(("192.168.", "10.", "127.", "172.")):
        return "local"
     
    if reader:
        try:
            response = reader.country(ip)
            return response.country.iso_code
        except:
            return "None"
    return "NoDB"

def run_sniffer(ui_callback, check_status):
    def internal_callback(packet):
        if not check_status(): return

        if packet.haslayer("IP"):
            src = packet["IP"].src
            dst = packet['IP'].dst
            country = get_country(dst)
            ui_callback(f"[local] {src} -> {dst} [{country}]")
        else:
            ui_callback(packet.summary())

    def stop_check(packet):
            return not check_status()

    sniff(iface="neko-tun", prn=internal_callback, store=0, stop_filter=stop_check)