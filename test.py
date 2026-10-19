from scapy.all import sniff

try:
    print("Sniffing... Press Ctrl+C to stop.")
    sniff(prn=lambda p: print(p.summary()), store=False)

except KeyboardInterrupt:
    print("\nCtrl+C caught!")

finally:
    print("Finally executed.")