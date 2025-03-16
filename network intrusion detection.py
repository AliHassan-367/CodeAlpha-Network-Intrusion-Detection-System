import tkinter as tk
from tkinter import messagebox
from scapy.all import sniff, IP, TCP, UDP
import threading

# Predefined suspicious rules (Modify as needed)
suspicious_ips = {"192.168.1.100", "10.0.0.5"}  # Suspicious IPs
suspicious_ports = {4444, 5555, 6666}  # Known malicious ports
monitoring = False  # Flag to control sniffing

# Function to check packet against rules
def analyze_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        alert_msg = None

        packet_info = f"Packet: {src_ip} -> {dst_ip}"
        root.after(0, lambda: log_packet(packet_info))  # Ensure thread-safe GUI updates

        if src_ip in suspicious_ips or dst_ip in suspicious_ips:
            alert_msg = f"[ALERT] Suspicious IP detected: {src_ip} -> {dst_ip}"

        if packet.haslayer(TCP):
            port = packet[TCP].dport
        elif packet.haslayer(UDP):
            port = packet[UDP].dport
        else:
            port = None

        if port and port in suspicious_ports:
            alert_msg = f"[ALERT] Suspicious Port detected: {port} on {src_ip}"

        if alert_msg:
            root.after(0, lambda: log_alert(alert_msg))
            root.after(0, lambda: display_alert(alert_msg))

# Function to log alert to GUI
def log_alert(alert_msg):
    alert_listbox.insert(tk.END, alert_msg)
    alert_listbox.itemconfig(tk.END, {'fg': 'red'})

# Function to log packet traffic to GUI
def log_packet(packet_msg):
    packet_listbox.insert(tk.END, packet_msg)
    packet_listbox.itemconfig(tk.END, {'fg': 'green'})

# Function to display a pop-up alert
def display_alert(msg):
    messagebox.showwarning("Intrusion Alert", msg)

# Function to start packet sniffing
def start_sniffing():
    global monitoring
    monitoring = True
    while monitoring:
        sniff(prn=analyze_packet, store=False, timeout=5)  # Sniff in short bursts

# Function to start sniffing in a separate thread
def start_sniffer_thread():
    global monitoring
    if not monitoring:
        sniffer_thread = threading.Thread(target=start_sniffing, daemon=True)
        sniffer_thread.start()

# Function to stop monitoring
def stop_monitoring():
    global monitoring
    monitoring = False

# GUI Setup
root = tk.Tk()
root.title("Network Intrusion Detection System")
root.geometry("600x500")
root.configure(bg="black")

tk.Label(root, text="Intrusion Alerts", font=("Arial", 14, "bold"), fg="white", bg="black").pack()

alert_listbox = tk.Listbox(root, width=80, height=10, bg="black", fg="white")
alert_listbox.pack(pady=5)

tk.Label(root, text="Captured Traffic", font=("Arial", 14, "bold"), fg="white", bg="black").pack()

packet_listbox = tk.Listbox(root, width=80, height=10, bg="black", fg="white")
packet_listbox.pack(pady=5)

start_btn = tk.Button(root, text="Start Monitoring", font=("Arial", 12), bg="green", fg="white", command=start_sniffer_thread)
start_btn.pack(pady=5)

stop_btn = tk.Button(root, text="Stop Monitoring", font=("Arial", 12), bg="orange", fg="white", command=stop_monitoring)
stop_btn.pack(pady=5)

exit_btn = tk.Button(root, text="Exit", font=("Arial", 12), bg="red", fg="white", command=root.quit)
exit_btn.pack(pady=5)

root.mainloop()
