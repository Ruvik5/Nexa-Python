import scapy.all as scapy
import psutil
import logging
import threading
import tkinter as tk
from tkinter import scrolledtext

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


class NetworkMonitor:
    def __init__(self, interface="Realtek Gaming GbE Family Controller", gui=None):
        self.interface = interface
        self.gui = gui
        self.running = False

    def packet_handler(self, packet):
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            message = f"Packet: {src_ip} -> {dst_ip}"
            logging.info(message)
            if self.gui:
                self.gui.update_log(message)
            self.detect_suspicious_activity(packet)

    def detect_suspicious_activity(self, packet):
        if packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == 2:  # SYN flag check
            warning_message = f"⚠️ Possible SYN scan from {packet[scapy.IP].src}"
            logging.warning(warning_message)
            if self.gui:
                self.gui.update_log(warning_message)

    def start_capture(self):
        self.running = True
        logging.info(f"Starting packet capture on {self.interface}")
        while self.running:
            scapy.sniff(iface=self.interface, prn=self.packet_handler, store=False, count=10)

    def stop_capture(self):
        self.running = False
        logging.info("Packet capture stopped")

    @staticmethod
    def check_system_resources():
        cpu_usage = psutil.cpu_percent(interval=1)
        mem_usage = psutil.virtual_memory().percent
        return f"CPU: {cpu_usage}%, Memory: {mem_usage}%"


class NetworkMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Monitor")
        self.monitor = NetworkMonitor(gui=self)

        # Boutons
        self.start_button = tk.Button(root, text="Démarrer", command=self.start_capture)
        self.start_button.pack(pady=5)

        self.stop_button = tk.Button(root, text="Arrêter", command=self.stop_capture, state=tk.DISABLED)
        self.stop_button.pack(pady=5)

        # Zone de log
        self.log_area = scrolledtext.ScrolledText(root, width=60, height=15)
        self.log_area.pack(padx=10, pady=10)
        self.log_area.insert(tk.END, "🔍 Network Monitor prêt...\n")

        # Afficher l'utilisation du CPU et RAM
        self.resource_label = tk.Label(root, text=self.monitor.check_system_resources())
        self.resource_label.pack(pady=5)

    def update_log(self, message):
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.yview(tk.END)

    def start_capture(self):
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.monitor.running = True
        self.capture_thread = threading.Thread(target=self.monitor.start_capture)
        self.capture_thread.start()

    def stop_capture(self):
        self.monitor.stop_capture()
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)


if __name__ == "__main__":
    root = tk.Tk()
    gui = NetworkMonitorGUI(root)
    root.mainloop()