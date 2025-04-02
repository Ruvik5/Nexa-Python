import socket
import threading

# Scanner de port
def scan_port(host, port):
    try:
        # Création d'un objet socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Définir un délai pour éviter le TIMEOUT et blocage
        sock.settimeout(1)

        # Tentative de connexion sur le port (0 si la connexion a réussi)
        result = sock.connect_ex((host, port))

        # Si le port est ouvert (result == 0), on l'affiche
        if result == 0:
            print(f"[+] Port {port} ouvert")

        # On ferme le socket
        sock.close()
    except Exception as e:
        # Gestion des erreurs
        print(f"[-] Erreur sur le port {port}: {e}")

# On demande à l'utilisateur l'adresse IP de la cible
target = input("Entrer l'IP cible : ")

# On demande la plage d'adresse à scanner
start_port = int(input("Port de début : "))
end_port = int(input("Port de fin : "))

# On informe l'utilisateur qu'on commence le scan
print(f"\n[***] Scan de la cible {target} sur les ports {start_port} à {end_port} [***]\n")

threads = []

for port in range(start_port, end_port + 1):
    # On crée un thread (exécution parallèle) pour chaque port
    t = threading.Thread(target=scan_port, args=(target, port))
    t.start()
    threads.append(t)

# On attend que tous les threads terminent
for t in threads:
    t.join()
