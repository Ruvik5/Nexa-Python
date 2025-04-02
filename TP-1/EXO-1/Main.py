import platform
import subprocess

# demander une adresse IP à l'user

ip_adress = input("Entrez une adresse IP à ping : ")
print(f"L'adresse IP fournie par l'utilisateur est : {ip_adress}")

# on detecte l'os pour adapter la commande
param = "-n" if platform.system().lower() == "windows" else "-c"

# Construction du ping dans une liste
commande = ["ping", param, "1", ip_adress]

print("ping en cours")

# Executer le ping
try:
    result = subprocess.run(commande, stdout=subprocess.DEVNULL)
    if result.returncode == 0:
        print("La cible est en ligne")
    else:
        print("La cible n'est pas en ligne")
except Exception as e :
        print(f"Erreur lors du ping {e}")