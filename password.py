import re
import hashlib
import json
import os

# Fonction de hachage du mot de passe
def hash_password(password):
    try:
        password_bytes = password.encode('utf-8')
        hash_object = hashlib.sha256(password_bytes)
        return hash_object.hexdigest()
    except Exception as e:
        print(f"Erreur lors du hashage: {e}")
        return None

def add_password(hashed_password):
    # Vérifie si passwords.json existe
    if not os.path.exists('passwords.json'):
        # Si passwords.json n'existe pas, création d'une liste vide
        saved_passwords = []
    else:
        # Charger les mots de passe existants depuis passwords.json
        try:
            with open('passwords.json', 'r') as file:
                saved_passwords = json.load(file)
        except json.JSONDecodeError:
            saved_passwords = []

    # Vérifie si le mot de passe haché est déjà dans la liste
    if any(entry == hashed_password for entry in saved_passwords):
        print("Erreur : Ce mot de passe a déjà été enregistré")
        return False
    else:
        # Ajoute de nouveau mot de passe haché à la liste
        saved_passwords.append(hashed_password)

        # Ajoute le mot de passe dans le fichier passwords.json
        with open('passwords.json', 'w') as file:
            json.dump(saved_passwords, file)

        print("Mot de passe haché ajouté avec succès dans 'passwords.json'")
        return True

# Boucle pour la saisie du mot de passe
while True:
    passwd = input("Veuillez entrer votre mot de passe : ")

    if len(passwd) < 8:
        print("La longueur de votre mot de passe ne doit pas être inférieure à 8")
        continue
    if not re.search("[a-z]", passwd):
        print("Votre mot de passe doit contenir au moins un caractère en minuscule")
        continue
    if not re.search("[0-9]", passwd):
        print("Votre mot de passe doit contenir au moins un numéro")
        continue
    if not re.search("[A-Z]", passwd):
        print("Votre mot de passe doit contenir au moins un caractère en majuscule")
        continue
    if not re.search("[!@*$#]", passwd):
        print("Votre mot de passe doit contenir au moins un symbole parmi !@#$%^&*")
        continue

    # Hash du mot de passe
    hashed_password = hash_password(passwd)

    # Appel la fonction add_password pour sauvegarder le password haché
    if add_password(hashed_password):
        break  # Sors de la boucle si le mdp a été ajouté avec succés
    else:
        print("Veuillez réessayer")
