"""
Ce script implémente une application web de gestion de mots de passe utilisant Flask et Redis.

L'application permet aux utilisateurs de stocker de manière sécurisée des mots de passe pour une durée spécifiée.
Les mots de passe sont chiffrés à l'aide du chiffrement symétrique Fernet et stockés dans Redis.

Fonctions :
- check_redis_alive : Fonction décoratrice pour vérifier si Redis est actif avant d'exécuter une fonction.
- encrypt : Chiffre une chaîne de caractères de mot de passe à l'aide du chiffrement symétrique Fernet.
- decrypt : Déchiffre un mot de passe chiffré à l'aide de la clé fournie.
- parse_token : Analyse un jeton en clé de stockage et clé de déchiffrement.
- set_password : Chiffre et stocke un mot de passe pour une durée spécifiée, renvoyant un jeton.
- get_password : Récupère le mot de passe initial à partir d'un jeton, en le déchiffrant si nécessaire.
- password_exists : Vérifie si un mot de passe existe pour un jeton donné.
- empty : Fonction d'aide pour vérifier si une valeur est vide.
- clean_input : Nettoie et valide les données d'entrée provenant de l'interface utilisateur.
- index : Renvoie le modèle set_password.html pour la page d'accueil.
- handle_password : Gère la soumission d'un formulaire de mot de passe, stocke le mot de passe et renvoie un lien.
- preview_password : Renvoie le modèle preview.html pour une page de prévisualisation de mot de passe.
- show_password : Récupère et affiche le mot de passe déchiffré pour un jeton donné.
- about : Renvoie le modèle about.html pour la page À propos.
- main : Fonction principale pour démarrer l'application Flask avec SSL et la servir à l'aide de Waitress.
"""
import os
import sys
import uuid

import redis

from cryptography.fernet import Fernet
from flask import abort, Flask, render_template, request, jsonify, send_from_directory
from redis.exceptions import ConnectionError
from urllib.parse import quote_plus
from urllib.parse import unquote_plus
from distutils.util import strtobool
from waitress import serve

NO_SSL = bool(strtobool(os.environ.get('NO_SSL', 'False')))     # Récupérer la variable d'environnement NO_SSL et la convertir en booléen
URL_PREFIX = os.environ.get('URL_PREFIX', None)     # Récupérer le préfixe d'URL de la variable d'environnement URL_PREFIX
HOST_OVERRIDE = os.environ.get('HOST_OVERRIDE', None)       # Récupérer l'hôte de remplacement de la variable d'environnement HOST_OVERRIDE
TOKEN_SEPARATOR = '~'       # Définir le séparateur de jeton


# Initialize Flask Application
app = Flask(__name__)   # Création de l'application Flask
if os.environ.get('DEBUG'):     # Si la variable d'environnement DEBUG est définie
    app.debug = True        # Activer le mode débogage de Flask
app.secret_key = os.environ.get('SECRET_KEY', 'Secret Key')     # Définir la clé secrète de l'application Flask
app.config.update(      # Mettre à jour la configuration de l'application Flask
    dict(STATIC_URL=os.environ.get('STATIC_URL', 'static')))        # Définir l'URL statique de l'application Flask

# Initialize Redis
if os.environ.get('MOCK_REDIS'):        # Si la variable d'environnement MOCK_REDIS est définie
    from fakeredis import FakeStrictRedis       # Importer la classe FakeStrictRedis de fakeredis
    redis_client = FakeStrictRedis()        # Créer une instance de FakeStrictRedis
elif os.environ.get('REDIS_URL'):       # Si la variable d'environnement REDIS_URL est définie
    redis_client = redis.StrictRedis.from_url(os.environ.get('REDIS_URL'))      # Créer une instance de StrictRedis à partir de l'URL Redis
else:       
    redis_host = os.environ.get('REDIS_HOST', 'localhost')      # Récupérer l'hôte Redis de la variable d'environnement REDIS_HOST
    redis_port = os.environ.get('REDIS_PORT', 6379)     # Récupérer le port Redis de la variable d'environnement REDIS_PORT
    redis_db = os.environ.get('SNAPPASS_REDIS_DB', 0)       # Récupérer la base de données Redis de la variable d'environnement SNAPPASS_REDIS_DB
    redis_client = redis.StrictRedis(       # Créer une instance de StrictRedis
        host=redis_host, port=redis_port, db=redis_db)      # Spécifier l'hôte, le port et la base de données Redis
REDIS_PREFIX = os.environ.get('REDIS_PREFIX', 'snappass')       # Récupérer le préfixe Redis de la variable d'environnement REDIS_PREFIX

TIME_CONVERSION = {'two weeks': 1209600, 'week': 604800, 'day': 86400, 'hour': 3600}        # Définir les conversions de temps en secondes


def check_redis_alive(fn):
    """
    Fonction décoratrice pour vérifier si Redis est actif avant d'exécuter une fonction.

    Si la fonction est la fonction principale, elle quittera le programme si Redis n'est pas actif.

    Si la fonction n'est pas la fonction principale, elle renverra une erreur 500 si Redis n'est pas actif.
    """
    def inner(*args, **kwargs):
        try:
            if fn.__name__ == 'main':    # Si le nom de la fonction est main
                redis_client.ping()     # Vérifier la connexion à Redis
            return fn(*args, **kwargs)    # Exécuter la fonction
        except ConnectionError as e:        # Gérer l'erreur de connexion
            print('Failed to connect to redis! %s' % e.message)     # Afficher un message d'erreur
            if fn.__name__ == 'main':       # Si le nom de la fonction est main
                sys.exit(0)     # Quitter le programme si la fonction est main
            else:
                return abort(500)       # Renvoyer une erreur 500 si la fonction n'est pas main
    return inner


def encrypt(password):
    """
    Prend une chaîne de caractères de mot de passe, la chiffre avec le chiffrement symétrique Fernet,
    et renvoie le résultat (bytes), avec la clé de déchiffrement (bytes)
    """
    encryption_key = Fernet.generate_key()
    fernet = Fernet(encryption_key)
    encrypted_password = fernet.encrypt(password.encode('utf-8'))
    return encrypted_password, encryption_key


def decrypt(password, decryption_key):
    """
    Déchiffre un mot de passe (bytes) en utilisant la clé fournie (bytes),
    et renvoie le mot de passe en texte clair (bytes).
    """
    fernet = Fernet(decryption_key)
    return fernet.decrypt(password)


def parse_token(token):
    """
    Analyse un jeton en clé de stockage et clé de déchiffrement (si présente).

    Args:
        token (str): Le jeton à analyser.

    Returns:
        tuple: Un tuple contenant la clé de stockage et la clé de déchiffrement (si présente).
    """

    token_fragments = token.split(TOKEN_SEPARATOR, 1)
    storage_key = token_fragments[0]

    try:
        decryption_key = token_fragments[1].encode('utf-8')
    except IndexError:
        decryption_key = None

    return storage_key, decryption_key

# Permet de servir les fichiers de certificat et de clé pour la vérification ACME
@app.route('/.well-known/acme-challenge/<path:filename>')       # Décorateur de route pour le chemin /.well-known/acme-challenge/<filename>
def well_known(filename):       # Définition de la fonction well_known avec le paramètre filename
    return send_from_directory('.well-known/acme-challenge', filename)      # Renvoyer le fichier du répertoire .well-known/acme-challenge

@check_redis_alive
def set_password(password, ttl):
    """
    Chiffre et stocke le mot de passe pour la durée spécifiée.

    Renvoie un jeton composé de la clé où le mot de passe chiffré est stocké et de la clé de déchiffrement.
    """
    storage_key = REDIS_PREFIX + uuid.uuid4().hex    # Générer une clé de stockage unique
    encrypted_password, encryption_key = encrypt(password)   # Chiffrer le mot de passe et obtenir la clé de déchiffrement
    redis_client.setex(storage_key, ttl, encrypted_password)    # Stocker le mot de passe chiffré dans Redis avec une durée de vie spécifiée
    encryption_key = encryption_key.decode('utf-8')         # Décoder la clé de déchiffrement en UTF-8
    token = TOKEN_SEPARATOR.join([storage_key, encryption_key])     # Créer un jeton en joignant la clé de stockage et la clé de déchiffrement
    return token


@check_redis_alive
def get_password(token):
    """
    À partir d'un jeton donné, renvoie le mot de passe initial.

    Si le jeton est séparé par des tilde, nous déchiffrons le mot de passe récupéré depuis Redis.
    Sinon, le mot de passe est simplement renvoyé tel quel.
    """
    storage_key, decryption_key = parse_token(token)    # Analyser le jeton pour obtenir la clé de stockage et la clé de déchiffrement
    password = redis_client.get(storage_key)    # Récupérer le mot de passe chiffré à partir de la clé de stockage
    redis_client.delete(storage_key)    # Supprimer le mot de passe chiffré de Redis après l'avoir récupéré

    if password is not None:    # Si un mot de passe est présent

        if decryption_key is not None:    # Si une clé de déchiffrement est présente
            password = decrypt(password, decryption_key)    # Déchiffrer le mot de passe avec la clé de déchiffrement

        return password.decode('utf-8')


@check_redis_alive
def password_exists(token):
    storage_key, decryption_key = parse_token(token)
    return redis_client.exists(storage_key)


def empty(value):
    if not value:
        return True


def clean_input():
    """
    Assurez-vous de ne pas obtenir de mauvaises données de l'interface utilisateur,
    formatez les données pour qu'elles soient lisibles par la machine
    """
    if empty(request.form.get('password', '')): 
        abort(400)

    if empty(request.form.get('ttl', '')):
        abort(400)

    time_period = request.form['ttl'].lower()
    if time_period not in TIME_CONVERSION:
        abort(400)

    return TIME_CONVERSION[time_period], request.form['password']


@app.route('/', methods=['GET'])    # Décorateur de route pour la méthode GET sur la racine
def index():        # Définition de la fonction index
    return render_template('set_password.html')     # Renvoyer le modèle set_password.html pour la page d'accueil


@app.route('/', methods=['POST'])       # Décorateur de route pour la méthode POST sur la racine
def handle_password():
    """
    Gère la création d'un mot de passe sécurisé et renvoie le lien correspondant.

    :return: Le lien vers la page de confirmation du mot de passe.
    :rtype: str
    """
    
    ttl, password = clean_input()       # Nettoyer les données d'entrée et les stocker dans ttl et password
    token = set_password(password, ttl)     # Stocker le mot de passe chiffré et renvoyer un jeton

    if NO_SSL:      # Si NO_SSL est défini
        if HOST_OVERRIDE:       # Si HOST_OVERRIDE est défini
            base_url = f'http://{HOST_OVERRIDE}/'       # Définir l'URL de base avec l'hôte de remplacement
        else:
            base_url = request.url_root
    else:
        if HOST_OVERRIDE:
            base_url = f'http://{HOST_OVERRIDE}/'
        else:
            base_url = request.url_root.replace("http://", "http://")
    if URL_PREFIX:      # Si URL_PREFIX est défini
        base_url = base_url + URL_PREFIX.strip("/") + "/"       # Ajouter le préfixe d'URL à l'URL de base
    link = base_url + quote_plus(token)     # Créer un lien avec le jeton encodé
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:       # Si le client accepte le JSON et n'accepte pas le HTML
        return jsonify(link=link, ttl=ttl)         # Renvoyer le lien et le TTL au format JSON
    else:
        return render_template('confirm.html', password_link=link)      # Renvoyer le modèle confirm.html avec le lien


@app.route('/<password_key>', methods=['GET'])
def preview_password(password_key):
    """
    Affiche un aperçu du mot de passe correspondant à la clé donnée.

    Args:
        password_key (str): La clé du mot de passe à afficher.

    Returns:
        tuple: Un tuple contenant le template HTML à afficher et le code d'état HTTP.
    """
    password_key = unquote_plus(password_key)
    if not password_exists(password_key):
        return render_template('expired.html'), 404

    return render_template('preview.html')


@app.route('/<password_key>', methods=['POST'])
def show_password(password_key):
    """
    Récupère et affiche le mot de passe déchiffré pour la clé donnée.

    Args:
        password_key (str): La clé du mot de passe à afficher.
    
    Returns:
        tuple: Un tuple contenant le template HTML à afficher et le code d'état HTTP.
    """
    password_key = unquote_plus(password_key)
    password = get_password(password_key)
    if not password:
        return render_template('expired.html'), 404

    return render_template('password.html', password=password)

@app.route('/about')  
def about():
    return render_template('about.html')


@check_redis_alive
def main():
    # Chemin vers les fichiers de certificat et de clé
    cert_path = "selfsigned.crt"
    key_path = "selfsigned.key"
    
    # Démarrer l'application Flask avec SSL grace à pyopenssl
    #app.run(host='0.0.0.0', port=443, ssl_context=(cert_path, key_path))

    # Démarrer l'application Flask en local
    #app.run(host='0.0.0.0', port=80)

    # Démarrer l'application Flask avec Waitress
    serve(app, host='127.0.0.1', port=8080)

if __name__ == '__main__':
    main()