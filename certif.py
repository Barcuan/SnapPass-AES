from OpenSSL import crypto, SSL
from datetime import datetime, timedelta

# Chemins pour les fichiers de certificat et de clé
CERT_FILE = "selfsigned.crt"
KEY_FILE = "selfsigned.key"

def generate_self_signed_cert(cert_file, key_file):
    # Crée une paire de clés
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    # Crée un certificat auto-signé
    cert = crypto.X509()
    cert.get_subject().C = "FR"
    cert.get_subject().ST = "Nord-De-France"
    cert.get_subject().L = "St-Laurent-Blangy"
    cert.get_subject().O = "Ma Société"
    cert.get_subject().OU = "Mon Département"
    cert.get_subject().CN = "*.ngrok-free.app"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)

    # Ajout de l'extension SAN
    san_list = [f"IP:192.168.11.192"]
    cert.add_extensions([
        crypto.X509Extension(b"subjectAltName", False, ", ".join(san_list).encode())
    ])

    cert.sign(key, 'sha256')

    # Écriture du certificat et de la clé dans les fichiers
    with open(cert_file, "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    with open(key_file, "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

generate_self_signed_cert(CERT_FILE, KEY_FILE)
print(f"Certificat et clé générés : {CERT_FILE}, {KEY_FILE}")