from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import datetime
import os
import sys
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
  


# A) X.509 Certificate Parser and Analyzer


def load_certificate(cert_path):
   # Load a PEM or DER encoded certificate from file
   with open(cert_path, "rb") as f:
       data = f.read()
       try:
           cert = x509.load_pem_x509_certificate(data, default_backend())
       except ValueError:
           cert = x509.load_der_x509_certificate(data, default_backend())
   return cert


def parse_certificate(cert):
   # Display key certificate fields
   print("\nCertificate Information")
   print("-----------------------")
   print(f"Version: {cert.version.name}")
   print(f"Serial Number: {cert.serial_number}")
   print(f"Signature Algorithm: {cert.signature_hash_algorithm.name}")
   print(f"Issuer: {cert.issuer.rfc4514_string()}")
   print(f"Subject: {cert.subject.rfc4514_string()}")
   print(f"Validity Period:")
   print(f"   Not Before: {cert.not_valid_before_utc}")
   print(f"   Not After : {cert.not_valid_after_utc}")
   print(f"Public Key Algorithm: {cert.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)[:30]}...")


   # Display extensions
   print("\nExtensions:")
   for ext in cert.extensions:
       print(f" - {ext.oid._name}: {ext.value}")


def generate_fingerprint(cert):
   # Generate SHA-256 fingerprint of the certificate
   fingerprint = cert.fingerprint(hashes.SHA256())
   print("\nFingerprint (SHA-256):", fingerprint.hex())


# B) Certificate Chain Validation Engine


def verify_chain(end_cert, issuer_cert):
   # Verify if end_cert is signed by issuer_cert
   try:
       issuer_public_key = issuer_cert.public_key()
       issuer_public_key.verify(
           end_cert.signature,
           end_cert.tbs_certificate_bytes,
           padding.PKCS1v15(),
           end_cert.signature_hash_algorithm,
       )
       print("Signature Verification: SUCCESS")
   except Exception as e:
       print("Signature Verification: FAILED ->", e)
       return False


   # Check validity period using UTC naive datetime
   now = datetime.datetime.now(datetime.timezone.utc)
   # Normalize certificate validity times to timezone-aware UTC datetimes
   nb = end_cert.not_valid_before_utc
   na = end_cert.not_valid_after_utc
   if nb.tzinfo is None:
       nb = nb.replace(tzinfo=datetime.timezone.utc)
   else:
       nb = nb.astimezone(datetime.timezone.utc)
   if na.tzinfo is None:
       na = na.replace(tzinfo=datetime.timezone.utc)
   else:
       na = na.astimezone(datetime.timezone.utc)
   if now < nb or now > na:
       print("Certificate Validity: EXPIRED or NOT YET VALID")
       return False
   print("Certificate Validity: OK")


   # Verify issuer-subject relationship
   if end_cert.issuer != issuer_cert.subject:
       print("Issuer/Subject Mismatch")
       return False


   print("Chain Verification: PASSED")
   return True


# C) Simple Certificate Authority (CA) Simulation


def generate_ca():
   # Generate a CA key pair and self-signed root certificate
   print("\nGenerating Root CA...")
   key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
   subject = issuer = x509.Name([
       x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
       x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SimpleCA"),
       x509.NameAttribute(NameOID.COMMON_NAME, "RootCA"),
   ])
   cert = (
       x509.CertificateBuilder()
       .subject_name(subject)
       .issuer_name(issuer)
       .public_key(key.public_key())
       .serial_number(x509.random_serial_number())
       .not_valid_before(datetime.datetime.utcnow())
       .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
       .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
       .sign(key, hashes.SHA256())
   )


   with open("rootCA.pem", "wb") as f:
       f.write(cert.public_bytes(serialization.Encoding.PEM))
   with open("rootCA_key.pem", "wb") as f:
       f.write(key.private_bytes(
           encoding=serialization.Encoding.PEM,
           format=serialization.PrivateFormat.TraditionalOpenSSL,
           encryption_algorithm=serialization.NoEncryption()
       ))
   print("Root CA generated: rootCA.pem, rootCA_key.pem")


def issue_certificate(ca_cert_path, ca_key_path, common_name):
   # Issue an end-entity certificate signed by the CA
   with open(ca_key_path, "rb") as f:
       ca_key = serialization.load_pem_private_key(f.read(), password=None)
   ca_cert = load_certificate(ca_cert_path)


   key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
   subject = x509.Name([
       x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
       x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Client"),
       x509.NameAttribute(NameOID.COMMON_NAME, common_name),
   ])
   cert = (
       x509.CertificateBuilder()
       .subject_name(subject)
       .issuer_name(ca_cert.subject)
       .public_key(key.public_key())
       .serial_number(x509.random_serial_number())
       .not_valid_before(datetime.datetime.utcnow())
       .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=180))
       .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
       .sign(ca_key, hashes.SHA256()) # type: ignore
   )


   filename = f"{common_name}_cert.pem"
   keyfile = f"{common_name}_key.pem"
   with open(filename, "wb") as f:
       f.write(cert.public_bytes(serialization.Encoding.PEM))
   with open(keyfile, "wb") as f:
       f.write(key.private_bytes(
           encoding=serialization.Encoding.PEM,
           format=serialization.PrivateFormat.TraditionalOpenSSL,
           encryption_algorithm=serialization.NoEncryption()
       ))
   print(f"Issued certificate: {filename}")
   print(f"Private key saved: {keyfile}")


def revoke_certificate(serial_number):
   # Simulate certificate revocation (append to a text-based CRL)
   with open("revoked.txt", "a") as f:
       f.write(str(serial_number) + "\n")
   print("Certificate revoked and added to revoked.txt")


def check_revocation(cert):
   # Simulate revocation check by reading from revoked.txt
   if not os.path.exists("revoked.txt"):
       print("No revocations found.")
       return
   with open("revoked.txt", "r") as f:
       revoked = [line.strip() for line in f.readlines()]
   if str(cert.serial_number) in revoked:
       print("Certificate Status: REVOKED")
   else:
       print("Certificate Status: GOOD")


# D) Menu-Driven Interface


def main_menu():
   while True:
       print("\n=== X.509 Certificate System ===")
       print("1) Parse X.509 Certificate")
       print("2) Verify Certificate Chain")
       print("3) CA Operations (Generate/Issue/Revoke)")
       print("4) Certificate Status Check")
       print("5) Quit")
       choice = input("Enter choice: ")


       if choice == "1":
           path = input("Enter certificate path: ")
           cert = load_certificate(path)
           parse_certificate(cert)
           generate_fingerprint(cert)


       elif choice == "2":
           end_path = input("Enter end-entity certificate path: ")
           issuer_path = input("Enter issuer (CA) certificate path: ")
           end_cert = load_certificate(end_path)
           issuer_cert = load_certificate(issuer_path)
           verify_chain(end_cert, issuer_cert)


       elif choice == "3":
           print("\nCA Operations:")
           print("1) Generate Root CA")
           print("2) Issue New Certificate")
           print("3) Revoke Certificate")
           sub = input("Enter option: ")
           if sub == "1":
               generate_ca()
           elif sub == "2":
               cn = input("Enter common name for new certificate: ")
               issue_certificate("rootCA.pem", "rootCA_key.pem", cn)
           elif sub == "3":
               serial = input("Enter certificate serial number to revoke: ")
               revoke_certificate(serial)
           else:
               print("Invalid option")


       elif choice == "4":
           path = input("Enter certificate path: ")
           cert = load_certificate(path)
           check_revocation(cert)


       elif choice == "5":
           print("Exiting...")
           break
       else:
           print("Invalid choice, try again.")


# Main Entry Point
if __name__ == "__main__":
   main_menu()