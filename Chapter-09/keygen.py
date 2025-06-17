from Crypto.PublicKey import RSA
from datetime import datetime
import os

def generate_rsa_keys(bits=2048, e=65537, save_to_disk=True, output_dir="keys"):
    print(f"[+] Generating {bits}-bit RSA key pair...")
    new_key = RSA.generate(bits, e=e)

    public_key = new_key.publickey().exportKey("PEM")
    private_key = new_key.exportKey("PEM")

    if save_to_disk:
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        pub_path = os.path.join(output_dir, f"rsa_pub_{timestamp}.pem")
        priv_path = os.path.join(output_dir, f"rsa_priv_{timestamp}.pem")

        with open(pub_path, "wb") as f:
            f.write(public_key)
        with open(priv_path, "wb") as f:
            f.write(private_key)

        print(f"[+] Public key saved to: {pub_path}")
        print(f"[+] Private key saved to: {priv_path}")
    else:
        print("----- BEGIN PUBLIC KEY -----")
        print(public_key.decode())
        print("----- END PUBLIC KEY -----\n")

        print("----- BEGIN PRIVATE KEY -----")
        print(private_key.decode())
        print("----- END PRIVATE KEY -----")

    return public_key, private_key

if __name__ == "__main__":
    generate_rsa_keys()
