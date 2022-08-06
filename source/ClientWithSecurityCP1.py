import pathlib
import socket
import sys
import time
from datetime import datetime
import secrets
import traceback

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


def read_bytes(socket, length):
    """
    Reads the specified length of bytes from the given socket and returns a bytestring
    """
    buffer = []
    bytes_received = 0
    while bytes_received < length:
        data = socket.recv(min(length - bytes_received, 1024))
        if not data:
            raise Exception("Socket connection broken")
        buffer.append(data)
        bytes_received += len(data)

    return b"".join(buffer)


def convert_int_to_bytes(x):
    """
    Convenience function to convert Python integers to a length-8 byte representation
    """
    return x.to_bytes(8, "big")


def convert_bytes_to_int(xbytes):
    """
    Convenience function to convert byte value to integer value
    """
    return int.from_bytes(xbytes, "big")


def main(args):
    port = int(args[0]) if len(args) > 0 else 4321
    server_address = args[1] if len(args) > 1 else "localhost"
    address = args[1] if len(args) > 1 else "localhost"

    start_time = time.time()

    ###########################################################################

    # try:
    print("Establishing connection to server...")

    # Connect to server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_address, port))
        print("Connected")
        
        # authentication message
        nonce = secrets.token_urlsafe()

        # authentication message bytes
        auth_msg_bytes = bytes(nonce, encoding="utf8")

        while True:
            ######################## Send mode 3 to check ##########################

            # Send mode 3
            s.sendall(convert_int_to_bytes(3))
            # Send M1
            s.sendall(convert_int_to_bytes(len(auth_msg_bytes)))
            # Send M2
            s.sendall(auth_msg_bytes)

            ######################### CHECK SERVER ID ##############################

            firstM1 = s.recv(4096)  # size of incoming M2 in bytes
            firstM2 = s.recv(4096)  # signed authentication message

            # size of incoming M2 in bytes (this is server_signed.crt)
            secondM1 = s.recv(4096)
            secondM2 = s.recv(4096)  # server_signed.crt

            # Verify the signed certificate sent by the Server using ca’s public key ( from cacsertificate.crt )
            print("Verification of server cert start...")
            try:
                f = open("auth/cacsertificate.crt", "rb")
                ca_cert_raw = f.read()
                ca_cert = x509.load_pem_x509_certificate(
                    data=ca_cert_raw, backend=default_backend()
                )
                ca_public_key = ca_cert.public_key()
                server_cert = x509.load_pem_x509_certificate(
                    data=secondM2, backend=default_backend()
                )
                ca_public_key.verify(
                    signature=server_cert.signature,
                    data=server_cert.tbs_certificate_bytes,
                    padding=padding.PKCS1v15(),
                    algorithm=server_cert.signature_hash_algorithm,
                )
            except Exception as e:
                print("Connection will now close due to failed check 1")
                print(e)
                s.sendall(convert_int_to_bytes(2))
                break

            print("Verification of server cert valid")

            # Extraction of server public key
            try:
                with open("auth/server_private_key.pem", mode="r", encoding="utf8") as key_file:
                    private_key = serialization.load_pem_private_key(
                        bytes(key_file.read(), encoding="utf8"), password=None
                    )
            except Exception as e:
                print("Connection will now close due to failed check 2")
                print(e)
                s.sendall(convert_int_to_bytes(2))
                break

            public_key = private_key.public_key()

            # Verify signed authentication message
            print("Verifying Authentication Message...")
            try:
                public_key.verify(
                    firstM2,
                    auth_msg_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
            except Exception as e:
                print("Connection will now close due to failed check 3")
                print(e)
                s.sendall(convert_int_to_bytes(2))
                break

            print("Verified")

            # Check server cert valid or not
            print("Server Cert valid?")
            try:
                assert server_cert.not_valid_before <= datetime.utcnow() <= server_cert.not_valid_after
            except Exception as e:
                print("Connection will now close due to failed check 4")
                print(e)
                s.sendall(convert_int_to_bytes(2))
                break

            print("Server Cert is valid.")

            #######################################################################

            filename = input("Enter a filename to send (enter -1 to exit):")

            while filename != "-1" and (not pathlib.Path(filename).is_file()):
                filename = input("Invalid filename. Please try again:")

            if filename == "-1":
                s.sendall(convert_int_to_bytes(2))
                break

            # number of bytes of filename
            filename_bytes = bytes(filename, encoding="utf8")

            # Send the filename
            s.sendall(convert_int_to_bytes(0))
            s.sendall(convert_int_to_bytes(len(filename_bytes)))
            s.sendall(filename_bytes)

            # Send the file
            with open(filename, mode="rb") as fp:
                #This is already in bytestring
                data = fp.read()

                if len(data) < 60:
                    encrypted_data = public_key.encrypt(
                        data,
                        padding.OAEP(
                            mgf=padding.MGF1(hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None,
                        ),
                    )

                    filename = "enc_" + filename.split("/")[-1]
                    with open(
                        f"send_files_enc/{filename}", mode="wb"
                    ) as fp:
                        fp.write(encrypted_data)

                    s.sendall(convert_int_to_bytes(1))
                    s.sendall(convert_int_to_bytes(len(encrypted_data)))
                    s.sendall(encrypted_data)
                else:
                    n = 60
                    split_data = [data[i:i+n] for i in range(0, len(data), n)]

                    to_send = b''

                    for i in split_data:
                        encrypted_data = public_key.encrypt(
                            i,
                            padding.OAEP(
                                mgf=padding.MGF1(hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None,
                            ),
                        )
                        to_send += encrypted_data

                    filename = "enc_" + filename.split("/")[-1]
                    with open(
                        f"send_files_enc/{filename}", mode="wb"
                    ) as fp:
                        fp.write(to_send)

                    s.sendall(convert_int_to_bytes(1))
                    s.sendall(convert_int_to_bytes(len(to_send)))
                    s.sendall(to_send)

    end_time = time.time()
    print(f"Program took {end_time - start_time}s to run.")


if __name__ == "__main__":
    main(sys.argv[1:])
