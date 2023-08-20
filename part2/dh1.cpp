#include <iostream>
#include <openssl/dh.h>
#include <openssl/pem.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/evp.h>
 #include <openssl/rsa.h>
#include <iostream>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/bn.h>
using namespace std;
void performKeyExchange(int clientSocket, DH* dh);

void generateAndSendDHParams(int clientSocket) {
    cout<<"generateAndSendDHParams";
    DH *dh = DH_new();
    if (!dh) {
        std::cerr << "Error creating DH parameters" << std::endl;
        return;
    }

    // Generate 2048-bit DH parameters
    if (DH_generate_parameters_ex(dh, 2048, DH_GENERATOR_2, nullptr) != 1) {
        std::cerr << "Error generating DH parameters" << std::endl;
        DH_free(dh);
        return;
    }

    // Convert DH parameters to a buffer
    BIO *bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_DHparams(bio, dh)) {
        std::cerr << "Error writing DH parameters to BIO" << std::endl;
        DH_free(dh);
        BIO_free(bio);
        return;
    }

    // Read the buffer and send it to the client
    char *buf;
    long len = BIO_get_mem_data(bio, &buf);
    send(clientSocket, buf, len, 0);
     if (!DH_generate_key(dh)) {
        // handleErrors();
        cout<<"error";
        return;
    }

     performKeyExchange(clientSocket, dh);

    // Clean up
    DH_free(dh);
    BIO_free(bio);
}

unsigned char* generateSharedSecret(DH* dh, BIGNUM* peer_pub_key) {
     cout<<"generateSharedSecret";
    unsigned char* secret;
    secret = (unsigned char*)malloc(DH_size(dh));
    if (!secret) {
        // handleErrors();
    }

    if (DH_compute_key(secret, peer_pub_key, dh) == -1) {
        // handleErrors();
    }

    return secret;
}

void performKeyExchange(int clientSocket, DH* dh) {
    // Send public key to the client

    cout<<"performKeyExchange";

    const BIGNUM* pub_key = DH_get0_pub_key(reinterpret_cast<const DH*>(dh));
    int pub_key_len = BN_num_bytes(pub_key);
    send(clientSocket, &pub_key_len, sizeof(pub_key_len), 0);
    unsigned char* pub_key_bin = (unsigned char*)malloc(pub_key_len);
    BN_bn2bin(pub_key, pub_key_bin);
    send(clientSocket, pub_key_bin, pub_key_len, 0);

    // Receive client's public key
    int peer_pub_key_len;
    recv(clientSocket, &peer_pub_key_len, sizeof(peer_pub_key_len), 0);
    unsigned char* peer_pub_key_bin = (unsigned char*)malloc(peer_pub_key_len);
    recv(clientSocket, peer_pub_key_bin, peer_pub_key_len, 0);
    BIGNUM* peer_pub_key = BN_bin2bn(peer_pub_key_bin, peer_pub_key_len, nullptr);



    // Generate shared secret
    unsigned char* shared_secret = generateSharedSecret(dh, peer_pub_key);

    cout<<endl;
    for(int i=0;i<DH_size(dh);i++)
    {
        cout<<hex<<(int)shared_secret[i];
    }

    

    // Use shared secret for encryption (OpenSSL envelope functions)
//     EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
//     EVP_CIPHER_CTX_init(ctx);
//     EVP_CIPHER_CTX_set_padding(ctx, 1);

//     const EVP_CIPHER* cipher = EVP_aes_256_cbc();
//     unsigned char iv[EVP_MAX_IV_LENGTH];
//     RAND_bytes(iv, EVP_MAX_IV_LENGTH);

//     if (EVP_EncryptInit_ex(ctx, cipher, nullptr, shared_secret, iv) != 1) {
//         // handleErrors();
//     }

//     // Your encryption and decryption logic using ctx

//     // Clean up
//     EVP_CIPHER_CTX_free(ctx);
//     free(peer_pub_key_bin);
//     free(shared_secret);
}

// Function to generate Diffie-Hellman parameters and send them to the client over a socket
// void generateAndSendDHParams(int clientSocket) {
//     DH *dh = DH_new();
//     if (!dh) {
//         std::cerr << "Error creating DH parameters" << std::endl;
//         return;
//     }

//     // Generate 2048-bit DH parameters
//     if (DH_generate_parameters_ex(dh, 2048, DH_GENERATOR_2, nullptr) != 1) {
//         std::cerr << "Error generating DH parameters" << std::endl;
//         DH_free(dh);
//         return;
//     }

//     // Send DH parameters to the client
//     if (PEM_write_DHparams_fd(clientSocket, dh) != 1) {
//         std::cerr << "Error sending DH parameters to the client" << std::endl;
//         DH_free(dh);
//         return;
//     }

//     // Clean up
//     DH_free(dh);
// }

// Function to receive DH parameters from the server over a socket and load them
void receiveAndLoadDHParams(int serverSocket) {
    // Receive DH parameters from the server
    char buffer[4096]; // Adjust the size based on your requirements
    ssize_t bytesRead = recv(serverSocket, buffer, sizeof(buffer), 0);
    if (bytesRead <= 0) {
        std::cerr << "Error receiving DH parameters from the server" << std::endl;
        return;
    }

    // Create a BIO and write the received buffer to it
    BIO *bio = BIO_new(BIO_s_mem());
    BIO_write(bio, buffer, bytesRead);

    // Read DH parameters from the BIO
    DH *dh = PEM_read_bio_DHparams(bio, nullptr, nullptr, nullptr);


    if (!DH_generate_key(dh)) {
        // handleErrors();
        cout<<"error";
        return;
    }

    performKeyExchange(serverSocket, dh);
    // At this point, 'dh' contains the received DH parameters.

    // Clean up
    DH_free(dh);
    BIO_free(bio);
}

int main() {
    const int PORT = 5554;

    // Server code
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        std::cerr << "Error creating server socket" << std::endl;
        return 1;
    }

    int opt = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        std::cerr << "Failed to set socket options\n";
        return 1;
    }

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(PORT);

    if (bind(serverSocket, reinterpret_cast<struct sockaddr*>(&serverAddr), sizeof(serverAddr)) == -1) {
        std::cerr << "Error binding server socket" << std::endl;
        close(serverSocket);
        return 1;
    }

    if (listen(serverSocket, 1) == -1) {
        std::cerr << "Error listening on server socket" << std::endl;
        close(serverSocket);
        return 1;
    }

    std::cout << "Server waiting for connection..." << std::endl;

    int clientSocket = accept(serverSocket, nullptr, nullptr);
    if (clientSocket == -1) {
        std::cerr << "Error accepting client connection" << std::endl;
        close(serverSocket);
        return 1;
    }

    std::cout << "Client connected!" << std::endl;

    // Generate and send DH parameters from the server
    generateAndSendDHParams(clientSocket);

    // Client code
  
    return 0;
}
