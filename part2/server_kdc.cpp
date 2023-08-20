#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <vector>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <random>
#include <arpa/inet.h>
#include <unistd.h>
#include <iostream>
#include <unistd.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <arpa/inet.h>
#include <random>
#include <memory>
#include <stdexcept>
#include <vector>

#include <cassert>
#include <sstream>
#include <iostream>
#include <fstream>
#include <cstring>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <chrono>
#include <thread>

#include <iostream>
#include <string>
#include <memory>
#include <limits>
#include <stdexcept>

#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;



static const size_t KEY_SIZE = 256 / 8, BLOCK_SIZE = 128 / 8;

class AESBase {
protected:
    const uint8_t *key, *iv;
    EVP_CIPHER_CTX *ctx;
    AESBase(const uint8_t *key, const uint8_t *iv) : key(key), iv(iv) {
        if (!(ctx = EVP_CIPHER_CTX_new()))
            handleErrors();
    }
    ~AESBase() {
        EVP_CIPHER_CTX_free(ctx);
    }
    static void handleErrors(void) {
        ERR_print_errors_fp(stderr);
        abort();
    }
};

class Encrypt : AESBase {
public:
    Encrypt(const uint8_t *key, const uint8_t *iv) : AESBase(key, iv) {
        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
            handleErrors();
    }
    int update(const char *plaintext, int plaintext_len, char *ciphertext) {
        int len;
        if (1 != EVP_EncryptUpdate(ctx, (uint8_t*)ciphertext, &len, (const uint8_t*)plaintext, plaintext_len))
            handleErrors();
        return len;
    }
    int final(char *ciphertext) {
        int len;
        if (1 != EVP_EncryptFinal_ex(ctx, (uint8_t*)ciphertext, &len))
            handleErrors();
        return len;
    }
};

class Decrypt : AESBase {
public:
    Decrypt(const uint8_t *key, const uint8_t *iv) : AESBase(key, iv) {
        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
            handleErrors();
    }
    int update(const char *ciphertext, int ciphertext_len, char *plaintext) {
        int len;
        if (1 != EVP_DecryptUpdate(ctx, (uint8_t*)plaintext, &len, (const uint8_t*)ciphertext, ciphertext_len))
            handleErrors();
        return len;
    }
    int final(char *plaintext) {
        int len;
        if (1 != EVP_DecryptFinal_ex(ctx, (uint8_t*)plaintext, &len))
            handleErrors();
        return len;
    }
};

class Server {
    public:
    unsigned char keyAS[32], keyBS[32];
    bool logs;

    void handleErrors(void){
        ERR_print_errors_fp(stderr);
        abort();
    }
    std::string base64Encode(const unsigned char* buffer, size_t length) {   
        unsigned char* encodedData = new  unsigned char[EVP_ENCODE_LENGTH(length)];
        int encodedDataLength;
        encodedDataLength = EVP_EncodeBlock(encodedData, (const unsigned char*)buffer, length);
        std::string encoded(reinterpret_cast<char*>(encodedData), encodedDataLength);
        return encoded;

    }



static const unsigned int KEY_SIZE = 32;
static const unsigned int BLOCK_SIZE = 16;

template <typename T>
struct zallocator
{
public:
    typedef T value_type;
    typedef value_type* pointer;
    typedef const value_type* const_pointer;
    typedef value_type& reference;
    typedef const value_type& const_reference;
    typedef std::size_t size_type;
    typedef std::ptrdiff_t difference_type;

    pointer address (reference v) const {return &v;}
    const_pointer address (const_reference v) const {return &v;}

    pointer allocate (size_type n, const void* hint = 0) {
        if (n > std::numeric_limits<size_type>::max() / sizeof(T))
            throw std::bad_alloc();
        return static_cast<pointer> (::operator new (n * sizeof (value_type)));
    }

    void deallocate(pointer p, size_type n) {
        OPENSSL_cleanse(p, n*sizeof(T));
        ::operator delete(p); 
    }
    
    size_type max_size() const {
        return std::numeric_limits<size_type>::max() / sizeof (T);
    }
    
    template<typename U>
    struct rebind
    {
        typedef zallocator<U> other;
    };

    void construct (pointer ptr, const T& val) {
        new (static_cast<T*>(ptr) ) T (val);
    }

    void destroy(pointer ptr) {
        static_cast<T*>(ptr)->~T();
    }

#if __cpluplus >= 201103L
    template<typename U, typename... Args>
    void construct (U* ptr, Args&&  ... args) {
        ::new (static_cast<void*> (ptr) ) U (std::forward<Args> (args)...);
    }

    template<typename U>
    void destroy(U* ptr) {
        ptr->~U();
    }
#endif
};

typedef unsigned char byte;
typedef std::basic_string<char, std::char_traits<char>, zallocator<char> > secure_string;
using EVP_CIPHER_CTX_free_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;

// void gen_params(byte key[KEY_SIZE], byte iv[BLOCK_SIZE]);
// void aes_encrypt(const byte key[KEY_SIZE], const byte iv[BLOCK_SIZE], const secure_string& ptext, secure_string& ctext);
// void aes_decrypt(const byte key[KEY_SIZE], const byte iv[BLOCK_SIZE], const secure_string& ctext, secure_string& rtext);

// g++ -Wall -std=c++11 evp-encrypt.cxx -o evp-encrypt.exe -lcrypto

// void gen_params(byte key[KEY_SIZE], byte iv[BLOCK_SIZE])
// {
//     int rc = RAND_bytes(key, KEY_SIZE);
//     if (rc != 1)
//       throw std::runtime_error("RAND_bytes key failed");

//     rc = RAND_bytes(iv, BLOCK_SIZE);
//     if (rc != 1)
//       throw std::runtime_error("RAND_bytes for iv failed");
// }

void aes_encrypt(const byte key[KEY_SIZE], const byte iv[BLOCK_SIZE], const secure_string& ptext, secure_string& ctext)
{
    EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    int rc = EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), NULL, key, iv);
    if (rc != 1)
      throw std::runtime_error("EVP_EncryptInit_ex failed");

    // Recovered text expands upto BLOCK_SIZE
    ctext.resize(ptext.size()+BLOCK_SIZE);
    int out_len1 = (int)ctext.size();

    rc = EVP_EncryptUpdate(ctx.get(), (byte*)&ctext[0], &out_len1, (const byte*)&ptext[0], (int)ptext.size());
    if (rc != 1)
      throw std::runtime_error("EVP_EncryptUpdate failed");
  
    int out_len2 = (int)ctext.size() - out_len1;
    rc = EVP_EncryptFinal_ex(ctx.get(), (byte*)&ctext[0]+out_len1, &out_len2);
    if (rc != 1)
      throw std::runtime_error("EVP_EncryptFinal_ex failed");

    // Set cipher text size now that we know it
    ctext.resize(out_len1 + out_len2);
}

void aes_decrypt(const byte key[KEY_SIZE], const byte iv[BLOCK_SIZE], const secure_string& ctext, secure_string& rtext)
{
    EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    int rc = EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), NULL, key, iv);
    if (rc != 1)
      throw std::runtime_error("EVP_DecryptInit_ex failed");

    // Recovered text contracts upto BLOCK_SIZE
    rtext.resize(ctext.size());
    int out_len1 = (int)rtext.size();

    rc = EVP_DecryptUpdate(ctx.get(), (byte*)&rtext[0], &out_len1, (const byte*)&ctext[0], (int)ctext.size());
    if (rc != 1)
      throw std::runtime_error("EVP_DecryptUpdate failed");
  
    int out_len2 = (int)rtext.size() - out_len1;
    rc = EVP_DecryptFinal_ex(ctx.get(), (byte*)&rtext[0]+out_len1, &out_len2);
    if (rc != 1)
      throw std::runtime_error("EVP_DecryptFinal_ex failed");

    // Set recovered text size now that we know it
    rtext.resize(out_len1 + out_len2);
}




    int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            const unsigned char *iv, unsigned char *plaintext){
        EVP_CIPHER_CTX *ctx;

        int len;

        int plaintext_len;

        /* Create and initialise the context */
        if(!(ctx = EVP_CIPHER_CTX_new()))
            handleErrors();

        /*
        * Initialise the decryption operation. IMPORTANT - ensure you use a key
        * and IV size appropriate for your cipher
        * In this example we are using 256 bit AES (i.e. a 256 bit key). The
        * IV size for *most* modes is the same as the block size. For AES this
        * is 128 bits
        */
        if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
            handleErrors();

        /*
        * Provide the message to be decrypted, and obtain the plaintext output.
        * EVP_DecryptUpdate can be called multiple times if necessary.
        */
        if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
            handleErrors();
        plaintext_len = len;

        /*
        * Finalise the decryption. Further plaintext bytes may be written at
        * this stage.
        */
        if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
            handleErrors();
        plaintext_len += len;

        /* Clean up */
        EVP_CIPHER_CTX_free(ctx);

        return plaintext_len;
    }


    int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext){
        EVP_CIPHER_CTX *ctx;

        int len;

        int ciphertext_len;

        /* Create and initialise the context */
        if(!(ctx = EVP_CIPHER_CTX_new()))
            handleErrors();

        /*
        * Initialise the encryption operation. IMPORTANT - ensure you use a key
        * and IV size appropriate for your cipher
        * In this example we are using 256 bit AES (i.e. a 256 bit key). The
        * IV size for *most* modes is the same as the block size. For AES this
        * is 128 bits
        */
        if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
            handleErrors();

        /*
        * Provide the message to be encrypted, and obtain the encrypted output.
        * EVP_EncryptUpdate can be called multiple times if necessary
        */
        if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
            handleErrors();
        ciphertext_len = len;

        /*
        * Finalise the encryption. Further ciphertext bytes may be written at
        * this stage.
        */
        if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
            handleErrors();
        ciphertext_len += len;

        /* Clean up */
        EVP_CIPHER_CTX_free(ctx);

        return ciphertext_len;
    }

    auto EncodeBase64(auto& to_encode) -> std::string {
  /// @sa https://www.openssl.org/docs/manmaster/man3/EVP_EncodeBlock.html

        const auto predicted_len = 4 * ((to_encode.length() + 2) / 3);  // predict output size

        const auto output_buffer{std::make_unique<char[]>(predicted_len + 1)};

        const std::vector<unsigned char> vec_chars{to_encode.begin(), to_encode.end()};  // convert to_encode into uchar container

        const auto output_len = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(output_buffer.get()), vec_chars.data(), static_cast<int>(vec_chars.size()));

        if (predicted_len != static_cast<unsigned long>(output_len)) {
            throw std::runtime_error("EncodeBase64 error");
        }

        return output_buffer.get();
    }

    auto DecodeBase64(auto& to_decode) -> std::string {
        /// @sa https://www.openssl.org/docs/manmaster/man3/EVP_DecodeBlock.html

        const auto predicted_len = 3 * to_decode.length() / 4;  // predict output size

        const auto output_buffer{std::make_unique<char[]>(predicted_len + 1)};

        const std::vector<unsigned char> vec_chars{to_decode.begin(), to_decode.end()};  // convert to_decode into uchar container

        const auto output_len = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(output_buffer.get()), vec_chars.data(), static_cast<int>(vec_chars.size()));

        if (predicted_len != static_cast<unsigned long>(output_len)) {
            throw std::runtime_error("DecodeBase64 error");
        }

        return output_buffer.get();
    }

    std::vector<std::string> encrypt_sk(const std::string& keyAB, const std::string& Na, const std::string& Nb) {
        unsigned char iv[16];
        RAND_bytes(iv, sizeof(iv));
        std::string ivStr(reinterpret_cast<char*>(iv), sizeof(iv));
        std::string encodedIv = EncodeBase64(ivStr);
        
        std::cout << "IV: " << encodedIv << "\n";


        if(logs){
            for(int i = 0 ; i< 16; i++){
                cout<<hex<<(int)iv[i]<<" ";
            }
            cout<<endl;
        }

        // Assuming that keyAS and keyBS are defined somewhere else
        // unsigned char keyAS[32], keyBS[32];

        // EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        // EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, keyAS, iv);

        string p = keyAB + " B " + Na;

        secure_string plaintext(p.c_str());
        cout<<plaintext<<endl;
        // unsigned char* ciphertext = new unsigned char[plaintext.size() + 16];
        secure_string ciphertext;
        // int len;

        // Encrypt aes(keyAS, iv);
        aes_encrypt(keyAS, iv, plaintext, ciphertext);
        // int cipherlen = aes.update(plaintext.c_str(), plaintext.size(), reinterpret_cast<char*>(ciphertext));  
        // cipherlen += aes.final(reinterpret_cast<char*>(ciphertext));
        // fout.write((char*)iv, sizeof(iv));
        
        // int cipherlen = encrypt(reinterpret_cast<unsigned char*>(const_cast<char*>(plaintext.c_str())), plaintext.size(), keyAS, iv, ciphertext);

        if(logs){
            cout<<"cipher1 length:" <<ciphertext.size()<<endl;
            for(int i=0;i<ciphertext.size();i++){
                cout<<hex<<(int)ciphertext[i]<<" ";
            }
            cout<<endl;
        }

        // ciphertext[cipherlen] = '\0';
        string p2 = keyAB + " A " + Nb;
        secure_string plaintext1(p2.c_str());
        // unsigned char* ciphertext1 = new unsigned char[plaintext1.size() + 16];
        // int len;

        secure_string ciphertext1;
        aes_encrypt(keyBS, iv, plaintext1, ciphertext1);
        // Encrypt aes1(keyBS, iv);
        // int cipherlen1 = aes1.update(plaintext1.c_str(), plaintext1.size(), reinterpret_cast<char*>(ciphertext1));  
        // cipherlen1 += aes1.final(reinterpret_cast<char*>(ciphertext1));


        // int cipherlen1 = encrypt(reinterpret_cast<unsigned char*>(const_cast<char*>(plaintext1.c_str())), plaintext1.size(), keyBS, iv, ciphertext1);
        // ciphertext1[cipherlen1] = '\0';

        if(logs){
            cout<<"cipher2 length:" <<ciphertext1.size()<<endl;
            //  for(int i=0;i<ciphertext1.size();i++){
            //     cout<<hex<<(int)ciphertext1[i]<<" ";
            // }
            // cout<<endl;
        }

        
        // std::string encodedCiphertext2(reinterpret_cast< char*>(ciphertext1), cipherlen1);
        // std::string encodedCiphertext1(reinterpret_cast< char*>(ciphertext), cipherlen);
        // if(logs){
        //     cout<<"encodedCiphertext1 length:" <<encodedCiphertext1.size()<<endl;
        //     cout<<"encodedCiphertext2 length:" <<encodedCiphertext2.size()<<endl;

        //     for(int i=0;i<encodedCiphertext1.size();i++){
        //         cout<<hex<<(int)encodedCiphertext1[i]<<" ";
        //     }
        // }

        std::string encodedCiphertext2(ciphertext1.data(), ciphertext1.size());
        std::string encodedCiphertext1(ciphertext.data(), ciphertext.size());
        
        encodedCiphertext1 = EncodeBase64(encodedCiphertext1);
        encodedCiphertext2 = EncodeBase64(encodedCiphertext2);
        
        if(logs){
            cout<<"encodedCiphertext1 length:" <<encodedCiphertext1.size()<<endl;
            cout<<"encodedCiphertext2 length:" <<encodedCiphertext2.size()<<endl;
        }



        return {encodedIv, encodedCiphertext1, encodedCiphertext2};
    }
    void respond(const std::vector<std::string>& message) {
        std::string keyAB = generate_keyAB();
        std::vector<std::string> ct = encrypt_sk(keyAB, message[2], message[3]);

        int socketA = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in addressA;
        addressA.sin_family = AF_INET;
        addressA.sin_port = htons(1027);
        inet_pton(AF_INET, "127.0.0.1", &(addressA.sin_addr));

        connect(socketA, (struct sockaddr *)&addressA, sizeof(addressA));
        std::cout << "Sending ciphertext (S->A): " << ct[0]<<" " << ct[1]<<" " << ct[2] << "\n";
        uint32_t sizeCt = htonl(ct.size());
        // write(socketA, reinterpret_cast<const void*>((int)ct.size()), sizeof(int));
        write(socketA, &sizeCt, sizeof(sizeCt));
        for (const auto& line : ct) {
            // std::this_thread::sleep_for(std::chrono::milliseconds(100));
            if(logs){
                cout<<"line "<<line.size()<<endl;
                // cout<<"size1 "<<size1<<endl;
            }
            uint32_t sizeLine = htonl(line.size());
            write(socketA, &sizeLine, sizeof(sizeLine));
            // write(socketA, reinterpret_cast<const void*>((int)line.size()), sizeof(int));
            write(socketA, line.c_str(), line.size());
        }
        close(socketA);
    }
    void listenAndRespond() {
        int server_socket = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in server_address;
        server_address.sin_family = AF_INET;
        server_address.sin_port = htons(1025);
        server_address.sin_addr.s_addr = INADDR_ANY;

        bind(server_socket, (struct sockaddr*)&server_address, sizeof(server_address));
        listen(server_socket, 5);

        sockaddr_in client_address;
        socklen_t client_len = sizeof(client_address);
        int client_socket = accept(server_socket, (struct sockaddr*)&client_address, &client_len);

        std::vector<std::string> message(4);
        for (int i = 0; i < 4; i++) {
            char buffer[1024] = {0};
            uint32_t sizeNet;
            // read(socketB, &sizeNet, sizeof(sizeNet));
            read(client_socket, &sizeNet, sizeof(sizeNet));
            uint32_t size = ntohl(sizeNet);
            ssize_t bytes_received = recv(client_socket, buffer, size, 0);
            if (bytes_received <= 0) {
                break;
            }
            message[i] = std::string(buffer, bytes_received);
        }

        std::cout << "Message received (A->S): " << message[0] << " " << message[1] << " " << message[2] << " " << message[3] << "\n";

        close(client_socket);

        // Call the respond function here with the received message
        respond(message);
    }

    // std::string base64Encode(const unsigned char* buffer, size_t length) {
    //     BIO *bio, *b64;
    //     BUF_MEM *bufferPtr;

    //     b64 = BIO_new(BIO_f_base64());
    //     bio = BIO_new(BIO_s_mem());
    //     bio = BIO_push(b64, bio);

    //     BIO_write(bio, buffer, length);
    //     BIO_flush(bio);
    //     BIO_get_mem_ptr(bio, &bufferPtr);
    //     BIO_set_close(bio, BIO_NOCLOSE);
    //     BIO_free_all(bio);

    //     std::string encoded(bufferPtr->data, bufferPtr->length);
    //     BUF_MEM_free(bufferPtr);
    //     return encoded;
    // }

    void sendKeys() {
        
        RAND_bytes(keyAS, sizeof(keyAS));
        RAND_bytes(keyBS, sizeof(keyBS));

        // Send key to A
        int socketA = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in addressA;
        addressA.sin_family = AF_INET;
        addressA.sin_port = htons(8000);
        inet_pton(AF_INET, "127.0.0.1", &(addressA.sin_addr));
        connect(socketA, (struct sockaddr *)&addressA, sizeof(addressA));
        std::string encodedKeyAS(reinterpret_cast<char*>(keyAS), sizeof(keyAS));
        encodedKeyAS = EncodeBase64(encodedKeyAS);
        uint32_t sizeAS = htonl(encodedKeyAS.size());
        write(socketA, &sizeAS, sizeof(sizeAS));
        // write(socketA, reinterpret_cast<const void*>((int)encodedKeyAS.size()), sizeof(int));
        write(socketA, encodedKeyAS.c_str(), encodedKeyAS.size());
        cout<<"Sending key to A"<<endl;

        close(socketA);

        if (logs) {
            std::cout << "Sending key AS: " << encodedKeyAS << "\n";
            for (int i = 0; i < 32; i++) {
                std::cout << std::hex << (int)keyAS[i] << " ";
            }
            cout<<endl;
        }

        // Send key to B
        int socketB = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in addressB;
        addressB.sin_family = AF_INET;
        addressB.sin_port = htons(8001);
        inet_pton(AF_INET, "127.0.0.1", &(addressB.sin_addr));

        connect(socketB, (struct sockaddr *)&addressB, sizeof(addressB));
        std::string encodedKeyBS = base64Encode(keyBS, sizeof(keyBS));
        uint32_t sizeBS = htonl(encodedKeyBS.size());
        write(socketB, &sizeBS, sizeof(uint32_t));
        write(socketB, encodedKeyBS.c_str(), encodedKeyBS.size());
        close(socketB);

        if (logs) {
            std::cout << "Sending key BS: " << encodedKeyBS << "\n";
        }
    }

    std::string generateSecretKey() {
        unsigned char key[32];
        RAND_bytes(key, sizeof(key));
        return std::string(reinterpret_cast<char*>(key), sizeof(key));
    }

    std::string SecretKeyAS() {
        return generateSecretKey();
    }

    std::string SecretKeyBS() {
        return generateSecretKey();
    }
 

    std::string generate_keyAB() {
        unsigned char key[16];
        RAND_bytes(key, sizeof(key));

        BIO* b64 = BIO_new(BIO_f_base64());
        BIO* bmem = BIO_new(BIO_s_mem());
        b64 = BIO_push(b64, bmem);
        BIO_write(b64, key, sizeof(key));
        BIO_flush(b64);

        BUF_MEM* bptr;
        BIO_get_mem_ptr(b64, &bptr);

        std::string keyAB(bptr->data, bptr->length - 1); // -1 to remove the newline added by BIO_f_base64

        BIO_free_all(b64);

        return keyAB;
    }
};

int main() {
    // Create a Server object
    Server S; // Assuming Server is defined somewhere else

    // Read user input
    std::string log_choice;
    std::cout << "Logs? (true/false) ";
    // std::getline(std::cin, log_choice);

    // Set logs
    // bool logs = (log_choice == "false") ? false : true;

    // Call methods of Server
    S.sendKeys(); // Assuming sendkeys is defined somewhere else
    S.listenAndRespond(); // Assuming listen is defined somewhere else
    // std::string keyAB = S.generate_keyAB();
    // std::random_device rd;
    // std::mt19937 gen(rd());
    // string Na = std::to_string(gen()); // Assuming Na is defined somewhere else
    // string Nb = std::to_string(gen());
    // RAND_bytes(S.keyAS, sizeof(S.keyAS));
    // RAND_bytes(S.keyBS, sizeof(S.keyBS));
    //  std::vector<std::string> ct=  S.encrypt_sk(keyAB, Na, Nb); // Assuming encrypt_sk is defined somewhere else
    // std::cout << "Sending ciphertext (S->A): " << ct[0] << ct[1] << ct[2] << "\n";
    

    return 0;
}