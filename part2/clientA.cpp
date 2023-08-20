#include <iostream>
#include <string>
#include <vector>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/aes.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>


#include <arpa/inet.h>
#include <random>

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
#include <memory>
#include <stdexcept>
#include <vector>

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


// static const size_t KEY_SIZE = 256 / 8, BLOCK_SIZE = 128 / 8;


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

class Client {
    public:
    string clientname;
    string keyAB;
    string Na, Nb;
    string serverkey;
    bool logs = true;

    void handleErrors(void){
        cout<<"Error"<<endl;
        ERR_print_errors_fp(stderr);
        abort();
    }
    std::string base64Encode(const unsigned char* buffer, size_t length) {
        BIO *bio, *b64;
        BUF_MEM *bufferPtr;

        b64 = BIO_new(BIO_f_base64());
        bio = BIO_new(BIO_s_mem());
        bio = BIO_push(b64, bio);

        BIO_write(bio, buffer, length);
        BIO_flush(bio);
        BIO_get_mem_ptr(bio, &bufferPtr);
        BIO_set_close(bio, BIO_NOCLOSE);
        BIO_free_all(bio);

        std::string encoded(bufferPtr->data, bufferPtr->length);
        BUF_MEM_free(bufferPtr);
        return encoded;
    }

    




    void getServerKey(string client) {
        int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in serverAddress{};
        serverAddress.sin_family = AF_INET;
        serverAddress.sin_port = htons((client == "A") ? 8000 : 8001);
        serverAddress.sin_addr.s_addr = INADDR_ANY;

        bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress));
        listen(serverSocket, 1);

        int clientSocket = accept(serverSocket, NULL, NULL);

        

        uint32_t sizeNet;
        read(clientSocket, &sizeNet, sizeof(sizeNet));
        uint32_t size = ntohl(sizeNet);
        char* buffer = new char[size+1];

        read(clientSocket, buffer, size);
        std::string key(buffer,size);

        if (logs) { // Assuming logs is defined somewhere else
            cout<<"size "<<size<<endl;
            std::cout << "serverkey: " << key << "\n";
        }

        std::string keyb = DecodeBase64(key);
        // Assuming serverkey is defined somewhere else

        // std::string str = "serverkey";
        unsigned char* uchar_ptr = reinterpret_cast<unsigned char*>(const_cast<char*>(keyb.c_str()));
        serverkey = keyb;
        cout<<"serverkey"<<endl;
         for (int i = 0; i < keyb.size(); i++) {
            std::cout << std::hex << (int)uchar_ptr[i] << " ";
        }
        cout<<endl;



        close(clientSocket);
        close(serverSocket);
    }


    std::string base64Decode(const std::string& encoded) {
        BIO *bio, *b64;
        size_t decodeLen = encoded.size();
        std::vector<unsigned char> decoded(decodeLen);

        bio = BIO_new_mem_buf(encoded.data(), -1);
        b64 = BIO_new(BIO_f_base64());
        bio = BIO_push(b64, bio);

        decodeLen = BIO_read(bio, decoded.data(), encoded.size());
        decoded.resize(decodeLen);

        BIO_free_all(bio);

        return std::string(reinterpret_cast<char*>(decoded.data()), decodeLen);
    }

    string decode64(const std::string& encoded) {
        const char *input = encoded.c_str();
        const auto length = encoded.size();
        const auto pl = 3*length/4;
        unsigned char *output = new unsigned char[length];
        // auto output = reinterpret_cast<unsigned char *>(calloc(length, 1));
        auto ol = EVP_DecodeBlock(output, reinterpret_cast<const unsigned char *>(input), length);


        if(logs){
            cout<<"length "<<length<<endl;
            cout<<"pl "<<pl<<endl;
            cout<<"ol "<<ol<<endl;
        }
        if (pl != ol) { std::cerr << "Whoops, decode predicted " << pl << " but we got " << ol << "\n"; }
        // if (input[strlen(input) - 1] == '=' && strlen(input) > 1) {
        //     ol--;
        // }
        // if (input[strlen(input) - 2] == '=' && strlen(input) > 2) {
        //     ol--;
        // }

        // output[ol] = '\0';
        // cout<<string(reinterpret_cast<char*>(output)).size()<<endl;

        return std::string(reinterpret_cast<char*>(output),ol);
    }



    auto EncodeBase64(const std::string& to_encode) -> std::string {
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

    auto DecodeBase64(const std::string& to_decode) -> std::string {
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


    std::string decrypt_S(const std::string& siv, const std::string& message) {
        // cout<<message<<endl;
        auto decoded = DecodeBase64(message);

       
        // cout<<encoded<<endl;
        std::cout << "Initialization Vector for Decryption: " << siv << "\n";
        auto iv1 = DecodeBase64(siv);
        int encoded_len = decoded.size();
        // char* iv1 = iv1_pair.first;
        // unsigned char* iv = new unsigned char[iv1.size()];
        // std::string str = "serverkey";
        unsigned char* iv = reinterpret_cast<unsigned char*>(const_cast<char*>(iv1.c_str()));
        unsigned char* key = reinterpret_cast<unsigned char*>(const_cast<char*>(serverkey.c_str()));
        // unsigned char* ciphertext2 = reinterpret_cast<unsigned char*>(const_cast<char*>(decoded.c_str()));
        // unsigned char* ciphertext3 = new unsigned char[encoded_len+16];
        // for(int i = 0; i < encoded_len; i++){
        //     ciphertext3[i] = ciphertext2[i];
        // }
        // for(int i = 0; i < 16; i++){
        //     ciphertext3[encoded_len+i] = '\0';
        // }
        // unsigned char* decryptedtext = new unsigned char[encoded_len+32];

        
        if(logs){
            cout<<"Cipher length "<<decoded.size()<<endl;
            // cout<<"Cipher2 length "<<kBScipher.size()<<endl;
        

            for(int i = 0; i < iv1.size(); i++){
                cout<< hex<<(int) iv[i]<<" ";
            }
            cout<<endl;

            cout<<"serverkey"<<endl;
            for (int i = 0; i < 32; i++) {
                std::cout << std::hex << (int)key[i] << " ";
            }
            cout<<endl;

            cout<<"cipher "<<endl;

            for(int i = 0; i < decoded.size(); i++){
                cout<< hex<< (int)decoded[i]<<" ";

            }
            cout<<endl;
        }

        
        // int decryptedtext_len = decrypt(ciphertext2, encoded_len, key, iv,
        //                         decryptedtext);

        // decryptedtext[decryptedtext_len] = '\0';

        // Decrypt aes(key, iv);
        secure_string plaintext1;
        secure_string ciphertext3(decoded.c_str());
        aes_decrypt(key,iv,ciphertext3, plaintext1);
        // int len = aes.update(reinterpret_cast<char*>(ciphertext3), encoded_len + 32, reinterpret_cast<char*>(decryptedtext));
        // len += aes.final(reinterpret_cast<char*>(decryptedtext));
        // decryptedtext[len] = '\0';
        std::string plaintext(plaintext1.data(), plaintext1.size());

        return plaintext;
    }




    void initiate() {
        std::string msg[4];
        msg[0] = "A";
        msg[1] = "B";

        // Generate nonce Na and Nb
        std::random_device rd;
        std::mt19937 gen(rd());
        Na = std::to_string(gen()); // Assuming Na is defined somewhere else
        Nb = std::to_string(gen()); // Assuming Nb is defined somewhere else
        msg[2] = Na;
        msg[3] = Nb;

        std::cout << "Sending message (A->S): " << msg[0] << " " << msg[1] << " " << msg[2] << " " << msg[3] << "\n";

        int socketFD = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in serverAddress{};
        serverAddress.sin_family = AF_INET;
        serverAddress.sin_port = htons(1025);
        inet_pton(AF_INET, "127.0.0.1", &serverAddress.sin_addr);

        connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress));

        for (const auto& m : msg) {
            // std::this_thread::sleep_for(std::chrono::milliseconds(100)); // wait for 1 second
            uint32_t sizeM = htonl(m.size());
            write(socketFD, &sizeM, sizeof(sizeM));
            write(socketFD, m.c_str(), m.size());
            // write(socketFD, "\n", 1);
        }
        // cout<<"Hii"<<endl;
        close(socketFD);
        listentoS(); // Assuming listentoS is defined somewhere else
    }




    void listentoS() {
        int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in serverAddress{};
        serverAddress.sin_family = AF_INET;
        serverAddress.sin_port = htons(1027);
        serverAddress.sin_addr.s_addr = INADDR_ANY;

        bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress));
        listen(serverSocket, 5);

        int clientSocket = accept(serverSocket, NULL, NULL);

        // int size;
        uint32_t sizeNet;
        // read(socketB, &sizeNet, sizeof(sizeNet));
        read(clientSocket, &sizeNet, sizeof(sizeNet));
        uint32_t size = ntohl(sizeNet);
        string iv = "";
        string kAScipher = "";
        string kBScipher = "";
        if(logs){
            cout<<"size "<<size<<endl;
        }
        for(int i = 0; i < size; i++){
            // int line;
            uint32_t sizeNet1;
            read(clientSocket, &sizeNet1, sizeof(sizeNet1));
            // read(clientSocket, reinterpret_cast<char*>(&line), sizeof(int));
            uint32_t line = ntohl(sizeNet1);
            unsigned char ciphertext[line+1];
            int size1 = read(clientSocket, reinterpret_cast<char*>(ciphertext), line);
            if(logs){
                cout<<"line "<<line<<endl;
                cout<<"size1 "<<size1<<endl;
            }
            ciphertext[line] = '\0';
            if(i == 0)
                iv += string(reinterpret_cast<char*>(ciphertext),line);
            if(i == 1)
                kAScipher += string(reinterpret_cast<char*>(ciphertext),line);
            if(i == 2)
                kBScipher += string(reinterpret_cast<char*>(ciphertext),line);
        }


   
        // close(clientSocket);


        // char buffer[1024];
        // char buffer1[1024];
        // char buffer2[1024];
        // read(clientSocket, buffer, sizeof(buffer));
        // std::string iv = buffer;
        // read(clientSocket, buffer1, sizeof(buffer1));
        // std::string kAScipher = buffer1;
        // read(clientSocket, buffer2, sizeof(buffer2));
        // std::string kBScipher = buffer2;

     
        // size_t pos = iv.find('\n');
        // if (pos != std::string::npos) {
        //     iv = iv.substr(0, pos);
        // }
        // pos = kAScipher.find('\n');
        // if (pos != std::string::npos) {
        //     kAScipher = kAScipher.substr(0, pos);
        // }
        // pos = kBScipher.find('\n');
        // if (pos != std::string::npos) {
        //     kAScipher = kBScipher.substr(0, pos);
        // }
        close(clientSocket);
        close(serverSocket);

        std::cout << "Received ciphertext (S->A): " << iv << " " << kAScipher << " " << kBScipher << "\n";
        std::string plaintext = decrypt_S(iv, kAScipher); // Assuming decrypt_S is defined somewhere else
        std::vector<std::string> tokens;
        int count = 0;
        std::string token;
        std::istringstream iss(plaintext);
        while(std::getline(iss, token, ' ') && count < 4) {
            tokens.push_back(token);
            count++;
        }
        // assert(tokens.size() >= 3);
        keyAB = decode64(tokens[0]); // Assuming keyAB is defined somewhere else
        assert(tokens[1] == "B");
        assert(tokens[2] == Na); // Assuming Na is defined somewhere else

        if (logs) { // Assuming logs is defined somewhere else
            std::cout << "Decrypted ciphertext (serverkey): " << tokens[0] << " B " << Na << "\n";
        }

        forwardtoB(iv, kBScipher); // Assuming forwardtoB is defined somewhere else
    }


    void forwardtoB(const std::string& iv, const std::string& kBScipher) {
        std::cout << "Forwarding to B (A->B): " << iv << " " << kBScipher << "\n";

        int socketFD = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in serverAddress{};
        serverAddress.sin_family = AF_INET;
        serverAddress.sin_port = htons(1026);
        inet_pton(AF_INET, "127.0.0.1", &serverAddress.sin_addr);

        connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress));

        int s = 2;

        uint32_t line = htonl(s);
        // write(socketA, reinterpret_cast<const void*>((int)ct.size()), sizeof(int));
        write(socketFD, &line, sizeof(line));
        // write(socketFD, reinterpret_cast<const void*>(s), sizeof(int));


        uint32_t ivS = htonl(iv.size());

        write(socketFD, &ivS, sizeof(ivS));

        write(socketFD, iv.c_str(), iv.size());
        // write(socketFD, "\n\n\n\n", 4);
        // std::this_thread::sleep_for(std::chrono::milliseconds(100));

        uint32_t kBS = htonl(kBScipher.size());
        write(socketFD, &kBS, sizeof(kBS));
        write(socketFD, kBScipher.c_str(), kBScipher.size());
        // write(socketFD, "\n", 1);


        

        close(socketFD);

        // listen for response from B
        int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
        serverAddress.sin_port = htons(1028);
        bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress));
        listen(serverSocket, 1);

        int clientSocket = accept(serverSocket, NULL, NULL);


        char buffer[1024];
        read(clientSocket, buffer, sizeof(buffer));
        std::string message = buffer;
        std::istringstream iss(message);
        std::string token;
        std::getline(iss, token, ' ');
        assert(token == "B");
        std::getline(iss, token, ' ');
        assert(token == Nb); // Assuming Nb is defined somewhere else

        std::cout << "(B->A): Nonce received and accepted from B: " << message << "\n";

        close(clientSocket);
        close(serverSocket);
    }

    void listentoA() {
        int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in serverAddress{};
        serverAddress.sin_family = AF_INET;
        serverAddress.sin_port = htons(1026);
        serverAddress.sin_addr.s_addr = INADDR_ANY;

        bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress));
        listen(serverSocket, 1);

        int clientSocket = accept(serverSocket, NULL, NULL);

        uint32_t sizeLine;
        read(clientSocket, &sizeLine, sizeof(sizeLine));
        uint32_t size = ntohl(sizeLine);

        // int size;
        // read(clientSocket, reinterpret_cast<char*>(&size), sizeof(int));
        string iv = "";
        string kBScipher = "";
        for(int i = 0; i < size; i++){
            int line;
            uint32_t sizeL;
            read(clientSocket, &sizeL, sizeof(sizeL));
            uint32_t lineSize = ntohl(sizeL);
            // read(clientSocket, reinterpret_cast<char*>(&line), sizeof(int));
            unsigned char ciphertext[lineSize+1];
            int size1 = read(clientSocket, reinterpret_cast<char*>(ciphertext), lineSize);

            ciphertext[size1] = '\0';
            if(i == 0)
                iv += string(reinterpret_cast<char*>(ciphertext));
            if(i == 1)
                kBScipher += string(reinterpret_cast<char*>(ciphertext));
            // if(i == 2)
            //     kBScipher += string(reinterpret_cast<char*>(ciphertext));
        }

        // char buffer[1024];
        // read(clientSocket, buffer, sizeof(buffer));
        // std::string iv = buffer;
        // read(clientSocket, buffer, sizeof(buffer));
        // std::string kBScipher = buffer;

        // size_t pos = iv.find("\n\n\n\n");
        // if (pos != std::string::npos) {
        //     iv = iv.substr(0, pos);
        // }
        // pos = kBScipher.find("\n\n\n\n");
        // if (pos != std::string::npos) {
            
        //     size_t pos1 = kBScipher.find('\n', pos+1);
        //     if (pos1!= std::string::npos)
        //         kBScipher = kBScipher.substr(pos1, pos1);
        // } else{
        //     size_t pos1 = kBScipher.find('\n', pos+1);
        //     if (pos1!= std::string::npos)
        //         kBScipher = kBScipher.substr(0, pos1);
        // }
        close(clientSocket);
        close(serverSocket);

        close(clientSocket);
        close(serverSocket);

        std::cout << "Received ciphertext (A->B): " << iv << " " << kBScipher << "\n";
        std::string plaintext = decrypt_S(iv, kBScipher); // Assuming decrypt_S is defined somewhere else
        std::istringstream iss(plaintext);
        std::string token;
        std::getline(iss, token, ' ');
        keyAB = decode64(token); // Assuming keyAB is defined somewhere else
        std::getline(iss, token, ' ');
        assert(token == "A");
        std::getline(iss, token, ' ');
        Nb = token; // Assuming Nb is defined somewhere else

        if (logs) { // Assuming logs is defined somewhere else
            std::cout << "Decrypted ciphertext: " << keyAB << " A " << Nb << "\n";
        }

        respondtoA(Nb); // Assuming respondtoA is defined somewhere else
    }




// void gen_params(byte key[KEY_SIZE], byte iv[BLOCK_SIZE]);
// void aes_encrypt(const byte key[KEY_SIZE], const byte iv[BLOCK_SIZE], const secure_string& ptext, secure_string& ctext);
// void aes_decrypt(const byte key[KEY_SIZE], const byte iv[BLOCK_SIZE], const secure_string& ctext, secure_string& rtext);

// g++ -Wall -std=c++11 evp-encrypt.cxx -o evp-encrypt.exe -lcrypto

void gen_params(byte key[KEY_SIZE], byte iv[BLOCK_SIZE])
{
    int rc = RAND_bytes(key, KEY_SIZE);
    if (rc != 1)
      throw std::runtime_error("RAND_bytes key failed");

    rc = RAND_bytes(iv, BLOCK_SIZE);
    if (rc != 1)
      throw std::runtime_error("RAND_bytes for iv failed");
}

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
    if (rc != 1){
      handleErrors();
      throw std::runtime_error("EVP_DecryptFinal_ex failed");
    }

    // Set recovered text size now that we know it
    rtext.resize(out_len1 + out_len2);
}

    void respondtoA(const std::string& Nb) {
        std::cout << "Responding (B->A): B " << Nb << "\n";

        int socketFD = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in serverAddress{};
        serverAddress.sin_family = AF_INET;
        serverAddress.sin_port = htons(1028);
        inet_pton(AF_INET, "127.0.0.1", &serverAddress.sin_addr);

        connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress));

        std::string message = "B " + Nb;
        write(socketFD, message.c_str(), message.size());
        write(socketFD, "\n", 1);

        close(socketFD);
    }

    std::string secure_send(unsigned char* iv, const std::string& msg) {
        // unsigned char iv[AES_BLOCK_SIZE];
        // for(int i = 0; i < iv1.size(); i++){
        //     iv[i] = iv1[i];
        // }
        
        int maxCiphertextLength = msg.length() + AES_BLOCK_SIZE;
        unsigned char* ciphertext = new unsigned char[maxCiphertextLength];
        // int ciphertextLength = 0;

        unsigned char *plaintext =  new unsigned char[msg.length()];
        for(int i = 0; i < msg.length(); i++)
            plaintext[i] = msg[i];

        int ciphertext_len;

        unsigned char* key = new unsigned char[keyAB.size()];
        for(int i = 0; i < keyAB.size(); i++){
            key[i] = keyAB[i];
        }
        
        ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), key, iv,
                                ciphertext);
        string ciphertext2(ciphertext, ciphertext + ciphertext_len);       
        // std::string ciphertext2 = encrypt_msg(iv, msg); // Assuming encrypt_msg is defined somewhere else
        std::cout << "Sending ciphertext: " << ciphertext2 << "\n";
        std::string plaintext2 = secure_send_BA(iv, ciphertext2); // Assuming secure_send_BA is defined somewhere else
        std::string plaintext1 = secure_send_AB(iv, ciphertext2); // Assuming secure_send_AB is defined somewhere else
        return (clientname == "B") ? plaintext1 : plaintext2; // Assuming clientname is defined somewhere else
    }


    std::string secure_send_AB(const unsigned char* iv, const std::string& msg) {
        std::string plaintext = "";
        if (clientname == "B") { // Assuming clientname is defined somewhere else
            int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
            sockaddr_in serverAddress{};
            serverAddress.sin_family = AF_INET;
            serverAddress.sin_port = htons(500);
            serverAddress.sin_addr.s_addr = INADDR_ANY;

            bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress));
            listen(serverSocket, 1);

            int clientSocket = accept(serverSocket, NULL, NULL);

            char buffer[1024];
            read(clientSocket, buffer, sizeof(buffer));
            std::string ciphertext1 = buffer;
                // std::string ciphertext1 = buffer;
            int maxPlaintextLength = ciphertext1.size();
            unsigned char* decryptedtext = new unsigned char[maxPlaintextLength];
            int plaintextLength = 0;

            unsigned char* key = reinterpret_cast<unsigned char*>(const_cast<char*>(serverkey.c_str()));
        // for(int i = 0; i < iv1.size(); i++){
        //     iv[i] = iv1[i];
        // }
            // for(int i = 0; i < serverkey.size(); i++){
            //     key[i] = serverkey[i];
            // }
            unsigned char* ciphertext2 = new unsigned char[ciphertext1.size()];
            for(int i=0; i < ciphertext1.size(); i++){
                ciphertext2[i] = ciphertext1[i];
            }
            ciphertext2[ciphertext1.size()-1] = '\0';
            int decryptedtext_len = decrypt(ciphertext2, ciphertext1.size(), key, iv,
                                decryptedtext);

            decryptedtext[decryptedtext_len] = '\0';
            // plaintext = decrypt_msg(iv, ciphertext1); // Assuming decrypt_msg is defined somewhere else
            // plaintext(reinterpret_cast<char*>(decryptedtext));
            string plaintext1(reinterpret_cast<char*>(decryptedtext));
            plaintext = plaintext1;
            // plaintext = decrypt_msg(iv, ciphertext1); // Assuming decrypt_msg is defined somewhere else

            close(clientSocket);
            close(serverSocket);
        } else if (clientname =="A") {
            int socketFD = socket(AF_INET, SOCK_STREAM, 0);
            sockaddr_in serverAddress{};
            serverAddress.sin_family = AF_INET;
            serverAddress.sin_port = htons(500);
            inet_pton(AF_INET, "127.0.0.1", &serverAddress.sin_addr);

            connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress));

            write(socketFD, msg.c_str(), msg.size());
            write(socketFD, "\n", 1);

            close(socketFD);
        }
        return plaintext;
    }


    std::string secure_send_BA(const unsigned char* iv, const std::string& msg) {
        std::string plaintext = "";
        if (clientname == "A") { // Assuming clientname is defined somewhere else
            int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
            sockaddr_in serverAddress{};
            serverAddress.sin_family = AF_INET;
            serverAddress.sin_port = htons(502);
            serverAddress.sin_addr.s_addr = INADDR_ANY;

            bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress));
            listen(serverSocket, 1);

            int clientSocket = accept(serverSocket, NULL, NULL);

            char buffer[1024];
            read(clientSocket, buffer, sizeof(buffer));
            std::string ciphertext1 = buffer;
            int maxPlaintextLength = ciphertext1.size() + 4096;

            unsigned char* key = reinterpret_cast<unsigned char*>(const_cast<char*>(serverkey.c_str()));
        // for(int i = 0; i < iv1.size(); i++){
        //     iv[i] = iv1[i];
        // }
            // for(int i = 0; i < serverkey.size(); i++){
            //     key[i] = serverkey[i];
            // }
            unsigned char* decryptedtext = new unsigned char[maxPlaintextLength];
            int plaintextLength = 0;
            unsigned char* ciphertext2 = new unsigned char[ciphertext1.size()];
            for(int i=0; i < ciphertext1.size(); i++){
                ciphertext2[i] = ciphertext1[i];
            }
            ciphertext2[ciphertext1.size()-1] = '\0';
            int decryptedtext_len = decrypt(ciphertext2, ciphertext1.size(), key, iv,
                                decryptedtext);

            decryptedtext[decryptedtext_len] = '\0';
            // plaintext = decrypt_msg(iv, ciphertext1); // Assuming decrypt_msg is defined somewhere else
            string plaintext1(reinterpret_cast<char*>(decryptedtext));
            plaintext = plaintext1;

            close(clientSocket);
            close(serverSocket);
        } else if (clientname == "B") {
            int socketFD = socket(AF_INET, SOCK_STREAM, 0);
            sockaddr_in serverAddress{};
            serverAddress.sin_family = AF_INET;
            serverAddress.sin_port = htons(502);
            inet_pton(AF_INET, "127.0.0.1", &serverAddress.sin_addr);

            connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress));

            write(socketFD, msg.c_str(), msg.size());
            write(socketFD, "\n", 1);

            close(socketFD);
        }
        return plaintext;
    }


    // std::string encrypt_msg(const std::vector<unsigned char>& iv, const std::string& msg) {
    //     EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    //     EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, keyAB.c_str(), iv); // Assuming keyAB is defined somewhere else

    //     std::vector<unsigned char> ciphertext(msg.size() + AES_BLOCK_SIZE);
    //     int len;
    //     EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(msg.data()), msg.size());
    //     int ciphertext_len = len;
    //     EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    //     ciphertext_len += len;

    //     EVP_CIPHER_CTX_free(ctx);

    //     return base64Encode(ciphertext.data(), ciphertext_len); // Assuming base64Encode is defined somewhere else
    // }

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


        cout<<"hoo "<<ciphertext_len<<endl;

        /*
        * Provide the message to be decrypted, and obtain the plaintext output.
        * EVP_DecryptUpdate can be called multiple times if necessary.
        */
        if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
            handleErrors();
        plaintext_len = len;

         cout<<"hoo1 "<<ciphertext_len<<endl;

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


    // int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
    //         unsigned char *iv, unsigned char *plaintext){
    //     EVP_CIPHER_CTX *ctx;

    //     int len;

    //     int plaintext_len;

    //     /* Create and initialise the context */
    //     if(!(ctx = EVP_CIPHER_CTX_new()))
    //         handleErrors();

    //     /*
    //     * Initialise the decryption operation. IMPORTANT - ensure you use a key
    //     * and IV size appropriate for your cipher
    //     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
    //     * IV size for *most* modes is the same as the block size. For AES this
    //     * is 128 bits
    //     */
    //     if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    //         handleErrors();

    //     /*
    //     * Provide the message to be decrypted, and obtain the plaintext output.
    //     * EVP_DecryptUpdate can be called multiple times if necessary.
    //     */
    //     if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    //         handleErrors();
    //     plaintext_len = len;

    //     /*
    //     * Finalise the decryption. Further plaintext bytes may be written at
    //     * this stage.
    //     */
    //     if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    //         handleErrors();
    //     plaintext_len += len;

    //     /* Clean up */
    //     EVP_CIPHER_CTX_free(ctx);

    //     return plaintext_len;
    // }

    // std::string decrypt_msg(const std::vector<unsigned char>& iv, const std::string& ciphertext) {
    //     string ct = base64Decode(ciphertext); // Assuming base64Decode is defined somewhere else


    //     EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    //     EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, keyAB.c_str(), iv);

    //     unsigned char* decryptedtext = new unsigned char[ct.size()];
    //     int len = 0;
    //     EVP_DecryptUpdate(ctx, decryptedtext, &len, ct.c_str(), ct.size());
    //     int plaintext_len = len;
    //     EVP_DecryptFinal_ex(ctx, decryptedtext + len, &len);
    //     plaintext_len += len;

    //     EVP_CIPHER_CTX_free(ctx);

    //     return std::string(decryptedtext);
    // }
    
    Client(string& name) {
        this->clientname = name;
    }

    void generateRandomIV(unsigned char* iv, size_t size) {
        RAND_bytes(iv, size);
        std::cout << "Generated IV: "<<std::endl;
        for (int i = 0; i < size; i++) {
            std::cout << std::hex << (int)iv[i] << " ";
        }
        std::cout << std::endl;
    }

};


int main() {
        std::string name;
        std::cout << "Enter clientname: (A/B) ";
        std::cin >> name;

        Client client(name); // Assuming Client class is defined somewhere else

        std::string log_choice;
        std::cout << "Logs? (true/false) ";
        // std::cin >> log_choice;

        // logs = (log_choice == "false") ? false : true;

        client.getServerKey(client.clientname); // Assuming getServerKey is defined in Client class

        if (client.clientname == "A") {
            client.initiate(); // Assuming initiate is defined in Client class
        } else {
            client.listentoA(); // Assuming listentoA is defined in Client class
        }

        std::cout << "\nSession key successfully established\n";
        std::cout << "Welcome to the Secure Communication Network\n";
        // if (logs) {
        //     std::cout << "Session Key: " << base64Encode(keyAB.c_str(), keyAB.size()) << "\n"; // Assuming keyAB is defined somewhere else
        // }

        int round = 1;
        unsigned char iv[16];
        client.generateRandomIV(iv,16);
        while (true) {
            std::string message;

            std::cout << "\nRound " << round << "\n";

            std::cout << "Enter message to send securely: ";
            std::cin >> message;
            if (client.logs) {
                std::cout << "Sending message: " << message << "\n";
            }

            iv[round % 16] ^= 1;
            std::string siv = client.base64Encode(iv, 16);
            if (client.logs) {
                std::cout << "Round IV: " << siv << "\n";
            }

            std::string plaintext = client.secure_send(iv, message); // Assuming secure_send is defined in Client class
            std::cout << "Received message:  " << plaintext << "\n";
            round++;
        }

        return 0;
    }