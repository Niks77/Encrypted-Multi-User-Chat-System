#include <iostream>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <cstring>

#include <iostream>
#include <fstream>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/hmac.h>
#include <fstream>



using namespace std;

void generateRandomIV(unsigned char* iv, size_t size) {
    RAND_bytes(iv, size);
    std::cout << "Generated IV: "<<std::endl;
    for (int i = 0; i < size; i++) {
        std::cout << std::hex << (int)iv[i] << " ";
    }
    std::cout << std::endl;
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}
void generateHMAC(const unsigned char* data, size_t data_length, const unsigned char* key, size_t key_length, unsigned char* hmac, unsigned int* hmac_length) {
    HMAC(EVP_sha256(), key, key_length, data, data_length, hmac, hmac_length);
}






void encrypt(std::ifstream& input, int fout, unsigned char *key, unsigned char *iv, off_t size)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char buffer[4096]; 
    unsigned char encryptedBuffer[4096 + EVP_MAX_BLOCK_LENGTH]; 
    int len;


    // int fileLength = input.tellg();
    // cout<<"file "<<fileLength<<endl;

    // write(fout, "start", 5);
    // cout<<size<<" "<<size<<endl;
    write(fout, reinterpret_cast<const char*>(iv), AES_BLOCK_SIZE);
    write(fout, reinterpret_cast<const char*>(&size), sizeof(off_t));
    // outputFile.write(reinterpret_cast<const char*>(iv), AES_BLOCK_SIZE);


    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handleErrors();

    while (int bytesRead = input.read((char*)buffer, sizeof(buffer)).gcount())
    {
        // cout<<"Hii"<<endl;
        if(1 != EVP_EncryptUpdate(ctx, encryptedBuffer, &len, buffer, bytesRead)) handleErrors();
        write(fout, reinterpret_cast<const char*>(&len), sizeof(int));
        write(fout, reinterpret_cast<const char*>(encryptedBuffer), len);
        unsigned char hmac[EVP_MAX_MD_SIZE];
        unsigned int hmacLength;
        generateHMAC(encryptedBuffer, len, (const unsigned char*)key, 64, hmac, &hmacLength);
        write(fout,reinterpret_cast<const char*>(&hmacLength), sizeof(int));
        // cout<<hmacLength<<endl;
        write(fout,reinterpret_cast<const char*>(hmac), hmacLength);
    }

    if(1 != EVP_EncryptFinal_ex(ctx, encryptedBuffer, &len)) handleErrors();
    // outputFile.write(reinterpret_cast<const char*>(iv), AES_BLOCK_SIZE);
    write(fout, reinterpret_cast<const char*>(&len), sizeof(int));
    write(fout, reinterpret_cast<const char*>(encryptedBuffer), len);
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int hmacLength;
    generateHMAC(encryptedBuffer, len, (const unsigned char*)key, 64, hmac, &hmacLength);
    write(fout,reinterpret_cast<const char*>(&hmacLength), sizeof(int));
    write(fout,reinterpret_cast<const char*>(hmac), hmacLength);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
}
int main() {

    const char* temp_dir_template = "/tmp/mytempdirXXXXXX"; 
    char* temp_dir = new char[strlen(temp_dir_template) + 1];
    strcpy(temp_dir, temp_dir_template);

     unsigned char key[64] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                           0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
                           0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33,
                           0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31
                         };
    unsigned char iv[AES_BLOCK_SIZE];
    generateRandomIV(iv, AES_BLOCK_SIZE);

    string inputFilePath;
    cout<<"Enter the path of the file to be encrypted"<<endl;
    cin>>inputFilePath;
    // std::ofstream file(inputFilePath);
    // file.close();
    std::ifstream inputFile(inputFilePath, std::ios::binary);
    if (!inputFile) {
        std::cerr << "Error: Unable to open input file." << std::endl;
        return 1;
    }
    if (mkdtemp(temp_dir) != nullptr) {
        std::cout << "Created temporary directory: " << temp_dir << std::endl;

        remove(temp_dir);
        std::string fifoPath(temp_dir);

        if (mkfifo(fifoPath.c_str(), 0666) == -1) {
            perror("Error creating FIFO");
            return 1;
        }

        // std::ofstream pipeFile(fifoPath);

        pid_t ncpid = fork();

       

        if (ncpid == -1) {
            perror("Error forking process");
            return 1;
        }

        cout<<ncpid<<endl;

        if (ncpid == 0) {
            cout<<"closed process"<<endl;
            int fifo_in = open(fifoPath.c_str(), O_RDONLY);
            dup2(fifo_in, STDIN_FILENO);
            close(fifo_in);

            int fifo_out = open(fifoPath.c_str(), O_WRONLY);
            dup2(fifo_out, STDOUT_FILENO);
            close(fifo_out);
            cout<<"starting nc "<<endl;
            execlp("nc", "nc", "127.0.0.1", "1234", NULL);
            perror("execlp failed");
            exit(1);    
        } else {
            cout<<"parent process"<<endl;
            int fifo_out = open(fifoPath.c_str(), O_WRONLY);
            // int fifo_in = open(fifoPath, O_RDONLY);

            if (fifo_out == -1) {
                perror("Error opening FIFO in parent process");
                return 1;
            }
            // cout<<"parent process 1"<<endl;
            // std::string message = "Hello, Server\n";
            // write(fifo_out, message.c_str(), message.size());
            
            // while(true){
            //     char buffer[1024];
            //     ssize_t bytesRead = read(fifo_out, buffer, sizeof(1));

            //     if (bytesRead > 0) {
                    // buffer[bytesRead] = '\0';
                    // std::cout << "p1 received from nc2: " << buffer << std::endl;
            struct stat st;
            if (stat(inputFilePath.c_str(), &st) != 0) {
                std::cerr << "Unable to get file properties.\n";
                return 1;
            }

            off_t size = st.st_size;

            std::cout << "Size of file: " << size << " bytes\n";


            encrypt(inputFile, fifo_out, key, iv, size);
            inputFile.close();
            // pipeFile.close();
            // closed(fout)
                    // break;
            //     } 
            // }
           


            close(fifo_out);

            int status;
            waitpid(ncpid, &status, 0);

            // if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            //     std::cout << "Child process finished successfully." << std::endl;
            // } else {
            //     std::cerr << "Child process encountered an error." << std::endl;
            // }

            remove(fifoPath.c_str());
        }
    } else {
        std::cerr << "Failed to create a temporary directory." << std::endl;
    }
    
    return 0;
}
