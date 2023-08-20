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
#include <algorithm>
#include <cctype>


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


bool verifyHMAC(const unsigned char* data, size_t data_length, const unsigned char* key, size_t key_length, const unsigned char* hmac, unsigned int hmac_length) {
    unsigned char calculatedHMAC[EVP_MAX_MD_SIZE];
    unsigned int calculatedHMACLength;

    HMAC(EVP_sha256(), key, key_length, data, data_length, calculatedHMAC, &calculatedHMACLength);
    if (calculatedHMACLength != hmac_length) {
        return false;
    }

    return CRYPTO_memcmp(calculatedHMAC, hmac, hmac_length) == 0;
}



void encrypt(std::ifstream& input, std::ofstream& outputFile, unsigned char *key, unsigned char *iv)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char buffer[4096]; 
    unsigned char encryptedBuffer[4096 + EVP_MAX_BLOCK_LENGTH]; 
    int len;

    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handleErrors();

    while (int bytesRead = input.read((char*)buffer, sizeof(buffer)).gcount())
    {
        if(1 != EVP_EncryptUpdate(ctx, encryptedBuffer, &len, buffer, bytesRead)) handleErrors();
        outputFile.write(reinterpret_cast<const char*>(iv), AES_BLOCK_SIZE);
        outputFile.write(reinterpret_cast<const char*>(&len), sizeof(int));
        outputFile.write(reinterpret_cast<const char*>(encryptedBuffer), len);
        unsigned char hmac[EVP_MAX_MD_SIZE];
        unsigned int hmacLength;
        generateHMAC(encryptedBuffer, len, (const unsigned char*)key, 64, hmac, &hmacLength);
        outputFile.write(reinterpret_cast<const char*>(&hmacLength), sizeof(int));
        outputFile.write(reinterpret_cast<const char*>(hmac), hmacLength);
    }

    if(1 != EVP_EncryptFinal_ex(ctx, encryptedBuffer, &len)) handleErrors();
    outputFile.write(reinterpret_cast<const char*>(iv), AES_BLOCK_SIZE);
    outputFile.write(reinterpret_cast<const char*>(&len), sizeof(int));
    outputFile.write(reinterpret_cast<const char*>(encryptedBuffer), len);
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int hmacLength;
    generateHMAC(encryptedBuffer, len, (const unsigned char*)key, 64, hmac, &hmacLength);
    outputFile.write(reinterpret_cast<const char*>(&hmacLength), sizeof(int));
    outputFile.write(reinterpret_cast<const char*>(hmac), hmacLength);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
}


void decrypt(int fin, std::ofstream& output, unsigned char *key)
{
    char b[4096];

    read(fin,b, 13);

    unsigned char iv[AES_BLOCK_SIZE];
    read(fin, reinterpret_cast<char*>(iv), AES_BLOCK_SIZE);

    std::cout << "fetched IV: "<<std::endl;
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        std::cout << std::hex << (int)iv[i] << " ";
    }
    std::cout << std::endl;

    off_t fileLength;
    read(fin, reinterpret_cast<char*>(&fileLength), sizeof(off_t));

    std::cout << "fetched fileLength: "<<fileLength<<std::endl;


    // int cipherLength; // The length of the HMAC is variable.
    // inputFile.read(reinterpret_cast<char*>(&cipherLength), sizeof(int));

    // unsigned char ciphertext[cipherLength];
    // inputFile.read(reinterpret_cast<char*>(ciphertext), cipherLength);

    // // std::cout<<"Ciphertext "<<(reinterpret_cast<const char*>(ciphertext))<<std::endl;

    // // std::cout<<"Cipher Length "<<cipherLength<<std::endl;
    // int hmacLength; // The length of the HMAC is variable.
    // inputFile.read(reinterpret_cast<char*>(&hmacLength), sizeof(int));

    // // unsigned int hmacLength = EVP_MAX_MD_SIZE;
    // unsigned char hmac[EVP_MAX_MD_SIZE];
    // inputFile.read(reinterpret_cast<char*>(hmac), hmacLength);

    EVP_CIPHER_CTX *ctx;
    // unsigned char buffer[4096 + EVP_MAX_BLOCK_LENGTH]; // Buffer to hold file data
    // unsigned char decryptedBuffer[4096]; // Buffer to hold decrypted data
    // int len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the decryption operation */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handleErrors();

    // if (verifyHMAC(ciphertext, cipherLength, (const unsigned char*)key, 64, hmac, hmacLength)) {
    //     // std::cout << "HMAC verification successful. Data is authentic." << std::endl;
    //     // Write the plaintext to the output file
    //     // std::ofstream outputFile(outputFilePath, std::ios::binary);
    //     // outputFile.write(reinterpret_cast<const char*>(decryptedtext), decryptedtext_len);
    // } else {
    //     std::cerr << "HMAC verification failed. The data may have been tampered with." << std::endl;
    //     exit(1);
    // }

    while(fileLength > 0){
        
        // unsigned char iv1[AES_BLOCK_SIZE];
        // inputFile.read(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE);

        // std::cout << "fetched IV: "<<std::endl;
        // for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        //     std::cout << std::hex << (int)iv[i] << " ";
        // }
        // std::cout << std::endl;


        

        int cipherLength; // The length of the HMAC is variable.
        int len1 = read(fin, reinterpret_cast<char*>(&cipherLength), sizeof(int));
        fileLength -= len1;

        // cout<<len1<<endl;
        // cout<<"c "<< cipherLength<<endl;
        if(len1 == 0){
            cout<<"End of file"<<endl;
            exit(1);
        }

        unsigned char ciphertext[cipherLength];
        len1 = read(fin, reinterpret_cast<char*>(ciphertext), cipherLength);
        if(len1 == 0){
            cout<<"End of file"<<endl;
            exit(1);
        }
        fileLength -= len1;

        // std::cout<<"Ciphertext "<<(reinterpret_cast<const char*>(ciphertext))<<std::endl;

        // std::cout<<"Cipher Length "<<cipherLength<<std::endl;
        int hmacLength; // The length of the HMAC is variable.
        len1 = read(fin,reinterpret_cast<char*>(&hmacLength), sizeof(int));
        if(len1 == 0){
            cout<<"End of file"<<endl;
            exit(1);
        }
        fileLength -= len1;

        // unsigned int hmacLength = EVP_MAX_MD_SIZE;
        unsigned char hmac[EVP_MAX_MD_SIZE];
        len1 = read(fin, reinterpret_cast<char*>(hmac), hmacLength);
        if(len1 == 0){
            cout<<"End of file"<<endl;
            exit(1);
        }
        fileLength -= len1;
        if (verifyHMAC(ciphertext, cipherLength, (const unsigned char*)key, 64, hmac, hmacLength)) {
        std::cout << "HMAC verification successful. Data is authentic. " << hmacLength << std::endl;
        // Write the plaintext to the output file
        // std::ofstream outputFile(outputFilePath, std::ios::binary);
        // outputFile.write(reinterpret_cast<const char*>(decryptedtext), decryptedtext_len);
        } else {
            std::cerr << "HMAC verification failed. The data may have been tampered with." << std::endl;
            exit(1);
        }
        int len = 0;
        unsigned char decryptedBuffer[4096]; // Buffer to hold decrypted data
        // if(inputFile.eof()){
        //     if(1 != EVP_DecryptFinal_ex(ctx, decryptedBuffer, &len)) handleErrors();
        //     output.write((char*)decryptedBuffer, len);
        // }
        if(1 != EVP_DecryptUpdate(ctx, decryptedBuffer, &len, ciphertext, cipherLength)) handleErrors();
        fileLength -= len1;
        output.write((char*)decryptedBuffer, len);
        // cout<<"wrote "<<len<<endl;
        // int buffer[4096];
        // int len = read(fifo_in, buffer, sizeof(buffer));
        decryptedBuffer[len] = '\0';
        std::string str(reinterpret_cast<char*>(decryptedBuffer), len);
        cout<<str<<endl;
        // cout<<fileLength<<endl;
    }
    output.close();




    /* Read the file and decrypt its content */
    // while (int bytesRead = input.read((char*)buffer, sizeof(buffer)).gcount())
    // {
    //     unsigned char iv[AES_BLOCK_SIZE];
    //     inputFile.read(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE);
    //     if(1 != EVP_DecryptUpdate(ctx, decryptedBuffer, &len, buffer, bytesRead)) handleErrors();
    //     output.write((char*)decryptedBuffer, len);
    // }

    /* Decrypt the final block and write it to the file */


    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
}

std::string trim(const std::string& str) {
    std::string s = str;
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), s.end());
    return s;
}

int main() {

    // const char* temp_dir_template = "/tmp/mytempdirXXXXXX"; 
    // char* temp_dir = new char[strlen(temp_dir_template) + 1];
    // strcpy(temp_dir, temp_dir_template);

    int fd[2];
    pipe(fd);

     unsigned char key[64] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                           0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
                           0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33,
                           0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31
                         };

    // unsigned char iv[AES_BLOCK_SIZE];
    // generateRandomIV(iv, AES_BLOCK_SIZE);

    string outputFilePath;
    cout<<"Enter the name to be saved"<<endl;
    cin>>outputFilePath;
  


    std::ofstream outputFile(outputFilePath, std::ios::binary);
    if (!outputFile) {
        std::cerr << "Error: Unable to open input file." << std::endl;
        return 1;
    }

    // if (mkfifo(fifoPath.c_str(), 0666) == -1) {
    //     perror("Error creating FIFO");
    //     return 1;
    // }


    pid_t ncpid = fork();

    if (ncpid == -1) {
        perror("Error forking process");
        return 1;
    }

    if (ncpid == 0) {
        cout<<"closed process"<<endl;
        int fifo_in = fd[0];
        // dup2(fifo_in, STDIN_FILENO);
        close(fifo_in);

        int fifo_out = fd[1];
        dup2(fifo_out, STDOUT_FILENO);
        close(fifo_out);
        // cout<<"starting nc "<<endl;
        execlp("nc", "nc", "-l", "1234", NULL);
        perror("execlp failed");
        exit(1);    
    } else {
        cout<<"parent process"<<endl;
        int fifo_out = fd[1];
        int fifo_in = fd[0];
        if (fifo_out == -1) {
            perror("Error opening FIFO in parent process");
            return 1;
        }
        // outputFile.write("1",1);
        // cout<<"parent process 1"<<endl;
        // std::string message = "Hello, Server\n";
        // write(fifo_out, message.c_str(), message.size());
        // int ciphertext_len;
        // std::ifstream pipeFile(fifoPath, std::ios::out | std::ios::binary);
        // string str = "";
        // do{
        //     char buffer[4096];
        //     int len = read(fifo_in, buffer, sizeof(buffer));
        //     cout<<len<<endl;
        //     if(len <= 0){
        //         // cout<<"continue"<<endl;
        //         continue;
        //     }
        //     buffer[len-1] = '\0';
        //     // cout<<len<<" k"<<endl;
        //     string str1(buffer,len-1);
        //     str = str1;
        //     cout<<str1<<endl;
        //     // cout<<str.size()<<endl;
        //     trim(str);
        //         // cout<<str.size()<<endl;
        //     // string str2 = "start";
        //     // cout<<str2.size()<<endl;
        //     // if(str == str2)
        //     //     break;
        //     // cout<<(str != "start  ")<<endl;

        //     // cout<<(str != "start ")<<endl;
        //     // cout<<(str != "start")<<endl;

        // } while(str != "start");

        cout<<"start"<<endl;
        
        decrypt(fifo_in, outputFile, key);
        outputFile.close();
        // pipeFile.close();


        close(fifo_out);
        close(fifo_in);

        int status;
        waitpid(ncpid, &status, 0);

        // if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        //     std::cout << "Child process finished successfully." << std::endl;
        // } else {
        //     std::cerr << "Child process encountered an error." << std::endl;
        // }

        // remove(fifoPath.c_str());
    }

    
    return 0;
}
