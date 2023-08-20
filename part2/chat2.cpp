#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <string.h>
#include <iostream>

#include <thread>
using namespace std;
string userid;

DH* bytes_to_dh(DH* dh, const unsigned char* pub_key_bytes, size_t len) {
    // DH* dh = DH_new();
    if (!dh) {
        // Handle error
        return nullptr;
    }

    BIGNUM* pub_key_bn = BN_bin2bn(pub_key_bytes, len, nullptr);
    if (!pub_key_bn) {
        // Handle error
        DH_free(dh);
        return nullptr;
    }

    if (DH_set0_key(dh, pub_key_bn, nullptr) != 1) {
        // Handle error
        BN_free(pub_key_bn);
        DH_free(dh);
        return nullptr;
    }


    return dh;
}

void handle_client(int client_fd, std::string user_id) {
    char buffer[4096] = {0};
    //  char buffer[4096] = {0};
    DH* dh = DH_new();
    while(true){
        int valread = read(client_fd, buffer, sizeof(buffer) - 1);
        buffer[valread] = '\0';
        std::string command(buffer, valread);
        cout<<command<<endl;
        if (command.substr(0, 17) == "/init_group_dhxchg") {
            // size_t space_pos = command.find(' ', 18); // Find the space after the group ID
            // std::string group_id = command.substr(18, space_pos - 18); // Extract the group ID
            // std::string target_user_id = command.substr(space_pos + 1, command.find(' ', space_pos + 1) - (space_pos + 1)); // Extract the user ID
            // int size = command.substr(command.find(' ', space_pos + 1 + target_user_id.size() + 1) + 1).size();
            // std::string bytes(command.substr(command.find(' ', space_pos + 1 + target_user_id.size() + 1) + 1),size); // The rest of the command is the bytes

            // // if (groups.find(group_id) != groups.end() && clients.find(target_user_id) != clients.end()) {
            // std::string response = "/init_group_dhxchg " + group_id + " " + target_user_id + " " + bytes;
            // // write(clients[target_user_id].socket, response.c_str(), response.size());
            // dh = bytes_to_dh(dh, reinterpret_cast<unsigned char>(bytes.c_str()), bytes.size());
            // EVP_PKEY *pkey1 = generate_dh_key(ndh);


            // }
        }
    }

}
int main() {
    // Define the server address
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(12345); // Server port number
    inet_pton(AF_INET, "127.0.0.1", &(server_address.sin_addr)); // Server IP

    // Create a socket
    int sock = 0;
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cout << "Socket creation error" << std::endl;
        return -1;
    }

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
        std::cout << "Connection Failed" << std::endl;
        return -1;
    }

    // Send a message to the server
    std::string hello = "Hello from client";
    send(sock, hello.c_str(), hello.size(), 0);
    std::cout << "Hello message sent" << std::endl;


    char buffer[4096] = {0};
    int valread = read(sock, buffer, 6);
    userid = string(buffer,6);
    std::cout << "userid " <<userid<< std::endl;


    std::thread client_thread(handle_client, sock, userid);
    client_thread.detach();

    // Send a message to the server
    while(true){
        std::string message;
        std::getline(std::cin, message);
        if (message == "quit") {
            break;
        }
        // cout<<"message "<<message<<endl;
        write(sock, message.c_str(), message.size());
     
        // string msg(buffer);
        // cout<<msg<<endl;

    }

    // Close the socket
    close(sock);

    return 0;
}