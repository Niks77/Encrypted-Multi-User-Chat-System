#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <iostream>
#include <map>
#include <string>
#include <random>
#include <arpa/inet.h>

#include <thread>
struct ClientInfo {
    int socket;
    // Add more fields as needed
    std::string ip;
    int port;
};

using namespace std;

std::map<std::string, ClientInfo> clients;
std::map<std::string, std::vector<std::string>> groups;

std::random_device rd;
std::mt19937 gen(rd());
std::uniform_int_distribution<> distr(100000, 999999); // Generate six-digit user IDs

void handle_client(int client_fd, std::string user_id, std::string ip, int port) {
    // TODO: Implement logic to handle client
    // Don't forget to close the client socket when done

    // cout<<"hiiii"<<endl;
    
    write(client_fd, user_id.c_str(), user_id.size());
    char buffer[4096] = {0};
    while (true) {
        ssize_t bytes_read = read(client_fd, buffer, sizeof(buffer) - 1);
        if (bytes_read <= 0) {
            // Client disconnected or error
            break;
        }

        buffer[bytes_read] = '\0'; // Null-terminate the string

        std::string command(buffer,bytes_read);
        // cout<<command<<endl;
        cout<<command.substr(0, 15)<<endl;

        if (command == "/who") {
            std::string response;
            for (const auto& pair : clients) {
                response += "User ID: " + pair.first + ", IP: " + pair.second.ip + ", Port: " + std::to_string(pair.second.port) + "\n";
            }
            
            write(client_fd, response.c_str(), response.size());
        } else if (std::string(buffer) == "/create_group") {
            //todo unique
            std::string group_id = std::to_string(distr(gen)); // Generate random group ID
            groups[group_id] = {user_id}; // Create group with the current user as the only member

            std::string response = "Group created with ID: " + group_id + "\n";
            cout<<response<<endl;
            write(client_fd, response.c_str(), response.size());
        } else if (command.substr(0, 20) == "/group_invite_accept") {
            size_t space_pos = command.find(' ', 20); // Find the space after the group ID
            std::string group_id = command.substr(space_pos+1, 6); // Extract the group ID
            space_pos = command.find(' ', space_pos+1);
            std::string inviter_user_id = command.substr(space_pos + 1,6); // The rest of the command is the inviter's user ID
            space_pos = command.find(' ', space_pos+1);
            std::string user_id = command.substr(space_pos + 1,6); // The rest of the command is the user ID to invite

            cout<<"/group invite accept "<<group_id<<" "<<inviter_user_id<<" "<<user_id<<endl;
            if (groups.find(group_id) != groups.end() && clients.find(inviter_user_id) != clients.end()) {
                groups[group_id].push_back(user_id); // Add the current user to the group

                std::string response = "User " + user_id + " has accepted your invite to join group " + group_id + "\n";
                write(clients[inviter_user_id].socket, response.c_str(), response.size());
            }
        }else if (command.substr(0, 13) == "/group_invite") {
            std::string group_id = command.substr(14, 6); // Assuming group IDs are six digits
            std::string invite_user_id = command.substr(21); // The rest of the command is the user ID to invite
            cout<<"/group_invite1 "<<group_id<<" "<<invite_user_id<<endl;
            if (groups.find(group_id) != groups.end() && clients.find(invite_user_id) != clients.end()) {
                std::string response = "You have been invited to join group " + group_id + " by user " + user_id + "\n";
                write(clients[invite_user_id].socket, response.c_str(), response.size());
            }
        } else if (command.substr(0, 15) == "/request_public") {
            std::string target_user_id = command.substr(16); // The rest of the command is the user ID to request the public key from

            if (clients.find(target_user_id) != clients.end()) {
                std::string response = "/send_public_key " + user_id + "\n";
                write(clients[target_user_id].socket, response.c_str(), response.size());
            }
        } else if (command.substr(0, 16) == "/send_public_key") {
            size_t space_pos = command.find(' ', 17); // Find the space after the user ID
            std::string target_user_id = command.substr(17, space_pos - 17); // Extract the user ID
            std::string public_key = command.substr(space_pos + 1); // The rest of the command is the public key

            if (clients.find(target_user_id) != clients.end()) {
                std::string response = "User " + user_id + " has sent you their public key: " + public_key + "\n";
                write(clients[target_user_id].socket, response.c_str(), response.size());
            }
        } else if (command.substr(0, 10) == "/write_all") {
            std::string message = command.substr(11); // The rest of the command is the message to broadcast

            for (const auto& pair : clients) {
                if (pair.first != user_id) { // Don't send the message to the user who sent it
                    std::string response = "Message from user " + user_id + ": " + message + "\n";
                    write(pair.second.socket, response.c_str(), response.size());
                }
            }
        } else if (command.substr(0, 12) == "/write_group") {
            size_t space_pos = command.find(' ', 13); // Find the space after the group ID
            std::string group_id = command.substr(13, space_pos - 13); // Extract the group ID
            std::string message = command.substr(space_pos + 1); // The rest of the command is the message

            if (groups.find(group_id) != groups.end()) {
                for (const std::string& member_user_id : groups[group_id]) {
                    if (member_user_id != user_id) { // Don't send the message to the user who sent it
                        std::string response = "Message to group " + group_id + " from user " + user_id + ": " + message + "\n";
                        write(clients[member_user_id].socket, response.c_str(), response.size());
                    }
                }
            }
        } else if (command.substr(0, 17) == "/init_group_dhxchg") {
            // sting res = command.substr(18);
            // std::istringstream iss(res);
            // std::string command, group_id, user_id, bytes;
            // std::getline(iss, command, ' ');
            // std::getline(iss, group_id, ' ');
            // std::getline(iss, user_id, ' ');
            // std::getline(iss, bytes, ' ');

            size_t space_pos = command.find(' ', 18); // Find the space after the group ID
            std::string group_id = command.substr(18, space_pos - 18); // Extract the group ID
            std::string target_user_id = command.substr(space_pos + 1, command.find(' ', space_pos + 1) - (space_pos + 1)); // Extract the user ID
            int size = command.substr(command.find(' ', space_pos + 1 + target_user_id.size() + 1) + 1).size();
            std::string bytes(command.substr(command.find(' ', space_pos + 1 + target_user_id.size() + 1) + 1),size); // The rest of the command is the bytes

            if (groups.find(group_id) != groups.end() && clients.find(user_id) != clients.end()) {
                std::string response("/init_group_dhxchg " + group_id + " " + user_id + " " + bytes, command.size() + group_id.size() + user_id.size() + bytes.size() + 3);
                write(clients[user_id].socket, response.c_str(), response.size());
            }
        }else {
            // TODO: Handle other commands
        }
    }
    clients.erase(user_id);
    cout<<endl;
    close(client_fd);
}

int main() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        std::cerr << "Failed to create socket\n";
        return 1;
    }
    cout<<endl;

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        std::cerr << "Failed to set socket options\n";
        return 1;
    }

  
    
    sockaddr_in server_addr = {};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(12345); // Use your desired port
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        std::cerr << "Failed to bind socket\n";
        return 1;
    cout<<endl;
    }

    if (listen(server_fd, 10) == -1) {
        std::cerr << "Failed to listen on socket\n";
        return 1;
    }

   

    while (true) {
        sockaddr_in client_addr = {};
        socklen_t client_addr_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_addr_len);
        if (client_fd == -1) {
            std::cerr << "Failed to accept client\n";
            continue;
        }

        std::string user_id; // Get user ID from client
        do {
            user_id = std::to_string(distr(gen)); // Generate random user ID
        } while (clients.find(user_id) != clients.end()); // Repeat if user ID is already in use

    // clients[user_id] = {client_fd};
        char buff [1024] = {0};
        read(client_fd, buff, sizeof(buff) - 1);

        

        char ipstr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(client_addr.sin_addr), ipstr, sizeof(ipstr));
        int port = ntohs(client_addr.sin_port);

        clients[user_id] = {client_fd, ipstr, port};

        

        std::thread client_thread(handle_client, client_fd, user_id, ipstr, port);
        client_thread.detach();
    }

    close(server_fd);

    return 0;
}