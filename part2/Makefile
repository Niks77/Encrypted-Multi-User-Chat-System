# Compiler and compiler flags
CXX = g++
CXXFLAGS = -std=c++14

# Server and Client executables
SERVER_EXEC = server
CLIENT_EXEC = client
AES = aes
CHAT = chat
CHAT2 = chat2
DH2 = dh2
DH1 = dh1

# Source files
SERVER_SRC = server_kdc.cpp -lssl -lcrypto
CLIENT_SRC = clientA.cpp -lssl -lcrypto

CHAT_SRC = chat.cpp -lcrypto -lssl
CHAT2_SRC = chat2.cpp -lcrypto -lssl
DH2_SRC = dh2.cpp -lcrypto -lssl
DH1_SRC = dh1.cpp -lcrypto -lssl


all: $(SERVER_EXEC) $(CLIENT_EXEC) $(CHAT) $(CHAT2) $(DH2) $(DH1)

$(SERVER_EXEC): $(SERVER_SRC)
	$(CXX)  $(CXXFLAGS) -o $(SERVER_EXEC) $(SERVER_SRC)

$(CLIENT_EXEC): $(CLIENT_SRC)
	$(CXX)  $(CXXFLAGS) -o $(CLIENT_EXEC) $(CLIENT_SRC)


$(CHAT): $(CHAT_SRC)
	$(CXX)  $(CXXFLAGS) -o $(CHAT) $(CHAT_SRC)

$(CHAT2): $(CHAT2_SRC)
	$(CXX)  $(CXXFLAGS) -o $(CHAT2) $(CHAT2_SRC)

$(DH2): $(DH2_SRC)
	$(CXX)  $(CXXFLAGS) -o $(DH2) $(DH2_SRC)

$(DH1): $(DH1_SRC)
	$(CXX)  $(CXXFLAGS) -o $(DH1) $(DH1_SRC)



clean:
	rm -f $(SERVER_EXEC) 	$(CLIENT_EXEC)


# obj-m += hook2.o

# nf: 
# 	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
# 	sudo rmmod hook2.ko
# 	sudo insmod hook2.ko

# clean1:
# 	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
