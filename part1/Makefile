# Compiler and compiler flags
CXX = g++
CXXFLAGS = -std=c++11

# Server and Client executables
SERVER_EXEC = server
CLIENT_EXEC = client

# Source files
SERVER_SRC = server.cpp -lssl -lcrypto
CLIENT_SRC = client.cpp -lssl -lcrypto

all: $(SERVER_EXEC) $(CLIENT_EXEC)

$(SERVER_EXEC): $(SERVER_SRC)
	$(CXX) -g $(CXXFLAGS) -o $(SERVER_EXEC) $(SERVER_SRC)

$(CLIENT_EXEC): $(CLIENT_SRC)
	$(CXX) -g $(CXXFLAGS) -o $(CLIENT_EXEC) $(CLIENT_SRC)

clean:
	rm -f $(SERVER_EXEC) 	$(CLIENT_EXEC)


obj-m += hook2.o

nf: 
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	sudo rmmod hook2.ko
	sudo insmod hook2.ko

clean1:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
