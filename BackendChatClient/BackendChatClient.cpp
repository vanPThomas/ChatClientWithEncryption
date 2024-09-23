#include <iostream>
#include <cstring>
#include <thread>
#include <fstream>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <string>
#include <openssl/sha.h>
#include <boost/interprocess/shared_memory_object.hpp>
#include <boost/interprocess/mapped_region.hpp>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

void handleSystemCallError(std::string errorMsg);
int createClientSocket(const std::string& serverIP, int serverPort);
void receiveMessages(int clientSocket, int bufferSize, std::string password);
void sendMessage(int clientSocket, char outMessage[1024], int bufferSize, const std::string& username, std::string password);
std::string decryptData(const std::string& data, const std::string& key);
std::string encryptData(const std::string& data, const std::string& key);
const int bufferSize = 10240;

int main()
{
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed.\n";
        return 1;
    }
#endif

    char buffer[bufferSize];
    char outMessage[bufferSize];

    std::cout << "Enter server IP: ";
    std::string serverIP;
    std::cin >> serverIP;

    std::cout << "Enter server port: ";
    int serverPort;
    std::cin >> serverPort;

    std::cout << "Enter your username: ";
    std::string username;
    std::cin >> username;

    std::cout << "Enter encryption password: ";
    std::string encrPSWD;
    std::cin >> encrPSWD;

    int clientSocket = createClientSocket(serverIP, serverPort);

    int bytesRead = recv(clientSocket, buffer, sizeof(buffer), 0);
    if (bytesRead > 0)
    {
        buffer[bytesRead] = '\0';
        std::cout << buffer << "\n";
    }
    else
    {
        std::cerr << "Error receiving message\n";
    }

    std::thread first(receiveMessages, clientSocket, bufferSize, encrPSWD);
    std::thread second(sendMessage, clientSocket, outMessage, bufferSize, username, encrPSWD);

    first.join();
    second.join();

#ifdef _WIN32
    closesocket(clientSocket);
    WSACleanup();
#else
    close(clientSocket);
#endif
}

// error handler
void handleSystemCallError(std::string errorMsg)
{
#ifdef _WIN32
    std::cout << errorMsg << ", WSA error code: " << WSAGetLastError() << "\n";
#else
    std::cout << errorMsg << ", errno: " << errno << "\n";
#endif
    exit(EXIT_FAILURE);
}

// creates a client socket
int createClientSocket(const std::string& serverIP, int serverPort)
{
#ifdef _WIN32
    SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientSocket == INVALID_SOCKET)
    {
        handleSystemCallError("Failed to create socket");
    }
#else
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == -1)
    {
        handleSystemCallError("Failed to create socket");
    }
#endif

    // Set up the server address structure
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(serverPort);

    // check IP validity by converting it to binary
    if (inet_pton(AF_INET, serverIP.c_str(), &serverAddress.sin_addr) <= 0)
    {
        handleSystemCallError("Invalid address or address not supported\n");
#ifdef _WIN32
        closesocket(clientSocket);
#else
        close(clientSocket);
#endif
        exit(EXIT_FAILURE);
    }

    // connect to server
    if (connect(clientSocket, reinterpret_cast<struct sockaddr*>(&serverAddress), sizeof(serverAddress)) == -1)
    {
        handleSystemCallError("Error when connecting to server\n");
#ifdef _WIN32
        closesocket(clientSocket);
#else
        close(clientSocket);
#endif
        exit(EXIT_FAILURE);
    }

    return clientSocket;
}

// Helper function to receive a specific number of bytes
//int recvAll(int socket, char* buffer, int length)
//{
//    int totalBytesReceived = 0;
//    while (totalBytesReceived < length)
//    {
//        int bytesReceived = recv(socket, buffer + totalBytesReceived, length - totalBytesReceived, 0);
//        if (bytesReceived <= 0)
//        {
//            return bytesReceived;  // Error or connection closed
//        }
//        totalBytesReceived += bytesReceived;
//    }
//    return totalBytesReceived;
//}

// receive messages from server
void receiveMessages(int clientSocket, int bufferSize, std::string password)
{
    char receiveBuffer[10240];

    while (true)
    {
        int bytesRead = recv(clientSocket, receiveBuffer, bufferSize -1, 0);

        if (bytesRead > 0)
        {
            receiveBuffer[bytesRead] = '\0';
            std::cout << bytesRead << "\n";
            std::string decryptedData = decryptData(receiveBuffer, password);
            std::cout << decryptedData << "\n";
        }
    }
}

// send messages to server
void sendMessage(int clientSocket, char outMessage[bufferSize], int bufferSize, const std::string& username, std::string password)
{
    while (true)
    {
        std::string userMessage;
        std::getline(std::cin, userMessage);

        if (userMessage.length() > bufferSize - username.length() - 3) // Considering space for ": " and null terminator
        {
            std::cout << "Warning: Message is too long. Please keep it within " << bufferSize - username.length() - 3 << " characters.\n";
            continue;
        }
        if (!userMessage.empty())
        {
            userMessage = username + ": " + userMessage;

            std::string encryptedData = encryptData(userMessage, password); // Create a string with the received data
            std::cout << encryptedData.size() << "\n";

            send(clientSocket, encryptedData.c_str(), encryptedData.length() + 1, 0);
        }
    }
}

std::string decryptData(const std::string& data, const std::string& password)
{
    // Generate a 32-byte key from the password using SHA256
    unsigned char key[32];
    SHA256(reinterpret_cast<const unsigned char*>(password.c_str()), password.length(), key);

    // Use the first 16 bytes of the key as the IV (for testing purposes)
    std::string iv(reinterpret_cast<char*>(key), 16);

    // Set up the OpenSSL decryption context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    // Initialize the decryption operation with AES 256 CBC and the generated key and IV
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, reinterpret_cast<const unsigned char*>(iv.c_str())))
    {
        std::cerr << "Error initializing decryption\n";
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    int len;
    int plaintext_len;
    unsigned char* plaintext = new unsigned char[data.length() + EVP_CIPHER_block_size(EVP_aes_256_cbc())];

    // Perform the decryption
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, reinterpret_cast<const unsigned char*>(data.c_str()), data.length()))
    {
        std::cerr << "Error during decryption\n";
        EVP_CIPHER_CTX_free(ctx);
        delete[] plaintext;
        return "";
    }
    plaintext_len = len;

    // Finalize the decryption
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0)
    {
        std::cerr << "Error finalizing decryption\n";
        EVP_CIPHER_CTX_free(ctx);
        delete[] plaintext;
        return "";
    }
    plaintext_len += len;

    // Clean up the context
    EVP_CIPHER_CTX_free(ctx);

    // Convert the decrypted data to a string
    std::string decryptedData(reinterpret_cast<char*>(plaintext), plaintext_len);

    // Clean up allocated memory
    delete[] plaintext;

    return decryptedData;
}

std::string encryptData(const std::string& data, const std::string& password)
{
    // Generate a 32-byte key from the password using SHA256
    unsigned char key[32];
    SHA256(reinterpret_cast<const unsigned char*>(password.c_str()), password.length(), key);

    // Use the first 16 bytes of the key as the IV (for testing purposes)
    std::string iv(reinterpret_cast<char*>(key), 16);

    // Set up the OpenSSL encryption context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    // Initialize the encryption operation with AES 256 CBC and the generated key and IV
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, reinterpret_cast<const unsigned char*>(iv.c_str())))
    {
        std::cerr << "Error initializing encryption\n";
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    int len;
    int ciphertext_len;
    unsigned char* ciphertext = new unsigned char[data.length() + EVP_CIPHER_block_size(EVP_aes_256_cbc())];

    // Perform the encryption
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, reinterpret_cast<const unsigned char*>(data.c_str()), data.length()))
    {
        std::cerr << "Error during encryption\n";
        EVP_CIPHER_CTX_free(ctx);
        delete[] ciphertext;
        return "";
    }
    ciphertext_len = len;

    // Finalize the encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) <= 0)
    {
        std::cerr << "Error finalizing encryption\n";
        EVP_CIPHER_CTX_free(ctx);
        delete[] ciphertext;
        return "";
    }
    ciphertext_len += len;

    // Clean up the context
    EVP_CIPHER_CTX_free(ctx);

    // Convert the encrypted data to a string
    std::string encryptedData(reinterpret_cast<char*>(ciphertext), ciphertext_len);

    // Clean up allocated memory
    delete[] ciphertext;

    return encryptedData;
}
