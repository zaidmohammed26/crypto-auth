#include <iostream>
#include <boost/asio.hpp>
#include <vector>

#include "auth.pb.h"
#include "pb_encode.h"
#include "pb_decode.h"
#include "CryptoHelper.hpp"

using boost::asio::ip::tcp;

const std::vector<uint8_t> MY_PRIVATE_KEY = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

void send_message(tcp::socket& socket, const AuthMessage& msg) {
    uint8_t buffer[256];
    pb_ostream_t stream = pb_ostream_from_buffer(buffer, sizeof(buffer));
    
    if (!pb_encode(&stream, AuthMessage_fields, &msg)) return;
    boost::asio::write(socket, boost::asio::buffer(buffer, stream.bytes_written));
}

AuthMessage read_message(tcp::socket& socket) {
    uint8_t buffer[256];
    boost::system::error_code error;
    size_t len = socket.read_some(boost::asio::buffer(buffer), error);
    
    if (error) return AuthMessage_init_zero;

    AuthMessage msg = AuthMessage_init_zero;
    pb_istream_t stream = pb_istream_from_buffer(buffer, len);
    pb_decode(&stream, AuthMessage_fields, &msg);
    return msg;
}

int main() {
    try {
        boost::asio::io_context io_context;
        tcp::socket socket(io_context);
        tcp::resolver resolver(io_context);
        boost::asio::connect(socket, resolver.resolve("127.0.0.1", "8080"));
        std::cout << "[Client] Connected.\n";

        int32_t my_serial = 12345;
        std::vector<uint8_t> serial_bytes(sizeof(my_serial));
        std::memcpy(serial_bytes.data(), &my_serial, sizeof(my_serial));
        auto hash1 = CryptoHelper::sha256(serial_bytes);
        auto sig1 = CryptoHelper::sign(hash1, MY_PRIVATE_KEY);

        AuthMessage initMsg = AuthMessage_init_zero;
        initMsg.which_payload = AuthMessage_init_tag;
        initMsg.payload.init.serial_id = my_serial;
        initMsg.payload.init.signature.size = sig1.size();
        std::memcpy(initMsg.payload.init.signature.bytes, sig1.data(), sig1.size());
        send_message(socket, initMsg);

        AuthMessage response = read_message(socket);
        if (response.which_payload == AuthMessage_challenge_tag) {
            std::cout << "[Client] Got Challenge. Signing...\n";
            std::vector<uint8_t> challenge(
                response.payload.challenge.random_data.bytes, 
                response.payload.challenge.random_data.bytes + response.payload.challenge.random_data.size);

            auto hash2 = CryptoHelper::sha256(challenge);
            auto sig2 = CryptoHelper::sign(hash2, MY_PRIVATE_KEY);

            AuthMessage respMsg = AuthMessage_init_zero;
            respMsg.which_payload = AuthMessage_response_tag;
            respMsg.payload.response.signature.size = sig2.size();
            std::memcpy(respMsg.payload.response.signature.bytes, sig2.data(), sig2.size());
            send_message(socket, respMsg);
        }

        AuthMessage result = read_message(socket);
        if (result.which_payload == AuthMessage_result_tag) {
            std::cout << "[Client] Server Says: " << result.payload.result.message << "\n";
        }

    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
    }
    return 0;
}