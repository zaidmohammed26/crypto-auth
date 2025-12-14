#include <iostream>
#include <boost/asio.hpp>
#include <vector>

#include "auth.pb.h"
#include "pb_encode.h"
#include "pb_decode.h"
#include "CryptoHelper.hpp"

using boost::asio::ip::tcp;


const std::vector<uint8_t> KNOWN_CLIENT_PUBKEY = {
    0x02,                                           
    0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 
    0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
    0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
    0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98
};
class Session : public std::enable_shared_from_this<Session> {
public:
    Session(tcp::socket socket) : socket_(std::move(socket)) {}

    void start() {
        do_read();
    }

private:
    void do_read() {
        auto self(shared_from_this());
        socket_.async_read_some(boost::asio::buffer(data_, max_length),
            [this, self](boost::system::error_code ec, std::size_t length) {
                if (!ec) {
                    handle_message(length);
                }
            });
    }

    void handle_message(std::size_t length) {
        AuthMessage msg = AuthMessage_init_zero;
        pb_istream_t stream = pb_istream_from_buffer(data_, length);

        if (!pb_decode(&stream, AuthMessage_fields, &msg)) {
            std::cerr << "[Server] Decode failed\n";
            return;
        }

        if (msg.which_payload == AuthMessage_init_tag) {
            std::cout << "[Server] Received Init from Serial: " << msg.payload.init.serial_id << "\n";

            int32_t serial = msg.payload.init.serial_id;
            std::vector<uint8_t> serial_bytes(sizeof(serial));
            std::memcpy(serial_bytes.data(), &serial, sizeof(serial));
            
            auto hash = CryptoHelper::sha256(serial_bytes);
            std::vector<uint8_t> sig(msg.payload.init.signature.bytes, msg.payload.init.signature.bytes + msg.payload.init.signature.size);
            
            if (CryptoHelper::verify(KNOWN_CLIENT_PUBKEY, hash, sig)) {
                std::cout << "[Server] Verified! Sending Challenge...\n";
                send_challenge();
            } else {
                std::cout << "[Server] Verification Failed.\n";
            }
        }
        else if (msg.which_payload == AuthMessage_response_tag) {
            std::cout << "[Server] Received Challenge Response.\n";
            auto hash = CryptoHelper::sha256(last_challenge_);
            std::vector<uint8_t> sig(msg.payload.response.signature.bytes, msg.payload.response.signature.bytes + msg.payload.response.signature.size);

            if (CryptoHelper::verify(KNOWN_CLIENT_PUBKEY, hash, sig)) {
                std::cout << "[Server] CLIENT AUTHENTICATED!\n";
                send_result(true);
            } else {
                std::cout << "[Server] Challenge Failed.\n";
                send_result(false);
            }
        }
    }

    void send_challenge() {
        last_challenge_ = CryptoHelper::generateRandom32();
        AuthMessage msg = AuthMessage_init_zero;
        msg.which_payload = AuthMessage_challenge_tag;
        msg.payload.challenge.random_data.size = last_challenge_.size();
        std::memcpy(msg.payload.challenge.random_data.bytes, last_challenge_.data(), last_challenge_.size());
        send_protobuf(msg);
    }

    void send_result(bool success) {
        AuthMessage msg = AuthMessage_init_zero;
        msg.which_payload = AuthMessage_result_tag;
        msg.payload.result.success = success;
        std::string txt = success ? "Welcome Client!" : "Auth Failed.";
        strncpy((char*)msg.payload.result.message, txt.c_str(), sizeof(msg.payload.result.message));
        send_protobuf(msg);
    }

    void send_protobuf(const AuthMessage& msg) {
    auto buffer = std::make_shared<std::vector<uint8_t>>(256);
    
    pb_ostream_t stream = pb_ostream_from_buffer(buffer->data(), buffer->size());
    pb_encode(&stream, AuthMessage_fields, &msg);
    
    buffer->resize(stream.bytes_written);

    auto self(shared_from_this());
    
    boost::asio::async_write(socket_, boost::asio::buffer(*buffer),
        [this, self, buffer](boost::system::error_code ec, std::size_t len) {
            if (!ec) do_read();
        });
}

    tcp::socket socket_;
    enum { max_length = 1024 };
    uint8_t data_[max_length];
    std::vector<uint8_t> last_challenge_;
};

class Server {
public:
    Server(boost::asio::io_context& io_context, short port)
        : acceptor_(io_context, tcp::endpoint(tcp::v4(), port)) {
        do_accept();
    }
private:
    void do_accept() {
        acceptor_.async_accept(
            [this](boost::system::error_code ec, tcp::socket socket) {
                if (!ec) std::make_shared<Session>(std::move(socket))->start();
                do_accept();
            });
    }
    tcp::acceptor acceptor_;
};

int main() {
    try {
        boost::asio::io_context io_context;
        Server s(io_context, 8080);
        std::cout << "Server running on port 8080...\n";
        io_context.run();
    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
    }
    return 0;
}