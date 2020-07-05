//
// Created by ywt on 2020/5/5.
//

#ifndef BLACKSHEEP_REMOTE_SERVER_H
#define BLACKSHEEP_REMOTE_SERVER_H

#include "public_include.h"

namespace bs {

class RemoteServer {
public:
    ~RemoteServer();

    static RemoteServer& instance() {
        if (_s_instance == nullptr) {
            _s_instance = new RemoteServer();
        }
        return *_s_instance;
    }

    int start();
private:
    RemoteServer();

    int do_accept();

    void accept_handle(boost::system::error_code ec, boost::asio::ip::tcp::socket socket);

    int do_udp_recv();

    void udp_recv_handle(boost::system::error_code ec, std::size_t len);

private:
    boost::asio::io_context _io_context;
    boost::asio::ip::tcp::acceptor _acceptor;

    boost::asio::ip::udp::socket _udp_socket;
    std::string _udp_buffer;
    boost::asio::ip::udp::endpoint _sender_ep;

    static RemoteServer* _s_instance;
};

}  // namespace bs

#endif //BLACKSHEEP_REMOTE_SERVER_H
