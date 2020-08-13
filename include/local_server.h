//
// Created by ywt on 2020/5/5.
//

#ifndef BLACKSHEEP_LOCAL_SERVER_H
#define BLACKSHEEP_LOCAL_SERVER_H

#include <memory>
#include <boost/asio.hpp>

namespace bs {

class LocalServer {
public:
    ~LocalServer();

    static LocalServer& instance() {
        static LocalServer _s_instance;
        return _s_instance;
    }

    int start();
private:

    LocalServer();

    int do_accept();

    int do_udp_recv();

    void accept_handle(boost::system::error_code ec, boost::asio::ip::tcp::socket socket);

    void udp_recv_handle(boost::system::error_code ec, std::size_t len);

private:
    boost::asio::io_context _io_context;
    boost::asio::ip::tcp::acceptor _acceptor;
    boost::asio::ip::udp::socket _udp_socket;
    std::string _udp_buffer;
    boost::asio::ip::udp::endpoint _sender_ep;
};

}  // namesapce bs

#endif //BLACKSHEEP_LOCAL_SERVER_H
