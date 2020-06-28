//
// Created by ywt on 2020/5/5.
//

#ifndef BLACKSHEEP_LOCAL_SERVER_H
#define BLACKSHEEP_LOCAL_SERVER_H

#include <boost/asio.hpp>

namespace bs {

class LocalServer {
public:
    static LocalServer& instance() {
        return _s_instance;
    }

    int start();
private:

    LocalServer();

    int do_accept();

    void accept_handle(boost::system::error_code ec, boost::asio::ip::tcp::socket socket);

private:
    boost::asio::io_context _io_context;
    boost::asio::ip::tcp::acceptor _acceptor;

    static LocalServer _s_instance;
};

}  // namesapce bs

#endif //BLACKSHEEP_LOCAL_SERVER_H
