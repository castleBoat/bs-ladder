//
// Created by ywt on 2020/5/5.
//

#ifndef BLACKSHEEP_REMOTE_SERVER_H
#define BLACKSHEEP_REMOTE_SERVER_H

#include "public_include.h"

namespace bs {

class RemoteServer {
public:
    static RemoteServer& instance() {
        return _s_instance;
    }

    int start();
private:
    RemoteServer();

    int do_accept();

    void accept_handle(boost::system::error_code ec, boost::asio::ip::tcp::socket socket);

private:
    boost::asio::io_context _io_context;
    boost::asio::ip::tcp::acceptor _acceptor;

    static RemoteServer _s_instance;
};

}  // namespace bs

#endif //BLACKSHEEP_REMOTE_SERVER_H
