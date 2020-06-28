//
// Created by ywt on 2020/5/5.
//

#include "remote_server.h"
#include "bs.pb.h"

DECLARE_int32(remote_port);
DECLARE_string(passwd);

namespace bs {

using boost::asio::ip::tcp;
using std::placeholders::_1;
using std::placeholders::_2;

class RemoteSession : public std::enable_shared_from_this<RemoteSession> {
public:
    RemoteSession(tcp::socket socket, boost::asio::io_context* io_context) :
            _io_context(io_context), _socket(std::move(socket)), _target_socket(*io_context),
            _state(CLIENT_AUTH), _target_atyp(bs::ATYP_NONE), _target_port(0),
            _local_read_buff(DEFAULT_BUFF_SIZE), _local_read_len(0),
            _local_write_len(0),
            _target_read_buff(DEFAULT_BUFF_SIZE), _target_read_len(0),
            _target_write_len(0), _forward_to_local_fin(true), _forward_to_target_fin(true), _logid(0) {
        _client_ep = _socket.remote_endpoint();
        _local_write_buff.reserve(DEFAULT_BUFF_SIZE);
        _target_write_buff.reserve(DEFAULT_BUFF_SIZE);
    }

    int start();
private:
    // client socket read handle
    void local_read_handle(boost::system::error_code ec, std::size_t len);

    int try_parse_auth(const char* data, size_t len);

    int auth_process(const char* data, size_t len);

    int connect_target();

    void connect_target_handle(boost::system::error_code ec);

    void do_local_read();

    void do_local_write();

    void do_target_read();

    void do_target_write();

    void local_write_handle(boost::system::error_code ec, std::size_t len);

    int client_auth_response(bs::BsResErr err_no = bs::NO_ERR);

    void target_read_handle(boost::system::error_code ec, size_t len);

    void target_write_handle(boost::system::error_code ec, size_t len);

    std::string addr_to_string();

private:
    enum RemoteSessionState {
        SOCKS_AUTH = 0,
        SOCKS_CONNECTING = 1,
        SOCKS_DISCONNECTED = 2,
        REMOTE_CONNECTING = 3,
        REMOTE_CONNECTED = 4,
        REMOTE_DISCONNECTED = 5,
        CLIENT_AUTH = 6,
        TARGET_CONNECTING = 7,
        TARGET_FORWARD = 8
    };

    boost::asio::io_context* _io_context;
    tcp::socket _socket;
    tcp::endpoint _client_ep;
    tcp::socket _target_socket;
    tcp::endpoint _target_ep;
    RemoteSessionState _state;
    std::shared_ptr<RemoteSession> _self_container;

    bs::AType _target_atyp;
    std::string _target_addr;
    int _target_port;

    std::vector<char> _local_read_buff;
    size_t _local_read_len;
    std::string _local_write_buff;
    size_t _local_write_len;

    std::vector<char> _target_read_buff;
    size_t _target_read_len;
    std::string _target_write_buff;
    size_t _target_write_len;

    bool _forward_to_local_fin;
    bool _forward_to_target_fin;

    std::size_t _logid;
};

int RemoteSession::start() {
    _self_container = shared_from_this();

    do_local_read();
    return 0;
}

void RemoteSession::local_read_handle(boost::system::error_code ec, std::size_t len) {
    if (ec) {
        LOG(ERROR) << "[local_read_handle][logid:" << _logid
            << "][ec:" << ec.message()
            << "][client:" << _client_ep.address().to_string()
            << "] read local socket failed";
        // _self_container.reset();
        return;
    }

    _local_read_len += len;

    int ret = 0;
    int processed_len = 0;
    while (processed_len < _local_read_len) {
        if (CLIENT_AUTH == _state) {
            LOG(INFO) << "[RemoteSession::local_read_handle][logid:" << _logid
                << "][state:CLIENT_AUTH][len:" << len << "]";
            // ltv password auth
            int res = try_parse_auth(
                    &_local_read_buff[processed_len], _local_read_len - processed_len);
            if (res != 0) {
                LOG(INFO) << "not enough client auth data";
                break;
            }
            int consume_len = auth_process(&_local_read_buff[processed_len],
                                           _local_read_len - processed_len);
            if (consume_len < 0) {
                client_auth_response(bs::AUTH_FAILED);
                LOG(ERROR) << "[process_sock][logid:" << _logid << "] fail to auth_process";
                ret = -1;
                break;
            }

            // 建立与 target 的连接后返回 client auth 的 response
            ret = connect_target();
            if (ret != 0) {
                client_auth_response(bs::TARGET_CONNECT_ERR);
                LOG(ERROR) << "[RemoteSession::local_read_handle] fail to connect target server";
                break;
            }

            processed_len += consume_len;
            // _state = TARGET_CONNECTED;
        } else if (TARGET_FORWARD == _state) {
            LOG(INFO) << "[RemoteSession::local_read_handle][logid:" << _logid
                << "][state:TARGET_FORWARD][len:" << len << "]";
            //  target 连接已经建立，这是正式数据
            _target_write_buff.clear();
            _target_write_buff.append(&_local_read_buff[processed_len], _local_read_len - processed_len);
            do_target_write();
            _forward_to_target_fin = false;

            processed_len = _local_read_len;
        }
    }

    LOG(INFO) << "[RemoteSession::local_read_handle][logid:" << _logid
        << "][processed_len:" << processed_len << "]";
    if (ret != 0) {
        // _self_container.reset();
        return;
    }

    if (0 < processed_len && processed_len < _local_read_len) {
        memmove(&_local_read_buff[0], &_local_read_buff[processed_len], _local_read_len - processed_len);
    }
    _local_read_len -= processed_len;

    // do_local_read();
}

int RemoteSession::try_parse_auth(const char* data, size_t len) {
    if (len <= sizeof(int32_t)) {
        return -1;
    }
    int32_t param_len = 0;
    memcpy(&param_len, data, sizeof(int32_t));

    LOG(INFO) << "[param_len:" << param_len << "][len:" << len;
    if (len < sizeof(int32_t) + param_len) {
        return -1;
    }

    return 0;
}

int RemoteSession::auth_process(const char* data, size_t len) {
    int32_t param_len = 0;

    memcpy(&param_len, data, sizeof(int32_t));

    uint8_t type = data[4];
    if (type != PARAM_PACKAGE) {
        LOG(ERROR) << "auth_process][type:" << type << "] client auth type error";
        return -1;
    }

    bs::BsRequest req;
    req.ParseFromArray(&data[5], param_len - 1);

    if (req.passwd() != FLAGS_passwd) {
        LOG(ERROR) << "[auth_process][passwd:" << req.passwd()
            << "] client auth passwd error";
        return -1;
    }

    _target_atyp = req.atyp();
    _target_addr.append(req.target_addr().data(), req.target_addr().size());
    _target_port = req.target_port();
    _logid = req.logid();

//    if (bs::IP_V4 == _target_atyp) {
//
//    } else if (bs::DOMAINAME == _target_atyp) {
//
//    } else if (bs::IP_V6 == _target_atyp) {
//
//    } else {
//        LOG(ERROR) << "[auth_process][atyp" << _target_atyp
//            << "] atype error";
//        return -1;
//    }

    LOG(INFO) << "[RemoteSession::auth_process][logid:" << _logid
        << "][atyp:" << (int)_target_atyp
        << "][target_addr:" << addr_to_string()
        << "][target_port:" << (int)_target_port << "]";
    return param_len + sizeof(int32_t);
}

int RemoteSession::connect_target() {
    tcp::endpoint target_ep;

    if (bs::IP_V4 == _target_atyp) {
        boost::asio::ip::address_v4::bytes_type n_v4_bytes;
        memcpy(n_v4_bytes.data(), _target_addr.data(), 4);
        boost::asio::ip::address_v4 addr(n_v4_bytes);
        target_ep = tcp::endpoint(boost::asio::ip::address(addr), _target_port);
    } else if (bs::IP_V6 == _target_atyp) {
        boost::asio::ip::address_v6::bytes_type n_v6_bytes;
        memcpy(n_v6_bytes.data(), _target_addr.data(), 16);
        boost::asio::ip::address_v6 addr(n_v6_bytes);
        target_ep = tcp::endpoint(boost::asio::ip::address(addr), _target_port);
    } else {
        // TODO dns query here may exists some problems
        tcp::resolver resolver(*_io_context);
        if (_target_port == 80) {
            target_ep = resolver.resolve(_target_addr, "http").begin()->endpoint();
        } else if (_target_port == 443) {
            target_ep = resolver.resolve(_target_addr, "https").begin()->endpoint();
        } else {
            LOG(ERROR) << "[connect_target][logid:" << _logid
                << "][target addr:" << _target_addr << "][port:" << _target_port
                << "] port != 80 && port != 443fail to dns query";
        }
    }

    LOG(INFO) << "[connect_target][logid:" << _logid
              << "][real target addr:" << target_ep.address().to_string() << "][port:" << _target_port
              << "] async connecting";

    _target_socket.async_connect(target_ep,
            std::bind(&RemoteSession::connect_target_handle, this, _1));

    _target_ep = target_ep;

    return 0;
}

void RemoteSession::connect_target_handle(boost::system::error_code ec) {
    if (ec) {
        LOG(ERROR) << "[RemoteSession::connect_target_handle][ec:" << ec.message()
            << "][target:" << addr_to_string() << "] fail to connect";
        return;
    }

    LOG(INFO) << "[connect_target_handle][logid:" << _logid
        << "] target connect successfully";
    assert(_state == CLIENT_AUTH);

    client_auth_response();
}

void RemoteSession::do_local_read() {
    _socket.async_read_some(boost::asio::buffer(&_local_read_buff[_local_read_len], _local_read_buff.size() - _local_read_len),
            std::bind(&RemoteSession::local_read_handle, this, _1, _2));
}

void RemoteSession::do_local_write() {
    _socket.async_write_some(boost::asio::buffer(_local_write_buff.data(), _local_write_buff.size()),
            std::bind(&RemoteSession::local_write_handle, this, _1, _2));
}

void RemoteSession::do_target_read() {
    _target_socket.async_read_some(boost::asio::buffer(&_target_read_buff[_target_read_len], _target_read_buff.size() - _target_read_len),
                        std::bind(&RemoteSession::target_read_handle, this, _1, _2));
}

void RemoteSession::do_target_write() {
    _target_socket.async_write_some(boost::asio::buffer(_target_write_buff.data(), _target_write_buff.size()),
            std::bind(&RemoteSession::target_write_handle, this, _1, _2));
}

void RemoteSession::local_write_handle(boost::system::error_code ec, std::size_t len) {
    if (ec) {
        LOG(ERROR) << "[RemoteSession::local_write_handle][logid:" << _logid
            << "][ec:" << ec.message() << "] fail to write to client";
        return;
    }
    LOG(INFO) << "[RemoteSession::local_write_handle][logid:" << _logid
        << "][len:" << len << "]";

    if (CLIENT_AUTH == _state) {
        _state = TARGET_FORWARD;
        do_local_read();
        do_target_read();
    }

    if (!_forward_to_local_fin) {
        _forward_to_local_fin = false;
        do_target_read();
    }
}

int RemoteSession::client_auth_response(bs::BsResErr err_no) {
    bs::BsResponse res;
    res.set_err_no(err_no);
    res.set_err_msg("ok");
    res.set_atyp(_target_atyp);
    // res.set_target_addr(_target_ep.address().to_string());  // response network order bytes
    if (_target_ep.address().is_v4()) {
        res.set_target_addr(_target_ep.address().to_v4().to_bytes().data(),
                _target_ep.address().to_v4().to_bytes().size());
    } else {
        res.set_target_addr(_target_ep.address().to_v6().to_bytes().data(),
                _target_ep.address().to_v6().to_bytes().size());
    }
    res.set_target_port(_target_ep.port());

    std::string res_cnt;
    res.SerializeToString(&res_cnt);
    int32_t param_len = res_cnt.size() + 1;
    uint8_t type = PARAM_PACKAGE;

    _local_write_buff.clear();
    _local_write_buff.append((char*)&param_len, sizeof(param_len));
    _local_write_buff.append((char*)&type, sizeof(type));
    _local_write_buff.append(res_cnt.data(), res_cnt.size());

    LOG(INFO) << "[RemoteSession::client_auth_response][logid:" << _logid
        << "][real_target_addr:" << _target_ep.address().to_string()
        << "][real_target_port:" << _target_ep.port() << "]";

    do_local_write();

    return 0;
}

void RemoteSession::target_read_handle(boost::system::error_code ec, size_t len) {
    if (ec) {
        LOG(ERROR) << "[RemoteSession::target_read_handle][logid:" << _logid
            << "][ec:" << ec.message() << "] target socket error";
        // _self_container.reset();
        return;
    }

    LOG(INFO) << "[RemoteSession::target_read_handle][logid:" << _logid
        << "][len:" << len << "]";
    assert(_state == TARGET_FORWARD);

    _local_write_buff.clear();
    _local_write_buff.append(_target_read_buff.data(), len);
    do_local_write();
    _forward_to_local_fin = false;
}

void RemoteSession::target_write_handle(boost::system::error_code ec, size_t len) {
    if (ec) {
        LOG(ERROR) << "[RemoteSession::target_write_handle][logid:" << _logid
            << "][ec:" << ec.message() << "] fail to write target";
        return;
    }
    LOG(INFO) << "[RemoteSession::target_write_handle][logid:" << _logid
        << "][len:" << len << "]";

    assert(_state == TARGET_FORWARD);

    // do_target_read();

    if (!_forward_to_target_fin) {
        _forward_to_target_fin = true;
        do_local_read();
    }
}


std::string RemoteSession::addr_to_string() {
    std::string addr_str;

    if (_target_atyp == IP_V4) {
        boost::asio::ip::address_v4::bytes_type n_v4_bytes;
        memcpy(n_v4_bytes.data(), _target_addr.data(), 4);
        boost::asio::ip::address_v4 addr(n_v4_bytes);
        addr_str = addr.to_string();
    } else if (_target_atyp == DOMAINAME) {
        addr_str = _target_addr;
    } else if (_target_atyp == IP_V6) {
        boost::asio::ip::address_v6::bytes_type n_v6_bytes;
        memcpy(n_v6_bytes.data(), _target_addr.data(), 16);
        boost::asio::ip::address_v6 addr(n_v6_bytes);
        addr_str = addr.to_string();
    } else {
        LOG(ERROR) << "_atyp not determined";
        return "";
    }
    return addr_str;
}

RemoteServer RemoteServer::_s_instance;

RemoteServer::RemoteServer() : _io_context(),
    _acceptor(_io_context, tcp::endpoint(tcp::v4(), FLAGS_remote_port)) {
}

int RemoteServer::start() {
    int ret = 0;

    do {
        ret = do_accept();
        if (0 != ret) {
            LOG(ERROR) << "RemoteServer fail to init";
            break;
        }

        LOG(INFO) << "remote server start, port:" << FLAGS_remote_port << ", enjoy yourself ...";
        _io_context.run();
    } while (false);

    return ret;
}

int RemoteServer::do_accept() {
    _acceptor.async_accept(std::bind(&RemoteServer::accept_handle, this, _1, _2));
    return 0;
}

void RemoteServer::accept_handle(boost::system::error_code ec, boost::asio::ip::tcp::socket socket) {
    if (ec) {
        LOG(ERROR) << "[RemoteServer::accept_handle][ec:" << ec.message()
            << "] fail to accept socket";
        return;
    }
    tcp::endpoint remote_ep = socket.remote_endpoint();
    LOG(INFO) << "new accept socket, remote:" << remote_ep.address().to_string();
    std::make_shared<RemoteSession>(std::move(socket), &_io_context)->start();

    do_accept();  // need call do_accept again
}


}