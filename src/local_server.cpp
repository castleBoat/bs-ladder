//
// Created by ywt on 2020/5/5.
//

#include "public_include.h"
#include "local_server.h"
#include "socks5.h"
#include "bs.pb.h"
#include "utility.h"

DECLARE_int32(local_port);
DECLARE_string(remote_addr);
DECLARE_int32(remote_port);
DECLARE_string(passwd);

namespace bs {

using boost::asio::ip::tcp;
using std::placeholders::_1;
using std::placeholders::_2;

// TODO 把状态机做在 Session 里，连接 remote 也是用异步

class Session : public std::enable_shared_from_this<Session> {
public:
    Session(tcp::socket socket, boost::asio::io_context* io_context) :
            _io_context(io_context), _socket(std::move(socket)), _remote_socket(*io_context),
            _state(SOCKS_AUTH), _real_target_atyp(bs::ATYP_NONE), _real_target_port(0),
            _local_read_buff(DEFAULT_BUFF_SIZE), _local_read_len(0),
            _local_write_len(0),
            _remote_read_buff(DEFAULT_BUFF_SIZE), _remote_read_len(0),
            _remote_write_len(0), _forward_to_local_fin(true), _forward_to_remote_fin(true),
            _logid(0) {
        _local_write_buff.reserve(DEFAULT_BUFF_SIZE);
        _remote_write_buff.reserve(DEFAULT_BUFF_SIZE);

        _logid = gen_logid();
        LOG(INFO) << "[Session::Session][logid:" << _logid << "]";
    }

    int start();
private:
    void do_local_read();

    void do_local_write();

    void local_read_handle(boost::system::error_code ec, std::size_t len);

    void local_write_handle(boost::system::error_code ec, std::size_t len);

    int socks_auth_response();

    int socks_req_response(Socks5::REP res_err = Socks5::SUCCEEDED);

    int connect_remote();

    void do_remote_write();

    void do_remote_read();

    void remote_connect_handle(boost::system::error_code ec);

    void remote_write_handle(boost::system::error_code ec, size_t len);

    int prepare_request();

    void remote_read_handle(boost::system::error_code ec, size_t len);

    int process_remote_param(const char *data, size_t len);

private:
    enum SessionState {
        SOCKS_AUTH = 0,
        SOCKS_CONNECTING = 1,
        SOCKS_DISCONNECTED = 2,
        REMOTE_CONNECTING = 3,
        REMOTE_CONNECTED = 4,
        REMOTE_DISCONNECTED = 5,
        REMOTE_AUTH = 6,
        REMOTE_FORWARD = 7,
    };

    boost::asio::io_context* _io_context;
    tcp::socket _socket;
    tcp::socket _remote_socket;
    tcp::endpoint _remote_ep;
    SessionState _state;
    Socks5 _socks5;
    std::shared_ptr<Session> _self_container;

    bs::AType _real_target_atyp;
    std::string _real_target_addr;
    int _real_target_port;

    std::vector<char> _local_read_buff;
    size_t _local_read_len;
    std::string _local_write_buff;
    size_t _local_write_len;

    std::vector<char> _remote_read_buff;
    size_t _remote_read_len;
    std::string _remote_write_buff;
    size_t _remote_write_len;

    bool _forward_to_remote_fin;
    bool _forward_to_local_fin;

    std::size_t _logid;
};

int Session::start() {
    _self_container = shared_from_this();

    do_local_read();
    return 0;
}

void Session::do_local_read() {
    _socket.async_read_some(
        boost::asio::buffer(&_local_read_buff[_local_read_len], _local_read_buff.size() - _local_read_len),
        std::bind(&Session::local_read_handle, this, _1, _2));
}

void Session::do_local_write() {
    _socket.async_write_some(
            boost::asio::buffer(_local_write_buff.data(), _local_write_buff.size()),
            std::bind(&Session::local_write_handle, this, _1, _2));
}

void Session::local_read_handle(boost::system::error_code ec, std::size_t len) {
    if (ec) {
        LOG(ERROR) << "[Session::local_read_handle][logid:" << _logid
            << "][ec:" << ec.message() << "] read local socket failed";
        // TODO local end of file close normally, when to dtor the object
        // _self_container.reset();
        return;
    }

    _local_read_len += len;

    int ret = 0;
    int processed_len = 0;
    while (processed_len < _local_read_len) {
        if (SOCKS_AUTH == _state) {
            LOG(INFO) << "[Session::local_read_handle][logid:" << _logid
                << "][state:SOCKS_AUTH][len:" << len << "]";
            int res = _socks5.try_parse_auth(
                    &_local_read_buff[processed_len], _local_read_len - processed_len);
            if (res != 0) {
                break;
            }
            int consume_len = _socks5.auth_process(&_local_read_buff[processed_len],
                                                   _local_read_len - processed_len);
            if (consume_len < 0) {
                // TODO 这里 socks 认证失败也需要 response
                LOG(ERROR) << "[local_read_handle] fail to auth_process";
                socks_auth_response();

                ret = -1;
                break;
            }

            socks_auth_response();
            processed_len += consume_len;
            break;
        } else if (SOCKS_CONNECTING == _state) {
            LOG(INFO) << "[Session::local_read_handle][logid:" << _logid
                << "][state:SOCKS_CONNECTING][len:" << len << "]";
            int res = _socks5.try_parse_req(&_local_read_buff[processed_len], _local_read_len - processed_len);
            if (res != 0) {
                LOG(INFO) << "[Session::local_read_handle] SOCKS_CONNECTING not enough data";
                ret = -1;
                break;
            }

            int consume_len = _socks5.req_process(&_local_read_buff[processed_len], _local_read_len - processed_len);
            if (consume_len < 0) {
                LOG(ERROR) << "[Session::local_read_handle] fail to req process,"
                          << " response local error response";
                socks_req_response();

                ret = -1;
                break;
            }

            processed_len += consume_len;

            connect_remote();
            break;

            // TODO 但是这里又不能 wait 阻塞住
            // 验证 remote 的回复， remote 正常连接上 target server 了。
            // 发送 Socks 连接的 response
            // socks_req_response();

            // _state = REMOTE_CONNECTED;
        } else if (REMOTE_FORWARD == _state) {
            // 与 remote server 的连接已经建立，这是正式数据
            LOG(INFO) << "[Session::local_read_handle][logid:" << _logid
                << "][state:REMOTE_FORWARD][len:" << len << "]";
            _remote_write_buff.clear();
            _remote_write_buff.append(&_local_read_buff[processed_len], _local_read_len - processed_len);
            do_remote_write();
            _forward_to_remote_fin = false;
            processed_len = _local_read_len;
        }
    }

    LOG(INFO) << "[Session::local_read_handle][logid:" << _logid
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

void Session::local_write_handle(boost::system::error_code ec, std::size_t len) {
    if (ec) {
        LOG(ERROR) << "[Session::local_write_handle][logid:" << _logid
            << "][ec:" << ec.message() << "] fail to write remote server";
        return;
    }
    LOG(INFO) << "[Session::local_write_handle][logid:" << _logid
        << "][len:" << len << "]";

    if (_state == SOCKS_AUTH) {
        _state = SOCKS_CONNECTING;
        LOG(INFO) << "state -> SOCKS_CONNECTING";
        do_local_read();
    } else if (_state == REMOTE_AUTH) {
        _state = REMOTE_FORWARD;
        LOG(INFO) << "state -> REMOTE_FORWARD";
        do_local_read();
        do_remote_read();
    } else if (_state == REMOTE_FORWARD) {
        // do_remote_read();
        if (!_forward_to_local_fin) {
            _forward_to_local_fin = true;
            do_remote_read();
        }
    }

    // do_local_read();
}

int Session::socks_auth_response() {
    _local_write_buff.clear();
    _socks5.response_auth(_local_write_buff);

    LOG(INFO) << "[socks_auth_response][logid:" << _logid
        << "][ver:" << (int)_local_write_buff[0] << "][method:" << (int)_local_write_buff[1]
        << "] send socks5 auth response";

    do_local_write();
    return 0;
}

int Session::socks_req_response(Socks5::REP res_err) {
    _local_write_buff.clear();
    _socks5.set_rep(res_err);
    _socks5.req_response(_local_write_buff);

    do_local_write();
    return 0;
}

int Session::connect_remote() {
    // TODO 目前不支持 remote server dns
    // 这里没有连接上 remote
    _remote_ep = tcp::endpoint(
            boost::asio::ip::make_address(FLAGS_remote_addr), FLAGS_remote_port);

    LOG(INFO) << "[connect_remote][logid:" << _logid
        << "][remote addr:" << _remote_ep.address().to_string()
        << "][port:" << _remote_ep.port() << "]";
    _remote_socket.async_connect(_remote_ep,
            std::bind(&Session::remote_connect_handle, this, _1));
    _state = REMOTE_CONNECTING;

    return 0;
}

void Session::do_remote_write() {
    _remote_socket.async_write_some(boost::asio::buffer(_remote_write_buff.data(), _remote_write_buff.size()),
                                    std::bind(&Session::remote_write_handle, this, _1, _2));
}

void Session::do_remote_read() {
    _remote_socket.async_read_some(
            boost::asio::buffer(&_remote_read_buff[_remote_read_len], _remote_read_buff.size() - _remote_read_len),
            std::bind(&Session::remote_read_handle, this, _1, _2));
}

void Session::remote_connect_handle(boost::system::error_code ec) {
    if (ec) {
        LOG(ERROR) << "[Session::connect_remote][ec:" << ec.message()
            << "][remote:" << _remote_ep.address().to_string()
            << "] fail to connect remote server";
        return;
    }
    LOG(INFO) << "[Session::remote_connect_handle][logid:" << _logid
        << "][remote:" << _remote_ep.address().to_string()
        << "] connect remote successfully";
    assert(_state == REMOTE_CONNECTING);
    _state = REMOTE_CONNECTED;

    prepare_request();
    do_remote_write();
}

void Session::remote_write_handle(boost::system::error_code ec, size_t len) {
    if (ec) {
        LOG(ERROR) << "[Session::remote_write_handle][logid:" << _logid
            << "][ec:" << ec.message()
            << "][remote:" << _remote_ep.address().to_string()
            << "] fail to write to remote";
        return;
    }
    LOG(INFO) << "[Session::remote_write_handle][logid:" << _logid
        << "][len:" << len << "]";

    if (_state == REMOTE_CONNECTED) {
        _state = REMOTE_AUTH;
        do_remote_read();
    }

    // do_remote_read();
    if (!_forward_to_remote_fin) {
        _forward_to_remote_fin = true;
        do_local_read();
    }
}

int Session::prepare_request() {
    bs::BsRequest req;
    req.set_passwd(FLAGS_passwd);
    req.set_atyp((bs::AType)_socks5.atyp());
    req.mutable_target_addr()->append(_socks5.target_addr().data(), _socks5.target_addr().size());
    req.set_target_port(_socks5.target_port());
    req.set_logid(_logid);

    unsigned char type = PARAM_PACKAGE;  // PARAM_TYPE
    std::string ser_str;
    req.SerializeToString(&ser_str);
    int32_t len = 1 + ser_str.size();

    _remote_write_buff.clear();
    _remote_write_buff.append((char*)&len, sizeof(len));
    _remote_write_buff.push_back(type);
    _remote_write_buff.append(ser_str.data(), ser_str.size());

    return 0;
}

void Session::remote_read_handle(boost::system::error_code ec, size_t len) {
    if (ec) {
        LOG(ERROR) << "[Session::remote_read_handle][logid:" << _logid
            << "][logid:" << _logid << "][ec=" << ec.message()
            << "][remote:" << _remote_ep.address().to_string()
            << "] read from remote failed";
        // _self_container.reset();
        return;
    }

    _remote_read_len += len;

    int ret = 0;
    int processed_len = 0;
    while (processed_len < _remote_read_len) {
        if (REMOTE_AUTH == _state) {
            LOG(INFO) << "[Session::remote_read_handle][logid:" << _logid
                << "][state:REMOTE_AUTH][len:" << len << "]";
            if (_remote_read_len - processed_len < sizeof(int32_t) + 1) {
                LOG(ERROR) << "[Session::remote_handle] not enough data";
                // keep read
                break;
            }
            int32_t param_len = 0;
            memcpy(&param_len, &_remote_read_buff[processed_len], sizeof(int32_t));
            if (_remote_read_len - processed_len - sizeof(int32_t) < param_len) {
                LOG(ERROR) << "[Session::remote_read_handle] not enough data";
                break;
            }
            int consume_len = process_remote_param(&_remote_read_buff[processed_len], sizeof(int32_t) + param_len);
            if (consume_len < 0) {
                // remote auth failed
                socks_req_response(Socks5::HOST_UNREACHABLE);
                ret = -1;
                break;
            }

            socks_req_response();

            processed_len += consume_len;
        } else if (REMOTE_FORWARD == _state) {
            // forward to local socket
            LOG(INFO) << "[Session::remote_read_handle][logid:" << _logid
                << "][state:REMOTE_FORWARD][len:" << len << "]";
            _local_write_buff.clear();
            _local_write_buff.append(&_remote_read_buff[processed_len], _remote_read_len - processed_len);
            do_local_write();
            _forward_to_local_fin = false;

            processed_len = _remote_read_len;
        }
    }

    LOG(INFO) << "[Session::remote_read_handle][logid:" << _logid
        << "][processed_len:" << processed_len << "]";
    if (ret != 0) {
        // _self_container.reset();
        return;
    }

    if (0 < processed_len && processed_len < _remote_read_len) {
        memmove(&_remote_read_buff[0], &_remote_read_buff[processed_len], _remote_read_len - processed_len);
    }
    _remote_read_len -= processed_len;

    // do_remote_read();
}

int Session::process_remote_param(const char* data, size_t len) {
    int32_t param_len = 0;
    memcpy(&param_len, data, sizeof(int32_t));

    unsigned char type = data[4];
    if (type != PARAM_PACKAGE) {
        LOG(ERROR) << "process_remote_param, type:" << type << ", not param package";
        return -1;
    }

    bs::BsResponse response;
    response.ParseFromArray(&data[5], param_len - 1);
    if (response.err_no()) {
        LOG(ERROR) << "[Session::process_remote_param][logid:" << _logid
            << "][response err_no:" << response.err_no()
            << "][err_msg:" << response.err_msg() << "]";
        return -1;
    }

    _real_target_atyp = response.atyp();
    _real_target_addr.append(response.target_addr().data(), response.target_addr().size());
    _real_target_port = response.target_port();

    _socks5.set_real_target((Socks5::ATYP)_real_target_atyp, _real_target_addr, _real_target_port);

    return param_len + sizeof(int32_t);
}

LocalServer LocalServer::_s_instance;

LocalServer::LocalServer() : _io_context(),
    _acceptor(_io_context, tcp::endpoint(tcp::v4(), FLAGS_local_port)) {
}

int LocalServer::start() {
    int ret = 0;

    do {
        ret = do_accept();
        if (0 != ret) {
            LOG(INFO) << "LocalServer fail to init";
            break;
        }

        LOG(INFO) << "local server start, port:" << FLAGS_local_port << ", enjoy yourself ...";
        _io_context.run();
    } while (false);

    return ret;
}

int LocalServer::do_accept() {
    _acceptor.async_accept(std::bind(&LocalServer::accept_handle, this, _1, _2));
    return 0;
}

void LocalServer::accept_handle(boost::system::error_code ec, boost::asio::ip::tcp::socket socket) {
    LOG(INFO) << "accept a socket";
    std::make_shared<Session>(std::move(socket), &_io_context)->start();

    do_accept();  // need call do_accept again
}

}