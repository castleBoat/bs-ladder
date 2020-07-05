//
// Created by ywt on 2020/5/6.
//

#ifndef BLACKSHEEP_SOCKS5_H
#define BLACKSHEEP_SOCKS5_H

#include "local_server.h"

namespace bs {

class Socks5 {
public:

    enum ATYP {
        IP_V4 = 1,
        DOMAINAME = 3,
        IP_V6 = 4
    };

    enum REP {
        SUCCEEDED = 0,
        GENERAL_SERVER_FAIL = 1,
        CONNECTION_NOT_ALLOW = 2,
        NETWORK_UNREACHABLE = 3,
        HOST_UNREACHABLE = 4,
        CONNECTION_REFUSED = 5,
        TTL_EXPIRED = 6,
        CMD_NOT_SUPPORTED = 7,
        ADDRESS_TYPE_NOT_SUPPORTED = 8
    };

    // TODO add logid in socks5
    explicit Socks5(uint64_t logid) : _logid(logid), _target_port(0), _auth_method(NO_AUTHEN),
                _cmd(CONNECT), _atyp(DOMAINAME), _rep(SUCCEEDED),
                _real_atyp(DOMAINAME), _real_target_port(0) {}

    ATYP atyp() {
        return _atyp;
    }

    std::string target_addr() {
        return _target_addr;
    }

    int target_port() {
        return _target_port;
    }

    void set_rep(REP rep) {
        _rep = rep;
    };

    void set_real_target(ATYP atyp, std::string& addr, int port);

    int try_parse_auth(const char* data, size_t len);

    int auth_process(const char* data, size_t len);

    int response_auth(std::string& cnt);

    int try_parse_req(const char* data, size_t len);

    int req_process(const char* data, size_t len);

    int req_response(std::string& cnt);

    std::string addr_to_string();

    int process_udp_req(const char* data, size_t len);

    int udp_response(std::string& res, const std::string& udp_data);

private:
    enum AuthMethod {
        NO_AUTHEN = 0,
        GSSAPI = 1,
        USERNAME_PASSWD = 2,
        // IANA_ASSIGNED = 0x3-0x7F,
        // RESERVED  = 0x80-0xFE,
        NO_ACCEPTABLE_METHOD = 0xFF
    };

    enum CMD {
        CONNECT = 1,
        BIND = 2,
        UDP_ASSOCIATE = 3
    };


    uint64_t _logid;
    AuthMethod _auth_method;
    CMD _cmd;
    ATYP _atyp;
    std::string _target_addr;  // save network order integral format inner when ip_v4 or ip_v6
//    boost::asio::ip::address _target_addr;
    uint16_t _target_port;
    REP _rep;

    ATYP _real_atyp;
    std::string _real_target_addr;
    uint16_t _real_target_port;
};

}

#endif //BLACKSHEEP_SOCKS5_H
