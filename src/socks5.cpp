//
// Created by ywt on 2020/5/6.
//

#include <iostream>
#include <vector>
#include <cassert>
#include <string>
#include <algorithm>
#include "public_include.h"
#include "socks5.h"

namespace bs {

/*
 * TCP-based client
 *
 * authentication request
 *    +----+----------+----------+
 *    |VER | NMETHODS | METHODS  |
 *    +----+----------+----------+
 *    | 1  |    1     | 1 to 255 |
 *    +----+----------+----------+
 *
 * authentication response
 *    +----+--------+
 *    |VER | METHOD |
 *    +----+--------+
 *    | 1  |    1   |
 *    +----+--------+
 *
 *
 * The SOCKS request is formed as follows:
 *    +----+-----+-------+------+----------+----------+
 *    |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
 *    +----+-----+-------+------+----------+----------+
 *    | 1  |  1  | X'00' |  1   | Variable |    2     |
 *    +----+-----+-------+------+----------+----------+
 *
 * Replies
 *    +----+-----+-------+------+----------+----------+
 *    |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
 *    +----+-----+-------+------+----------+----------+
 *    | 1  |  1  | X'00' |  1   | Variable |    2     |
 *    +----+-----+-------+------+----------+----------+
 *
 *
 *  UDP-based client
 *
 *  Socks5 request/response
 *  +----+------+------+----------+----------+----------+
 *  |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
 *  +----+------+------+----------+----------+----------+
 *  | 2  |  1   |  1   | Variable |    2     | Variable |
 *  +----+------+------+----------+----------+----------+
 *
*/

int Socks5::auth_process(const char* data, size_t len) {
    // TODO 解析 socks 5 认证
    uint8_t ver = data[0];
    if (ver != 0x5) {
        LOG(ERROR) << "[auth_process] version != 0x5 in auto request";
        _auth_method = NO_ACCEPTABLE_METHOD;
        return -1;
    }

    uint8_t nmethods = data[1];
    int offset = 2;
    std::vector<int> methods;

    for (size_t i = 0; i < nmethods; ++i) {
        methods.push_back(data[i + offset]);
    }

    if (std::find(methods.begin(), methods.end(), NO_AUTHEN) == methods.end()) {
        LOG(ERROR) << "[auth_process] not found NO_AUTHENTICATION_METHOD in auto request"
           ;
        _auth_method = NO_ACCEPTABLE_METHOD;
        return -1;
    }

    return offset + nmethods;
}

void Socks5::set_real_target(ATYP atyp, std::string& addr, int port) {
    _real_atyp = atyp;
    _real_target_addr.append(addr.data(), addr.size());
    _real_target_port = port;
}

int Socks5::try_parse_auth(const char* data, size_t len) {
    // 尝试解析 SOCKS5 认证格式
    if (len < 3) {
        return -1;
    }
    // uint8_t ver = data[0];
    uint8_t nmethods = data[1];

    if (len - 2 < nmethods) {
        return -1;
    }

    return 0;
}

int Socks5::response_auth(std::string& cnt) {
    char ver = 0x5;
//    char method = NO_AUTHEN;
    char method = _auth_method;

    cnt.push_back(ver);
    cnt.push_back(method);

    return 0;
}

int Socks5::try_parse_req(const char* data, size_t len) {
    if (len < 10) {
        return -1;
    }

    uint8_t ver = data[0];
    uint8_t cmd = data[1];

    uint8_t atyp = data[3];
    LOG(INFO) << "ver:" << (int)ver << ", cmd:" << (int)cmd << ", atyp:" << (int)atyp;
    if (atyp == IP_V4) {
        if (len < 10) {
            return -1;
        }
    } else if (atyp == DOMAINAME) {
        uint8_t domain_len = data[4];
        if (len - 5 < domain_len + 2) {
            return -1;
        }
    } else if (atyp == IP_V6) {
        if (len < 22) {
            return -1;
        }
    } else {
        LOG(ERROR) << "[try_parse_req][atyp:" << atyp << "] err atype value";
        return -1;
    }
    return 0;
}

int Socks5::req_process(const char *data, size_t len) {
    uint8_t ver = data[0];
    if (ver != 0x5) {
        LOG(ERROR) << "[Socks5::req_process] version != 0x5 in auto request";
        return -1;
    }
    _cmd = (CMD)data[1];
    if (_cmd != CONNECT && _cmd != BIND && _cmd != UDP_ASSOCIATE) {
        LOG(ERROR) << "[Socks5::req_process] cmd=" << _cmd
            << ", error cmd in socks5 request";
        _rep = CMD_NOT_SUPPORTED;
        return -1;
    }
    if (_cmd != CONNECT) {
        LOG(ERROR) << "[Socks5::req_process] support CONNECT in socks5 current only";
        _rep = CMD_NOT_SUPPORTED;
        return -1;
    }

    _atyp = static_cast<ATYP>(data[3]);
    if (_atyp != IP_V4 && _atyp != DOMAINAME && _atyp != IP_V6) {
        LOG(ERROR) << "[Socks5::req_process] _=" << _atyp
            << ", error atyp in socks5 request";
        _rep = ADDRESS_TYPE_NOT_SUPPORTED;
        return -1;
    }
    int offset = 4;
    if (_atyp == IP_V4) {
//        boost::asio::ip::address_v4::bytes_type n_v4_bytes;
//        memcpy(n_v4_bytes.data(), &data[offset], 4);
//        boost::asio::ip::address_v4 addr(n_v4_bytes);
//        _target_addr = boost::asio::ip::address(addr);

        _target_addr.append(&data[offset], 4);
        offset += 4;
    } else if (_atyp == DOMAINAME) {
        uint8_t domain_len = data[offset++];
        _target_addr.append(&data[offset], domain_len);
        offset += domain_len;
    } else if (_atyp == IP_V6) {
        _target_addr.append(&data[offset], 16);
        offset += 16;
    }

    _target_port |= ((uint8_t)data[offset] << 8);
    _target_port |= (uint8_t)data[offset+1];
    offset += 2;

    LOG(INFO) << "[Socks5::req_process][atyp:" << (int)_atyp << "][target_addr:" << addr_to_string()
        << "][target_port:" << _target_port << "]";

    return offset;
}

int Socks5::req_response(std::string& cnt) {
    // 这里是接受 target addr 后与 target 成功建立链接后再返回
    uint8_t ver = 0x5;
    std::string s;

    cnt.clear();
    cnt.push_back(ver);
    cnt.push_back(_rep);
    cnt.push_back(0);
    cnt.push_back(_atyp);

    if (_atyp == IP_V4) {
        LOG(INFO) << "_real_target_addr.size():" << _real_target_addr.size();
        cnt.append(_real_target_addr.data(), _real_target_addr.size());
    } else if (_atyp == DOMAINAME) {
        cnt.push_back(_real_target_addr.size());
        cnt.append(_real_target_addr.data(), _real_target_addr.size());
    } else if (_atyp == IP_V6) {
        cnt.append( _real_target_addr.data(), _real_target_addr.size());
    } else {
        LOG(ERROR) << "[Socks5::req_response][atyp:" << _atyp << "] error value";
        abort();
    }

    cnt.push_back((uint8_t)((_real_target_port >> 8) & 0xff));
    cnt.push_back((uint8_t)(_real_target_port & 0xff));

    LOG(INFO) << "[Socks5::req_response][response:" << _rep << "][atyp:" << _atyp
        << "][target_addr:" << _real_target_addr << "][target_port:" << _real_target_port
        << "][cnt_size:" << cnt.size() << "]";
    return 0;
}

std::string Socks5::addr_to_string() {
    std::string addr_str;

    if (_atyp == IP_V4) {
        boost::asio::ip::address_v4::bytes_type n_v4_bytes;
        memcpy(n_v4_bytes.data(), _target_addr.data(), 4);
        boost::asio::ip::address_v4 addr(n_v4_bytes);
        addr_str = addr.to_string();
    } else if (_atyp == DOMAINAME) {
        addr_str = _target_addr;
    } else if (_atyp == IP_V6) {
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

int Socks5::process_udp_req(const char* data, size_t len) {
    if (len < 10) {
        LOG(ERROR) << "[Socks5::process_udp_req][logid:" << _logid
           << "][read_len:" << len << "] read len < 10";
        return -1;
    }
    if (data[0] != 0 || data[1] != 0 || data[2] != 0) {
        LOG(ERROR) << "[Socks5::process_udp_req][logid:" << _logid
            << "] first three bytes != 0";
        return -1;
    }

    _atyp = static_cast<ATYP>(data[3]);
    int offset = 4;
    if (_atyp == IP_V4) {
        _target_addr.append(&data[offset], 4);
        offset += 4;
    } else if (_atyp == DOMAINAME) {
        uint8_t dns_len = data[offset++];
        if (len < 7 + dns_len) {
            LOG(ERROR) << "[Socks5::process_udp_req][logid:" << _logid
               << "][read_len:" << len << "] dns len not enough";
            return -1;
        }
        _target_addr.append(&data[offset], dns_len);
        offset += dns_len;

    } else if (_atyp == IP_V6) {
        if (len < 22) {
            LOG(ERROR) << "[Socks5::process_udp_req][logid:" << _logid
               << "][read_len:" << len << "] IP_V6 len not enough";
            return -1;
        }
        _target_addr.append(&data[offset], 16);
        offset += 16;
    } else {
        LOG(ERROR) << "[Socks5::process_udp_req][logid:" << _logid
           << "][atyp:" << _atyp << "] atyp value error";
        return -1;

    }

    _target_port |= ((uint8_t)data[offset] << 8);
    _target_port |= (uint8_t)data[offset+1];
    offset += 2;

    return offset;
}

int Socks5::udp_response(std::string &res, const std::string &udp_data) {
    res.clear();

    res.append(3, 0x0);
    res.push_back(_real_atyp);
    if (_real_atyp == DOMAINAME) {
        res.push_back(_real_target_addr.size());
    }
    res.append(_real_target_addr.data(), _real_target_addr.size());
    res.push_back((_real_target_port >> 8) & 0xff);
    res.push_back(_real_target_port & 0xff);
    res.append(udp_data.data(), udp_data.size());

    return 0;
}

}