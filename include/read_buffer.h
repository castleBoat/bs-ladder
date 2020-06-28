//
// Created by ywt on 2020/5/6.
//

#ifndef BLACKSHEEP_READ_BUFFER_H
#define BLACKSHEEP_READ_BUFFER_H

#include <vector>
#include <cassert>

namespace bs {

static const size_t DEFAULT_INITIAL_SIZE = 1024;

class ReadBuff {
public:
    ReadBuff(int initial_size = DEFAULT_INITIAL_SIZE ) : _buf(initial_size),
        _data_len(0) {}

    size_t readable_size() {
        return _data_len;
    }

    const char* read_pos() const {
        return &*_buf.begin();
    }

    char* write_pos() {
        return &_buf[_data_len];
    }

    size_t left_size() {
        return _buf.size() - _data_len;
    }

    void retrieve(size_t len) {
        assert(len <= _data_len);
        memmove(begin(), begin() + len, _data_len - len);
        _data_len -= len;
    }

    void append_data_len(size_t len) {
        assert(_data_len + len < _buf.size());
        _data_len += len;
    }

private:
    char* begin() {
        return &*_buf.begin();
    }

private:
    std::vector<char> _buf;
    size_t _data_len;
};

}

#endif //BLACKSHEEP_READ_BUFFER_H
