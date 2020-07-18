//
// Created by ywt on 2020/6/23.
//


#include "utility.h"
#include "boost/uuid/uuid.hpp"
#include "boost/uuid/uuid_generators.hpp"
#include "boost/uuid/uuid_io.hpp"

namespace bs {

const uint8_t START_MASK = 0x33;

std::string gen_sn() {
    boost::uuids::uuid uid = boost::uuids::random_generator()();
    return boost::uuids::to_string(uid);
}

std::size_t gen_logid() {
    boost::uuids::uuid uid = boost::uuids::random_generator()();
    return boost::uuids::hash_value(uid);
}

void encrpt(uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        *(data + i) = *(data + i) ^ (START_MASK + i);
    }
}

void decrpt(uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        *(data + i) = *(data + i) ^ (START_MASK + i);
    }
}


}
