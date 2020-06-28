//
// Created by ywt on 2020/6/23.
//


#include "utility.h"
#include "boost/uuid/uuid.hpp"
#include "boost/uuid/uuid_generators.hpp"
#include "boost/uuid/uuid_io.hpp"

namespace bs {
std::string gen_sn() {
    boost::uuids::uuid uid = boost::uuids::random_generator()();
    return boost::uuids::to_string(uid);
}

std::size_t gen_logid() {
    boost::uuids::uuid uid = boost::uuids::random_generator()();
    return boost::uuids::hash_value(uid);
}


}
