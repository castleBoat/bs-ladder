//
// Created by ywt on 2020/6/23.
//

#ifndef BLACKSHEEP_UTILITY_H
#define BLACKSHEEP_UTILITY_H

#include <string>

namespace bs {

extern std::string gen_sn();

extern std::size_t gen_logid();

extern void encrpt(uint8_t* data, size_t len);

extern void decrpt(uint8_t* data, size_t len);

}

#endif //BLACKSHEEP_UTILITY_H
