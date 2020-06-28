//
// Created by ywt on 2020/5/10.
//

#ifndef BLACKSHEEP_PUBLIC_INCLUDE_H
#define BLACKSHEEP_PUBLIC_INCLUDE_H

#include <iostream>
#include <string>
#include <cassert>
#include <vector>

#ifdef _WIN32
#define GOOGLE_GLOG_DLL_DECL  // static lib define it
#define GLOG_NO_ABBREVIATED_SEVERITIES  // fix ERROR conflict in windows.h
// #include <windows.h>
#endif
#include <glog/logging.h>

#include <gflags/gflags.h>

#include "boost/asio.hpp"

static const size_t DEFAULT_BUFF_SIZE = 10240;

static const uint8_t PARAM_PACKAGE = 0x1;

#endif //BLACKSHEEP_PUBLIC_INCLUDE_H
