#include <iostream>
#include <gflags/gflags.h>
#include "local_server.h"
#include "remote_server.h"

DEFINE_string(conf_file, "conf/bs.conf", "conf file path");
DEFINE_string(mode, "local", "work mode. local/remote");
DEFINE_int32(local_port, 8802, "local listen port");
DEFINE_string(remote_addr, "127.0.0.1", "remote host address");
DEFINE_int32(remote_port, 8903, "remote listen port");
DEFINE_string(passwd, "", "connect remote passwd");
DEFINE_string(my_log_dir, "log", "log dir");

int main(int argc, char* argv[]) {
    if (argc >= 2) {
        google::SetCommandLineOption("flagfile", argv[1]);
    } else {
//        google::ParseCommandLineFlags(&argc, &argv, true);
        google::SetCommandLineOption("flagfile", "conf/bs.conf");
    }

    google::InitGoogleLogging(argv[0]);
    FLAGS_log_dir = FLAGS_my_log_dir;

    if (FLAGS_mode == "local") {
        bs::LocalServer::instance().start();
    } else if (FLAGS_mode == "remote") {
        bs::RemoteServer::instance().start();
    } else {
        LOG(ERROR) << "err mode: local/remote";
    }

    // TODO check receive udp and add udp relay
    LOG(INFO) << "server is going exit";

    return 0;
}