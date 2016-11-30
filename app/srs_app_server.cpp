/*
The MIT License (MIT)

Copyright (c) 2013-2015 SRS(ossrs)

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <srs_app_server.hpp>

#include <sys/types.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <algorithm>
using namespace std;

#include <srs_kernel_log.hpp>
#include <srs_kernel_error.hpp>
#include <srs_app_rtmp_conn.hpp>
#include <srs_app_config.hpp>
#include <srs_kernel_utility.hpp>
#include <srs_app_source.hpp>
#include <srs_app_utility.hpp>
#include <srs_app_statistic.hpp>

// signal defines.
#define SIGNAL_RELOAD SIGHUP

// system interval in ms,
// all resolution times should be times togother,
// for example, system-interval is x=1s(1000ms),
// then rusage can be 3*x, for instance, 3*1=3s,
// the meminfo canbe 6*x, for instance, 6*1=6s,
// for performance refine, @see: https://github.com/ossrs/srs/issues/194
// @remark, recomment to 1000ms.
#define SRS_SYS_CYCLE_INTERVAL 1000

// update time interval:
//      SRS_SYS_CYCLE_INTERVAL * SRS_SYS_TIME_RESOLUTION_MS_TIMES
// @see SYS_TIME_RESOLUTION_US
#define SRS_SYS_TIME_RESOLUTION_MS_TIMES 1

// update rusage interval:
//      SRS_SYS_CYCLE_INTERVAL * SRS_SYS_RUSAGE_RESOLUTION_TIMES
#define SRS_SYS_RUSAGE_RESOLUTION_TIMES 3

// update network devices info interval:
//      SRS_SYS_CYCLE_INTERVAL * SRS_SYS_NETWORK_RTMP_SERVER_RESOLUTION_TIMES
#define SRS_SYS_NETWORK_RTMP_SERVER_RESOLUTION_TIMES 3

// update rusage interval:
//      SRS_SYS_CYCLE_INTERVAL * SRS_SYS_CPU_STAT_RESOLUTION_TIMES
#define SRS_SYS_CPU_STAT_RESOLUTION_TIMES 3

// update the disk iops interval:
//      SRS_SYS_CYCLE_INTERVAL * SRS_SYS_DISK_STAT_RESOLUTION_TIMES
#define SRS_SYS_DISK_STAT_RESOLUTION_TIMES 6

// update rusage interval:
//      SRS_SYS_CYCLE_INTERVAL * SRS_SYS_MEMINFO_RESOLUTION_TIMES
#define SRS_SYS_MEMINFO_RESOLUTION_TIMES 6

// update platform info interval:
//      SRS_SYS_CYCLE_INTERVAL * SRS_SYS_PLATFORM_INFO_RESOLUTION_TIMES
#define SRS_SYS_PLATFORM_INFO_RESOLUTION_TIMES 9

// update network devices info interval:
//      SRS_SYS_CYCLE_INTERVAL * SRS_SYS_NETWORK_DEVICE_RESOLUTION_TIMES
#define SRS_SYS_NETWORK_DEVICE_RESOLUTION_TIMES 9

std::string srs_listener_type2string(SrsListenerType type) 
{
    switch (type) {
    case SrsListenerRtmpStream:
        return "RTMP";
    case SrsListenerHttpApi:
        return "HTTP-API";
    case SrsListenerHttpStream:
        return "HTTP-Server";
    case SrsListenerMpegTsOverUdp:
        return "MPEG-TS over UDP";
    case SrsListenerRtsp:
        return "RTSP";
    case SrsListenerFlv:
        return "HTTP-FLV";
    default:
        return "UNKONWN";
    }
}

SrsListener::SrsListener(SrsServer* svr, SrsListenerType t)
{
    port = 0;
    server = svr;
    type = t;
}

SrsListener::~SrsListener()
{
}

SrsListenerType SrsListener::listen_type()
{
    return type;
}

SrsStreamListener::SrsStreamListener(SrsServer* svr, SrsListenerType t) : SrsListener(svr, t)
{
    listener = NULL;
}

SrsStreamListener::~SrsStreamListener()
{
    srs_freep(listener);
}

int SrsStreamListener::listen(string i, int p)
{
    int ret = ERROR_SUCCESS;
    
    ip = i;
    port = p;

    srs_freep(listener);
    listener = new SrsTcpListener(this, ip, port);

    if ((ret = listener->listen()) != ERROR_SUCCESS) {
        srs_error("tcp listen failed. ret=%d", ret);
        return ret;
    }
    
    srs_info("listen thread current_cid=%d, "
        "listen at port=%d, type=%d, fd=%d started success, ep=%s:%d",
        _srs_context->get_id(), p, type, listener->fd(), i.c_str(), p);

    srs_trace("%s listen at tcp://%s:%d, fd=%d", srs_listener_type2string(type).c_str(), ip.c_str(), port, listener->fd());

    return ret;
}

int SrsStreamListener::on_tcp_client(st_netfd_t stfd)
{
    int ret = ERROR_SUCCESS;
    
    if ((ret = server->accept_client(type, stfd)) != ERROR_SUCCESS) {
        srs_warn("accept client error. ret=%d", ret);
        return ret;
    }

    return ret;
}

SrsUdpStreamListener::SrsUdpStreamListener(SrsServer* svr, SrsListenerType t, ISrsUdpHandler* c) : SrsListener(svr, t)
{
    listener = NULL;
    caster = c;
}

SrsUdpStreamListener::~SrsUdpStreamListener()
{
    srs_freep(listener);
}

int SrsUdpStreamListener::listen(string i, int p)
{
    int ret = ERROR_SUCCESS;

    // the caller already ensure the type is ok,
    // we just assert here for unknown stream caster.
    srs_assert(type == SrsListenerMpegTsOverUdp);
    
    ip = i;
    port = p;

    srs_freep(listener);
    listener = new SrsUdpListener(caster, ip, port);

    if ((ret = listener->listen()) != ERROR_SUCCESS) {
        srs_error("udp caster listen failed. ret=%d", ret);
        return ret;
    }
    
    srs_info("listen thread current_cid=%d, "
        "listen at port=%d, type=%d, fd=%d started success, ep=%s:%d",
        _srs_context->get_id(), p, type, listener->fd(), i.c_str(), p);
    
    // notify the handler the fd changed.
    if ((ret = caster->on_stfd_change(listener->stfd())) != ERROR_SUCCESS) {
        srs_error("notify handler fd changed. ret=%d", ret);
        return ret;
    }

    srs_trace("%s listen at udp://%s:%d, fd=%d", srs_listener_type2string(type).c_str(), ip.c_str(), port, listener->fd());

    return ret;
}

SrsSignalManager* SrsSignalManager::instance = NULL;

SrsSignalManager::SrsSignalManager(SrsServer* server)
{
    SrsSignalManager::instance = this;
    
    _server = server;
    sig_pipe[0] = sig_pipe[1] = -1;
    pthread = new SrsEndlessThread("signal", this);
    signal_read_stfd = NULL;
}

SrsSignalManager::~SrsSignalManager()
{
    srs_close_stfd(signal_read_stfd);
    
    if (sig_pipe[0] > 0) {
        ::close(sig_pipe[0]);
    }
    if (sig_pipe[1] > 0) {
        ::close(sig_pipe[1]);
    }
    
    srs_freep(pthread);
}

int SrsSignalManager::initialize()
{
    int ret = ERROR_SUCCESS;
    
    /* Create signal pipe */
    if (pipe(sig_pipe) < 0) {
        ret = ERROR_SYSTEM_CREATE_PIPE;
        srs_error("create signal manager pipe failed. ret=%d", ret);
        return ret;
    }
    
    if ((signal_read_stfd = st_netfd_open(sig_pipe[0])) == NULL) {
        ret = ERROR_SYSTEM_CREATE_PIPE;
        srs_error("create signal manage st pipe failed. ret=%d", ret);
        return ret;
    }
    
    return ret;
}

int SrsSignalManager::start()
{
    /**
    * Note that if multiple processes are used (see below), 
    * the signal pipe should be initialized after the fork(2) call 
    * so that each process has its own private pipe.
    */
    struct sigaction sa;
    
    /* Install sig_catcher() as a signal handler */
    sa.sa_handler = SrsSignalManager::sig_catcher;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGNAL_RELOAD, &sa, NULL);
    
    sa.sa_handler = SrsSignalManager::sig_catcher;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);
    
    sa.sa_handler = SrsSignalManager::sig_catcher;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    
    sa.sa_handler = SrsSignalManager::sig_catcher;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGUSR2, &sa, NULL);
    
    srs_trace("signal installed");
    
    return pthread->start();
}

int SrsSignalManager::cycle()
{
    int ret = ERROR_SUCCESS;

    int signo;
    
    /* Read the next signal from the pipe */
    st_read(signal_read_stfd, &signo, sizeof(int), ST_UTIME_NO_TIMEOUT);
    
    /* Process signal synchronously */
    _server->on_signal(signo);
    
    return ret;
}

void SrsSignalManager::sig_catcher(int signo)
{
    int err;
    
    /* Save errno to restore it after the write() */
    err = errno;
    
    /* write() is reentrant/async-safe */
    int fd = SrsSignalManager::instance->sig_pipe[1];
    write(fd, &signo, sizeof(int));
    
    errno = err;
}

ISrsServerCycle::ISrsServerCycle()
{
}

ISrsServerCycle::~ISrsServerCycle()
{
}

SrsServer::SrsServer()
{
    signal_reload = false;
    signal_gmc_stop = false;
    signal_gracefully_quit = false;
    pid_fd = -1;
    
    signal_manager = NULL;
    
    handler = NULL;
    
    // donot new object in constructor,
    // for some global instance is not ready now,
    // new these objects in initialize instead.
}

SrsServer::~SrsServer()
{
    destroy();
}

void SrsServer::destroy()
{
    srs_warn("start destroy server");
    
    dispose();
    
    if (pid_fd > 0) {
        ::close(pid_fd);
        pid_fd = -1;
    }
    
    srs_freep(signal_manager);
}

void SrsServer::dispose()
{
    _srs_config->unsubscribe(this);
    
    // prevent fresh clients.
    close_listeners(SrsListenerRtmpStream);
    close_listeners(SrsListenerHttpApi);
    close_listeners(SrsListenerHttpStream);
    close_listeners(SrsListenerMpegTsOverUdp);
    close_listeners(SrsListenerRtsp);
    close_listeners(SrsListenerFlv);
    
    // @remark don't dispose ingesters, for too slow.
    
    // dispose the source for hls and dvr.
    SrsSource::dispose_all();
    
    // @remark don't dispose all connections, for too slow.
}

int SrsServer::initialize(ISrsServerCycle* cycle_handler)
{
    int ret = ERROR_SUCCESS;
    
    // ensure the time is ok.
    srs_update_system_time_ms();
    
    // for the main objects(server, config, log, context),
    // never subscribe handler in constructor,
    // instead, subscribe handler in initialize method.
    srs_assert(_srs_config);
    _srs_config->subscribe(this);
    
    srs_assert(!signal_manager);
    signal_manager = new SrsSignalManager(this);
    
    handler = cycle_handler;
    if(handler && (ret = handler->initialize()) != ERROR_SUCCESS){
        return ret;
    }

    return ret;
}

int SrsServer::initialize_st()
{
    int ret = ERROR_SUCCESS;
    
    // init st
    if ((ret = srs_st_init()) != ERROR_SUCCESS) {
        srs_error("init st failed. ret=%d", ret);
        return ret;
    }
    
    // @remark, st alloc segment use mmap, which only support 32757 threads,
    // if need to support more, for instance, 100k threads, define the macro MALLOC_STACK.
    // TODO: FIXME: maybe can use "sysctl vm.max_map_count" to refine.
    if (_srs_config->get_max_connections() > 32756) {
        ret = ERROR_ST_EXCEED_THREADS;
        srs_error("st mmap for stack allocation must <= %d threads, "
                  "@see Makefile of st for MALLOC_STACK, please build st manually by "
                  "\"make EXTRA_CFLAGS=-DMALLOC_STACK linux-debug\", ret=%d", ret);
        return ret;
    }
    
    // set current log id.
    _srs_context->generate_id();
    srs_trace("server main cid=%d", _srs_context->get_id());
    
    return ret;
}

int SrsServer::initialize_signal()
{
    return signal_manager->initialize();
}

int SrsServer::acquire_pid_file()
{
    int ret = ERROR_SUCCESS;
    
    std::string pid_file = _srs_config->get_pid_file();
    
    // -rw-r--r-- 
    // 644
    int mode = S_IRUSR | S_IWUSR |  S_IRGRP | S_IROTH;
    
    int fd;
    // open pid file
    if ((fd = ::open(pid_file.c_str(), O_WRONLY | O_CREAT, mode)) < 0) {
        ret = ERROR_SYSTEM_PID_ACQUIRE;
        srs_error("open pid file %s error, ret=%#x", pid_file.c_str(), ret);
        return ret;
    }
    
    // require write lock
    struct flock lock;

    lock.l_type = F_WRLCK; // F_RDLCK, F_WRLCK, F_UNLCK
    lock.l_start = 0; // type offset, relative to l_whence
    lock.l_whence = SEEK_SET;  // SEEK_SET, SEEK_CUR, SEEK_END
    lock.l_len = 0;
    
    if (fcntl(fd, F_SETLK, &lock) < 0) {
        if(errno == EACCES || errno == EAGAIN) {
            ret = ERROR_SYSTEM_PID_ALREADY_RUNNING;
            srs_error("srs is already running! ret=%#x", ret);
            return ret;
        }
        
        ret = ERROR_SYSTEM_PID_LOCK;
        srs_error("require lock for file %s error! ret=%#x", pid_file.c_str(), ret);
        return ret;
    }

    // truncate file
    if (ftruncate(fd, 0) < 0) {
        ret = ERROR_SYSTEM_PID_TRUNCATE_FILE;
        srs_error("truncate pid file %s error! ret=%#x", pid_file.c_str(), ret);
        return ret;
    }

    int pid = (int)getpid();
    
    // write the pid
    char buf[512];
    snprintf(buf, sizeof(buf), "%d", pid);
    if (write(fd, buf, strlen(buf)) != (int)strlen(buf)) {
        ret = ERROR_SYSTEM_PID_WRITE_FILE;
        srs_error("write our pid error! pid=%d file=%s ret=%#x", pid, pid_file.c_str(), ret);
        return ret;
    }

    // auto close when fork child process.
    int val;
    if ((val = fcntl(fd, F_GETFD, 0)) < 0) {
        ret = ERROR_SYSTEM_PID_GET_FILE_INFO;
        srs_error("fnctl F_GETFD error! file=%s ret=%#x", pid_file.c_str(), ret);
        return ret;
    }
    val |= FD_CLOEXEC;
    if (fcntl(fd, F_SETFD, val) < 0) {
        ret = ERROR_SYSTEM_PID_SET_FILE_INFO;
        srs_error("fcntl F_SETFD error! file=%s ret=%#x", pid_file.c_str(), ret);
        return ret;
    }
    
    srs_trace("write pid=%d to %s success!", pid, pid_file.c_str());
    pid_fd = fd;
    
    return ret;
}

int SrsServer::listen()
{
    int ret = ERROR_SUCCESS;
    
    if ((ret = listen_rtmp()) != ERROR_SUCCESS) {
        return ret;
    }
    
    if ((ret = listen_http_api()) != ERROR_SUCCESS) {
        return ret;
    }
    
    if ((ret = listen_http_stream()) != ERROR_SUCCESS) {
        return ret;
    }
    
    if ((ret = listen_stream_caster()) != ERROR_SUCCESS) {
        return ret;
    }
    
    return ret;
}

int SrsServer::register_signal()
{
    // start signal process thread.
    return signal_manager->start();
}

int SrsServer::http_handle()
{
    return ERROR_SUCCESS;
}

int SrsServer::ingest()
{
    return ERROR_SUCCESS;
}

int SrsServer::cycle()
{
    int ret = ERROR_SUCCESS;

    ret = do_cycle();

    // normally quit with neccessary cleanup by dispose().
    srs_warn("main cycle terminated, system quit normally.");
    dispose();
    srs_trace("srs terminated");
    exit(0);

    return ret;
}

void SrsServer::remove(SrsConnection* conn)
{
    std::vector<SrsConnection*>::iterator it = std::find(conns.begin(), conns.end(), conn);
    
    // removed by destroy, ignore.
    if (it == conns.end()) {
        srs_warn("server moved connection, ignore.");
        return;
    }
    
    conns.erase(it);
    
    srs_info("conn removed. conns=%d", (int)conns.size());
    
    SrsStatistic* stat = SrsStatistic::instance();
    stat->kbps_add_delta(conn);
    stat->on_disconnect(conn->srs_id());
    
    // all connections are created by server,
    // so we free it here.
    srs_freep(conn);
}

void SrsServer::on_signal(int signo)
{
    if (signo == SIGNAL_RELOAD) {
        signal_reload = true;
        return;
    }
    
    if (signo == SIGINT || signo == SIGUSR2) {
        srs_trace("user terminate program");
        exit(0);
        return;
    }
    
    if (signo == SIGTERM && !signal_gracefully_quit) {
        srs_trace("user terminate program, gracefully quit.");
        signal_gracefully_quit = true;
        return;
    }
}

int SrsServer::do_cycle()
{
    int ret = ERROR_SUCCESS;
    
    // find the max loop
    int max = srs_max(0, SRS_SYS_TIME_RESOLUTION_MS_TIMES);
    
    // the deamon thread, update the time cache
    while (true) {
        if(handler && (ret = handler->on_cycle((int)conns.size())) != ERROR_SUCCESS){
            srs_error("cycle handle failed. ret=%d", ret);
            return ret;
        }
            
        // the interval in config.
        int heartbeat_max_resolution = (int)(_srs_config->get_heartbeat_interval() / SRS_SYS_CYCLE_INTERVAL);
        
        // dynamic fetch the max.
        int temp_max = max;
        temp_max = srs_max(temp_max, heartbeat_max_resolution);
        
        for (int i = 0; i < temp_max; i++) {
            st_usleep(SRS_SYS_CYCLE_INTERVAL * 1000);
            
            // gracefully quit for SIGINT or SIGTERM.
            if (signal_gracefully_quit) {
                srs_trace("cleanup for gracefully terminate.");
                return ret;
            }
        
            // do reload the config.
            if (signal_reload) {
                signal_reload = false;
                srs_info("get signal reload, to reload the config.");
                
                if ((ret = _srs_config->reload()) != ERROR_SUCCESS) {
                    srs_error("reload config failed. ret=%d", ret);
                    return ret;
                }
                srs_trace("reload config success.");
            }
            
            // notice the stream sources to cycle.
            if ((ret = SrsSource::cycle_all()) != ERROR_SUCCESS) {
                return ret;
            }
            
            // update the cache time
            if ((i % SRS_SYS_TIME_RESOLUTION_MS_TIMES) == 0) {
                srs_info("update current time cache.");
                srs_update_system_time_ms();
            }
            
            srs_info("server main thread loop");
        }
    }

    return ret;
}

int SrsServer::listen_rtmp()
{
    int ret = ERROR_SUCCESS;
    
    // stream service port.
    std::vector<std::string> ip_ports = _srs_config->get_listens();
    srs_assert((int)ip_ports.size() > 0);
    
    close_listeners(SrsListenerRtmpStream);
    
    for (int i = 0; i < (int)ip_ports.size(); i++) {
        SrsListener* listener = new SrsStreamListener(this, SrsListenerRtmpStream);
        listeners.push_back(listener);
        
        std::string ip;
        int port;
        srs_parse_endpoint(ip_ports[i], ip, port);
        
        if ((ret = listener->listen(ip, port)) != ERROR_SUCCESS) {
            srs_error("RTMP stream listen at %s:%d failed. ret=%d", ip.c_str(), port, ret);
            return ret;
        }
    }
    
    return ret;
}

int SrsServer::listen_http_api()
{
    int ret = ERROR_SUCCESS;
    
    return ret;
}

int SrsServer::listen_http_stream()
{
    int ret = ERROR_SUCCESS;
    
    return ret;
}

int SrsServer::listen_stream_caster()
{
    int ret = ERROR_SUCCESS;
    return ret;
}

void SrsServer::close_listeners(SrsListenerType type)
{
    std::vector<SrsListener*>::iterator it;
    for (it = listeners.begin(); it != listeners.end();) {
        SrsListener* listener = *it;
        
        if (listener->listen_type() != type) {
            ++it;
            continue;
        }
        
        srs_freep(listener);
        it = listeners.erase(it);
    }
}

void SrsServer::resample_kbps()
{
    SrsStatistic* stat = SrsStatistic::instance();
    
    // collect delta from all clients.
    for (std::vector<SrsConnection*>::iterator it = conns.begin(); it != conns.end(); ++it) {
        SrsConnection* conn = *it;
        
        // add delta of connection to server kbps.,
        // for next sample() of server kbps can get the stat.
        stat->kbps_add_delta(conn);
    }
    
    // TODO: FXME: support all other connections.

    // sample the kbps, get the stat.
    SrsKbps* kbps = stat->kbps_sample();
    
    srs_update_rtmp_server((int)conns.size(), kbps);
}

int SrsServer::accept_client(SrsListenerType type, st_netfd_t client_stfd)
{
    int ret = ERROR_SUCCESS;
    
    int fd = st_netfd_fileno(client_stfd);
    
    int max_connections = _srs_config->get_max_connections();
    if ((int)conns.size() >= max_connections) {
        srs_error("exceed the max connections, drop client: "
            "clients=%d, max=%d, fd=%d", (int)conns.size(), max_connections, fd);
            
        srs_close_stfd(client_stfd);
        
        return ret;
    }
    
    // avoid fd leak when fork.
    // @see https://github.com/ossrs/srs/issues/518
    if (true) {
        int val;
        if ((val = fcntl(fd, F_GETFD, 0)) < 0) {
            ret = ERROR_SYSTEM_PID_GET_FILE_INFO;
            srs_error("fnctl F_GETFD error! fd=%d. ret=%#x", fd, ret);
            srs_close_stfd(client_stfd);
            return ret;
        }
        val |= FD_CLOEXEC;
        if (fcntl(fd, F_SETFD, val) < 0) {
            ret = ERROR_SYSTEM_PID_SET_FILE_INFO;
            srs_error("fcntl F_SETFD error! fd=%d ret=%#x", fd, ret);
            srs_close_stfd(client_stfd);
            return ret;
        }
    }
    
    SrsConnection* conn = NULL;
    if (type == SrsListenerRtmpStream) {
        conn = new SrsRtmpConn(this, client_stfd);
    } else if (type == SrsListenerHttpApi) {
        srs_warn("close http client for server not support http-api");
        srs_close_stfd(client_stfd);
        return ret;
    } else if (type == SrsListenerHttpStream) {
        srs_warn("close http client for server not support http-server");
        srs_close_stfd(client_stfd);
        return ret;
    } else {
        // TODO: FIXME: handler others
    }
    srs_assert(conn);
    
    // directly enqueue, the cycle thread will remove the client.
    conns.push_back(conn);
    srs_verbose("add conn to vector.");
    
    // cycle will start process thread and when finished remove the client.
    // @remark never use the conn, for it maybe destroyed.
    if ((ret = conn->start()) != ERROR_SUCCESS) {
        return ret;
    }
    srs_verbose("conn started success.");

    srs_verbose("accept client finished. conns=%d, ret=%d", (int)conns.size(), ret);
    
    return ret;
}

int SrsServer::on_reload_listen()
{
    return listen();
}

int SrsServer::on_reload_pid()
{
    if (pid_fd > 0) {
        ::close(pid_fd);
        pid_fd = -1;
    }
    
    return acquire_pid_file();
}

int SrsServer::on_reload_vhost_added(std::string vhost)
{
    int ret = ERROR_SUCCESS;

    return ret;
}

int SrsServer::on_reload_vhost_removed(std::string /*vhost*/)
{
    int ret = ERROR_SUCCESS;
    return ret;
}

int SrsServer::on_reload_http_api_enabled()
{
    int ret = ERROR_SUCCESS;
    
    return ret;
}

int SrsServer::on_reload_http_api_disabled()
{
    int ret = ERROR_SUCCESS;
    
    return ret;
}

int SrsServer::on_reload_http_stream_enabled()
{
    int ret = ERROR_SUCCESS;
    
    return ret;
}

int SrsServer::on_reload_http_stream_disabled()
{
    int ret = ERROR_SUCCESS;
    return ret;
}

// TODO: FIXME: rename to http_remux
int SrsServer::on_reload_http_stream_updated()
{
    int ret = ERROR_SUCCESS;
    
    return ret;
}

int SrsServer::on_publish(SrsSource* s, SrsRequest* r)
{
    int ret = ERROR_SUCCESS;
    
    return ret;
}

void SrsServer::on_unpublish(SrsSource* s, SrsRequest* r)
{
}

