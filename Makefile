CXX = g++
LINK = g++
CXXFLAGS = -ansi -Wall -g -O0 -fPIC

CORE_OBJS = \
	core/srs_core.o \
	core/srs_core_autofree.o \
	core/srs_core_performance.o

KERNEL_OBJS = \
	kernel/srs_kernel_error.o \
	kernel/srs_kernel_log.o \
	kernel/srs_kernel_stream.o \
	kernel/srs_kernel_utility.o \
	kernel/srs_kernel_flv.o \
	kernel/srs_kernel_codec.o \
	kernel/srs_kernel_file.o \
	kernel/srs_kernel_consts.o \
	kernel/srs_kernel_buffer.o

PROTOCOL_OBJS = \
	protocol/srs_rtmp_amf0.o \
	protocol/srs_rtmp_io.o \
	protocol/srs_rtmp_stack.o \
	protocol/srs_rtmp_handshake.o \
	protocol/srs_rtmp_utility.o \
	protocol/srs_rtmp_msg_array.o \
	protocol/srs_protocol_buffer.o \
	protocol/srs_raw_avc.o \
	protocol/srs_protocol_kbps.o \
	protocol/srs_protocol_json.o

APP_OBJS = \
	app/srs_app_server.o \
	app/srs_app_conn.o \
	app/srs_app_rtmp_conn.o \
	app/srs_app_source.o \
	app/srs_app_refer.o \
	app/srs_app_forward.o \
	app/srs_app_encoder.o \
	app/srs_app_thread.o \
	app/srs_app_bandwidth.o \
	app/srs_app_st.o \
	app/srs_app_log.o \
	app/srs_app_config.o \
	app/srs_app_pithy_print.o \
	app/srs_app_reload.o \
	app/srs_app_ffmpeg.o \
	app/srs_app_utility.o \
	app/srs_app_edge.o \
	app/srs_app_empty.o \
	app/srs_app_recv_thread.o \
	app/srs_app_security.o \
	app/srs_app_statistic.o \
	app/srs_app_listener.o \
	app/srs_app_async_call.o

MAIN_OBJS = \
	main/srs_main_server.o 

srs: $(CORE_OBJS) $(KERNEL_OBJS) $(PROTOCOL_OBJS) $(APP_OBJS) $(MAIN_OBJS) st/libst.a
	$(LINK) -static -o $@ $^ -ldl

core/%.o: core/%.cpp
	$(CXX) -c $(CXXFLAGS) -Icore -I. -o $@ $<

kernel/%.o: kernel/%.cpp
	$(CXX) -c $(CXXFLAGS) -Icore -Ikernel -I. -o $@ $<

protocol/%.o: protocol/%.cpp
	$(CXX) -c $(CXXFLAGS) -Icore -Ikernel -Iprotocol -I. -o $@ $<

app/%.o: app/%.cpp
	$(CXX) -c $(CXXFLAGS) -Icore -Ikernel -Iprotocol -Iapp -Ist -I. -o $@ $<

main/%.o: main/%.cpp
	$(CXX) -c $(CXXFLAGS) -Icore -Ikernel -Iprotocol -Iapp -Imain -Ist -I. -o $@ $<

clean:
	rm -f srs $(CORE_OBJS) $(KERNEL_OBJS) $(PROTOCOL_OBJS) $(APP_OBJS) $(MAIN_OBJS)
