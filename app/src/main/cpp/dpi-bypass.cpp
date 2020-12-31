#include "dpi-bypass.h"
#include "dns.h"
#include "hostlist.h"
#include "packet.h"
#include "socket.h"
#include "sni.h"

Settings settings;
JavaVM* javaVm;

const std::string CONNECTION_ESTABLISHED_RESPONSE("HTTP/1.1 200 Connection established\r\n\r\n");
const std::string SNI_REPLACE_VARIABLE("${SNI}");
//std::vector<pid_t> child_processes;
std::vector<std::thread> threads;
bool stop_flag;
int server_socket;
int interrupt_pipe[2];

jclass localdnsserver_class;
jclass utils_class;

void replaceAll(std::string &s, const std::string &search, const std::string &replace )
{
    for(size_t pos = 0; ;pos += replace.length())
    {
        // Locate the substring to replace
        pos = s.find( search, pos );
        if(pos == std::string::npos) break;
        // Replace by erasing and inserting
        s.erase(pos, search.length());
        s.insert(pos, replace);
    }
}

void proxy_https(int client_socket, std::string host, int port)
{
	std::string log_tag = "CPP/proxy_https";

	int remote_server_socket;

	// In VPN mode when connecting to https sites proxy server gets CONNECT requests with ip addresses
	// So if we receive ip address we need to find hostname for it
	reverse_resolve_host(host);

	// Search in host list one time to save cpu time
	bool hostlist_condition = settings.hostlist.is_use_hostlist ? find_in_hostlist(host) : true;

	// Connect to remote server
	if(init_remote_server_socket(remote_server_socket, host, port, true, hostlist_condition) == -1)
	{
		return;
	}

	// Split only first https packet, what contains unencrypted sni
	bool is_clienthello_request = true;

	// Set proper timeout
	struct timeval structtimeval;
	structtimeval.tv_sec = 0;
	structtimeval.tv_usec = 0;
	if(setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, (char *) &structtimeval, sizeof(structtimeval)) < 0)
	{
		log_error(log_tag.c_str(), "Can't setsockopt on socket");
		return;
	}
	// Init tlse if SNI replace enabled
	struct TLSContext *server_server_context;
	struct TLSContext *server_client_context;
	SSL *client_context;
	if(settings.sni.is_use_sni_replace && hostlist_condition)
	{
		// Create server. It will decrypt client's traffic
        server_server_context = init_tls_server_server(host);
        if(server_server_context == NULL)
        {
            SSL_CTX_free(server_server_context);
            close(client_socket);
            close(remote_server_socket);
            return;
        }
		server_client_context = init_tls_server_client(client_socket, server_server_context);
		if(server_client_context == NULL){
            SSL_shutdown(server_client_context);
            shutdown(client_socket, SHUT_RDWR);
            close(client_socket);
            SSL_free(server_client_context);
            close(remote_server_socket);
			return;
		}

		// Insert original host address if need
		std::string fake_sni = settings.sni.sni_spell;
        replaceAll(fake_sni, SNI_REPLACE_VARIABLE, host);

        // Create client. It will encrypt and send traffic with fake SNI
		client_context = init_tls_client(remote_server_socket, fake_sni);
        if(client_context == NULL){
            SSL_shutdown(client_context);
            close(remote_server_socket);
            SSL_CTX_free(client_context);

			SSL_CTX_free(server_server_context);
            SSL_shutdown(server_client_context);
            shutdown(client_socket, SHUT_RDWR);
            close(client_socket);
            SSL_free(server_client_context);
            return;
        }
	}

    struct pollfd fds[3];

	// fds[0] is client socket
	fds[0].fd = client_socket;
	fds[0].events = POLLIN;

	// fds[1] is remote server socket
	fds[1].fd = remote_server_socket;
	fds[1].events = POLLIN;

	// fds[2] is interrupt pipe
	fds[2].fd = interrupt_pipe[0];
	fds[2].events = POLLIN;

	// Set poll() timeout
	int timeout = 10000;

	std::string buffer(1024, ' ');

	bool is_first_time = true;

	while (!stop_flag)
	{
		int ret = poll(fds, 3, timeout);

		// Check state
		if ( ret == -1 )
		{
			log_error(log_tag.c_str(), "Poll error. Errno: %s", std::strerror(errno));
			break;
		}
		else if ( ret == 0 ) // Just timeout
			continue;
		else
		{
			if(fds[0].revents & POLLERR || fds[1].revents & POLLERR ||
			   fds[0].revents & POLLHUP || fds[1].revents & POLLHUP ||
			   fds[0].revents & POLLNVAL || fds[1].revents & POLLNVAL)
				break;
			// Process client socket
			if (fds[0].revents & POLLIN)
			{
				fds[0].revents = 0;

				// Transfer data
				if(settings.sni.is_use_sni_replace && hostlist_condition)
				{
				    if (recv_string_tls(client_socket, server_client_context, buffer) ==
				        -1) // Receive request from client
				        break;


					if (send_string_tls(remote_server_socket, client_context, buffer) ==
						-1) // Send request to server
						break;
				}
				else
				{
					if(recv_string(client_socket, buffer) == -1) // Receive request from client
						break;

					// Check if split is need
					if(hostlist_condition && settings.https.is_use_split && is_clienthello_request)
					{
						if(send_string(remote_server_socket, buffer, settings.https.split_position) == -1) // Send request to server
							break;
						// VPN mode specific
						// VPN mode requires splitting for all packets
						is_clienthello_request = settings.other.is_use_vpn;
					}
					else
						if(send_string(remote_server_socket, buffer) == -1) // Send request to server
							break;
				}
			}

			// Process server socket
			if (fds[1].revents & POLLIN)
			{
				fds[1].revents = 0;

				// Transfer data
				if(settings.sni.is_use_sni_replace && hostlist_condition)
				{
					if (recv_string_tls(remote_server_socket, client_context, buffer) ==
						-1) // Receive response from server
						break;
					if (send_string_tls(client_socket, server_client_context, buffer) ==
						-1)  // Send response to client
						break;
				}
				else
				{
					if(recv_string(remote_server_socket, buffer) == -1) // Receive response from server
						break;
					if(send_string(client_socket, buffer) == -1) // Send response to client
						break;
				}
			}

			fds[0].revents = 0;
			fds[1].revents = 0;
			fds[2].revents = 0;
		}
	}

	if(settings.sni.is_use_sni_replace && hostlist_condition)
	{
		SSL_shutdown(client_context);
		close(remote_server_socket);
		SSL_CTX_free(client_context);

		SSL_CTX_free(server_server_context);
		SSL_shutdown(server_client_context);
		shutdown(client_socket, SHUT_RDWR);
		close(client_socket);
		SSL_free(server_client_context);
	}
	else
	{
		close(remote_server_socket);
		close(client_socket);
	}
}

void proxy_http(int client_socket, std::string host, int port, std::string first_request)
{
	std::string log_tag = "CPP/proxy_http";

	int remote_server_socket;

	// Search in host list one time to save cpu time
	bool hostlist_condition = settings.hostlist.is_use_hostlist ? find_in_hostlist(host) : true;

	// Connect to remote server
	if(init_remote_server_socket(remote_server_socket, host, port, false, hostlist_condition) == -1)
	{
		return;
	}

	// Modify http request to bypass dpi
	modify_http_request(first_request, hostlist_condition);

	// Check if split is need
	if(hostlist_condition && settings.http.is_use_split)
	{
		if(send_string(remote_server_socket, first_request, settings.http.split_position) == -1) // Send request to serv$
		{
			close(remote_server_socket);
			close(client_socket);
			return;
		}
	}
	else
	{
		if(send_string(remote_server_socket, first_request) == -1) // Send request to server
		{
			close(remote_server_socket);
			close(client_socket);
			return;
		}
	}

	struct pollfd fds[3];

	// fds[0] is client socket
	fds[0].fd = client_socket;
	fds[0].events = POLLIN;

	// fds[1] is remote server socket
	fds[1].fd = remote_server_socket;
	fds[1].events = POLLIN;

	// fds[2] is interrupt pipe
	fds[2].fd = interrupt_pipe[0];
	fds[2].events = POLLIN;

	// Set poll() timeout
	int timeout = 10000;

	std::string buffer(1024, ' ');

	while (!stop_flag)
	{
		int ret = poll(fds, 3, timeout);

		// Check state
		if ( ret == -1 )
		{
			log_error(log_tag.c_str(), "Poll error. Errno: %s", std::strerror(errno));
			break;
		}
		else if ( ret == 0 ) // Just timeout
			continue;
		else
		{
			// Process client socket
			if(fds[0].revents & POLLERR || fds[1].revents & POLLERR ||
				fds[0].revents & POLLHUP || fds[1].revents & POLLHUP ||
				fds[0].revents & POLLNVAL || fds[1].revents & POLLNVAL)
				break;
			if (fds[0].revents & POLLIN)
			{
				fds[0].revents = 0;

				// Transfer data
				if(recv_string(client_socket, buffer) == -1) // Receive request from client
					break;
				// Modify http request to bypass dpi
				modify_http_request(buffer, hostlist_condition);

				// Check if split is need
				if(hostlist_condition && settings.http.is_use_split)
				{
					if(send_string(remote_server_socket, buffer, settings.http.split_position) == -1) // Send request to serv$
						break;
				}
				else
					if(send_string(remote_server_socket, buffer) == -1) // Send request to server
						break;
			}

			// Process server socket
			if (fds[1].revents & POLLIN)
			{
				fds[1].revents = 0;

				// Transfer data
				if(recv_string(remote_server_socket, buffer) == -1) // Receive response from server
					break;
				if(send_string(client_socket, buffer) == -1) // Send response to client
					break;
			}

			fds[0].revents = 0;
			fds[1].revents = 0;
			fds[2].revents = 0;
		}
	}

	close(remote_server_socket);
	close(client_socket);
}

void process_client(int client_socket)
{
    std::string log_tag = "CPP/process_client";

	std::string request(1024, ' ');

	// Receive with timeout
    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;

	if(recv_string(client_socket, request, timeout) == -1)
	{
		close(client_socket);
		return;
	}

	std::string method;
	std::string host;
	int port;
	if(parse_request(request, method, host, port) == -1)
	{
		log_error(log_tag.c_str(), "Can't parse first http request, so can't process client");
		close(client_socket);
		return;
	}

	if(method == "CONNECT")
	{
		if(send_string(client_socket, CONNECTION_ESTABLISHED_RESPONSE) == -1)
		{
			close(client_socket);
			return;
		}

		proxy_https(client_socket, host, port);
	}
	else
	{
		proxy_http(client_socket, host, port, request);
	}
}

extern "C" JNIEXPORT jint JNICALL Java_ru_evgeniy_dpitunnel_service_NativeService_init(JNIEnv* env, jobject obj, jobject prefs_object, jstring app_files_path)
{
    std::string log_tag = "CPP/init";

    // Store JavaVM globally
    env->GetJavaVM(&javaVm);

    // Reset resources
    threads.clear();
    stop_flag = false;

	jclass temp;

	// Find LocalDNSServer class
	temp = env->FindClass("ru/evgeniy/dpitunnel/service/LocalDNSServer");
	if(temp == NULL)
	{
		log_error(log_tag.c_str(), "Failed to find LocalDNSServer class");
		return -1;
	}
	// Store globally
	localdnsserver_class = (jclass) env->NewGlobalRef(temp);
	env->DeleteLocalRef(temp);

	// Find Utils class
	temp = env->FindClass("ru/evgeniy/dpitunnel/Utils");
	if(temp == NULL)
	{
		log_error(log_tag.c_str(), "Failed to find Utils class");
		return -1;
	}
	// Store globally
	utils_class = (jclass) env->NewGlobalRef(temp);
	env->DeleteLocalRef(temp);

    // Find SharedPreferences
    jclass prefs_class = env->FindClass("android/content/SharedPreferences");
    if(prefs_class == NULL)
    {
        log_error(log_tag.c_str(), "Failed to find SharedPreferences class");
        return -1;
    }

    // Find method
    jmethodID prefs_getBool = env->GetMethodID(prefs_class, "getBoolean", "(Ljava/lang/String;Z)Z");
    if(prefs_getBool == NULL)
    {
        log_error(log_tag.c_str(), "Failed to find getInt method");
        return -1;
    }

    // Find method
    jmethodID prefs_getString = env->GetMethodID(prefs_class, "getString", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
    if(prefs_getString == NULL)
    {
        log_error(log_tag.c_str(), "Failed to find getInt method");
        return -1;
    }

    // Fill settings
    jobject string_object;
    jobject string_object1;

    // HTTPS options
    string_object1 = env->NewStringUTF("https_split");
    settings.https.is_use_split = env->CallBooleanMethod(prefs_object, prefs_getBool, (jstring) string_object1, false);
    env->DeleteLocalRef(string_object1);

    string_object1 = env->NewStringUTF("https_split_position");
    string_object = env->CallObjectMethod(prefs_object, prefs_getString, (jstring) string_object1, NULL);
    settings.https.split_position = (unsigned int) atoi(env->GetStringUTFChars((jstring) string_object, 0));
    env->DeleteLocalRef(string_object1);
    env->DeleteLocalRef(string_object);

    string_object1 = env->NewStringUTF("https_socks5");
    settings.https.is_use_socks5 = env->CallBooleanMethod(prefs_object, prefs_getBool, string_object1, false);
    env->DeleteLocalRef(string_object1);

    string_object1 = env->NewStringUTF("https_http_proxy");
    settings.https.is_use_http_proxy = env->CallBooleanMethod(prefs_object, prefs_getBool, (jstring) string_object1, false);
    env->DeleteLocalRef(string_object1);

    // SNI options
    string_object1 = env->NewStringUTF("sni_enable");
    settings.sni.is_use_sni_replace = env->CallBooleanMethod(prefs_object, prefs_getBool, (jstring) string_object1, false);
    env->DeleteLocalRef(string_object1);

    string_object1 =  env->NewStringUTF("sni_spell");
    string_object = env->CallObjectMethod(prefs_object, prefs_getString, (jstring) string_object1, NULL);
    settings.sni.sni_spell = env->GetStringUTFChars((jstring) string_object, 0);
    env->DeleteLocalRef(string_object1);
    env->DeleteLocalRef(string_object);

    // HTTP options
    string_object1 = env->NewStringUTF("http_split");
    settings.http.is_use_split = env->CallBooleanMethod(prefs_object, prefs_getBool, (jstring) string_object1, false);
    env->DeleteLocalRef(string_object1);

    string_object1 = env->NewStringUTF("http_split_position");
    string_object = env->CallObjectMethod(prefs_object, prefs_getString, string_object1, NULL);
    settings.http.split_position = (unsigned int) atoi(env->GetStringUTFChars((jstring) string_object, 0));
    env->DeleteLocalRef(string_object1);
    env->DeleteLocalRef(string_object);

    string_object1 = env->NewStringUTF("http_header_switch");
    settings.http.is_change_host_header = env->CallBooleanMethod(prefs_object, prefs_getBool, (jstring) string_object1, false);
    env->DeleteLocalRef(string_object1);

    string_object1 = env->NewStringUTF("http_header_spell");
    string_object = env->CallObjectMethod(prefs_object, prefs_getString, (jstring) string_object1, NULL);
    settings.http.host_header = env->GetStringUTFChars((jstring) string_object, 0);
    env->DeleteLocalRef(string_object1);
    env->DeleteLocalRef(string_object);

    string_object1 = env->NewStringUTF("http_dot");
    settings.http.is_add_dot_after_host = env->CallBooleanMethod(prefs_object, prefs_getBool, (jstring) string_object1, false);
    env->DeleteLocalRef(string_object1);

    string_object1 = env->NewStringUTF("http_tab");
    settings.http.is_add_tab_after_host = env->CallBooleanMethod(prefs_object, prefs_getBool, (jstring) string_object1, false);
    env->DeleteLocalRef(string_object1);

    string_object1 = env->NewStringUTF("http_space_host");
    settings.http.is_remove_space_after_host = env->CallBooleanMethod(prefs_object, prefs_getBool, (jstring) string_object1, false);
    env->DeleteLocalRef(string_object1);

    string_object1 = env->NewStringUTF("http_space_method");
    settings.http.is_add_space_after_method = env->CallBooleanMethod(prefs_object, prefs_getBool, (jstring) string_object1, false);
    env->DeleteLocalRef(string_object1);

    string_object1 = env->NewStringUTF("http_newline_method");
    settings.http.is_add_newline_before_method = env->CallBooleanMethod(prefs_object, prefs_getBool, (jstring) string_object1, false);
    env->DeleteLocalRef(string_object1);

    string_object1 = env->NewStringUTF("http_unix_newline");
    settings.http.is_use_unix_newline = env->CallBooleanMethod(prefs_object, prefs_getBool, (jstring) string_object1, false);
    env->DeleteLocalRef(string_object1);

    string_object1 = env->NewStringUTF("http_socks5");
    settings.http.is_use_socks5 = env->CallBooleanMethod(prefs_object, prefs_getBool, (jstring) string_object1, false);
    env->DeleteLocalRef(string_object1);

    string_object1 = env->NewStringUTF("http_http_proxy");
    settings.http.is_use_http_proxy = env->CallBooleanMethod(prefs_object, prefs_getBool, (jstring) string_object1, false);
    env->DeleteLocalRef(string_object1);

    // DoH options
    string_object1 = env->NewStringUTF("dns_doh");
    settings.dns.is_use_doh = env->CallBooleanMethod(prefs_object, prefs_getBool, (jstring) string_object1, false);
    env->DeleteLocalRef(string_object1);

    string_object1 = env->NewStringUTF("dns_doh_hostlist");
    settings.dns.is_use_doh_only_for_site_in_hostlist = env->CallBooleanMethod(prefs_object, prefs_getBool, (jstring) string_object1, false);
    env->DeleteLocalRef(string_object1);

    string_object1 = env->NewStringUTF("dns_doh_server");
    string_object = env->CallObjectMethod(prefs_object, prefs_getString, (jstring) string_object1, NULL);
    settings.dns.dns_doh_servers = env->GetStringUTFChars((jstring) string_object, 0);
    env->DeleteLocalRef(string_object1);
    env->DeleteLocalRef(string_object);

    // Hostlist options
    string_object1 = env->NewStringUTF("hostlist_enable");
    settings.hostlist.is_use_hostlist = env->CallBooleanMethod(prefs_object, prefs_getBool, (jstring) string_object1, false);
    env->DeleteLocalRef(string_object1);

    string_object1 = env->NewStringUTF("hostlist_path");
    string_object = env->CallObjectMethod(prefs_object, prefs_getString, (jstring) string_object1, NULL);
    settings.hostlist.hostlist_path = env->GetStringUTFChars((jstring) string_object, 0);
    env->DeleteLocalRef(string_object1);
    env->DeleteLocalRef(string_object);

    string_object1 = env->NewStringUTF("hostlist_format");
	string_object = env->CallObjectMethod(prefs_object, prefs_getString, (jstring) string_object1, NULL);
	settings.hostlist.hostlist_format = env->GetStringUTFChars((jstring) string_object, 0);
    env->DeleteLocalRef(string_object1);
    env->DeleteLocalRef(string_object);

    // Other options
    string_object1 = env->NewStringUTF("other_socks5");
    string_object = env->CallObjectMethod(prefs_object, prefs_getString, (jstring) string_object1, NULL);
    settings.other.socks5_server = env->GetStringUTFChars((jstring) string_object, 0);
    env->DeleteLocalRef(string_object1);
    env->DeleteLocalRef(string_object);

    string_object1 = env->NewStringUTF("other_http_proxy");
    string_object = env->CallObjectMethod(prefs_object, prefs_getString, (jstring) string_object1, NULL);
    settings.other.http_proxy_server = env->GetStringUTFChars((jstring) string_object, 0);
    env->DeleteLocalRef(string_object1);
    env->DeleteLocalRef(string_object);

    string_object1 = env->NewStringUTF("other_bind_port");
    string_object = env->CallObjectMethod(prefs_object, prefs_getString, (jstring) string_object1, NULL);
    settings.other.bind_port = atoi(env->GetStringUTFChars((jstring) string_object, 0));
    env->DeleteLocalRef(string_object1);
    env->DeleteLocalRef(string_object);

    string_object1 = env->NewStringUTF("other_vpn_setting");
    settings.other.is_use_vpn = env->CallBooleanMethod(prefs_object, prefs_getBool, (jstring) string_object1, false);
    env->DeleteLocalRef(string_object1);

    settings.app_files_dir = env->GetStringUTFChars(app_files_path, 0);

	// Parse hostlist if need
	if(settings.hostlist.is_use_hostlist)
	{
		if(parse_hostlist() == -1)
		{
			return -1;
		}
	}

	// Create socket
	if((server_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		log_error(log_tag.c_str(), "Can't create server socket");
		return -1;
	}

	// Set options for socket
	int opt = 1;
	if(setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int)))
	{
        log_error(log_tag.c_str(), "Can't setsockopt on server socket. Errno: %s", strerror(errno));
		return -1;
	}
	// Server address options
	struct sockaddr_in server_address;
	server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = INADDR_ANY;
	server_address.sin_port = htons(settings.other.bind_port);

	// Bind socket
	if(bind(server_socket, (struct sockaddr *) &server_address, sizeof(server_address)) < 0)
	{
		log_error(log_tag.c_str(), "Can't bind server socket. Errno: %s", strerror(errno));
		return -1;
	}

	// Listen to socket
	if(listen(server_socket, 10) < 0)
	{
		log_error(log_tag.c_str(), "Can't listen to server socket");
		return -1;
	}

	// Init interrupt pipe
	pipe(interrupt_pipe);
	return 0;
}

extern "C" JNIEXPORT void Java_ru_evgeniy_dpitunnel_service_NativeService_acceptClientCycle(JNIEnv* env, jobject obj)
{
    std::string log_tag = "CPP/acceptClientCycle";

    while(!stop_flag)
    {
        //Accept client
        int client_socket;
        struct sockaddr_in client_address;
        socklen_t client_address_size = sizeof(client_address);
        if((client_socket = accept(server_socket, (sockaddr *) &client_address, &client_address_size)) < 0)
        {
            log_error(log_tag.c_str(), "Can't accept client socket. Error: %s", std::strerror(errno));
            return;
        }

        // Create new thread
        std::thread t1(process_client, client_socket);
        threads.push_back(std::move(t1));
    }
}

extern "C" JNIEXPORT void Java_ru_evgeniy_dpitunnel_service_NativeService_deInit(JNIEnv* env, jobject obj)
{
    std::string log_tag = "CPP/deInit";

    stop_flag = true;
    // Interrupt poll()
    std::string interrupt = "interrupt";
    send(interrupt_pipe[1], interrupt.c_str(), interrupt.size(), 0);
	// Stop all threads
	for(auto& t1 : threads)
		if(t1.joinable())
			t1.join();

    // Shutdown server socket
    if(shutdown(server_socket, SHUT_RDWR) == -1)
    {
        log_error(log_tag.c_str(), "Can't shutdown server socket. Errno: %s", strerror(errno));
    }
    if(close(server_socket) == -1)
    {
        log_error(log_tag.c_str(), "Can't close server socket. Errno: %s", strerror(errno));
    }
}