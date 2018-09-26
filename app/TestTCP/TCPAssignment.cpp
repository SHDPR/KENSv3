/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"

namespace E
{

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{

}

void TCPAssignment::initialize()
{

}

void TCPAssignment::finalize()
{

}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	switch(param.syscallNumber)
	{
	case SOCKET:
		this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case CLOSE:
		this->syscall_close(syscallUUID, pid, param.param1_int);
		break;
	case READ:
		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
		//this->syscall_connect(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		//this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		//this->syscall_accept(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND:
		this->syscall_bind(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				(socklen_t) param.param3_int);
		break;
	case GETSOCKNAME:
		this->syscall_getsockname(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case GETPEERNAME:
		//this->syscall_getpeername(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{

}

void TCPAssignment::timerCallback(void* payload)
{

}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type){
	int socket = this->createFileDescriptor(pid);
	this->returnSystemCall(syscallUUID, socket);
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int socket){
	std::list<struct sock_comp>::iterator it;

	for(it = this->sock_list.begin(); it != this->sock_list.end(); it++){
		if((*it).socket == socket){
			break;
		}
	}

	if(it != this->sock_list.end()){
		this->sock_list.erase(it);
	}

	this->removeFileDescriptor(pid, socket);
	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int socket, sockaddr *address, socklen_t address_len){
	sock_comp new_sock;
	struct sockaddr_in* sock_info = (struct sockaddr_in *)address;
	new_sock.socket = socket;
	new_sock.addr = sock_info->sin_addr.s_addr;
	new_sock.port = sock_info->sin_port;

	std::list<struct sock_comp>::iterator it;
	// Overlap Check
	for(it = this->sock_list.begin(); it != sock_list.end(); it++){
		bool overlap = ((*it).socket == new_sock.socket) ||
									 (((*it).addr == 0 || new_sock.addr == 0) && ((*it).port == new_sock.port)) ||
									 (((*it).addr == new_sock.addr) && ((*it).port == new_sock.port));
		if(overlap){
			this->returnSystemCall(syscallUUID, -1);
		}
	}

	this->sock_list.push_back(new_sock);
	this->returnSystemCall(syscallUUID, 0);

}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int socket, sockaddr *address, socklen_t *address_len){
	struct sockaddr_in *sock_info = (struct sockaddr_in *)address;
	std::list<struct sock_comp>::iterator it;

	for(it = this->sock_list.begin(); it != this->sock_list.end(); it++){
		if((*iter).socket == socket){
			break;
		}
	}
	sock_info->sin_family = AF_INET;
	sock_info->sin_addr.s_addr = (*it).addr;
	sock_info->sin_port = (*it).port;
	this->returnSystemCall(syscallUUID, 0);
}

}
