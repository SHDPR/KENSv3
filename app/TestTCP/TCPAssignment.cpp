/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 			  20150310 Sangmin Park
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
	// Search for the socket
	std::list<struct connection>::iterator it;
	for(it = this->sock_list.begin(); it != this->sock_list.end(); it++){
		if((*it).socket == socket){
			break;
		}
	}
	// Remove from socket list
	if(it != this->sock_list.end()){
		this->sock_list.erase(it);
	}
	this->removeFileDescriptor(pid, socket);
	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int socket, sockaddr *address, socklen_t address_len){
	// Define new connection
	connection sock0;
	struct sockaddr_in* addr = (struct sockaddr_in *)address;
	sock0.socket = socket;
	sock0.address = addr->sin_addr.s_addr;
	sock0.port = addr->sin_port;
	// Overlap Check
	std::list<struct connection>::iterator it;
	for(it = this->sock_list.begin(); it != sock_list.end(); it++){
		// 1. Is socket number same?
		// 2. Is either one of address zero? && Is port same?
		// 3. Are address and port both same?
		bool overlap = ((*it).socket == sock0.socket) ||
									 (((*it).address == 0 || sock0.address == 0) && ((*it).port == sock0.port)) ||
									 (((*it).address == sock0.address) && ((*it).port == sock0.port));
		// Return -1 if overlap
		if(overlap){
			this->returnSystemCall(syscallUUID, -1);
		}
	}
	// Insert on the end if no overlap
	this->sock_list.push_back(sock0);
	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int socket, sockaddr *address, socklen_t *address_len){
	struct sockaddr_in *addr = (struct sockaddr_in *)address;
	std::list<struct connection>::iterator it;
	// Search for the socket
	for(it = this->sock_list.begin(); it != this->sock_list.end(); it++){
		if((*it).socket == socket){
			break;
		}
	}
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = (*it).address;
	addr->sin_port = (*it).port;
	this->returnSystemCall(syscallUUID, 0);
}

}
