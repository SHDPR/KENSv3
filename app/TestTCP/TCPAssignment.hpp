/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 				20150310 Sangmin Park
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_


#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>


#include <E/E_TimerModule.hpp>

namespace E
{
// Socket connection structure defined
struct connection{
  int socket;
	long address;
	short port;
};

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:
	// Private Virtual Functions Added
	virtual void syscall_socket(UUID syscallUUID, int pid, int domain, int type);
	virtual void syscall_close(UUID syscallUUID, int pid, int socket);
	virtual void syscall_bind(UUID syscallUUID, int pid, int socket, sockaddr *address, socklen_t address_len);
	virtual void syscall_getsockname(UUID syscallUUID, int pid, int socket, sockaddr *address, socklen_t *address_len);
  // Sock_comp structure list for socket management
  std::list<struct connection> sock_list;
	virtual void timerCallback(void* payload) final;

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();

protected:
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
};

class TCPAssignmentProvider
{
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

}


#endif /* E_TCPASSIGNMENT_HPP_ */
