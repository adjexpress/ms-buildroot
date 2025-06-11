#ifndef _SERVER__H__
#define _SERVER__H__

#include "Packet.h"
#include "Shell.h"
#include "Filesystem.h"
#include "Encryption.h"
#include "md5.h"
#include "Base64.h"
#include "Authenticator.h"
#include <fcntl.h>

/// class Server: starts a server-side object
/// It should be only called with constructor Server(StreamMode sm, unsigned int port_number);
/// All other constructor tries will be failed and terminate the application
/// 
class Server {
	private:
		int              server_;
		sockaddr_in      serv_addr_;
		unsigned int     port_number_;
		StreamMode       sm_;
		Packet*          internal_packet_;
		File_Attributes* file_attributes_;
		Encryption*      enc;

	public:
		/// Server CTOR. This is the only acceptable CTOR of the class
		///
		explicit Server         (StreamMode sm, unsigned int port_number, Encryption* enc);
		
		/// Server DTOR. This is the only acceptable DTOR of the class
		///
		~        Server         ();
		
		/// server object calls this method stablishing a new socket connection
		/// @param nothing
		/// @returns int: it depends on the status of the connection. Any failure returns -1 and successful connection will be resulted in 0
		///
		int      CreateSocket   ();
		
		/// attach socket to the port provide in CTOR
		/// @param nothing
		/// @returns int: it depends on the status of the connection. Any failure returns -1 and successful connection will be resulted in 0
		///
		int      BindSocket     ();
		
		/// starts listening (waiting) for any connection and/or reveiving packet from peer
		/// @param number_of_clients -> how many clients can be handeled at once
		/// @returns int: it depends on the status of the connection. Any failure returns -1 and successful connection will be resulted in 0
		///
		int      Listen         (unsigned int number_of_clients);
		
		/// an infinite loop calling method Accept
		/// @param nothing
		/// @returns nothing
		///
		void     InfiniteAccept ();
		
		/// the principal method accepting any comming packet from client-side
		/// Server will be assured by the validity of the packet and will acknowledge with another response packet
		/// @param nothing
		/// @returns nothing
		///
		void     Accept         ();
		
		/// shuts down the server-side entirelly and clean up all resources
		/// @param nothing
		/// @returns nothing
		///
		void     ShutDown       ();
};

#endif
