#ifdef __linux__
#		include "../include/Server.h"
#elif defined _WIN32
#		include "Server.h"
#endif

// define a size holder for serv_addr size
static size_t serv_addr_size = sizeof(sockaddr_in);

// define a signal to show if this is the first time for socket creation
static bool first_time_socket = true;

// define a global socket id which shows the server
static int new_socket = -1;

// check out if a pipe has more bytes to read
static bool pipe_has_more(int fd)
{
	struct pollfd fds;
	fds.fd     = fd;
	fds.events = POLLIN;
	int res    = poll(&fds, 1, 0);
	return fds.revents & POLLIN;
}

// Check out if a process is still alive
// We have to tackle the ZOMBIE processes as well, therefore, we cannot use "kill(pid, 0) == 0" functionality
static bool process_alive(unsigned int pid)
{
	// define a status holder
	int sts;

	// Check if the state of the child process has been changed
	waitpid(static_cast<pid_t>(pid), &sts, WNOHANG);

	// Report the existance or death of child process
	return WIFEXITED(sts) ? false : true;
}

// this is a global boolean flag to terminate the server side application residing on PC or phone
static bool breaking_server_connection = false;

// define a data structure to have index and address of executables
typedef struct _Executable_Id {
	unsigned int index;
	std::string  path;
	unsigned int pid;
	int          opipe[2];
	int          ipipe[2];
} Executable_Id;

// define a global executable indices
static std::vector<Executable_Id> executable_indices;

// wrapped_index calculation
static Wrapped_Index wrap_index(const std::vector<std::string>& vec)
{
	// This is a magic number
	Wrapped_Index wi = 0xF5AD829D;

	// Where is available in the global 'executable_indices' vector
	unsigned int current_available_index = executable_indices.size();

	// Create an Executable_Id entry based on the information from the given executable file address
	Executable_Id ex_id = { current_available_index, vec[0], static_cast<unsigned int>(~0), false};

	// Add this entry to the global 'executable_indices' vector
	executable_indices.push_back(ex_id);

	// Calculate the wrapped index and return it
	return wi | (current_available_index << 0x0B);
}

// unwrap index calculation
static inline unsigned int unwrap_index(const Wrapped_Index& wi)
{
	return static_cast<unsigned int>((0xF5AD829D ^ wi) >> 0x0B);
}

// Server CTOR
Server::Server(StreamMode sm, unsigned int port_number)
	:
	sm_              { sm },
	port_number_     { port_number },
	server_          { 0 },
	serv_addr_       {  },
	internal_packet_ { nullptr },
	file_attributes_ { nullptr }
{
}

// Server DTOR
Server::~Server()
{ // We do not destruct anything here
}

int Server::CreateSocket()
{
	// create the server socket
	this->server_ = ::socket(AF_INET, this->sm_, 0);

	// check its existance
	if (this->server_ < 0)
	{
		LOG("Socket creation error");
		return -1;
	}

	// attaching socket to the port this->port_number_
	int opt = 1;

	// define a status holder
	int status = -1;

	// With 'TCP_NODELAY', we can run server only with superuser previlage
	/*status = ::setsockopt(this->server_, SOL_SOCKET, TCP_NODELAY, &opt, sizeof(opt));
	if (status)
	{
		LOG("setsockopt failed");
		return -1;
	}*/
	opt = 1;
	status = ::setsockopt(this->server_, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
	if (status)
	{
		LOG("setsockopt failed");
		return -1;
	}
	opt = 1;
	status = ::setsockopt(this->server_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	if (status)
	{
		LOG("setsockopt failed");
		return -1;
	}

	// return successfully
	return 0;
}

int Server::BindSocket()
{
	// sockaddr_in is a structure containing an internet address and is defined in netinet/in.h
	// populate its necessary fields
	serv_addr_.sin_family      = AF_INET;
	serv_addr_.sin_port        = htons(this->port_number_);
	serv_addr_.sin_addr.s_addr = INADDR_ANY;

	// attach socket to the port this->port_number_
	int status = ::bind(this->server_, reinterpret_cast<sockaddr*>(&serv_addr_), sizeof(serv_addr_));

	// check the status of binding
	if (status < 0)
	{
		LOG("binding failed");
		return -1;
	}

	// return successfully
	return 0;
}

int Server::Listen(unsigned int number_of_clients)
{
	// start listening
	int status = ::listen(this->server_, number_of_clients);

	// check the status of the listening
	if (status < 0)
	{
		LOG("listening Failed");
		return -1;
	}

	// return successfully
	return 0;
}

void Server::InfiniteAccept()
{
	// run up until the 'breaking_server_connection' is still false
	try
	{
		while (breaking_server_connection == false)
		{
			// is it the first time we are here?
			if (first_time_socket)
			{
				// stablish the connection until termination will be fired
				new_socket = ::accept(this->server_, reinterpret_cast<sockaddr*>(&serv_addr_), reinterpret_cast<socklen_t*>(&serv_addr_size));
				
				// send out the signal to 'false state'
				first_time_socket = false;
			}

			// accept the connection between client and server and ready to transfer data
			this->Accept();

			// put the server socket in a passive mode waiting for a client to come and connect
			if (this->Listen(10) < 0)
				return;
		}
	}
	catch (const std::exception& ex)
	{
		ex.what();
	}
	catch (...)
	{
		std::cerr << "Unknown Exception!" << std::endl;
	}

	// 'breaking_server_connection' had been already set to true. Bring it back to false
	breaking_server_connection = false;
}

void Server::Accept()
{
	//check the status of acceptance of any client
	if (new_socket < 0)
	{
		LOG("acception failed");
		return;
	}

	// start an empty packet (this will be populated by packet from client)
	start_packet(internal_packet_, NONE);

	// define a 'connection_lost' signal
	bool connection_lost = false;

	// read the comming packet from client
	read_a_packet_from_socket(internal_packet_, connection_lost, new_socket);

	// In case, server was not tesponsive and socket was closed, reopen a socket again and wait for client to approach
	while(connection_lost)
	{
		// signal that server socket is again up 
		connection_lost = false;

		// recreate a new socket for server
		new_socket = ::accept(this->server_, reinterpret_cast<sockaddr*>(&serv_addr_), reinterpret_cast<socklen_t*>(&serv_addr_size));

		// read the comming packet from client
		read_a_packet_from_socket(internal_packet_, connection_lost, new_socket);
	}

	// first off, check out the packet's checksum to be what has been written by client
	if(evaluate_checksum(internal_packet_) == false)
	{
		LOG("checksum of packet from client to server failed");

		// clean up the allocated body
		delete[] internal_packet_->body;

		// clean up the internal_packet_ for the next communication
		delete internal_packet_;

		// send error to the client
		set_error_packet(new_socket, internal_packet_, CHECKSUM_ERROR);

		// return to the caller
		return;
	}

	// define a holder for the size of decrypted data
	int decryptedtext_len = 0;

	// define a unique buffer for decrypted data.
	std::unique_ptr<unsigned char[]> decryptedtext {nullptr};

	// It will get the size from comming packet's header from client
	if (internal_packet_->header.SizeBody)
		decryptedtext = std::make_unique<unsigned char[]>(internal_packet_->header.SizeBody);

	// report that server got a packet
	LOG("Server received a packet");

	// Decrypt the cipher text message (body)
	if (internal_packet_->header.SizeBody)
	{
		// do the decryption and retrieve the size
		decryptedtext_len = encryption->decrypt(reinterpret_cast<unsigned char*>(internal_packet_->body), internal_packet_->header.SizeBody, decryptedtext.get());

		// Check out the validity
		if (decryptedtext_len == -1)
		{
			// report message			
			LOG("decryption failed");

			// Is it the KILL_SERVER packet? If, so completely return
			if (internal_packet_->header.Type == TERMINATE_SERVER || internal_packet_->header.Type == EXIT_SERVER || internal_packet_->header.Type == KILL_SERVER)
				breaking_server_connection = true;

			// clean up the allocated body
			delete[] internal_packet_->body;

			// clean up the internal_packet_ for the next communication
			delete internal_packet_;

			// send error to the client
			set_error_packet(new_socket, internal_packet_, ENCRYPT_DECRYPT_ERROR);

			// return to the caller
			return;			
		}
	}

	//what type of packet it is?
	switch (internal_packet_->header.Type)
	{
		case SHELL: // run shell on phone device and get the reply from it
		{
			// define a holder for replying from OS
			std::string phone_executed_message = "";

			// get command from the internal_packet_
			std::string run_shell_status = run_shell(std::string(reinterpret_cast<char*>(decryptedtext.get()))); //std::string run_shell_status = run_shell(string(internal_packet_->body));

			if(run_shell_status.size() == std::string::npos)
			{
				// report the error message
				LOG("SHELL :: running shell command in server failed");

				// clean up the internal_packet_ command string holder
				delete[] internal_packet_->body;

				// clean up the internal_packet_ for the next communication
				delete internal_packet_;

				// send error to the client
				set_error_packet(new_socket, internal_packet_, SHELL_ERROR);

				// terminate
				return;
			}

			else
			{
				// get the response from OS
				phone_executed_message = (run_shell_status == "") ? ".": run_shell_status;

				// clean up the internal_packet_ command string holder
				delete[] internal_packet_->body;

				// clean up the internal_packet_ for the next communication
				delete internal_packet_;
			}

			// start a REPLY_SHELL packet
			start_packet(this->internal_packet_, REPLY_SHELL);

			// if this packet is SHELL type, server will acknowledge wiht a REPLY_SHELL packet after receiving the client packet
			reply_shell_packet(this->internal_packet_, phone_executed_message);

			// create a buffer for the final message to be sent
			std::unique_ptr<char[]> final_message {nullptr};

			// prepare the final message
			unsigned int packet_size = prepare_final_message(internal_packet_, phone_executed_message, final_message);

			// send the server's prepared_message to the client
			::send(new_socket, final_message.get(), packet_size, 0);

			// display the sent message acknowledge
			LOG("SHELL :: Server sent a message");

			// clean up the internal_packet_ command string holder
			delete[] internal_packet_->body;

			// clean up the internal_packet_ for the next communication
			delete internal_packet_;

			// sleep 1 second
			sleep(1);
		} break;

		case START_SEND_FILE:
		{
			// file address
			std::string file_address = reinterpret_cast<char*>(decryptedtext.get()); //std::string file_address = string(internal_packet_->body);

			// file size
			unsigned long long file_size = internal_packet_->header.TotalFileSize;

			// keep file's attributes for data to come later in DATA_SEND_FILE packet
			this->file_attributes_ = new File_Attributes;
			this->file_attributes_->file_size_         = file_size;
			this->file_attributes_->file_descriptor_   = ~0;
			this->file_attributes_->bytes_handeled_    = 0ULL;
			this->file_attributes_->stream_file_buffer = nullptr;
			this->file_attributes_->stream_file_length = 0ULL;

			// clean up the internal_packet_ command string holder
			delete[] internal_packet_->body;

			// clean up the internal_packet_ for the next communication
			delete internal_packet_;

			// start a REPLY_START_SEND_FILE packet
			start_packet(this->internal_packet_, REPLY_START_SEND_FILE);

			// prepare the server acknowledgement message
			std::string message = "START_SEND_FILE :: Server: okay!";

			// set this message to the packet
			reply_start_send_file_packet(this->internal_packet_, message);

			// create a buffer for the final message to be sent
			std::unique_ptr<char[]> final_message {nullptr};

			// prepare the final message
			unsigned int packet_size = prepare_final_message(internal_packet_, message, final_message);

			// send the server's prepared_message to the client
			::send(new_socket, final_message.get(), packet_size, 0);

			// display the sent message acknowledge
			LOG("START_SEND_FILE :: Server sent a message");

			// clean up the internal_packet_ for the next communication
			delete internal_packet_;

			// sleep 1 second
			sleep(1);
		} break;

		case DATA_SEND_FILE:
		{
			// did we open file in a packet START_SEND_FILE before?
			if(this->file_attributes_ == nullptr)
			{
				LOG("DATA_SEND_FILE :: Error: no file was set before");

				// clean up the internal_packet_ command string holder
				delete[] internal_packet_->body;

				// clean up the internal_packet_ for the next communication
				delete internal_packet_;

				// send error to the client
				set_error_packet(new_socket, internal_packet_, INTERNAL_BUFFER_ERROR);

				// return to the caller
				return;
			}

			else
			{
				// is it the target file address to be opened?
				if (this->file_attributes_->file_descriptor_ == ~0)
				{
					// file address
					std::string file_address = reinterpret_cast<char*>(decryptedtext.get()); //std::string file_address = string(internal_packet_->body);

					// open file
					int fd = open(file_address.c_str(), O_CREAT | O_RDWR | O_APPEND | O_NONBLOCK, S_IRWXU);

					// if file opening failed
					if(fd < 0)
					{
						// report the error message
						LOG("DATA_SEND_FILE :: creating file in server failed");

						// clean up the internal_packet_ command string holder
						delete[] internal_packet_->body;

						// clean up the internal_packet_ for the next communication
						delete internal_packet_;

						// which kind of error did we get?
						Error_Types error_type = 
							( errno == EACCES ) ? START_SEND_FILE_PACKET_PERMISSION_ERROR : 
								( errno == EINVAL ) ? START_SEND_FILE_PACKET_PATH_ERROR :
									( errno == EFBIG ) ? START_SEND_FILE_PACKET_VOLUME_SPACE_ERROR :
										( errno == EOVERFLOW ) ? START_SEND_FILE_PACKET_VOLUME_SPACE_ERROR : INTERNAL_BUFFER_ERROR;

						// send error to the client
						set_error_packet(new_socket, internal_packet_, error_type);

						// terminate
						return;
					}

					// register the file's descriptor for the other coming DATA_SEND_FILE packets
					this->file_attributes_->file_descriptor_ = fd;

					// clean up the internal_packet_ command string holder
					delete[] internal_packet_->body;

					// clean up the internal_packet_ for the next communication
					delete internal_packet_;

					// start a REPLY_DATA_SEND_FILE packet
					start_packet(this->internal_packet_, REPLY_DATA_SEND_FILE);

					// prepare the acknowledgment message to be sent to the client
					std::string message = "DATA_SEND_FILE :: Server: okay!";

					// attach ths message to the packet
					reply_data_send_file_packet(this->internal_packet_, message);

					// create a buffer for the final message to be sent
					std::unique_ptr<char[]> final_message {nullptr};

					// prepare the final message
					unsigned int packet_size = prepare_final_message(internal_packet_, message, final_message);

					// send the server's prepared_message to the client
					::send(new_socket, final_message.get(), packet_size, 0);

					// display the sent message acknowledge
					LOG("DATA_SEND_FILE :: Server sent a message");

					// clean up the internal_packet_ command string holder
					delete[] internal_packet_->body;

					// clean up the internal_packet_ for the next communication
					delete internal_packet_;

					// return to the caller
					return;
				}				

				// write data into the file
				ssize_t bytes_written = write(this->file_attributes_->file_descriptor_, decryptedtext.get(), decryptedtext_len);

				// was writing successful?
				if (bytes_written != decryptedtext_len)
				{
					LOG("DATA_SEND_FILE :: Error: write to file failed");

					// clean up the internal_packet_ command string holder
					delete[] internal_packet_->body;

					// clean up the internal_packet_ for the next communication
					delete internal_packet_;

					// do the file closing
					int file_closed = close(this->file_attributes_->file_descriptor_);

					// check the status of file closing
					if (file_closed < 0)
					{
						LOG("DATA_SEND_FILE :: Error: closing the file descriptor failed");

						// send error to the client
						set_error_packet(new_socket, internal_packet_, DATA_SEND_FILE_PACKET_CLOSE_FILE_ERROR);
					}

					// clean up the file_descriptor_ internal object
					delete this->file_attributes_;

					// set it to nullptr
					this->file_attributes_ = nullptr;
					
					// send error to the client
					set_error_packet(new_socket, internal_packet_, DATA_SEND_FILE_PACKET_WRITE_FILE_ERROR);

					// return to the caller
					return;
				}

				// update the number of bytes already written by this packet
				this->file_attributes_->bytes_handeled_ += decryptedtext_len;

				// if written bytes, exceeds the demanded file size, send an error and terminate the flow of the communication
				if (this->file_attributes_->bytes_handeled_ > this->file_attributes_->file_size_)
				{
					LOG("DATA_SEND_FILE :: Error: bytes written to file overpassed the demanded total file size");

					// clean up the internal_packet_ command string holder
					delete[] internal_packet_->body;

					// clean up the internal_packet_ for the next communication
					delete internal_packet_;

					// do the file closing
					int file_closed = close(this->file_attributes_->file_descriptor_);

					// check the status of file closing
					if (file_closed < 0)
					{
						LOG("DATA_SEND_FILE :: Error: closing the file descriptor failed");

						// send error to the client
						set_error_packet(new_socket, internal_packet_, DATA_SEND_FILE_PACKET_CLOSE_FILE_ERROR);
					}
					
					// clean up the file_descriptor_ internal object
					delete this->file_attributes_;

					// set it to nullptr
					this->file_attributes_ = nullptr;

					// send error to the client
					set_error_packet(new_socket, internal_packet_, DATA_SEND_FILE_PACKET_OVERPASSED_BYTES_ERROR);

					// return to the caller
					return;
				}

				// if written bytes, equals the demanded file size, successfully, terminate the flow of the communication
				else if (this->file_attributes_->bytes_handeled_ == this->file_attributes_->file_size_)
				{
					LOG("DATA_SEND_FILE :: write to file finished successfully");

					// clean up the internal_packet_ command string holder
					delete[] internal_packet_->body;

					// clean up the internal_packet_ for the next communication
					delete internal_packet_;

					// do the file closing
					int file_closed = close(this->file_attributes_->file_descriptor_);

					// check the status of file closing
					if (file_closed < 0)
					{
						LOG("DATA_SEND_FILE :: Error: clsoing the file descriptor failed");

						// send error to the client
						set_error_packet(new_socket, internal_packet_, DATA_SEND_FILE_PACKET_CLOSE_FILE_ERROR);
					}

					// clean up the file_descriptor_ internal object
					delete this->file_attributes_;

					// set it to nullptr
					this->file_attributes_ = nullptr;
				}

				// if written bytes is less than the demanded file size, it means next packets must come
				else
				{
					// clean up the internal_packet_ command string holder
					delete[] internal_packet_->body;

					// clean up the internal_packet_ for the next communication
					delete internal_packet_;
				}
			}

			// start a REPLY_DATA_SEND_FILE packet
			start_packet(this->internal_packet_, REPLY_DATA_SEND_FILE);

			// prepare the acknowledgment message to be sent to the client
			std::string message = "DATA_SEND_FILE :: Server: okay!";

			// attach ths message to the packet
			reply_data_send_file_packet(this->internal_packet_, message);

			// create a buffer for the final message to be sent
			std::unique_ptr<char[]> final_message {nullptr};

			// prepare the final message
			unsigned int packet_size = prepare_final_message(internal_packet_, message, final_message);

			// send the server's prepared_message to the client
			::send(new_socket, final_message.get(), packet_size, 0);

			// display the sent message acknowledge
			LOG("DATA_SEND_FILE :: Server sent a message");

			// clean up the internal_packet_ command string holder
			delete[] internal_packet_->body;

			// clean up the internal_packet_ for the next communication
			delete internal_packet_;

		} break;

		case START_GET_FILE:
		{
			// file address
			std::string file_address = reinterpret_cast<char*>(decryptedtext.get()); //std::string file_address = string(internal_packet_->body);

			// open file wih only Read permissions
			int fd = open(file_address.c_str(), O_RDONLY, S_IRWXU | S_IRWXG | S_IRWXO);

			// if file opening failed
			if(fd < 0)
			{
				// report the error message
				LOG("START_GET_FILE :: opening file in server failed");

				// clean up the internal_packet_ command string holder
				delete[] internal_packet_->body;

				// clean up the internal_packet_ for the next communication
				delete internal_packet_;

				// which kind of error did we get?
				Error_Types error_type = 
					( errno == EACCES ) ? START_SEND_FILE_PACKET_PERMISSION_ERROR : 
						( errno == EINVAL ) ? START_SEND_FILE_PACKET_PATH_ERROR :
							( errno == EFBIG ) ? START_SEND_FILE_PACKET_VOLUME_SPACE_ERROR :
								( errno == EOVERFLOW ) ? START_SEND_FILE_PACKET_VOLUME_SPACE_ERROR : INTERNAL_BUFFER_ERROR;

				// send error to the client
				set_error_packet(new_socket, internal_packet_, error_type);

				// sleep 500 usec
				usleep(500);
				
				// break from this packet
				break;
			}

			else // retrieve size of the file
			{
				// define a holder for the file size
				unsigned int file_size = 0;

				// instantiate a Stat object
				Stat st;

				// get the file attributes into the Stat object and check its status
   				if (fstat(fd, &st) == -1) 
				{
   					LOG("START_GET_FILE :: obtaining file size in server failed");

   				   	// clean up the internal_packet_ command string holder
					delete[] internal_packet_->body;

					// clean up the internal_packet_ for the next communication
					delete internal_packet_;

					// do the file closing
					int file_closed = close(fd);

					// check the status of file closing
					if (file_closed < 0)
					{
						LOG("START_GET_FILE :: Error: closing the file descriptor failed");

						// send error to the client
						set_error_packet(new_socket, internal_packet_, START_GET_FILE_PACKET_CLOSE_FILE_ERROR);
					}

					// send error to the client
					set_error_packet(new_socket, internal_packet_, START_GET_FILE_PACKET_SIZEOF_FILE_ERROR);

					// terminate
					return;
   				}

				else
				{
					// set the file size from Stat object
					file_size = st.st_size;
				}

				// keep file's attributes for data to be sent later in DATA_GET_FILE packet
				this->file_attributes_ = new File_Attributes;
				this->file_attributes_->file_size_         = file_size;
				this->file_attributes_->file_descriptor_   = fd;
				this->file_attributes_->bytes_handeled_    = 0ULL;
				this->file_attributes_->stream_file_buffer = nullptr;
				this->file_attributes_->stream_file_length = file_size;

				// clean up the internal_packet_ command string holder
				delete[] internal_packet_->body;

				// clean up the internal_packet_ for the next communication
				delete internal_packet_;
			}

			// start a REPLY_START_GET_FILE packet
			start_packet(this->internal_packet_, REPLY_START_GET_FILE);

			// define the acknowledgement message to be sent to the client
			std::string message = "START_GET_FILE :: Server: okay!";

			// make the client packet to be ready by the message above
			reply_start_get_file_packet(this->internal_packet_, message, this->file_attributes_->file_size_);

			// create a buffer for the final message to be sent
			std::unique_ptr<char[]> final_message {nullptr};

			// prepare the final message
			unsigned int packet_size = prepare_final_message(internal_packet_, message, final_message);

			// send the server's prepared_message to the client
			::send(new_socket, final_message.get(), packet_size, 0);

			// display the sent message acknowledge on STDOUT
			LOG("START_GET_FILE :: Server sent a message");
			
			// clean up the internal_packet_ command string holder
			delete[] internal_packet_->body;

			// clean up the internal_packet_ for the next communication
			delete internal_packet_;

			// sleep 500 usec
			usleep(500);
		} break;

		case DATA_GET_FILE:
		{
			// did we open file in START_GET_FILE?
			if(this->file_attributes_ == nullptr)
			{
				LOG("DATA_GET_FILE :: Error: no file was opened before");
				
				// clean up the internal_packet_ command string holder
				delete[] internal_packet_->body;

				// clean up the internal_packet_ for the next communication
				delete internal_packet_;

				// send error to the client
				set_error_packet(new_socket, internal_packet_, INTERNAL_BUFFER_ERROR);

				// sleep 500 usec
				usleep(500);
				
				// break from this packet
				break;
			}

			else
			{
				// get the file descriptor
				int fd = this->file_attributes_->file_descriptor_;

				// how many chunks do we need to proceed?
				unsigned int chunks_number = this->file_attributes_->file_size_ / FILE_BLOCK;

				// how many bytes have been left for the very last round of data reading?
				unsigned int remained = this->file_attributes_->file_size_ - (chunks_number * FILE_BLOCK);
				
				// define a holder to track number of bytes already handled
				unsigned long long handeled_size = 0;

				// define a holder to hold file size from file_attributes_ object
				unsigned long long file_size = this->file_attributes_->file_size_;
				
				// We do not need the file_attribute_ object anymore, as such, clean it up
				delete this->file_attributes_;

				// zero it out
				this->file_attributes_ = nullptr;

				// clean up the internal_packet_ command string holder
				delete[] internal_packet_->body;

				// clean up the internal_packet_ for the next communication
				delete internal_packet_;

				// Quirk. Sometimes we have files with size zero, especially in filesystem retrieve, handle it separatelly
				if (file_size == 0)
				{
					// start a REPLY_DATA_GET_FILE packet
					start_packet(this->internal_packet_, REPLY_DATA_GET_FILE);

					// Prepare the packet
					reply_data_get_file_packet(this->internal_packet_, 0);

					// define a holder for final message to be sent to client
					std::unique_ptr<char[]> final_message {nullptr};

					// define a temporary char holder
					char tmp = ' ';

					// prepare the encrypted packet
					unsigned int packet_size = prepare_final_message(internal_packet_, &tmp, 0, final_message); // <------

					// send it to TCP channel
					::send(new_socket, final_message.get(), packet_size, 0);

					// Log on STDOUT
					LOG("DATA_GET_FILE :: Server sent a message");

					// Get rid of the body of the packet
					delete[] internal_packet_->body;

					// delete the packet
					delete internal_packet_;

					// break from this packet
					break;
				}

				// create a smart container to read data into it
				std::unique_ptr<char[]> block_bytes_buffer = std::make_unique<char[]>(FILE_BLOCK);

				// handle chunks number of FILE_BLOCK sized data reading from file by server and sending to client
				while (chunks_number)
				{
					// read 'FILE_BLOCK' bytes into the buffer
					ssize_t bytes_read = read(fd, block_bytes_buffer.get(), FILE_BLOCK);

					// was reading successful?
					if (bytes_read != FILE_BLOCK)
					{
						LOG("DATA_GET_FILE :: Error: read from file failed");

						// clean up the internal_packet_ command string holder
						delete[] internal_packet_->body;

						// clean up the internal_packet_ for the next communication
						delete internal_packet_;

						// do the file closing
						int file_closed = close(fd);

						// check the status of file closing
						if (file_closed < 0)
						{
							LOG("DATA_GET_FILE :: Error: closing the file descriptor failed");

							// send error to the client
							set_error_packet(new_socket, internal_packet_, DATA_GET_FILE_PACKET_CLOSE_FILE_ERROR);
						}

						// send error to the client
						set_error_packet(new_socket, internal_packet_, DATA_GET_FILE_PACKET_READ_FILE_ERROR);

						// return to the caller
						return;
					}

					// update the number of bytes already read by this packet
					handeled_size += FILE_BLOCK;

					// if read bytes, exceeds the demanded file size, send an error and terminate the flow of the communication
					if (handeled_size > file_size)
					{
						LOG("DATA_GET_FILE :: Error: bytes read from file overpassed the demanded total file size");

						// do the file closing
						int file_closed = close(fd);

						// check the status of file closing
						if (file_closed < 0)
						{
							LOG("DATA_GET_FILE :: Error: closing the file descriptor failed");

							// send error to the client
							set_error_packet(new_socket, internal_packet_, DATA_GET_FILE_PACKET_CLOSE_FILE_ERROR);

							// return to the caller
							return;
						}

						// send error to the client
						set_error_packet(new_socket, internal_packet_, DATA_GET_FILE_PACKET_OVERPASSED_BYTES_ERROR);

						// return to the caller
						return;
					}

					// if read bytes, equals the demanded file size, successfully, terminate the flow of the communication
					else if (handeled_size == file_size)
					{
						LOG("DATA_GET_FILE :: read from file finished successfully");

						// do the file closing
						int file_closed = close(fd);

						// check the status of file closing
						if (file_closed < 0)
						{
							LOG("DATA_GET_FILE :: Error: closing the file descriptor failed");

							// send error to the client
							set_error_packet(new_socket, internal_packet_, DATA_GET_FILE_PACKET_CLOSE_FILE_ERROR);

							// return to the caller
							return;
						}

						// start a REPLY_DATA_GET_FILE packet
						start_packet(this->internal_packet_, REPLY_DATA_GET_FILE);

						// attach the message to the packet
						reply_data_get_file_packet(this->internal_packet_, FILE_BLOCK);

						// create a buffer for the final message to be sent
						std::unique_ptr<char[]> final_message {nullptr};

						// prepare the final message
						unsigned int packet_size = prepare_final_message(internal_packet_, block_bytes_buffer.get(), FILE_BLOCK, final_message);

						// send the server's prepared_message to the client
						::send(new_socket, final_message.get(), packet_size, 0);

						// display the sent message acknowledge
						LOG("DATA_GET_FILE :: Server sent a message");

						// clean up the internal_packet_ command string holder
						delete[] internal_packet_->body;

						// clean up the internal_packet_ for the next communication
						delete internal_packet_;

						// sleep 500 usec
						usleep(500);

						// ...
						break;
					}

					// if read bytes is less than the demanded file size, it means next packets must go
					else
					{
						// start a REPLY_DATA_GET_FILE packet
						start_packet(this->internal_packet_, REPLY_DATA_GET_FILE);

						// attach the message to the packet
						reply_data_get_file_packet(this->internal_packet_, FILE_BLOCK);

						// create a buffer for the final message to be sent
						std::unique_ptr<char[]> final_message {nullptr};

						// prepare the final message
						unsigned int packet_size = prepare_final_message(internal_packet_, block_bytes_buffer.get(), FILE_BLOCK, final_message);

						// send the server's prepared_message to the client
						::send(new_socket, final_message.get(), packet_size, 0);
						
						// display the sent message acknowledge
						LOG("DATA_GET_FILE :: Server sent a message");

						// clean up the internal_packet_ command string holder
						delete[] internal_packet_->body;

						// clean up the internal_packet_ for the next communication
						delete internal_packet_;
					}

					// sleep 500 usec
					usleep(500);
	
					// decrement the chunk's counter
					chunks_number--;
				}

				// do we have any bytes remained
				if (remained)
				{
					// start a REPLY_DATA_GET_FILE packet
					start_packet(this->internal_packet_, REPLY_DATA_GET_FILE);

					// create a smart container to read data into it
					std::unique_ptr<char[]> remaining_bytes_buffer = std::make_unique<char[]>(remained);

					// read 'remained' bytes into the buffer
					ssize_t bytes_read = read(fd, remaining_bytes_buffer.get(), remained);

					// was reading successful?
					if (bytes_read != remained)
					{
						LOG("DATA_GET_FILE :: Error: read from file failed");

						// clean up the internal_packet_ command string holder
						delete[] internal_packet_->body;

						// clean up the internal_packet_ for the next communication
						delete internal_packet_;

						// do the file closing
						int file_closed = close(fd);

						// check the status of file closing
						if (file_closed < 0)
						{
							LOG("DATA_GET_FILE :: Error: closing the file descriptor failed");

							// send error to the client
							set_error_packet(new_socket, internal_packet_, DATA_GET_FILE_PACKET_CLOSE_FILE_ERROR);
						}

						// send error to the client
						set_error_packet(new_socket, internal_packet_, DATA_GET_FILE_PACKET_READ_FILE_ERROR);

						// return to the caller
						return;
					}

					// update the number of bytes already read by this packet
					handeled_size += remained;

					// if read bytes, exceeds the demanded file size, send an error and terminate the flow of communication
					if (handeled_size > file_size)
					{
						LOG("DATA_GET_FILE :: Error: bytes read from file overpassed the demanded total file size");

						// clean up the internal_packet_ command string holder
						delete[] internal_packet_->body;

						// clean up the internal_packet_ for the next communication
						delete internal_packet_;

						// do the file closing
						int file_closed = close(fd);

						// check the status of file closing
						if (file_closed < 0)
						{
							LOG("DATA_GET_FILE :: Error: closing the file descriptor failed");

							// send error to the client
							set_error_packet(new_socket, internal_packet_, DATA_GET_FILE_PACKET_CLOSE_FILE_ERROR);
						}

						// send error to the client
						set_error_packet(new_socket, internal_packet_, DATA_GET_FILE_PACKET_OVERPASSED_BYTES_ERROR);

						// return to the caller
						return;
					}

					// if read bytes, equals the demanded file size, successfully, terminate the flow of communication
					else if (handeled_size == file_size)
					{
						LOG("DATA_GET_FILE :: read from file finished successfully");

						// do the file closing
						int file_closed = close(fd);

						// check the status of file closing
						if (file_closed < 0)
						{
							LOG("DATA_GET_FILE :: Error: closing the file descriptor failed");

							// send error to the client
							set_error_packet(new_socket, internal_packet_, DATA_GET_FILE_PACKET_CLOSE_FILE_ERROR);

							// return to the caller
							return;
						}
					}

					// if read bytes is less than the demanded file size, it means error in this place
					else
					{
						LOG("DATA_GET_FILE :: Error: bytes read from file did not reach the demanded file size");

						// clean up the internal_packet_ command string holder
						delete[] internal_packet_->body;

						// clean up the internal_packet_ for the next communication
						delete internal_packet_;

						// do the file closing
						int file_closed = close(fd);

						// check the status of file closing
						if (file_closed < 0)
						{
							LOG("DATA_GET_FILE :: Error: closing the file descriptor failed");

							// send error to the client
							set_error_packet(new_socket, internal_packet_, DATA_GET_FILE_PACKET_CLOSE_FILE_ERROR);
						}

						// send error to the client
						set_error_packet(new_socket, internal_packet_, DATA_GET_FILE_PACKET_INCUFFICIENT_BYTES_ERROR);

						// return to the caller
						return;
					}

					// attach ths message to the packet
					reply_data_get_file_packet(this->internal_packet_, remained);

					// create a buffer for the final message to be sent
					std::unique_ptr<char[]> final_message{ nullptr };

					// prepare the final message
					unsigned int packet_size = prepare_final_message(internal_packet_, remaining_bytes_buffer.get(), remained, final_message);

					// send the server's prepared_message to the client
					::send(new_socket, final_message.get(), packet_size, 0);

					// display the sent message acknowledge
					LOG("DATA_GET_FILE :: Server sent a message");

					// clean up the internal_packet_ command string holder
					delete[] internal_packet_->body;

					// clean up the internal_packet_ for the next communication
					delete internal_packet_;

					// sleep 500 usec
					usleep(500);
				}
			}
		} break;

		case GET_DIRECTORIES:
		{
			// define a holder for the address of where we woud want to get directories
			std::string address = reinterpret_cast<char*>(decryptedtext.get());
			
			// define a vector of strings to get list of directories from OS
			std::vector<std::string> directories;

			// look through filesystem and populate the provided vector with directories' names
			int directory_search_result = search_through_filesystem(address, directories, DIRECTORY_DEMANDED);

			// Did it succeed?
			if (directory_search_result == -1)
			{
				// throw an error packet
				set_error_packet(new_socket, this->internal_packet_, GET_DIRECTORIES_PACKET_FILESYSTEM_ERROR);

				// sleep 500 usec
				usleep(500);

				// break
				break;
			}

			// start a REPLY_GET_DIRECTORIES packet
			start_packet(this->internal_packet_, REPLY_GET_DIRECTORIES);

			// pack all vector's entries in a final string separated with \n character
			std::string message = "";

			// loop through all vector entries
			for (const auto& entry : directories)
				message += entry + '\n';

			// Remove very last '\n' and replace with '\0'
			message.pop_back();
			message += '\0';
			
			// server will acknowledge wiht a REPLY_GET_DIRECTORIES packet after receiving the client packet
			reply_get_directories_packet(this->internal_packet_, message, directories.size());

			// create a buffer for the final message to be sent
			std::unique_ptr<char[]> final_message {nullptr};

			// prepare the final message
			unsigned int packet_size = prepare_final_message(internal_packet_, message, final_message);

			// send the server's prepared_message to the client
			::send(new_socket, final_message.get(), packet_size, 0);

			// display the sent message acknowledge
			LOG("GET_DIRECTORIES :: Server sent a message");

			// Get rid of the body of the packet
			delete[] internal_packet_->body;

			// clean up the internal_packet_ for the next communication
			delete internal_packet_;

			// sleep 500 usec
			usleep(500);
		} break;

		case GET_FILES:
		{
			// define a holder for the address of where we woud want to get files
			std::string address = reinterpret_cast<char*>(decryptedtext.get());
			
			// define a vector of strings to get list of files from OS
			std::vector<std::string> files;
			
			// look through filesystem and populate the provided vector with files' names
			int directory_search_result = search_through_filesystem(address, files, FILE_DEMANDED);

			// Did it succeed?
			if (directory_search_result == -1)
			{
				// throw an error packet
				set_error_packet(new_socket, this->internal_packet_, GET_DIRECTORIES_PACKET_FILESYSTEM_ERROR);

				// sleep 500 usec
				usleep(500);

				// break
				break;
			}

			// start a REPLY_GET_FILES packet
			start_packet(this->internal_packet_, REPLY_GET_FILES);

			// pack all vector's entries in a final string separated with \n character
			std::string message = "";

			// loop through all vector entries
			for (const auto& entry : files)
				message += entry + '\n';	

			// Remove very last '\n' and replace with '\0'
			message.pop_back();
			message += '\0';

			// server will acknowledge wiht a REPLY_GET_FILES packet after receiving the client packet
			reply_get_files_packet(this->internal_packet_, message, files.size());

			// create a buffer for the final message to be sent
			std::unique_ptr<char[]> final_message {nullptr};
			
			// prepare the final message
			unsigned int packet_size = prepare_final_message(internal_packet_, message, final_message);

			// send the server's prepared_message to the client
			::send(new_socket, final_message.get(), packet_size, 0);

			// display the sent message acknowledge
			LOG("GET_FILES :: Server sent a message");

			// Get rid of the body of the packet
			delete[] internal_packet_->body;

			// clean up the internal_packet_ for the next communication
			delete internal_packet_;

			// sleep 500 usec
			usleep(500);
		} break;

		case TERMINATE_SERVER: case EXIT_SERVER: case KILL_SERVER:
		{
			// signal the kill message
			LOG("KILL_SERVER :: Kill Server Message!");
			
			// neglect any packet from client and set the flag of killing server to true
			breaking_server_connection = true;

			// start a REPLY_GET_FILES packet
			start_packet(this->internal_packet_, NONE);

			// pack all vector's entries in a final string separated with \n character
			std::string message = "__kill__done__";			

			// server will acknowledge wiht a REPLY_GET_FILES packet after receiving the client packet
			termination_packet(this->internal_packet_, message);

			// create a buffer for the final message to be sent
			std::unique_ptr<char[]> final_message {nullptr};

			// prepare the final message
			unsigned int packet_size = prepare_final_message(internal_packet_, message, final_message);

			// send the server's prepared_message to the client
			::send(new_socket, final_message.get(), packet_size, 0);

			// display the sent message acknowledge
			LOG("KILL_SERVER :: Server sent a message");

			// clean up the internal_packet_ for the next communication
			delete internal_packet_;

			// sleep 1 second
			sleep(1);
		} break;

		case EXECUTE:
		{
			// We have to split executable address and all its arguments separated
			std::vector<std::string> executable_and_arguments;

			// Create a stringstream object with the input string 
    		std::stringstream ss(reinterpret_cast<char*>(decryptedtext.get())); 
  
    		// Tokenize the input string by ' ' delimiter 
    		std::string token;
    		char delimiter = ' '; 

			// start populating the associated vector
    		while (std::getline(ss, token, delimiter))
       			executable_and_arguments.push_back(token);		

			// Now we have to evaluate the existance of the executable file and handle any possible errors
			int fd = open(executable_and_arguments[0].c_str(), O_CREAT | O_RDWR | O_APPEND, S_IRWXU);
			
			// if file opening failed
			if(fd < 0)
			{
				// report the error message
				LOG("EXECUTE :: path of executable file in server failed");

				// clean up the internal_packet_ command string holder
				delete[] internal_packet_->body;

				// clean up the internal_packet_ for the next communication
				delete internal_packet_;

				// which kind of error did we get?
				Error_Types error_type = 
					( errno == EACCES ) ? EXECUTE_PACKET_PERMISSION_ERROR : 
						( errno == EINVAL ) ? EXECUTE_PACKET_NOT_FOUND_EXECUTABLE_ERROR :
							( errno == EFBIG ) ? EXECUTE_PACKET_VOLUME_SPACE_ERROR :
								( errno == EOVERFLOW ) ? EXECUTE_PACKET_VOLUME_SPACE_ERROR : INTERNAL_BUFFER_ERROR;

				// send error to the client
				set_error_packet(new_socket, internal_packet_, error_type);

				// terminate
				return;
			}
			else
			{
				// now we have a proper executable file available and ready to get authenticated and ran. Close the file descriptor
				int file_closed = close(fd);

				// Check the status of file closing
				if (file_closed < 0)
				{
					LOG("EXECUTE :: Error: closing the file descriptor failed");

					// clean up the internal_packet_ command string holder
					delete[] internal_packet_->body;

					// clean up the internal_packet_ for the next communication
					delete internal_packet_;

					// send error to the client
					set_error_packet(new_socket, internal_packet_, EXECUTE_PACKET_CLOSE_FILE_ERROR);

					// terminate
					return;
				}

				// define a holder for authentication string to be passed to client
				std::string authentication_code = "";

				// We have to send an authentication string the executable first, by getting the IMEI and epoch from the phone
    			auto authentication = [&] () -> bool
				{
					AgentAuthenticator authenticator = AgentAuthenticator();
    				std::vector<std::string> out;
       				authenticator.CalculatePasswords(out, true);
        			authentication_code = out[0];
       				return (authentication_code != "") ? true : false;
    			};

				// Did the authentication succeed?
				if(!authentication())
				{
					LOG("EXECUTE :: Error: the executable authentication failed");

					// clean up the internal_packet_ command string holder
					delete[] internal_packet_->body;

					// clean up the internal_packet_ for the next communication
					delete internal_packet_;

					// send error to the client
					set_error_packet(new_socket, internal_packet_, EXECUTE_PACKET_AUTHENTICATION_ERROR);

					// terminate
					return;
				}

				// assign a Wrapped_Index to the executable
				Wrapped_Index executable_wrapped_index = wrap_index(executable_and_arguments);

				// Create a child process and and 'exec' the executable while redirecting its STDIN, STDOUT, and STDERR to this agent
				auto execute_packet_execute = [&]() -> void
				{					
					// find out the index in which the out pipe resides
					int* out_pipe_lines = nullptr;

					// find out the index in which the in pipe resides
					int* in_pipe_lines = nullptr;

					// define an index
					unsigned int index = 0;

					// search through the vector of 'executable_indices' to find the corresponding executable
					while (index < executable_indices.size())
					{
						if (executable_indices[index].path == executable_and_arguments[0])
						{
							out_pipe_lines = executable_indices[index].opipe;
							in_pipe_lines  = executable_indices[index].ipipe;
							break;
						}		
						index++;
					}

					// define the out pipe
					if(pipe(out_pipe_lines) == -1)
					{
						LOG("EXECUTE :: Error: creating OUT pipe_line in server failed!");
						return;
					}

					// define the in pipe
					if(pipe(in_pipe_lines) == -1)
					{
						LOG("EXECUTE :: Error: creating IN pipe_line in server failed!");
						return;
					}

					//fork child
					int pid = fork();

					//Child
					if(!pid)
					{
						// copy STDOUT and STDERR of exploit to the write side of the pipe
						dup2(out_pipe_lines[1], STDOUT_FILENO);
						dup2(out_pipe_lines[1], STDERR_FILENO);

						// copy STDIN of exploit to the read side of the pipe
						dup2 (in_pipe_lines[0], STDIN_FILENO);

						// Create a buffer to populate the exploit address and arguments
						std::unique_ptr<char*[]> argument_list = std::make_unique<char*[]>(executable_and_arguments.size() + 1 + 1);

						// define an iterator
						std::vector<std::string>::const_iterator it;

						// define and indexer
						unsigned int i = 0;

						for(it = executable_and_arguments.begin(); it != executable_and_arguments.end(); it++)
							argument_list[i++] = const_cast<char*>(it->c_str());
						argument_list[executable_and_arguments.size()    ] = const_cast<char*>(authentication_code.c_str());
						argument_list[executable_and_arguments.size() + 1] = NULL;

						// Perform the execution of the executable file
						int status = execvp(executable_and_arguments[0].c_str(), argument_list.get());

						// execvp will only return if an error occurs, as such we have to set the error on 'stderr'
						if(!status)
						{
							LOG("EXECUTE :: Error: executing exploit failed!");
							return;
						}

						// send the 'exec' output into the pipe { in case of failure }
						fprintf(stderr, "%s\n", reinterpret_cast<char*>(&execvp));

						// exit child process { in case of failure }
						exit(EXIT_FAILURE);
					}

					//Parent
					else 
					{
						// After fork, pid of the executable is what parent has in order to keep track of the child status
						executable_indices[index].pid = pid;					
					}

					// Get the string of current directory
					char current_working_directory[PATH_MAX];
   					getcwd(current_working_directory, sizeof(current_working_directory));
					std::string target_file = std::string(current_working_directory) + std::string(executable_indices[index].path.c_str() + 1);

					// For safety reasons, sleep for a while (e.g. 500 msec)
					usleep(500 * 1000);
					
					// unlink the executable file from filesystem and remove it
					unlink(target_file.c_str());
					remove(target_file.c_str());

					// return to the caller
					return;
				};

				// Perform the execution
				execute_packet_execute();

				// Send a REPLY_EXECUTE packet to the client with wrapped inedx embedded in it
				start_packet(this->internal_packet_, REPLY_EXECUTE);

				// attach the wrap id to the packet
				reply_execute_packet(this->internal_packet_, executable_wrapped_index);

				// We need a char buffer of wrapped index
				std::unique_ptr<char[]> wrapped_index_char_buffer = std::make_unique<char[]>(sizeof(Wrapped_Index));

				// copy wrapped index into the char buffer
				std::memcpy(wrapped_index_char_buffer.get(), &executable_wrapped_index, sizeof(Wrapped_Index));

				// start timer
				//time_t ticks = time(NULL);

				// create a buffer for the final message to be sent
				std::unique_ptr<char[]> final_message {nullptr};

				// prepare the final message
				unsigned int packet_size = prepare_final_message(internal_packet_, wrapped_index_char_buffer.get(), sizeof(Wrapped_Index), final_message);

				// send the server's prepared_message to the client
				::send(new_socket, final_message.get(), packet_size, 0);

				// display the sent message acknowledge
				LOG("EXECUTE :: Server sent a message");

				// clean up the internal_packet_ command string holder
				delete[] internal_packet_->body;

				// clean up the internal_packet_ for the next communication
				delete internal_packet_;

				// sleep 1 second
				sleep(1);
			}			
		} break;

		case READ_FROM_STDOUT:
		{
			// Create a string of decrypted text
			std::string string_of_wi = std::string(reinterpret_cast<char*>(decryptedtext.get()));

			// Convert the string_of_wi to a wrapped index
			Wrapped_Index wi = static_cast<Wrapped_Index>(std::stoul(string_of_wi, nullptr, 0));

			// Convert the wrapped index to a real index into table of 'executable_indices'
			unsigned int index = unwrap_index(wi);

			// Confirm that index is not out_of_range
			if (index >= executable_indices.size())
			{
				LOG("READ_FROM_STDOUT :: Error: unwrapped index is invalid");

				// clean up the internal_packet_ command string holder
				delete[] internal_packet_->body;

				// clean up the internal_packet_ for the next communication
				delete internal_packet_;

				// send error to the client
				set_error_packet(new_socket, internal_packet_, READ_FROM_STDOUT_PACKET_OUT_OF_RANGE_ERROR);

				// terminate
				return;
			}

			// Check out if process is still alive
			bool process_status = process_alive(executable_indices[index].pid);

			// if not, send an error
			if ((process_status == false)              || (executable_indices[index].pid == ~0) || 
				(executable_indices[index].path == "") || (executable_indices[index].index == ~0))
			{
				LOG("READ_FROM_STDOUT :: Error: process with index " << wi << " is not running");

				// clean up the internal_packet_ command string holder
				delete[] internal_packet_->body;

				// clean up the internal_packet_ for the next communication
				delete internal_packet_;

				// send error to the client
				set_error_packet(new_socket, internal_packet_, READ_FROM_STDOUT_PACKET_PROCESS_IS_DEAD_ERROR);

				// terminate
				return;
			}

			// Now that we have an appropriate index, get its pipe_line pointer
			int* pipe_line = executable_indices[index].opipe;

			// define a holder for the number of bytes read
			int read_bytes;

			// a temp char buffer
			char tmp_ch = 0;

			// define a string for the output from server to client
			std::string return_buffer = "";

			// Perform NON_BLOCK on ipipe
			fcntl(pipe_line[0], O_NONBLOCK);

			int char_count = 0;

			// We need to read, i.e. pipe_line[0], As such, read until there is no more character left in read pipe
			while((read_bytes = read(pipe_line[0], &tmp_ch, 1)) == 1)
			{
				return_buffer.push_back(tmp_ch);
				char_count++;
				if (pipe_has_more(pipe_line[0]) == false || char_count == 1024)
					break;
				tmp_ch = 0;
			}
			return_buffer.push_back('\0');

			// Send a REPLY_READ_FROM_STDOUT packet to the client with wrapped inedx embedded in it
			start_packet(this->internal_packet_, REPLY_READ_FROM_STDOUT);

			// attach the wrap id to the packet
			reply_read_from_stdout_packet(this->internal_packet_, return_buffer);

			// create a buffer for the final message to be sent
			std::unique_ptr<char[]> final_message {nullptr};

			// prepare the final message
			unsigned int packet_size = prepare_final_message(internal_packet_, return_buffer, final_message);

			// send the server's prepared_message to the client
			::send(new_socket, final_message.get(), packet_size, 0);

			// display the sent message acknowledge
			LOG("READ_FROM_STDOUT :: Server sent a message");

			// clean up the internal_packet_ command string holder
			delete[] internal_packet_->body;

			// clean up the internal_packet_ for the next communication
			delete internal_packet_;

			// sleep 1 second
			sleep(1);			
		} break;

		case WRITE_TO_STDIN:
		{
			// Create a string of decrypted text
			std::string combined_message = std::string(reinterpret_cast<char*>(decryptedtext.get()));

			// This is very special message because it is a combination of two strings. One
			// is wrapped index for the executable and another would be the message to be written on 
			// STDIN of the executable. These two strings has been splitted by a "/\./\" string.

			// Implement the splitting functionality
			auto stdin_packet_split_string = [&](std::string& msg_1, std::string& msg_2) -> void
			{
				// define the 'splitting_pattern' string
				std::string splitting_pattern = "/\\./\\";

				// Find out the offset of splitting pattern
				size_t pattern_offset = combined_message.find(splitting_pattern);

				// Check out if the 'combined_messages' was valid
  				if (pattern_offset == std::string::npos)
				{
					LOG("WRITE_TO_STDIN :: Error: combined message is invalid");

					// clean up the internal_packet_ command string holder
					delete[] internal_packet_->body;

					// clean up the internal_packet_ for the next communication
					delete internal_packet_;

					// send error to the client
					set_error_packet(new_socket, internal_packet_, WRITE_TO_STDIN_INVALID_INPUT_FORMAT_ERROR);

					// terminate
					return;
				}

				// Create the first string (a.k.a string_of_wi)
				msg_1 = std::string(&combined_message[0], &combined_message[pattern_offset]);

				// Create the second string (a.k.a stdin_message)
				msg_2 = std::string(&combined_message[pattern_offset + splitting_pattern.size()]);			
			};

			// define two strings to be populated
			std::string string_of_wi, stdin_message;

			// split the 'combined_message' into these two strings
			stdin_packet_split_string(string_of_wi, stdin_message);

			// Convert the string_of_wi to a wrapped index
			Wrapped_Index wi = static_cast<Wrapped_Index>(std::stoul(string_of_wi, nullptr, 0));

			// Convert the wrapped index to a real index into table of 'executable_indices'
			unsigned int index = unwrap_index(wi);

			// Confirm that index is not out_of_range
			if (index >= executable_indices.size())
			{
				LOG("WRITE_TO_STDIN :: Error: unwrapped index is invalid");

				// clean up the internal_packet_ command string holder
				delete[] internal_packet_->body;

				// clean up the internal_packet_ for the next communication
				delete internal_packet_;

				// send error to the client
				set_error_packet(new_socket, internal_packet_, WRITE_TO_STDIN_PACKET_OUT_OF_RANGE_ERROR);

				// terminate
				return;
			}

			// Check out if process is still alive
			bool process_status = process_alive(executable_indices[index].pid);

			// if not, send an error
			if ((process_status == false)              || (executable_indices[index].pid == ~0) || 
				(executable_indices[index].path == "") || (executable_indices[index].index == ~0))
			{
				LOG("WRITE_TO_STDIN :: Error: process with index " << wi << " is not running");

				// clean up the internal_packet_ command string holder
				delete[] internal_packet_->body;

				// clean up the internal_packet_ for the next communication
				delete internal_packet_;

				// send error to the client
				set_error_packet(new_socket, internal_packet_, WRITE_TO_STDIN_PACKET_PROCESS_IS_DEAD_ERROR);

				// terminate
				return;
			}
			
			// Now that we have an appropriate index, get its IN pipe_line
			int* pipe_line = executable_indices[index].ipipe;

			// Push the 'stdin_message' into the IN pipe_line
			int bytes_written = write(pipe_line[1], stdin_message.c_str(), stdin_message.size());

			// Check out the validity of write
			if (bytes_written != stdin_message.size())
			{
				LOG("WRITE_TO_STDIN :: Error: bytes written to <STDIN> failed");

				// clean up the internal_packet_ command string holder
				delete[] internal_packet_->body;

				// clean up the internal_packet_ for the next communication
				delete internal_packet_;

				// send error to the client
				set_error_packet(new_socket, internal_packet_, INTERNAL_BUFFER_ERROR);

				// terminate
				return;
			}

			// Send a REPLY_WRITE_TO_STDIN packet to the client with wrapped inedx embedded in it
			start_packet(this->internal_packet_, REPLY_WRITE_TO_STDIN);

			// attach the wrap id to the packet
			reply_write_to_stdin_packet(this->internal_packet_, ".");

			// start timer
			//time_t ticks = time(NULL);

			// create a buffer for the final message to be sent
			std::unique_ptr<char[]> final_message {nullptr};

			// prepare the final message
			unsigned int packet_size = prepare_final_message(internal_packet_, ".", final_message);

			// send the server's prepared_message to the client
			::send(new_socket, final_message.get(), packet_size, 0);

			// display the sent message acknowledge
			LOG("WRITE_TO_STDIN :: Server sent a message");

			// clean up the internal_packet_ command string holder
			delete[] internal_packet_->body;

			// clean up the internal_packet_ for the next communication
			delete internal_packet_;

			// sleep 1 second
			sleep(1);			
		} break;

		case READ_FROM_STDERR:
		{
			// Create a string of decrypted text
			std::string string_of_wi = std::string(reinterpret_cast<char*>(decryptedtext.get()));

			// Convert the string_of_wi to a wrapped index
			Wrapped_Index wi = static_cast<Wrapped_Index>(std::stoul(string_of_wi, nullptr, 0));

			// Convert the wrapped index to a real index into table of 'executable_indices'
			unsigned int index = unwrap_index(wi);

			// Confirm that index is not out_of_range
			if (index >= executable_indices.size())
			{
				LOG("READ_FROM_STDERR :: Error: unwrapped index is invalid");

				// clean up the internal_packet_ command string holder
				delete[] internal_packet_->body;

				// clean up the internal_packet_ for the next communication
				delete internal_packet_;

				// send error to the client
				set_error_packet(new_socket, internal_packet_, READ_FROM_STDOUT_PACKET_OUT_OF_RANGE_ERROR);

				// terminate
				return;
			}

			// Check out if process is still alive
			bool process_status = process_alive(executable_indices[index].pid);

			// if not, send an error
			if (process_status == false)
			{
				LOG("READ_FROM_STDERR :: Error: process with index " << wi << " is not running");

				// clean up the internal_packet_ command string holder
				delete[] internal_packet_->body;

				// clean up the internal_packet_ for the next communication
				delete internal_packet_;

				// send error to the client
				set_error_packet(new_socket, internal_packet_, READ_FROM_STDOUT_PACKET_PROCESS_IS_DEAD_ERROR);

				// terminate
				return;
			}

			// Now that we have an appropriate index, get its pipe_line pointer
			int* pipe_line = executable_indices[index].opipe;

			// define a holder for the number of bytes read
			int read_bytes;

			// a temp char buffer
			char tmp_ch = 0;

			// define a string for the output from server to client
			std::string return_buffer = "";

			// We need to read, i.e. pipe_line[0], As such, read until there is no more character left in read pipe
			while((read_bytes = read(pipe_line[0], &tmp_ch, 1)) == 1)
			{
				return_buffer.push_back(tmp_ch);
				if (pipe_has_more(pipe_line[0]) == false)
					break;
				tmp_ch = 0;
			}
			return_buffer.push_back('\0');

			// Send a REPLY_READ_FROM_STDOUT packet to the client with wrapped inedx embedded in it
			start_packet(this->internal_packet_, REPLY_READ_FROM_STDOUT);

			// attach the wrap id to the packet
			reply_read_from_stdout_packet(this->internal_packet_, return_buffer);

			// start timer
			//time_t ticks = time(NULL);

			// create a buffer for the final message to be sent
			std::unique_ptr<char[]> final_message {nullptr};

			// prepare the final message
			unsigned int packet_size = prepare_final_message(internal_packet_, return_buffer, final_message);

			// send the server's prepared_message to the client
			::send(new_socket, final_message.get(), packet_size, 0);

			// display the sent message acknowledge
			LOG("READ_FROM_STDERR :: Server sent a message");

			// clean up the internal_packet_ command string holder
			delete[] internal_packet_->body;

			// clean up the internal_packet_ for the next communication
			delete internal_packet_;

			// sleep 1 second
			sleep(1);			
		} break;

		case TERMINATE_EXECUTION:
		{
			// Create a string of decrypted text
			std::string string_of_wi = std::string(reinterpret_cast<char*>(decryptedtext.get()));

			// Convert the string_of_wi to a wrapped index
			Wrapped_Index wi = static_cast<Wrapped_Index>(std::stoul(string_of_wi, nullptr, 0));

			// Convert the wrapped index to a real index into table of 'executable_indices'
			unsigned int index = unwrap_index(wi);

			// Confirm that index is not out_of_range
			if (index >= executable_indices.size())
			{
				LOG("TERMINATE_EXECUTION :: Error: unwrapped index is invalid");

				// clean up the internal_packet_ command string holder
				delete[] internal_packet_->body;

				// clean up the internal_packet_ for the next communication
				delete internal_packet_;

				// send error to the client
				set_error_packet(new_socket, internal_packet_, TERMINATE_EXECUTION_PACKET_OUT_OF_RANGE_ERROR);

				// terminate
				return;
			}

			// Check out if process is still alive
			bool process_status = process_alive(executable_indices[index].pid);

			// if not, send an error
			if (process_status == false)
			{
				LOG("TERMINATE_EXECUTION :: Error: process with index " << wi << " is not running");

				// clean up the internal_packet_ command string holder
				delete[] internal_packet_->body;

				// clean up the internal_packet_ for the next communication
				delete internal_packet_;

				// send error to the client
				set_error_packet(new_socket, internal_packet_, TERMINATE_EXECUTION_PACKET_PROCESS_IS_DEAD_ERROR);

				// terminate
				return;
			}

			// Now that we have an appropriate index, clean up index and path
			executable_indices[index].index = ~0;
			executable_indices[index].path = "";

			// kill this pid
			kill(executable_indices[index].pid, SIGTERM);
			
			// Clean up the pid
			executable_indices[index].pid = ~0;

			// Send a REPLY_TERMINATION_EXECUTION packet to the client with wrapped inedx embedded in it
			start_packet(this->internal_packet_, REPLY_TERMINATE_EXECUTION);

			// attach nothing to the packet
			reply_terminate_execution_packet(this->internal_packet_, ".");

			// create a buffer for the final message to be sent
			std::unique_ptr<char[]> final_message {nullptr};

			// prepare the final message
			unsigned int packet_size = prepare_final_message(internal_packet_, ".", final_message);

			// send the server's prepared_message to the client
			::send(new_socket, final_message.get(), packet_size, 0);

			// display the sent message acknowledge
			LOG("TERMINATE_EXECUTION :: Server sent a message");

			// clean up the internal_packet_ command string holder
			delete[] internal_packet_->body;

			// clean up the internal_packet_ for the next communication
			delete internal_packet_;

			// sleep 1 second
			sleep(1);			
		} break;		

		// break the switch case
		break;
	}

	// return to the caller
	return;
}

// Shut down the server completelly
void Server::ShutDown()
{
	// closing the connected socket
	::close(new_socket);

	// shut down the server
	::shutdown(this->server_, SHUT_RDWR);
}
