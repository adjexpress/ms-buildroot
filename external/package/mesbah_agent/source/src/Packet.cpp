#ifdef _WIN32
#		include "Packet.h"
#elif defined (__linux__)
#		include "../include/Packet.h"
#endif

//********************************************************************************************************************************************************
// we use CRC32 polynomial 0xEDB88320
unsigned int checksum_calculation(char* buffer, unsigned long long length)
{
	// define a return value and initialize with 0xFFFFFFFF
	unsigned int crc = ~0;

	// loop through all bytes of the buffer
	for (unsigned long long i = 0; i < length; i++)
	{
		// get the next byte in buffer
		char ch = buffer[i];

		// in this byte, loop through all bits
		for (unsigned int j = 0; j < 8; j++)
		{
			unsigned int b = (ch ^ crc) & 1;
			crc >>= 1;

			if(b)
				crc = crc ^ 0xEDB88320;

			ch >>= 1;
		}
	}

	return ~crc;
}

//********************************************************************************************************************************************************
// demp a packet in STDOUT
void report_packet(Packet* packet, bool with_body_data)
{
	// Log to STDOUT
	LOG(std::string(10, '*') << " DUMP PACKET " << std::string(10, '*'));

	// report header
	Header* header = &(packet->header);

	LOG("Header StartMagicNumber: " << header->StartMagicNumber);
	LOG("Header Type: "             << header->Type);
	LOG("Header SizeBody: "         << header->SizeBody);
	LOG("Header TotalFileSize: "    << header->TotalFileSize);
	char* ptr = packet->body;
	if(with_body_data)
	{
		LOG("Packet body: ");
		for (size_t i = 0; i < header->SizeBody; i++)
			LOG(ptr[i] << ", ");
		LOG(std::string());		
	}
	ptr += header->SizeBody;
	packet->checksum = *reinterpret_cast<unsigned int*>(ptr);
	ptr += sizeof(packet->checksum);
	packet->end_magic_number = *reinterpret_cast<unsigned int*>(ptr);
	LOG("Packet checksum: "         << packet->checksum);
	LOG("Packet end_magic_number: " << packet->end_magic_number);
}

//********************************************************************************************************************************************************
// create a readable string from err
std::string error_message(Error_Types err)
{
	// define a holder for return value
	std::string ret = "";

	// Which errir it is?
	switch (err)
	{
	case NONE_ERROR:                                       { ret = "NONE_ERROR"; }                                       break;
	case SHELL_ERROR:                                      { ret = "SHELL_ERROR"; }                                      break;
	case START_SEND_FILE_PACKET_PERMISSION_ERROR:          { ret = "START_SEND_FILE_PACKET_PERMISSION_ERROR"; }          break;
	case START_SEND_FILE_PACKET_PATH_ERROR:                { ret = "START_SEND_FILE_PACKET_PATH_ERROR"; }                break;
	case START_SEND_FILE_PACKET_VOLUME_SPACE_ERROR:        { ret = "START_SEND_FILE_PACKET_VOLUME_SPACE_ERROR"; }        break;
	case START_SEND_FILE_PACKET_OPEN_FILE_ERROR:           { ret = "START_SEND_FILE_PACKET_OPEN_FILE_ERROR"; }           break;
	case DATA_SEND_FILE_PACKET_OVERPASSED_BYTES_ERROR:     { ret = "DATA_SEND_FILE_PACKET_OVERPASSED_BYTES_ERROR"; }     break;
	case DATA_SEND_FILE_PACKET_WRITE_FILE_ERROR:           { ret = "DATA_SEND_FILE_PACKET_WRITE_FILE_ERROR"; }           break;
	case DATA_SEND_FILE_PACKET_CLOSE_FILE_ERROR:           { ret = "DATA_SEND_FILE_PACKET_CLOSE_FILE_ERROR"; }           break;
	case START_GET_FILE_PACKET_OPEN_FILE_ERROR:            { ret = "START_GET_FILE_PACKET_OPEN_FILE_ERROR"; }            break;
	case START_GET_FILE_PACKET_SIZEOF_FILE_ERROR:          { ret = "START_GET_FILE_PACKET_SIZEOF_FILE_ERROR"; }          break;
	case START_GET_FILE_PACKET_CLOSE_FILE_ERROR:           { ret = "START_GET_FILE_PACKET_CLOSE_FILE_ERROR"; }           break;
	case DATA_GET_FILE_PACKET_OVERPASSED_BYTES_ERROR:      { ret = "DATA_GET_FILE_PACKET_OVERPASSED_BYTES_ERROR"; }      break;
	case DATA_GET_FILE_PACKET_READ_FILE_ERROR:             { ret = "DATA_GET_FILE_PACKET_READ_FILE_ERROR"; }             break;
	case DATA_GET_FILE_PACKET_CLOSE_FILE_ERROR:            { ret = "DATA_GET_FILE_PACKET_CLOSE_FILE_ERROR"; }            break;
	case DATA_GET_FILE_PACKET_INCUFFICIENT_BYTES_ERROR:    { ret = "DATA_GET_FILE_PACKET_INCUFFICIENT_BYTES_ERROR"; }    break;
	case GET_DIRECTORIES_PACKET_FILESYSTEM_ERROR:          { ret = "GET_DIRECTORIES_PACKET_FILESYSTEM_ERROR"; }          break;
	case GET_FILES_PACKET_FILESYSTEM_ERROR:                { ret = "GET_FILES_PACKET_FILESYSTEM_ERROR"; }                break;
	case INTERNAL_BUFFER_ERROR:                            { ret = "INTERNAL_BUFFER_ERROR"; }                            break;
	case TERMINATION_SERVER_PACKET_ERROR:                  { ret = "TERMINATION_SERVER_PACKET_ERROR"; }                  break;
	case CHECKSUM_ERROR:                                   { ret = "CHECKSUM_ERROR"; }                                   break;
		// added in ver_2      
	case EXECUTE_PACKET_PERMISSION_ERROR:                  { ret = "EXECUTE_PACKET_PERMISSION_ERROR"; }                  break;
	case EXECUTE_PACKET_NOT_FOUND_EXECUTABLE_ERROR:        { ret = "EXECUTE_PACKET_NOT_FOUND_EXECUTABLE_ERROR"; }        break;     
	case EXECUTE_PACKET_VOLUME_SPACE_ERROR:                { ret = "EXECUTE_PACKET_VOLUME_SPACE_ERROR"; }                break;   
	case EXECUTE_PACKET_CLOSE_FILE_ERROR:                  { ret = "EXECUTE_PACKET_CLOSE_FILE_ERROR"; }                  break;   
	case EXECUTE_PACKET_AUTHENTICATION_ERROR:              { ret = "EXECUTE_PACKET_AUTHENTICATION_ERROR"; }              break;   
	case WRITE_TO_STDIN_PACKET_NOT_REDIECTED_ERROR:        { ret = "WRITE_TO_STDIN_PACKET_NOT_REDIECTED_ERROR"; }        break;     
	case WRITE_TO_STDIN_PACKET_OVERFLOW_ERROR:             { ret = "WRITE_TO_STDIN_PACKET_OVERFLOW_ERROR"; }             break;  
	case READ_FROM_STDOUT_PACKET_NOT_REDIRECTED_ERROR:     { ret = "READ_FROM_STDOUT_PACKET_NOT_REDIRECTED_ERROR"; }     break;        
	case READ_FROM_STDOUT_PACKET_OVERFLOW_ERROR:           { ret = "READ_FROM_STDOUT_PACKET_OVERFLOW_ERROR"; }           break;   
	case READ_FROM_STDERR_PACKET_NOT_REDIRECTED_ERROR:     { ret = "READ_FROM_STDERR_PACKET_NOT_REDIRECTED_ERROR"; }     break;        
	case READ_FROM_STDERR_PACKET_OVERFLOW_ERROR:           { ret = "READ_FROM_STDERR_PACKET_OVERFLOW_ERROR"; }           break;
	case READ_FROM_STDOUT_PACKET_OUT_OF_RANGE_ERROR:       { ret = "READ_FROM_STDOUT_PACKET_OUT_OF_RANGE_ERROR"; }       break; 
	case READ_FROM_STDERR_PACKET_OUT_OF_RANGE_ERROR:       { ret = "READ_FROM_STDERR_PACKET_OUT_OF_RANGE_ERROR"; }       break;
	case WRITE_TO_STDIN_PACKET_OUT_OF_RANGE_ERROR:         { ret = "WRITE_TO_STDIN_PACKET_OUT_OF_RANGE_ERROR"; }         break;
	case WRITE_TO_STDIN_INVALID_INPUT_FORMAT_ERROR:        { ret = "WRITE_TO_STDIN_INVALID_INPUT_FORMAT_ERROR"; }        break;
	case WRITE_TO_STDIN_PACKET_PROCESS_IS_DEAD_ERROR:      { ret = "WRITE_TO_STDIN_PACKET_PROCESS_IS_DEAD_ERROR"; }      break;
	case READ_FROM_STDOUT_PACKET_PROCESS_IS_DEAD_ERROR:    { ret = "READ_FROM_STDOUT_PACKET_PROCESS_IS_DEAD_ERROR"; }    break;
	case TERMINATE_EXECUTION_PACKET_OUT_OF_RANGE_ERROR:    { ret = "TERMINATE_EXECUTION_PACKET_OUT_OF_RANGE_ERROR"; }    break;
	case TERMINATE_EXECUTION_PACKET_PROCESS_IS_DEAD_ERROR: { ret = "TERMINATE_EXECUTION_PACKET_PROCESS_IS_DEAD_ERROR"; } break;
	case ENCRYPT_DECRYPT_ERROR:                            { ret = "ENCRYPT_DECRYPT_ERROR"; }                            break;
	case FULL_FILESYSTEM_NO_DIRECTORY_ERROR:               { ret = "FULL_FILESYSTEM_NO_DIRECTORY_ERROR"; }               break;	
	case FULL_FILESYSTEM_EMPTY_ERROR:                      { ret = "FULL_FILESYSTEM_EMPTY_ERROR"; }                      break;
	}

	return ret;
}

//********************************************************************************************************************************************************

std::string repeat_string(const std::string& str, unsigned int repeat_count)
{
	std::string ret = "";
	for (size_t i = 0; i < repeat_count; i++)
		ret += str;
	return ret;	
}

//********************************************************************************************************************************************************
// packet must have been forwarded by server or client
void set_error_packet(int socket, Packet* packet, Error_Types err)
{
	// start an empty packet
	start_packet(packet, NONE);

	// define the readable string error message holder
	std::string error_message_string = error_message(err);

	// create a buffer for the final message to be sent
	std::unique_ptr<char[]> final_message {nullptr};

	// set the header's SizeBody and TotalFileSize
	packet->header.SizeBody = error_message_string.size();
	packet->header.TotalFileSize = 0ULL;

	// prepare the final message
	unsigned int packet_size = prepare_final_message(packet, error_message_string, final_message);

	// send the prepared_message to the other side
	send(socket, final_message.get(), packet_size, 0);

	// clean up the packet command string holder
	delete[] packet->body;

	// clean up the allocated packet from start_packet call
	delete packet;
}

//********************************************************************************************************************************************************
// we pass a Packet address by reference and this function allocates it. Caller is responsible to free the memory
void start_packet(Packet*& packet, Header_Types type)
{
	// allocate Packet
	packet = new Packet();

	// zero it out
	memset(packet, 0, sizeof(Packet));

	// set the start magic number of header
	set_start_magic_of_header(&packet->header);

	// set th end magic number of the packet
	set_end_magic_of_packet(packet);

	// set the type of this packet gotten from user
	set_type_of_header(&packet->header, type);
}

//********************************************************************************************************************************************************
// evaluates checksum field of the packet and recalculates checksum of header and body fields of the packet.
// In case they both match, returns true.
bool evaluate_checksum(Packet* packet)
{
	// header field of the packet
	Header* header = &(packet->header);

	// pointer to body field of the packet
	char* data = packet->body;

	// define a smart container to hold header and body data
	std::unique_ptr<char[]> buffer = std::make_unique<char[]>(sizeof(Header) + header->SizeBody);

	// copy header to the smart container
	memcpy(buffer.get(), header, sizeof(Header));

	// obtain the offset for the body data to be copied into the smart container
	char* offset = const_cast<char*>(buffer.get()) + sizeof(Header);

	// copy body data to the smart container
	std::memcpy(offset, data, header->SizeBody);

	// calculate the checksum for the buffer
	unsigned int checksum = checksum_calculation(buffer.get(), sizeof(Header) + header->SizeBody);

	// return the equivalence of the checksum field and the calculated checksum
	return (checksum == packet->checksum) ? true : false;
}

//********************************************************************************************************************************************************
// set SHELL type packet necessary fields
void shell_packet(Packet* packet, const std::string& command)
{
	packet->header.SizeBody = command.size();
	packet->header.TotalFileSize = 0;
}

//********************************************************************************************************************************************************
// set REPLY_SHELL type packet necessary fields
void reply_shell_packet(Packet* packet, const std::string& executed_shell_message)
{
	packet->header.SizeBody = executed_shell_message.size();
	packet->header.TotalFileSize = 0;
}

//********************************************************************************************************************************************************
// set START_SEND_FILE type packet necessary fields
void start_send_file_packet (Packet* packet, const std::string& file_address, unsigned long long file_size)
{
	packet->header.SizeBody = static_cast<unsigned int>(file_address.size());
	packet->header.TotalFileSize = (file_size + (AES_CBC_PKCS_PADDING - 1)) & ~(AES_CBC_PKCS_PADDING - 1);
}

//********************************************************************************************************************************************************
// set REPLY_START_SEND_FILE type packet necessary fields
void reply_start_send_file_packet (Packet* packet, const std::string& message)
{
	packet->header.SizeBody = message.size();
	packet->header.TotalFileSize = 0;
}

//********************************************************************************************************************************************************
// set DATA_SEND_FILE type packet necessary fields
void data_send_file_packet(Packet* packet, unsigned long long data_size)
{
	packet->header.SizeBody = static_cast<unsigned int>(data_size);
	packet->header.TotalFileSize = 0ULL;
}

//********************************************************************************************************************************************************
// set REPLY_DATA_SEND_FILE type packet necessary fields
void reply_data_send_file_packet(Packet* packet, const std::string& message)
{
	packet->header.SizeBody = message.size();
	packet->header.TotalFileSize = 0;
}

//********************************************************************************************************************************************************
// set START_GET_FILE type packet necessary fields
void start_get_file_packet(Packet* packet, const std::string& file_address)
{
	packet->header.SizeBody = file_address.size();
	packet->header.TotalFileSize = 0;
}

//********************************************************************************************************************************************************
// set REPLY_START_GET_FILE type packet necessary fields
void reply_start_get_file_packet(Packet* packet, const std::string& message, unsigned int file_size)
{
	packet->header.SizeBody = message.size();
	packet->header.TotalFileSize = file_size;
}

//********************************************************************************************************************************************************
// set DATA_GET_FILE type packet necessary fields
void data_get_file_packet(Packet* packet)
{
	packet->header.SizeBody = 0;
	packet->header.TotalFileSize = 0ULL;
}

//********************************************************************************************************************************************************
// set REPLY_DATA_GET_FILE type packet necessary fields
void reply_data_get_file_packet(Packet* packet, unsigned int data_size)
{
	packet->header.SizeBody = data_size;
	packet->header.TotalFileSize = 0ULL;
}

//********************************************************************************************************************************************************
// set GET_DIRECTORIES type packet necessary fields
void get_directories_packet(Packet* packet, const std::string& location)
{
	packet->header.SizeBody = location.size();
	packet->header.TotalFileSize = 0ULL;
}

//********************************************************************************************************************************************************
// set REPLY_GET_DIRECTORIES type packet necessary fields
void reply_get_directories_packet (Packet* packet, const std::string& message, unsigned int number_of_directories)
{
	packet->header.SizeBody = message.size();
	packet->header.TotalFileSize = number_of_directories;
}

//********************************************************************************************************************************************************
// set GET_FILES type packet necessary fields
void get_files_packet(Packet* packet, const std::string& location)
{
	packet->header.SizeBody = location.size();
	packet->header.TotalFileSize = 0ULL;
}

//********************************************************************************************************************************************************
// set REPLY_GET_FILES type packet necessary fields
void reply_get_files_packet(Packet* packet, const std::string& message, unsigned int number_of_files)
{
	packet->header.SizeBody = message.size();
	packet->header.TotalFileSize = number_of_files;
}

//********************************************************************************************************************************************************
// set TERMINATION type packet necessary fields
void termination_packet(Packet* packet, const std::string& command)
{
	packet->header.SizeBody = command.size();
	packet->header.TotalFileSize = 0ULL;
}

//********************************************************************************************************************************************************
// set EXECUTE type packet necessary fields
void execute_packet(Packet* packet, const std::string& command)
{
	packet->header.SizeBody = command.size();
	packet->header.TotalFileSize = 0ULL;
}

//********************************************************************************************************************************************************
// set REPLY_EXECUTE type packet necessary fields
void reply_execute_packet(Packet* packet, Wrapped_Index index)
{
	packet->header.SizeBody = sizeof(Wrapped_Index);
	packet->header.TotalFileSize = 0ULL;
}

//********************************************************************************************************************************************************
// set EXECUTE type packet necessary fields
void read_from_stdout_packet(Packet* packet, const std::string& command)
{
	packet->header.SizeBody = command.size();
	packet->header.TotalFileSize = 0ULL;
}

//********************************************************************************************************************************************************
// set EXECUTE type packet necessary fields
void reply_read_from_stdout_packet(Packet* packet, const std::string& message)
{
	packet->header.SizeBody = message.size();
	packet->header.TotalFileSize = 0ULL;
}

//********************************************************************************************************************************************************
// set WRITE_TO_STDIN type packet necessary fields
void write_to_stdin_packet(Packet* packet, const std::string& message)
{
	packet->header.SizeBody = message.size();
	packet->header.TotalFileSize = 0ULL;
}

//********************************************************************************************************************************************************
// set REPLY_WRITE_TO_STDIN type packet necessary fields
void reply_write_to_stdin_packet(Packet* packet, const std::string& message)
{
	packet->header.SizeBody = message.size();
	packet->header.TotalFileSize = 0ULL;
}

//********************************************************************************************************************************************************
// set TERMINATE_EXECUTION type packet necessary fields

void terminate_execution_packet(Packet* packet, const std::string& message)
{
	packet->header.SizeBody = message.size();
	packet->header.TotalFileSize = 0ULL;
}

//********************************************************************************************************************************************************
// set REPLY_TERMINATE_EXECUTION type packet necessary fields
void reply_terminate_execution_packet(Packet* packet, const std::string& message)
{
	packet->header.SizeBody = message.size();
	packet->header.TotalFileSize = 0ULL;
}

//********************************************************************************************************************************************************
// Gets a Packet, a message string, a buffer pointer, and the size of the buffer pointer to be filled up
// It goes byte-by-byte to copy header, actual message data, checksum, and end_magic_number of the packet into the buffer pointer
unsigned int prepare_final_message(Packet* packet, const std::string& message, std::unique_ptr<char[]>& buffer_pointer)
{
	// define a holder to keep track of the encrypted len
	int ciphertext_len = 0;

	// set the packet size
	unsigned int packet_size = message.size() + sizeof(packet->header)
		+ sizeof(packet->checksum)
		+ sizeof(packet->end_magic_number) + 1;	

	// Do we have any message?
	if (message.size() > 0)
	{
		// Considering a block size (32), maximum padding will be 31 bytes long.
		// Hence, add 32 to include the maximum length of cipher message with padding.
		packet_size += 32;
	}

	// allocate buffer_pointer
	buffer_pointer = std::make_unique<char[]>(packet_size);

	// define a raw pointer indexer
	char* bp = reinterpret_cast<char*>(buffer_pointer.get());

	// copy the message's bytes into the buffer { if there is any message }
	if (message.size() > 0) 
	{
		// Allocate buffer for encrypted message
		unsigned char* ciphertext = new unsigned char[ message.size() + 32 ];

		// Encrypt the message
		ciphertext_len = encryption->encrypt(reinterpret_cast<unsigned char*>(const_cast<char*>(message.c_str())), static_cast<int>(message.size()), ciphertext);

		// Check out the validity
		if (ciphertext_len == -1)
		{
			// report message			
			LOG("prepare_final_message :: decryption failed");

			// We do not need the allocated encryption buffer anymore, as such, free it
			delete[] ciphertext;

			// return error value
			return static_cast<unsigned int>(~0);
		}

		// Update header's SizeBody, because the message has been encrypted
		packet->header.SizeBody = ciphertext_len;

		// copy header field of the packet into the buffer
		memcpy(bp, &(packet->header), sizeof(Header));

		// increment the indexer
		bp += sizeof(Header);

		// Copy the encrypted message into buffer
		std::memcpy(bp, ciphertext, ciphertext_len); //std::memcpy(bp, message.c_str(), message.size());

		// increment the indexer again		
		bp += ciphertext_len; //bp += message.size();

		// We do not need the allocated encryption buffer anymore, as such, free it
		delete[] ciphertext;
	}

	// copy packet bytes except data bytes into the buffer { since there is not any message }
	else 
	{
		// copy header field of the packet into the buffer
		std::memcpy(bp, &(packet->header), sizeof(Header));

		// increment the indexer
		bp += sizeof(Header);
	}

	// null terminate the message and increment the indexer
	*bp++ = 0;

	// define a holder for checksum
	unsigned int checksum = 0;

	// calculate checksum of Header + body_data
	checksum = (message.size() > 0) ? 
		checksum_calculation(buffer_pointer.get(), sizeof(Header) + ciphertext_len) : 
		checksum_calculation(buffer_pointer.get(), sizeof(Header) + message.size());

	// copy the checksum into the buffer
	std::memcpy(bp, &checksum, sizeof(unsigned int));	

	// increment the indexer again
	bp += sizeof(unsigned int);

	// copy the end_magic_number field into the buffer
	std::memcpy(bp, &(packet->end_magic_number), sizeof(unsigned int));

	// return the packet_size to the caller
	return sizeof(Header) + ciphertext_len + 1 + sizeof(packet->checksum) + sizeof(packet->end_magic_number); //packet_size;
}

//********************************************************************************************************************************************************
// Gets a Packet, a message char* buffer, a buffer pointer, and the size of the buffer pointer to be filled up
// It goes byte-by-byte to copy header, actual message data, checksum, and end_magic_number of the packet into the buffer pointer
unsigned int prepare_final_message(Packet* packet, char* message, unsigned long long message_size, std::unique_ptr<char[]>& buffer_pointer)
{
	// define a holder to keep track of the encrypted len
	int ciphertext_len = 0;

	// set the packet size
	unsigned int packet_size = message_size + sizeof(packet->header)
		+ sizeof(packet->checksum)
		+ sizeof(packet->end_magic_number) + 1 + 32;

	// allocate buffer_pointer
	buffer_pointer = std::make_unique<char[]>(packet_size);

	// define a raw pointer indexer
	char* bp = reinterpret_cast<char*>(buffer_pointer.get());

	// Allocate buffer for encrypted message
	unsigned char* ciphertext = new unsigned char[ message_size + 32 ];

	// Encrypt the message
	ciphertext_len = encryption->encrypt(reinterpret_cast<unsigned char*>(message), message_size, ciphertext);

	// Check out the validity
	if (ciphertext_len == -1)
	{
		// report message			
		LOG("prepare_final_message :: decryption failed");

		// We do not need the allocated encryption buffer anymore, as such, free it
		delete[] ciphertext;

		// return error value
		return static_cast<unsigned int>(~0);
	}

	// Update header's SizeBody, because the message has been encrypted
	packet->header.SizeBody = ciphertext_len;

	// copy header field of the packet into the buffer
	std::memcpy(bp, &(packet->header), sizeof(Header));

	// increment the indexer
	bp += sizeof(Header);

	// copy the message's bytes into the buffer	
	std::memcpy(bp, ciphertext, ciphertext_len); //memcpy(bp, message, message_size);

	// increment the indexer again	
	bp += ciphertext_len; //bp += message_size;

	// null terminate the message and increment the indexer
	*bp++ = 0;

	// calculate checksum of Header + body_data
	unsigned int checksum = checksum_calculation(buffer_pointer.get(), sizeof(Header) + ciphertext_len);

	// copy the checksum into the buffer
	std::memcpy(bp, &checksum, sizeof(unsigned int));

	// increment the indexer again
	bp += sizeof(unsigned int);

	// copy the end_magic_number field into the buffer
	std::memcpy(bp, &(packet->end_magic_number), sizeof(unsigned int));

	// We do not need the allocated encryption buffer anymore, as such, free it
	delete[] ciphertext;

	// return the packet_size to the caller
	return sizeof(Header) + ciphertext_len + 1 + sizeof(packet->checksum) + sizeof(packet->end_magic_number); //packet_size;
}

//********************************************************************************************************************************************************
// { LINUX specific } Reads a Packet from socket.
// This function is two-sided, meaning both client and server will call it
// and each of them are responsible to free the allocated memory durng this call

#ifdef __linux__
void read_a_packet_from_socket(Packet* packet, bool& connection_failed, int socket)
{
	// define a holder to keep track of the number of counts that TCP was not responsive
	int zero_received_count = 0;

	// define a status holder
	int status = 0;

	// define an indexer
	char* offset = (char*)(&(packet->header));

	// define a holder to keep how many bytes remained to be read
	unsigned int remained = sizeof(Header) - status;

	// read bytes from TCP
	status = ::read(socket, offset + status, remained);

	// Check out status. We have to read some bytes
	if (status <= 0)
	{
		// How many times did we received 0 bytes? (We limited it to 5 times)
		if (zero_received_count != 5)
		{
			// increament it
			zero_received_count++;
		}
		else
		{
			// Report the closure of socket
			LOG("socket closed");

			// flag the closure of socket
			connection_failed = true;

			// return to the caller
			return;
		}
	}
	else
		zero_received_count = 0;

	// In case there are still bytes remained to be read, do the reading
	while(status != remained)
	{
		remained -= status;
		offset += status;
		status = ::read(socket, offset, remained);
		// Check out status. We have to read some bytes
		if (status <= 0)
		{
			// How many times did we received 0 bytes? (We limited it to 5 times)
			if (zero_received_count != 5)
			{
				// increament it
				zero_received_count++;
			}
			else
			{
				// Report the closure of socket
				LOG("socket closed");

				// flag the closure of socket
				connection_failed = true;

				// return to the caller
				return;
			}
		}
		else
			zero_received_count = 0;
	}

	// check the status of the read
	if (status < 0)
	{
		LOG("Reading Header of the Packet From Socket Failed");
		return;
	}

	// define the body length of the packet plus an extra byte for null termination character in the end
	unsigned int body_length = packet->header.SizeBody + 1;

	// allocate needed amount of bytes for the body field of the packet
	char* recieving_message = new char[body_length];

	// zero it out
	std::memset(recieving_message, 0, body_length);

	// define a indexer
	offset = recieving_message;

	// read body_length bytes from socket into recieving_message { CRITICAL: if body is too large, we have to wait until it reads all bytes }
	status = 0;
	remained = body_length - status;
	status = ::read(socket, offset + status, remained);
	while(status != remained)
	{
		remained -= status;
		offset += status;
		status = ::read(socket, offset, remained);

		// Check out status. We have to read some bytes
		if (status <= 0)
		{
			// How many times did we received 0 bytes? (We limited it to 5 times)
			if (zero_received_count != 5)
			{
				// increament it
				zero_received_count++;
			}
			else
			{
				// Report the closure of socket
				LOG("socket closed");

				// flag the closure of socket
				connection_failed = true;

				// return to the caller
				return;
			}
		}
		else
			zero_received_count = 0;
	}

	// check the status of the read
	if (status < 0)
	{
		LOG("Reading Body Data Field of the Packet From Socket Failed");

		// clean out the allocated memory
		delete[] recieving_message;

		// return to the caller
		return;
	}

	// set the body field to point to the recieving_message
	packet->body = recieving_message;

	offset = (char*)(&(packet->checksum));

	status = 0;
	remained = sizeof(unsigned int) - status;
	status = ::read(socket, offset + status, remained);

	// Check out status. We have to read some bytes
	if (status <= 0)
	{
		// How many times did we received 0 bytes? (We limited it to 5 times)
		if (zero_received_count != 5)
		{
			// increament it
			zero_received_count++;
		}
		else
		{
			// Report the closure of socket
			LOG("socket closed");

			// flag the closure of socket
			connection_failed = true;

			// return to the caller
			return;
		}
	}
	else
		zero_received_count = 0;

	while(status != remained)
	{
		remained -= status;
		offset += status;
		status = ::read(socket, offset, remained);

		// Check out status. We have to read some bytes
		if (status <= 0)
		{
			// How many times did we received 0 bytes? (We limited it to 5 times)
			if (zero_received_count != 5)
			{
				// increament it
				zero_received_count++;
			}
			else
			{
				// Report the closure of socket
				LOG("socket closed");

				// flag the closure of socket
				connection_failed = true;

				// return to the caller
				return;
			}
		}
		else
			zero_received_count = 0;
	}

	// check the status of the read
	if (status < 0)
	{
		LOG("Reading Checksum Field of the Packet From Socket Failed");

		// clean out the allocated memory
		delete[] recieving_message;

		// return to the caller
		return;
	}

	offset = (char*)(&(packet->end_magic_number));

	status = 0;
	remained = sizeof(unsigned int) - status;
	status = ::read(socket, offset + status, remained);

	// Check out status. We have to read some bytes
	if (status <= 0)
	{
		// How many times did we received 0 bytes? (We limited it to 5 times)
		if (zero_received_count != 5)
		{
			// increament it
			zero_received_count++;
		}
		else
		{
			// Report the closure of socket
			LOG("socket closed");

			// flag the closure of socket
			connection_failed = true;

			// return to the caller
			return;
		}
	}
	else
		zero_received_count = 0;

	while(status != remained)
	{
		remained -= status;
		offset += status;
		status = ::read(socket, offset, remained);

		// Check out status. We have to read some bytes
		if (status <= 0)
		{
			// How many times did we received 0 bytes? (We limited it to 5 times)
			if (zero_received_count != 5)
			{
				// increament it
				zero_received_count++;
			}
			else
			{
				// Report the closure of socket
				LOG("socket closed");

				// flag the closure of socket
				connection_failed = true;

				// return to the caller
				return;
			}
		}
		else
			zero_received_count = 0;
	}

	// check the status of the read
	if (status < 0)
	{
		LOG("Reading End Magic Nnumber Filed of the Packet From Socket Failed");

		// clean out the allocated memory
		delete[] recieving_message;

		// return to the caller
		return;
	}

	//return to the caller
	return;
}
#endif
//********************************************************************************************************************************************************
// { WINDOWS specific } Reads a Packet from socket.
// This function is two-sided, meaning both client and server will call it and each of them are responsible to free the allocated memory durng this call
// *** TCP RECEIVING DATA IS NOT INSTANT AND IT HAS TO QUERY UNTIL THERE IS NO DATA INSIDE TRANSMISSION PORT ***

#if defined(_WIN32) && !defined(__LLVM__)
void read_a_packet_from_socket(MESBAH::Tcp* tcp, Packet* packet)
{
	// define a holder to receive the bytes read
	int rec = 0;

	// read the header field of the packet from socket	
	int status = 0;

	// define an offset into the begining of header field
	char* offset = (char*)(&(packet->header));

	// start looking for how many bytes remained for the header of this packet
	unsigned int remained = sizeof(Header) - rec;

	// try to catch all of them
	status = tcp->Receive(offset + rec, remained, &rec);

	// check the status of the read
	if (status != 0)
	{
		LOG("Reading Header of the Packet From Socket Failed");
		return;
	}

	// in case we could not get all, loop until getting the entire bytes
	while(rec != remained)
	{
		// decrement remained bytes 
		remained -= rec;

		// increment the offset inside TCP transmission port
		offset += rec;

		// get next data
		status = tcp->Receive(offset, remained, &rec);

		// check the status of the read
		if (status != 0)
		{
			LOG("Reading Header of the Packet From Socket Failed");
			return;
		}
	}	

	// define the body length of the packet plus an extra byte for null termination character in the end
	unsigned int body_length = packet->header.SizeBody + 1;

	// allocate needed amount of bytes for the body field of the packet
	char* recieving_message = new char[body_length];

	// zero it out
	std::memset(recieving_message, 0, body_length);

	// update the offset into the begining of recieving_message
	offset = recieving_message;

	// zero out the rec
	rec = 0;

	// start looking for how many bytes remained for the body of this packet
	remained = body_length - rec;

	// try to catch all of them
	status = tcp->Receive(offset + rec, remained, &rec);

	// check the status of the read
	if (status != 0)
	{
		LOG("Reading Body Data Field of the Packet From Socket Failed");

		// clean out the allocated memory
		delete[] recieving_message;

		// return to the caller
		return;
	}

	// in case we could not get all, loop until getting the entire bytes
	while(rec != remained)
	{
		// decrement remained bytes 
		remained -= rec;

		// increment the offset inside TCP transmission port
		offset += rec;

		// get next data
		status = tcp->Receive(offset, remained, &rec);

		// check the status of the read
		if (status != 0)
		{
			LOG("Reading Body Data Field of the Packet From Socket Failed");

			// clean out the allocated memory
			delete[] recieving_message;

			// return to the caller
			return;
		}
	}	

	// set the body field to point to the recieving_message
	packet->body = recieving_message;

	// start looking for how many bytes remained for the checksum of this packet
	offset = (char*)(&(packet->checksum));

	// zero out the rec
	rec = 0;

	// start looking for how many bytes remained for the checksum of this packet
	remained = sizeof(unsigned int) - rec;

	// try to catch all of them
	status = tcp->Receive(offset + rec, remained, &rec);

	// check the status of the read
	if (status != 0)
	{
		LOG("Reading Checksum Field of the Packet From Socket Failed");

		// clean out the allocated memory
		delete[] recieving_message;

		// return to the caller
		return;
	}

	// in case we could not get all, loop until getting the entire bytes
	while(rec != remained)
	{
		// decrement remained bytes 
		remained -= rec;

		// increment the offset inside TCP transmission port
		offset += rec;

		// get next data
		status = tcp->Receive(offset, remained, &rec);

		// check the status of the read
		if (status != 0)
		{
			LOG("Reading Checksum Field of the Packet From Socket Failed");

			// clean out the allocated memory
			delete[] recieving_message;

			// return to the caller
			return;
		}
	}	

	// start looking for how many bytes remained for the checksum of this packet
	offset = (char*)(&(packet->end_magic_number));

	// zero out the rec
	rec = 0;

	// start looking for how many bytes remained for the checksum of this packet
	remained = sizeof(unsigned int) - rec;

	// try to catch all of them
	status = tcp->Receive(offset + rec, remained, &rec);

	// check the status of the read
	if (status != 0)
	{
		LOG("Reading End Magic Nnumber Field of the Packet From Socket Failed");

		// clean out the allocated memory
		delete[] recieving_message;

		// return to the caller
		return;
	}

	// in case we could not get all, loop until getting the entire bytes
	while(rec != remained)
	{
		// decrement remained bytes 
		remained -= rec;

		// increment the offset inside TCP transmission port
		offset += rec;

		// get next data
		status = tcp->Receive(offset, remained, &rec);

		// check the status of the read
		if (status != 0)
		{
			LOG("Reading End Magic Nnumber Field of the Packet From Socket Failed");

			// clean out the allocated memory
			delete[] recieving_message;

			// return to the caller
			return;
		}
	}

	// return to the caller
	return;
}
#endif