#ifndef _PACKET__H__
#define _PACKET__H__

// a guide macro
#define __THIS_FUNCTION_IS_LINUX_SPECIFIC__

// AES CBC PKCS PADDING
#define AES_CBC_PKCS_PADDING 0x10

// Block size macros
#define KB(NUM) ((NUM) << 10)
#define MB(NUM) ((KB(NUM)) << 10)
#define GB(NUM) ((MB(NUM)) << 10)

// define DEBUG_LOG
#ifdef _WIN32
#	ifdef _DEBUG
#		define LOG(__EXPR__) std::cout << __EXPR__ << std::endl;
#	else
#		define LOG(__EXPR__) ;
#	endif
#elif defined (__linux__)
#	ifdef DEBUG
#		define LOG(__EXPR__) std::cout << __EXPR__ << std::endl;
#	else
#		define LOG(__EXPR__) ;
#	endif
#endif

// define DEBUG_LOG2
#ifdef _WIN32
#	ifdef _DEBUG
#		define LOG2(__EXPR__) std::cout << __EXPR__;
#	else
#		define LOG2(__EXPR__) ;
#	endif
#elif defined (__linux__)
#	ifdef DEBUG
#		define LOG2(__EXPR__) std::cout << __EXPR__;
#	else
#		define LOG2(__EXPR__) ;
#	endif
#endif

// define a standard/accepted block size for copying file's data around { I would set it to 256 KB }
#define FILE_BLOCK KB(256)

// Standard C/C++ header files
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <queue>
#include <memory>
#include <cstring>
#include <cstdint>
#include <time.h>
#include <sstream> 
#include <iterator>
//#include <filesystem> // There is problems with running std::filesystem on Android machines

// Platform specific header files
#ifdef _WIN32
#ifndef __LLVM__
#		include "libtcp.h"
#endif
#		include <Windows.h>
#       include "Encryption.h"
#		include "zip/miniz.h"
#		include "zip/ZipArchive.h"
#		include "zip/Zip.h"
#elif defined (__linux__)
#		include <netinet/tcp.h>
#		include <sys/socket.h>
#		include <arpa/inet.h>
#		include <sys/stat.h>
#		include <fcntl.h>
#		include <errno.h>
#		include <unistd.h>
#		include <sys/wait.h>
#		include <sys/types.h>
#		include <poll.h>
#		include <unistd.h>
#		include <stddef.h>
#		include <stdint.h>
#		include <sstream> 
#		include <iterator>
#		include <signal.h>
#		include <dirent.h> // This is to tackle std::filesystem issues on Android machines
#       include "../include/Encryption.h"
#endif

// Encryption object declared externally
extern Encryption* encryption;

// Some linux-specific file handling
#ifdef __linux__
	typedef struct stat Stat;
	typedef struct dirent Dirent;
#endif

// Data structure's alignment
#ifdef __linux__
#		define PACK_STRUCT( STRUCT_BODY ) STRUCT_BODY  __attribute__((__packed__))
#elif defined (_WIN32)
#		define PACK_STRUCT( STRUCT_BODY ) __pragma( pack(push, 1) ) STRUCT_BODY __pragma( pack(pop) )
#endif

// Formatted repeated string for logging
std::string repeat_string(const std::string& str, unsigned int repeat_count);

/// Header struct
/// A packed 20 bytes data structure for the header of the packet
/// 
PACK_STRUCT(struct Header
{
	unsigned int StartMagicNumber;
	unsigned int Type;
	unsigned int SizeBody;
	unsigned long long TotalFileSize;
});

/// Packet struct
/// 
struct Packet
{
	Header       header;           // fixed size
	char*        body;             // variable size
	unsigned int checksum;         // fixed size
	unsigned int end_magic_number; // fixed size
};

/// Stream Mode of the connection
/// TCP
/// UDP
/// 
typedef enum _StreamMode {
	TCP = SOCK_STREAM,
	UDP = SOCK_DGRAM
} StreamMode;

/// File_Attributes struct
/// This data structure can be used by both client and server
/// It keeps track of a specific file attributes such as size, name, its buffer, descriptor, etc
/// To be utilized later in another packet.
/// 
typedef struct _File_attributes {
	unsigned long long file_size_         = 0ULL;
	int                file_descriptor_   = ~0;
	unsigned long long bytes_handeled_    = 0ULL;
	std::string        stream_file_name   = "";
	void*              stream_file_buffer = nullptr;
	unsigned long long stream_file_length = 0ULL;
} File_Attributes;

// Wrapped_Index declaration
typedef unsigned int Wrapped_Index;

/// Header_Types
/// This enum holds all packet types handled inside 'Header' of a packet
/// 
typedef enum
{
	// starts an empty packet type
	NONE = 0,

	// principal execution types
	SHELL,
	REPLY_SHELL,
	START_SEND_FILE,
	REPLY_START_SEND_FILE,
	DATA_SEND_FILE,
	REPLY_DATA_SEND_FILE,
	START_GET_FILE,
	REPLY_START_GET_FILE,
	DATA_GET_FILE,
	REPLY_DATA_GET_FILE,
	GET_DIRECTORIES,
	REPLY_GET_DIRECTORIES,
	GET_FILES,
	REPLY_GET_FILES,

	// added in ver_2 
	EXECUTE,
	REPLY_EXECUTE,
	WRITE_TO_STDIN,
	REPLY_WRITE_TO_STDIN,
	READ_FROM_STDOUT,
	REPLY_READ_FROM_STDOUT,
	READ_FROM_STDERR,
	REPLY_READ_FROM_STDERR,
	TERMINATE_EXECUTION,
	REPLY_TERMINATE_EXECUTION,

	// added in ver_3
	FULL_FILESYSTEM,
	REPLY_FULL_FILESYSTEM,
	DATA_GET_FILE_TO_ZIP,

	// following commands do the same thing (killing the server in any status)
	TERMINATE_SERVER = 0xFFFD,
	KILL_SERVER      = 0xFFFE,
	EXIT_SERVER      = 0xFFFF,
} Header_Types;

/// Error_Types
/// A packet can throw an error with the specified values below
/// Both client and server have access to errors
/// 
typedef enum
{
	// starts an empty error packet
	NONE_ERROR = 0,
	
	// specific packets error values
	SHELL_ERROR,
	START_SEND_FILE_PACKET_PERMISSION_ERROR,
	START_SEND_FILE_PACKET_PATH_ERROR,
	START_SEND_FILE_PACKET_VOLUME_SPACE_ERROR,
	START_SEND_FILE_PACKET_OPEN_FILE_ERROR,
	DATA_SEND_FILE_PACKET_OVERPASSED_BYTES_ERROR,
	DATA_SEND_FILE_PACKET_WRITE_FILE_ERROR,
	DATA_SEND_FILE_PACKET_CLOSE_FILE_ERROR,
	START_GET_FILE_PACKET_OPEN_FILE_ERROR,
	START_GET_FILE_PACKET_SIZEOF_FILE_ERROR,
	START_GET_FILE_PACKET_CLOSE_FILE_ERROR,
	DATA_GET_FILE_PACKET_OVERPASSED_BYTES_ERROR,
	DATA_GET_FILE_PACKET_READ_FILE_ERROR,
	DATA_GET_FILE_PACKET_CLOSE_FILE_ERROR,
	DATA_GET_FILE_PACKET_INCUFFICIENT_BYTES_ERROR,
	GET_DIRECTORIES_PACKET_FILESYSTEM_ERROR,
	GET_FILES_PACKET_FILESYSTEM_ERROR,

	// added in ver_2
	EXECUTE_PACKET_PERMISSION_ERROR,
	EXECUTE_PACKET_NOT_FOUND_EXECUTABLE_ERROR,
	EXECUTE_PACKET_VOLUME_SPACE_ERROR,
	EXECUTE_PACKET_CLOSE_FILE_ERROR,
	EXECUTE_PACKET_AUTHENTICATION_ERROR,
	WRITE_TO_STDIN_PACKET_NOT_REDIECTED_ERROR,
	WRITE_TO_STDIN_PACKET_OVERFLOW_ERROR,
	WRITE_TO_STDIN_PACKET_OUT_OF_RANGE_ERROR,
	WRITE_TO_STDIN_INVALID_INPUT_FORMAT_ERROR, 
	WRITE_TO_STDIN_PACKET_PROCESS_IS_DEAD_ERROR,
	READ_FROM_STDOUT_PACKET_NOT_REDIRECTED_ERROR,
	READ_FROM_STDOUT_PACKET_OVERFLOW_ERROR,
	READ_FROM_STDOUT_PACKET_OUT_OF_RANGE_ERROR,
	READ_FROM_STDOUT_PACKET_PROCESS_IS_DEAD_ERROR,
	READ_FROM_STDERR_PACKET_NOT_REDIRECTED_ERROR,
	READ_FROM_STDERR_PACKET_OVERFLOW_ERROR,
	READ_FROM_STDERR_PACKET_OUT_OF_RANGE_ERROR,
	TERMINATE_EXECUTION_PACKET_OUT_OF_RANGE_ERROR,
	TERMINATE_EXECUTION_PACKET_PROCESS_IS_DEAD_ERROR,
	ENCRYPT_DECRYPT_ERROR,

	// added in ver_3
	FULL_FILESYSTEM_NO_DIRECTORY_ERROR,
	FULL_FILESYSTEM_EMPTY_ERROR,

	// general non-packets error values
	INTERNAL_BUFFER_ERROR,
	TERMINATION_SERVER_PACKET_ERROR, // not used
	CHECKSUM_ERROR,
} Error_Types;

/// dump a packet in STDOUT
/// @param packet
/// @param with_body_data -> a boolean to signal whether or not write body content on STDOUT
/// @return nothing
///
void         report_packet                    (Packet* packet, bool with_body_data = false);

// inline small functions to set packet's fields
inline void  set_start_magic_of_header        (Header* header)                    { header->StartMagicNumber = 0x46535452; /* 'FSTR' */ }
inline void  set_end_magic_of_packet          (Packet* packet)                    { packet->end_magic_number = 0x46454E44; /* 'FEND' */ }
inline void  set_type_of_header               (Header* header, Header_Types type) { header->Type = static_cast<unsigned int>(type);     }
     
/// setting a shell packet fields
/// @param packet
/// @param command
/// @return nothing
///
void         shell_packet                     (Packet* packet, const std::string& command);

/// setting a reply to shell packet fields
/// @param packet
/// @param executed_shell_message
/// @return nothing
///
void         reply_shell_packet               (Packet* packet, const std::string& executed_shell_message);

/// setting a start send file packet fields
/// @param packet
/// @param file_address
/// @param file_size
/// @return nothing
///
void         start_send_file_packet           (Packet* packet, const std::string& file_address, unsigned long long file_size);

/// setting a reply to start send file packet fields
/// @param packet
/// @param message
/// @return nothing
///
void         reply_start_send_file_packet     (Packet* packet, const std::string& message);

/// setting a data send file packet fields
/// @param packet
/// @param data_size
/// @return nothing
///
void         data_send_file_packet            (Packet* packet, unsigned long long data_size);

/// setting a reply to data send file packet fields
/// @param packet
/// @param message
/// @return nothing
///
void         reply_data_send_file_packet      (Packet* packet, const std::string& message);

/// setting a start get file packet fields
/// @param packet
/// @param file_address
/// @return nothing
///
void         start_get_file_packet            (Packet* packet, const std::string& file_address);

/// setting a reply to start get file packet fields
/// @param packet
/// @param message
/// @param file_size
/// @return nothing
///
void         reply_start_get_file_packet      (Packet* packet, const std::string& message, unsigned int file_size);

/// setting a data get file packet fields
/// @param packet
/// @return nothing
///
void         data_get_file_packet             (Packet* packet);

/// setting a reply to data get file packet fields
/// @param packet
/// @param data_size
/// @return nothing
///
void         reply_data_get_file_packet       (Packet* packet, unsigned int data_size);

/// setting a get directories packet fields
/// @param packet
/// @param location
/// @return nothing
///
void         get_directories_packet           (Packet* packet, const std::string& location);

/// setting a reply to get directories packet fields
/// @param packet
/// @param message
/// @param number_of_directories
/// @return nothing
///
void         reply_get_directories_packet     (Packet* packet, const std::string& message, unsigned int number_of_directories);

/// setting a get files packet fields
/// @param packet
/// @param location
/// @return nothing
///
void         get_files_packet                 (Packet* packet, const std::string& location);

/// setting a reply to get files packet fields
/// @param packet
/// @param message
/// @param number_of_files
/// @return nothing
///
void         reply_get_files_packet           (Packet* packet, const std::string& message, unsigned int number_of_files);

/// setting a termination packet fields
/// @param packet
/// @param command
/// @return nothing
///
void         termination_packet               (Packet* packet, const std::string& command);

/// setting an execute packet fields
/// @param packet
/// @param command
/// @return nothing
///
void         execute_packet                   (Packet* packet, const std::string& command);

/// setting a reply to execute packet fields
/// @param packet
/// @param index
/// @return nothing
///
void         reply_execute_packet             (Packet* packet, Wrapped_Index index);

/// setting a read from stdout packet fields
/// @param packet
/// @param command
/// @return nothing
///
void         read_from_stdout_packet          (Packet* packet, const std::string& command);

/// setting a reply to read from stdout packet fields
/// @param packet
/// @param message
/// @return nothing
///
void         reply_read_from_stdout_packet    (Packet* packet, const std::string& message);

/// setting a write to stdin packet fields
/// @param packet
/// @param message
/// @return nothing
///
void         write_to_stdin_packet            (Packet* packet, const std::string& message);

/// setting a reply to write to stdin packet fields
/// @param packet
/// @param message
/// @return nothing
///
void         reply_write_to_stdin_packet      (Packet* packet, const std::string& message);

/// setting a terminate execution (a.k.a. kill) packet fields
/// @param packet
/// @param message
/// @return nothing
///
void         terminate_execution_packet       (Packet* packet, const std::string& message);

/// setting a reply to terminate execution (a.k.a. kill) packet fields
/// @param packet
/// @param message
/// @return nothing
///
void         reply_terminate_execution_packet (Packet* packet, const std::string& message);

  										   
/// calculate checksum of a packet
/// @param buffer -> containing a packet
/// @param length -> specifies size of data in buffer
/// @return unsigned int -> CRC32 evaluated checksum
/// 
unsigned int checksum_calculation             (char* buffer, unsigned long long length);

/// start an opaque packet
/// @param packet
/// @param type
/// @return nothing
///
void         start_packet                     (Packet*& packet, Header_Types type);

/// taking a packet and prepare it (with encryption and body allocation) for the very last 'send' on TCP
/// @param packet -> containing a packet
/// @param message -> a std::string 
/// @param buffer_pointer -> it will be populated by data
/// @return unsigned int -> size of prepared data
/// 
unsigned int prepare_final_message            (Packet* packet, const std::string& message, std::unique_ptr<char[]>& buffer_pointer);

/// taking a packet and prepare it (with encryption and body allocation) for the very last 'send' on TCP
/// @param packet -> containing a packet
/// @param message -> a raw buffer
/// @param message_size -> size of data in message
/// @param buffer_pointer -> it will be populated by data
/// @return unsigned int -> size of prepared data
/// 
unsigned int prepare_final_message            (Packet* packet, char* message, unsigned long long message_size, std::unique_ptr<char[]>& buffer_pointer);

/// LINUX specific reading a packet
/// @param packet -> containing a packet
/// @param connection_failed -> signal if connection is failed and socket is closed
/// @param socket
/// @return nothing
/// 
void         read_a_packet_from_socket        (Packet* packet, bool& connection_failed, int socket = 0);

/// WINDOWS specific reading a packet
/// @param packet -> containing a packet
/// @param socket
/// @return nothing
/// 

#ifdef _WIN32
void         read_a_packet_from_socket        (MESBAH::Tcp* tcp, Packet* packet);
#endif

/// evaluates checksum of a packet (it is a wrapper around 'checksum_calculation')
/// @see checksum_calculation
/// @param packet -> containing a packet
/// @return bool -> failure: false and success: true
/// 
bool         evaluate_checksum                (Packet* packet);

/// put an error on STDOUT
/// @param err
/// @return std::string -> a string format of the error type
/// 
std::string  error_message                    (Error_Types err);

/// sets an error packet with specific error type and 'send' in on TCP
/// @param socket
/// @param packet
/// @param err
/// @return nothing
/// 
void         set_error_packet                 (int socket, Packet* packet, Error_Types err);

#endif
