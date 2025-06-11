#ifndef _FILESYSTEM__H__
#define _FILESYSTEM__H__

#include "Packet.h"

/// Definition of BOOLEAN flags
///
#define TRUE  1
#define FALSE 0

/// File_Or_Directory
/// Specifies if server was being asked for qurying directories or files in a specific path
///
typedef enum _File_Or_Directory {
    FILE_DEMANDED,
    DIRECTORY_DEMANDED
} File_Or_Directory;

/// Looks for all files or all directories inside a given path
/// Note that this method is not recursive
/// @param address -> path of directory to be quried
/// @param container -> an empty vector to gets filled with all files or all directories
/// @param fod -> specifies either files or directories was demanded
/// @return int -> success: 0 and failure: -1
///
__THIS_FUNCTION_IS_LINUX_SPECIFIC__
int search_through_filesystem(const std::string& address, std::vector<std::string>& container, File_Or_Directory fod);

#endif
