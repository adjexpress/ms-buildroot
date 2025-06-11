#ifndef _SHELL__H__
#define _SHELL__H__

#include "Packet.h"

/// runs a shell on server process
/// @param command -> a client-side shell command to be executed on phone
/// @return std::string -> containing the phone responce to be sent to client
///
std::string run_shell(const std::string& command);

#endif