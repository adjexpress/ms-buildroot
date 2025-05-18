#ifndef _Authenticator__H__
#define _Authenticator__H__

#       include <stdio.h>
#       include <stdint.h>
#       include <string.h>
#       include <stdlib.h>
#       include <unistd.h>
#       include <string>
#       include <sstream>
#       include <vector>
#       include <sys/mman.h>
#       include <sys/types.h>
#       include <sys/wait.h>
#       include <time.h>
#       include <memory>
#       include <algorithm>

#define MAX_IMEI_CHUNK           4
#define MAX_IMEI_CHUNK_SIZE      4
#define MAX_SECOND_BACKWARD_STEP 3

/// Starts an authentication object between agent and an executable
/// The only available CTOR is AgentAuthenticator() and all other types of constructores are forbidden
///
class AgentAuthenticator {
public:
		/// valid CTOR
		/// 
    explicit AgentAuthenticator    ();
    
		/// valid DTOR
		///
		~        AgentAuthenticator    ();
    
		/// calculates a password
		/// @param output_vec -> an empty vector to gets filled
		/// @param is_server -> a signal hints if we are agent or executable
		/// @return int -> success: 0 and failure: -1
		///
		int      CalculatePasswords    (std::vector<std::string>& output_vec, bool is_server);
private:
    int      extract_imei          (std::string& _out);
    int      extract_proc          (std::string& _out);
    int      _calculate            (int time, const std::string& imei, const std::string& proc, std::string& out);
		
protected:
		/// forbidden CTORs { should not be called by user at all! }
	  ///
		AgentAuthenticator            (const AgentAuthenticator&) = delete;
		AgentAuthenticator            (AgentAuthenticator&&)      = delete;
		AgentAuthenticator& operator= (const AgentAuthenticator&) = delete;
		AgentAuthenticator& operator= (AgentAuthenticator&&)      = delete;
		template <typename... _Ty> AgentAuthenticator(_Ty...) {  /* You cannot instantiate AgentAuthenticator class with parameters passed to its constructor */ };
};

#endif //!_Authenticator__H__
