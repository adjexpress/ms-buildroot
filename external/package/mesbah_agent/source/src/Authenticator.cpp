
#ifdef __linux__
#		include "../include/Base64.h"
#		include "../include/md5.h"
#		include "../include/Authenticator.h"
#elif defined _WIN32
#		include "Base64.h"
#		include "md5.h"
#		include "Authenticator.h"
#endif

AgentAuthenticator::AgentAuthenticator(){}
AgentAuthenticator::~AgentAuthenticator(){}

int AgentAuthenticator::extract_imei(std::string& _out){
    try{
        FILE* f = popen("service call iphonesubinfo 1 s16 com.android.shell","r");
        std::string stdout_str;
        if (f != NULL) {
            char content[1024];
            std::fill_n(content,1024,0);
            while( fgets(content,1024,f) != NULL){
                stdout_str = stdout_str + std::string(content);
                std::fill_n(content,1024,0);
            }
            stdout_str.erase(std::remove(stdout_str.begin(), stdout_str.end(), '.'), stdout_str.end());
            int last_index_first = stdout_str.find("\'",0);
            int last_index_second = stdout_str.find("\'",last_index_first+1);
            while(last_index_first != std::string::npos){
                last_index_second = stdout_str.find("\'",last_index_first+1);
                _out = _out + stdout_str.substr(last_index_first+1,last_index_second-last_index_first-1);
                last_index_first = stdout_str.find("\'",last_index_second+1);
            }
            _out.erase(std::remove(_out.begin(), _out.end(), ' '), _out.end());
        }
        else{
            return -1;
        }
        return 0;
    }
    catch(std::exception &e){
        printf("%s",e.what());
        return -1;
    }
}

int AgentAuthenticator::extract_proc(std::string& _out){
    // this module extracts pid in server and extract ppid of current proccess in client.
    // get current pid
    try
    {
        FILE* echo_f = popen("echo $$","r");
        if(echo_f ==NULL){
            return -1;
        }
        char content[1024];
        std::fill_n(content,1024,0);
        std::string current_proccess_id; 
        while( fgets(content,1024,echo_f) != NULL){
            current_proccess_id = current_proccess_id + std::string(content);
            std::fill_n(content,1024,0);
        }
        current_proccess_id.erase(remove(current_proccess_id.begin(), current_proccess_id.end(), '\n'), current_proccess_id.end());
        current_proccess_id.erase(remove(current_proccess_id.begin(), current_proccess_id.end(), ' '), current_proccess_id.end());
        // list os current ps
        FILE* ps_f = popen("ps -A","r");
        if(ps_f ==NULL){
            return -1;
        }
        std::fill_n(content,1024,0);
        std::string ps_result; 
        while( fgets(content,1024,ps_f) != NULL){
            ps_result = ps_result + std::string(content);
            std::fill_n(content,1024,0);
        }
        // extract pids and ppids from ps command execution stdout
        std::vector<std::string> ps_ids;
        std::vector<std::string> ps_pids;
        std::stringstream ss(ps_result);
        std::string to;
        while(std::getline(ss,to,'\n')){
            std::stringstream sss(to);
            std::string toto;
            std::vector<std::string> ps_temp;
            while(std::getline(sss,toto,' ')){
                if (toto != ""){
                    toto.erase(remove(toto.begin(), toto.end(), ' '), toto.end());
                    ps_temp.push_back(toto);
                }
            }
            ps_ids.push_back(ps_temp[1]);
            ps_pids.push_back(ps_temp[2]);
        }
        // search for pid and return its ppid.
        for(int i=0;i<ps_ids.size();i++)
        {
            if(strncmp(current_proccess_id.c_str() ,ps_ids[i].c_str(),current_proccess_id.length())==0){
                _out = ps_pids[i];
                break;
            }
        }
        return 0;
    }
    catch(std::exception &e){
        printf("%s",e.what());
        return -1;
    }
} 

int AgentAuthenticator::_calculate(int time, const std::string& imei, const std::string& proc, std::string& out) {
    try{
        int current_pos_imei_chunk = 0;
        int current_len_imei_chunk = MAX_IMEI_CHUNK_SIZE;
        std::string temp_out;
        for(int i =0; i <MAX_IMEI_CHUNK ; i++){
            std::string imei_chunk = imei.substr(current_pos_imei_chunk,current_len_imei_chunk);
            if (current_len_imei_chunk<MAX_IMEI_CHUNK_SIZE){
                int value = proc[0] ^ time;
                temp_out = temp_out + std::to_string(value);
            }
            for(int ch_i=0;ch_i<current_len_imei_chunk;ch_i++){
                int value = imei_chunk[ch_i] ^ time;
                temp_out = temp_out + std::to_string(value);
            }
            current_pos_imei_chunk = current_pos_imei_chunk + MAX_IMEI_CHUNK_SIZE;
            if(current_pos_imei_chunk + current_len_imei_chunk > imei.length())
                current_len_imei_chunk = imei.length() - current_pos_imei_chunk;
        }
        uint8_t md5_content[16];
        md5String((char*)temp_out.c_str(),md5_content);
        size_t base64_len;
        char* base64_content = base64_encode((char*)md5_content,(size_t)sizeof(md5_content),(size_t*)&base64_len);
        out = std::string(base64_content,base64_len);
        size_t decode_base64_len;
        char* base64_content_decoded = base64_decode((char*)out.c_str(),out.length(),(size_t*)&decode_base64_len);
        return 0;
    }
    catch(std::exception &e){
        printf("%s",e.what());
        return -1;
    }
}

int AgentAuthenticator::CalculatePasswords(std::vector<std::string> &output_vec,bool is_server){
    std::string out_imei;
    //Extraction of phone imei
    int res = extract_imei(out_imei);
    if(res!=0)return -1;
    std::string out_proc;
    //Extraction of target pid
    res = extract_proc(out_proc);
    if(res!=0)return -1;
    int generate_count = MAX_SECOND_BACKWARD_STEP;
    if(is_server)
        generate_count = 1;
    int seconds;
    seconds = time(NULL);
    for (int i =0;i<generate_count;i++){
        std::string temp_str;
        _calculate(seconds-i,out_imei,out_proc,temp_str);
        output_vec.push_back(temp_str);
    }
    return 0;
}