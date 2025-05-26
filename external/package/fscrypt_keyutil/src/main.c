#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <keyutils.h>
#include <linux/fscrypt.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <asm/unistd.h>
#include <string.h>

// // Define your raw 64-byte key (must match the policy on the directory!)


char* bytes_to_hex(const unsigned char* bytes, size_t len) {
    if (bytes == NULL || len == 0) {
        return NULL;
    }

    char* hex_str = (char*)malloc(2 * len + 1); // Allocate memory for 2 hex chars per byte + null terminator
    if (hex_str == NULL) {
        return NULL; // Allocation failed
    }

    for (size_t i = 0; i < len; ++i) {
        sprintf(hex_str + 2 * i, "%02x", bytes[i]); // Format each byte as 2 hex chars
    }
    hex_str[2 * len] = '\0'; // Null-terminate the string
    return hex_str;
}



int hex_digit_to_int(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    } else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    } else {
        return -1; // Invalid character
    }
}

void str2hex(char *string,unsigned char *res){
    size_t size = strlen(string) /2;
    // unsigned char res [size];
    // void *p = string;
    char *x = string;

    for (size_t c=0; c < size*2;c+=2){
        uint8_t aa = hex_digit_to_int(x[c]);
        uint8_t bb = hex_digit_to_int(x[c+1]);
        uint8_t hh = (uint8_t) ((aa << 4) | (bb));
        res[c/2]=hh;
    }

}


int setup_v1_encryption_key(struct fscrypt_policy_v1* p , char* key){

    struct fscrypt_key v1_key = {0};
    v1_key.mode = 1;
    v1_key.size = FSCRYPT_MAX_KEY_SIZE;
    memcpy(v1_key.raw, key, FSCRYPT_MAX_KEY_SIZE);
    char* desc= bytes_to_hex(p->master_key_descriptor,FSCRYPT_KEY_DESCRIPTOR_SIZE);

    char *fscrypt_str = "fscrypt:";
    char *f2fs_str = "f2fs:";
    char *ext4_str = "ext4:";

    strcat(fscrypt_str,desc);
    strcat(f2fs_str,desc);
    strcat(ext4_str,desc);

    key_serial_t logon_key_id = add_key("logon", fscrypt_str, &v1_key, sizeof(v1_key), KEY_SPEC_SESSION_KEYRING);

    if (logon_key_id < 0) {
        perror("add_key fscrypt-provisioning failed");
        printf("add_key ret: %d", logon_key_id);
        return logon_key_id;
    }

    return 0;

}

/*
 *
*/

int setup_v2_encryption_key(struct fscrypt_policy_v2* p , char* key, int* fd){

    // Step 1: Create provisioning key from given Key
    // Step 2: Add provisioning key to kernel KeyRing and get KEY_ID
    // Step 3: Add new Key to kernel KeyRing for given directory, which points to step 2 key's KEY_ID

    struct fscrypt_add_key_arg arg ={0};
    memset(&arg,0,sizeof(struct fscrypt_add_key_arg ));
    struct fscrypt_key_specifier spec = {0};
    memset(&spec,0,sizeof(struct fscrypt_key_specifier));

    spec.type = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
    memcpy(spec.u.identifier,p->master_key_identifier,FSCRYPT_KEY_IDENTIFIER_SIZE);

    arg.key_spec = spec;


    struct fscrypt_provisioning_key_payload *payload = malloc(sizeof(*payload)+FSCRYPT_MAX_KEY_SIZE);
    payload->type = spec.type;
    payload->__reserved = 0;
    memcpy(payload->raw, key, FSCRYPT_MAX_KEY_SIZE);

    char* id_hex = bytes_to_hex(p->master_key_identifier,FSCRYPT_KEY_IDENTIFIER_SIZE);

    key_serial_t fscrypt_provisioning_key_id = add_key("fscrypt-provisioning", id_hex,
                                                       payload, sizeof(*payload)+FSCRYPT_MAX_KEY_SIZE, KEY_SPEC_SESSION_KEYRING);



    if (fscrypt_provisioning_key_id < 0) {
        perror("add_key fscrypt-provisioning failed");
        printf("add_key ret: %d", fscrypt_provisioning_key_id);
        return fscrypt_provisioning_key_id;
    }

    arg.raw_size = 0;
    arg.key_id = fscrypt_provisioning_key_id;

    // Perform the ioctl
    if (ioctl(*fd, FS_IOC_ADD_ENCRYPTION_KEY, &arg) != 0) {
        perror("FS_IOC_ADD_ENCRYPTION_KEY failed");
        // close(*fd);
        return 1;
    }

}




int main(int argc, char* argv[]) {


    /*
     * read encryption contex for given directory.
     * check policy version ( v1=0 , v2=2)
     * perform key operation based on policy version
    */



    if(argc<3){
        // printf("usage: %s  directory_path key_descryptor/key_identifier key\n",argv[0]);
        printf("usage: %s  directory_path key\n",argv[0]);
        return 1;
    }

    const char *dir_path = argv[1]; // path/to/your/encrypted/directory
    // const char *id=        argv[2]; // key identifier
    const char *key=       argv[2]; // the key itself

    // if (strlen(id)<32 && (strlen(id)%2!=0) ){
    //     printf("invalid key_descryptor/key_identifier size");
    //     return 1;
    // }

    // unsigned char key_id[FSCRYPT_KEY_IDENTIFIER_SIZE];
    // str2hex(id,key_id);

    // char *d=bytes_to_hex(key_id,16);
    // printf("id: %s",d);



    // int key_size = sizeof(master_key) /*/ sizeof(unsigned char)*/;

    // printf("id: ");
    // for(int i = 0; i< FSCRYPT_KEY_IDENTIFIER_SIZE;i++){
    //     printf("0x%hhX, ",id_hex[i]);
    // }



    int fd = open(dir_path, O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        perror("error openinig %d");
        printf("dir: %d",dir_path);
        return 1;
    }

    struct fscrypt_get_policy_ex_arg policy_arg = {0};
    // memset(&policy_arg,0,sizeof(struct fscrypt_get_policy_ex_arg));
    policy_arg.policy_size = sizeof(policy_arg.policy);


    if(ioctl(fd,FS_IOC_GET_ENCRYPTION_POLICY_EX,&policy_arg) != 0){
        perror("ioctl FS_IOC_GET_ENCRYPTION_POLICY_EX failed");
        printf("error: getting file/directory policy failed");
        close(fd);
        return 1;
    }


    if (strlen(key)<64 && (strlen(key)%2!=0) ) {
        printf("invalid key size");
        return 1;
    }


    unsigned char master_key[FSCRYPT_MAX_KEY_SIZE];
    memset(master_key,0,FSCRYPT_MAX_KEY_SIZE);
    str2hex(key,master_key);

    int ret=0;
    switch (policy_arg.policy.version) {
    case 0:
        ret = setup_v1_encryption_key(&policy_arg.policy.v1,key);
        break;
    case 2:
        ret = setup_v2_encryption_key(&policy_arg.policy.v2,key,&fd);
        break;
    default:
        printf("unsupported policy version");
        return 1;
        // break;
    }


    if(ret !=0){
        printf("Adding Encryption key to kernel keyring: failed\n");
    }
    printf("Adding Encryption key to kernel keyring: successful \n");
    close(fd);
    return ret;



    // struct fscrypt_key v1_key = {0};
    // v1_key.mode = 1;
    // v1_key.size = key_size;
    // memcpy(v1_key.raw, master_key, key_size);
    // key_serial_t logon_key_id = add_key("logon", "fscrypt:5f8e844b01b7b85f", &v1_key, sizeof(v1_key), KEY_SPEC_SESSION_KEYRING);

    // if (logon_key_id < 0) {
    //     perror("add_key fscrypt-provisioning failed");
    //     printf("add_key ret: %d", logon_key_id);
    //     return logon_key_id;
    // }





    // struct fscrypt_add_key_arg arg ={0};
    // memset(&arg,0,sizeof(struct fscrypt_add_key_arg ));
    // struct fscrypt_key_specifier spec = {0};
    // memset(&spec,0,sizeof(struct fscrypt_key_specifier));

    // spec.type = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
    // memcpy(spec.u.identifier,key_id,FSCRYPT_KEY_IDENTIFIER_SIZE);

    // arg.key_spec = spec;


    // struct fscrypt_provisioning_key_payload *payload = malloc(sizeof(*payload)+key_size);
    // payload->type = spec.type;
    // payload->__reserved = 0;
    // memcpy(payload->raw, master_key, key_size);

    // // printf("size of struct fscrypt_provisioning_key_payload *payload + key: %d\n",sizeof(*payload)+key_size);
    // // // Step 2: Add it to the keyring
    // key_serial_t fscrypt_provisioning_key_id = add_key("fscrypt-provisioning", id,
    //                                                    payload, sizeof(*payload)+key_size, KEY_SPEC_SESSION_KEYRING);



    // if (fscrypt_provisioning_key_id < 0) {
    //     perror("add_key fscrypt-provisioning failed");
    //     printf("add_key ret: %d", fscrypt_provisioning_key_id);
    //     return fscrypt_provisioning_key_id;
    // }


    // // printf("Provisioning and logon key added with ID: %x and %x\n", fscrypt_provisioning_key_id, logon_key_id);

    // arg.raw_size = 0;
    // arg.key_id = fscrypt_provisioning_key_id;

    // // Perform the ioctl
    // if (ioctl(fd, FS_IOC_ADD_ENCRYPTION_KEY, &arg) != 0) {
    //     perror("FS_IOC_ADD_ENCRYPTION_KEY failed");
    //     close(fd);
    //     return 1;
    // }


}
