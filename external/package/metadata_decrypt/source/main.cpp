#include <ios>
#include <fstream>
#include <memory>
#include <iostream>
#include <string>

#include "libdm2/dm.h"



int main(int argc, char * argv[]){

    std::string KeyHex = "5c976e48accb9211b9c1c719f13fcdb6b2e01db9c901f2133303e1f97e55de7ad3847ee701f1966757949d92272a9362892d6a7928bf6659161ceacaf0eeef17";
    std::string DmName = "userdata";
    std::string cipher_aes_256_xts_name = "aes-xts-plain64";
    std::string cipher_adiantum_name = "xchacha12,aes-adiantum-plain64";
    int cipher_aes_256_xts_size = 64;
    int cipher_adiantum_size= 32;

    std::string BlkDevName = /*"./userdata.bin";//*/ argv[1];

    std::fstream inf( BlkDevName , std::ios::in | std::ios::binary);
    inf.seekg(0,std::ios::end);
    size_t inSize = inf.tellg();


    size_t nr_sectors = inSize / 512;

    std::cout << "file size: "<< inSize << std::endl <<"sectors: "<< nr_sectors << std::endl <<" aligned sectors: " <<  ( nr_sectors & ~7)<< std::endl;
    nr_sectors &= ~7;


    // auto dt = android::dm::DmTargetDefaultKey(0,nr_sectors,cipher_aes_256_xts_name,KeyHex,BlkDevName,0);
    // std::make_unique()


    auto target = std::make_unique<android::dm::DmTargetDefaultKey>(0,nr_sectors,cipher_aes_256_xts_name,/*KeyHex*/argv[2],BlkDevName,0);
    target.get()->SetSetDun();

    std::cout<< "Target is valid:" << target.get()->Valid()<< std::endl;

    android::dm::DmTable table;
    table.AddTarget(std::move(target));
    std::cout<< "Table is valid:" << table.valid() << std::endl;

    std::string crypto_blkdev;
    auto& dm = android::dm::DeviceMapper::Instance();
    if (!dm.CreateDevice(DmName, table, &crypto_blkdev, std::chrono::seconds(5))) {
        std::cout<< "Could not create default-key device " << DmName<< std::endl ;
        return -1;
    }

    std::cout<< "successfully  created mountable block device at this path:" << crypto_blkdev << std::endl;

    return 0;
}
