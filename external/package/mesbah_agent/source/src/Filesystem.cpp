#ifdef __linux__
#		include "../include/Filesystem.h"
#elif defined _WIN32
#	include "Filesystem.h"
#endif

__THIS_FUNCTION_IS_LINUX_SPECIFIC__
#ifdef __linux__
int search_through_filesystem(const std::string& address, std::vector<std::string>& container, File_Or_Directory fod)
{
	// define a directory object 
	DIR* directory = nullptr;

	// define a directory_entry object
	Dirent* directory_entry = nullptr;

	// open the directory object
	directory = opendir(address.c_str());

	// did we successfully opened the directory?
	if (directory)
	{
		// loop until there is still something in directory. If so, put it as a directory_entry object
		while ((directory_entry = readdir(directory)) != NULL) 
		{
			// Do we look for Directories?
			if (fod == DIRECTORY_DEMANDED)
			{
				// In case we hit a Directory, add to the output vector
				if (directory_entry-> d_type == DT_DIR)
				{
					container.push_back(directory_entry->d_name);
				}
			}
			
			// Do we look for Files?
			else if (fod == FILE_DEMANDED)
			{
				// In case we hit a File, add to the output vector
				if (directory_entry-> d_type != DT_DIR)
				{
					// define a Stat object to retrieve mode of the file
					Stat st;

					// make an alias for file path
					std::string file_path = address + "/" + directory_entry->d_name;

					// open file and obtain its descriptor. In case of piped files, we must pass O_NONBLOCK not to hang forever
					int fd = open(file_path.c_str(), O_RDONLY | O_NONBLOCK);

					// Did we open file?
					if (fd < 0)
					{
						LOG("pipe (fifo) file :: neglected file " << file_path);
						return -1;
					}

					// Get status of file
					fstat(fd, &st);

					// Check out file not being FIFO (a.k.a. named pipe), linked, character device, block device, directory, socket, message queue type, semaphore type, or shared memory type
					if (
					   S_ISFIFO   (st.st_mode) == FALSE 
					&& S_ISLNK    (st.st_mode) == FALSE 
					&& S_ISCHR    (st.st_mode) == FALSE 
					&& S_ISBLK    (st.st_mode) == FALSE 
					&& S_ISDIR    (st.st_mode) == FALSE 
					&& S_ISSOCK   (st.st_mode) == FALSE 
					&& S_TYPEISMQ (&st)        == FALSE 
					&& S_TYPEISSEM(&st)        == FALSE 
					&& S_TYPEISSHM(&st)        == FALSE
					)
						container.push_back(directory_entry->d_name);

					// Close the file descriptor
					close(fd);
				}
			}
		}
		
		// close the directory object
		closedir(directory);
	}

	else
	{
		// log to STDOUT of server
		LOG2("Faced error to access \"" << address << "\" with error: ");

		// print out the appropriate error message
		const char* str_error = strerror(errno);
		LOG(str_error);

		// return failure
		return -1;
	}

	// return success to the caller
	return 0;
}

#endif