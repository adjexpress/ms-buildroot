#include "../include/Shell.h"

static std::vector<std::string> space_split(const std::string& total_command)
{
		std::vector<std::string> result;

	std::string tmp_string = "";
	unsigned int i = 0;
	char* p = const_cast<char*>(total_command.c_str());

	while(i < total_command.size())
	{
		if (*p == ' ')
		{
			tmp_string += '\0';
			result.push_back(tmp_string);
			tmp_string = "";
			i++;
			p++;
			continue;
		}
		tmp_string += *p++;
		i++;
	}

	tmp_string += '\0';
	result.push_back(tmp_string);

	return result;
}

std::string run_shell(const std::string& command)
{
	// create pipe lines between parent and child processes
	int pipe_lines[2];

	// create the return buffer
	std::vector<char> return_buffer;

	// define the pipes
	if(pipe(pipe_lines) == -1)
	{
		LOG("Error: creating pipe_line in server failed!");
		return "";
	}

	//fork child
	int pid = fork();

	//Child
	if(!pid)
	{
		// copy STDOUT and STDERR of child process to be copied into write pipe
		dup2 (pipe_lines[1], STDOUT_FILENO);
		dup2 (pipe_lines[1], STDERR_FILENO);

		// child does not read from pipe at all
		close(pipe_lines[0]);

		// child does not write
		close(pipe_lines[1]); // perhaps must be close(stderr); close(stdout);

		std::vector<std::string> commands_vec = space_split(command);

		std::unique_ptr<char*[]> argument_list = std::make_unique<char*[]>(commands_vec.size() + 1);

		for(int i = 0; i < commands_vec.size(); i++)
			argument_list[i] = const_cast<char*>(commands_vec[i].c_str());
		argument_list[commands_vec.size()] = NULL;

		int status = execvp(commands_vec[0].c_str(), argument_list.get());

		// execvp will only return if an error occurs, as such we have to set the error on 'stderr'
		if(!status)
		{
			LOG("Error: executing shell command failed!");
			return "";
		}

		// send the 'exec' output into the pipe { in case of failure }
		fprintf(stderr, "%s\n", (char*)(&execvp));

		// exit child process { in case of failure }
		exit(EXIT_FAILURE);
	}

	//Parent
	else
	{
		// parent does not write
		close(pipe_lines[1]);

		// how many bytes have been read
		int read_bytes;

		// a temp char buffer
		char tmp_ch = 0;

		// read until there is no more character left in read pipe
		while((read_bytes = read(pipe_lines[0], &tmp_ch, 1)) == 1)
		{
			return_buffer.push_back(tmp_ch);
			tmp_ch = 0;
		}
		return_buffer.push_back('\0');

		// block the parent process until any of its children has finished
		wait(NULL); // or waitpid(pid, 0, 0) to only wait for a specific child to terminate
	}

	return std::string(return_buffer.data());
}
