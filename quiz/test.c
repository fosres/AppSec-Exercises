#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

char *get_config_value(const char *key, int value) {

	if ( key == NULL )
	{
		return NULL;
	}

	// No check if key == NULL

	// Not a security vulnerability since snprintf() copies

	// at most sizeof(buffer) - 1 bytes but will mention

	// anyway:

	// possible truncation of key if too large to fit in

	// buffer before NULL-byte
	
	// buffer is popped from stack after function call

	// instance ends. You will have to use dynamic memory

	// allocation and free the buffer later!

	// Below allocation should gurantee enough space since int

	// values cannot be larger than 11 characters long

	// so total_len == 11 (len of value string at worst) + strlen(key) + 1 ('=')

	// so total_len == strlen(key) + 12

	// but alloc_len for buffer must be total_len + 1 to leave

	// space for terminating NULL-byte

	size_t total_len = 0;

	if ( __builtin_add_overflow(strlen(key),12,&total_len) == true )
	{
		return NULL;
	}

	size_t one = 1;
	
	if ( __builtin_add_overflow(total_len,one,&total_len) == true )
	{
		return NULL;
	}

	size_t alloc_len = 0;
	
	if ( __builtin_add_overflow(total_len,one,&alloc_len) == true )
	{
		return NULL;
	}

	char * buffer = (char*)calloc(alloc_len,sizeof(char));

	if ( buffer == NULL )
	{
		return NULL;
	}

	// have to add 1 to total_len to gurantee space for NULL-byte
	
	snprintf(buffer,alloc_len, "%s=%d", key, value);
	
	return buffer;
}

int main() {
	
	// No error checking that get_config_value returns NULL

	char *config = NULL;

	if ( ( config = get_config_value("timeout",30) ) == NULL )
	{
		return 1;
	}
	
	printf("Config: %s\n", config);

	free(config);
	
	return 0;
}

