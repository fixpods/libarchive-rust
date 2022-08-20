#include "archive_platform.h"
__FBSDID("$FreeBSD$");

#include <stdio.h>
#include <stdlib.h>

void
archive_test_system()
{
  	int status = -1;
  	status = system("cd $(dirname $(find / -name verify.sh -print); pwd) && /bin/bash verify.sh");
	if (status != 0) {
		printf("\nerror\n");
	} else {
		printf("\nsuccess\n");
	}
}