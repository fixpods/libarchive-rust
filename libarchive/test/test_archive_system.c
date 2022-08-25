#include "test.h"
__FBSDID("$FreeBSD$");

#include <stdlib.h>
#include <stdio.h>

static void
archive_test_system()
{
	int status = -1;
	status = system("cd libarchive/system_test_case && /bin/bash verify.sh");
	if(status != 0) {
		printf("error");
	} else {
		printf("success");
	}
}

DEFINE_TEST(test_archive_system)
{
	archive_test_system();
}