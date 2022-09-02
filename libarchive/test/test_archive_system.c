#include "test.h"
__FBSDID("$FreeBSD$");

#include <stdlib.h>
#include <stdio.h>

static void
archive_test_system()
{
	int status = -1;
	status = system("cd $(dirname $(find / -name verify.sh -print); pwd) && /bin/bash verify.sh");
	assertEqualInt(status, 0);
}

DEFINE_TEST(test_archive_system)
{
	archive_test_system();
}