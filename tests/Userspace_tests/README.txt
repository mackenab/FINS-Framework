

Running make will generate a set of executables in the bin directory.  There are four categories of tests built.  Within each category there are executables for DGRAM, STREAM, and RAW socket testing.

clone:
	These tests show how the various socket calls interact with the kernel (sharing socket descriptors, or not) when clone is invoked.

fork:
	These tests show how the various socket calls interact with the kernel (sharing socket descriptors, or not) when fork is invoked.

pthread:
	These tests show how the various socket calls interact with the kernel (sharing socket descriptors, or not) when pthread_create is invoked.

sock:
	These tests make calls to a variety of socket calls in a single process and can be used to show the underlying kernel calls associated with the socketcalls if an appropriate module is loaded.


IMPORTANT:  Please note, the AF_FINS define in each of the source files must be defined to an appropriate (corresponding) value in the kernel or in a loadable kernel module that you are testing.  Remember, the userspace and kernelspace definitions of these constants are separate entities.  That allows for the socket interception strategy to work, but it also requires the programmer to pay attention and make sure the appropriate values are set in both locations.
