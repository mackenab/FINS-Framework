#include <stdio.h>
#include <stdlib.h> 
//#include "mean.h"
#include <dlfcn.h>
//#include <switch.h>

int main(int argc, char* argv[]) {

		//struct fins_module *(*module_create)(uint32_t index, uint32_t id, char *name);
		char *error;
		printf("hello\n");

		/*
		void *lib_handle = dlopen("./libavg.so", RTLD_NOW); //RTLD_LAZY | RTLD_GLOBAL?
		if (lib_handle == NULL) {
			fputs(dlerror(), stderr);
			exit(1);
		}
		void* initializer = dlsym(lib_handle, "avg");
		if ((error = dlerror()) != NULL) {
			fputs(error, stderr);
			exit(1);
		}
		typedef double (*avg_dec)(double, double);
		avg_dec avg = (avg_dec) initializer;


		void *lib_handle2 = dlopen("./libtimes.so", RTLD_NOW); //RTLD_LAZY | RTLD_GLOBAL?
		if (lib_handle2 == NULL) {
			fputs(dlerror(), stderr);
			exit(1);
		}
		void* initializer2 = dlsym(lib_handle2, "times");
		if ((error = dlerror()) != NULL) {
			fputs(error, stderr);
			exit(1);
		}
		typedef double (*times_dec)(double, double);
		times_dec times = (times_dec) initializer2;



  double v1, v2;//, m;
  v1 = 5.3;
  v2 = 2.1;

  //m  = mean(v1, v2);
  
  printf("The mean of %3.2f and %3.2f is %3.2f\n", v1, v2, (*avg)(v1, v2));
  printf("The mean of %3.2f and %3.2f is %3.2f\n", v1, v2, (*times)(v1, v2));

	dlclose(lib_handle);
	dlclose(lib_handle2);
*/

  return 0;
}
