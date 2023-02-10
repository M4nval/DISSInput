#include "branch_pred.h"
#include "debug.h"
#include "libdft_api.h"
#include "pin.H"
#include "syscall_hook.h"
#include <iostream>
#include "trimmer.h"
#include <unistd.h>

using namespace std;


KNOB<string> KnobInputFileName(KNOB_MODE_WRITEONCE, "pintool", "input_name", "", "specify input file name");

int main(int argc, char *argv[]) {

  PIN_InitSymbols();

  if (unlikely(PIN_Init(argc, argv))) {
    std::cerr
        << "Sth error in PIN_Init. Plz use the right command line options."
        << std::endl;
    return -1;
  }

  if (unlikely(libdft_init() != 0)) {
    std::cerr << "Sth error libdft_init." << std::endl;
    return -1;
  }
  if (KnobInputFileName.Value().length() <= 0){
    std::cerr << "lack param \"input_name\"" << std::endl;
    return -1;
  }

  hook_file_syscall(KnobInputFileName.Value().c_str());

  PIN_StartProgram();
  
  return 0;
}
