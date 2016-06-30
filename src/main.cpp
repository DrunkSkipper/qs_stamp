#include "quicksand.h"
#include <iostream>
#include <cstdlib>

int main(int argc, char** argv){
  if (argc == 1){
    std::cout<<"qs_timestamp generator\nUsage: qs iterations size edgePercentage shift header\n";
    return 1;
  }
  if (argc !=6) {
    std::cout<<"Wrong number of parameters."<<std::endl;
    return 1;
  }
  unsigned int iterations = std::atoll(argv[1]);
  unsigned int size = std::atoll(argv[2]);
  int edgePercentage = std::atoi(argv[3]);
  unsigned int shift = std::atoll(argv[4]);

  std::string header{argv[5]};
  auto result = quicksand::generateStamp(iterations, size, edgePercentage, shift, header);
  std::cout<<result<<std::endl;
  return 0;
}
