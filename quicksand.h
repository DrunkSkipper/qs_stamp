#include <set>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cstdio>
#include <sodium/crypto_hash_sha256.h>
#include <stdexcept>

namespace quicksand{

  std::string generateStamp(unsigned int iterations, unsigned int size,
      unsigned int edgePercentage, unsigned int shift, std::string header);
  class QuickSandHeader{
    public:
      typedef struct {
        unsigned int node1;
        unsigned int node2;
      }sipNoderes;
    private:
      unsigned int size;
      unsigned int halfSize;
      unsigned int field1;
      unsigned long long data[4];
      static unsigned long long u8ToU64(const unsigned char* data);
      static constexpr unsigned long long rotateLeft(unsigned long long numToRotate, unsigned int count){
        return (numToRotate<<count)|(numToRotate>>(64-count));
      };
      void sipRound(unsigned long long& v0 , unsigned long long& v1, unsigned long long& v2, unsigned long long& v3);
      unsigned long long sipHash24(unsigned long long msg);
    public:
      unsigned long long sipNode(unsigned int seed, unsigned int parity);
      unsigned int getSize() { return size;}
      unsigned int getHalfSize() { return halfSize;}
      sipNoderes sipEdge(unsigned int msg);
      QuickSandHeader(const char* header, unsigned int shift);
  };
  class QuickSandSolver{
    private:
      unsigned char stopFlag;
      unsigned int size;
      unsigned int edgePercentage;
      static unsigned int path(unsigned int value, std::vector<unsigned int>& v1, std::vector<unsigned int>& v2);
      static void recoverSolution(std::vector<unsigned int>& res, unsigned int index1, unsigned int index2, std::vector<unsigned int>& v1, std::vector<unsigned int>& v2, QuickSandHeader* qhInstance, unsigned int size, unsigned long long seed);
    public:
      QuickSandSolver(unsigned int size, int edgePercentage);
      std::vector<unsigned int> solve(QuickSandHeader* qhInstance);
      void setStopFlag(){stopFlag = 1;};
      int getStopFlag(){return stopFlag;};
      void resetStopFlag(){if (stopFlag) stopFlag = 0;};
  };


};
