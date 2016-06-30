#include "quicksand.h"

using namespace quicksand;

static inline std::string generateHeader(std::vector<unsigned int>& in){
  std::string result;
  for (auto& i: in)
    result+=std::to_string(i)+"=";
  result.pop_back();
  unsigned char hash_buff[32];
  crypto_hash_sha256(hash_buff, (unsigned char*)result.c_str(),result.length());
  std::stringstream ss;
  ss << std::hex << std::setfill('0');
  for (int i = 0; i < 32; ++i)
  {
        ss << std::setw(2) << static_cast<unsigned>(hash_buff[i]);
  }
  return ss.str();
};

std::string quicksand::generateStamp(unsigned int iterations, unsigned int size,
    unsigned int edgePercentage, unsigned int shift, std::string header){
  std::vector<std::vector<unsigned int>> result;
  std::stringstream ss;
  QuickSandSolver qs(size,edgePercentage);
  int curIter = 0;
  while (curIter<iterations) {
    QuickSandHeader qh(header.c_str(),shift);
    std::vector<unsigned int> solved = qs.solve(&qh);
    if (solved.size() == size) {
      header =  generateHeader(solved);
      result.push_back(solved);
    }
    else
      curIter--;
    curIter++;
  }
  for (int i = 0 ; i<result.size();i++){
    for (int j = 0 ; j<result[i].size();j++){
      ss<<result[i][j];
      if (j!=result[i].size()-1)
        ss<<",";
    }
    if (i!=result.size()-1)
      ss<<"|";
  }
  return ss.str();
}
QuickSandHeader::QuickSandHeader(const char* header, unsigned int shift){
  if (!(shift&32))
    size=1<<shift;
  halfSize=size>>1;
  field1=halfSize-2;
  unsigned char hash_buff[32];
  crypto_hash_sha256(hash_buff, (unsigned char*)header,strlen(header));
  unsigned long long res = u8ToU64(hash_buff);
  unsigned long long res2 = u8ToU64(&hash_buff[8]);
  data[0]=res^0x736f6d6670736575ULL;
  data[1]=res2^0x646f72616e646f6dULL;
  data[2]=res^0x6c7967656e657261ULL;
  data[3]=res2^0x7465646279746573ULL;
}
unsigned long long QuickSandHeader::u8ToU64(const unsigned char* data){
  unsigned long long res;
  memcpy(&res,data,8);
  return res;
}
void QuickSandHeader::sipRound(unsigned long long& v0 , unsigned long long& v1, unsigned long long& v2, unsigned long long& v3){
  v0 += v1;
  v1 = rotateLeft(v1, 0xe);
  v1 ^= v0;
  v0 = rotateLeft(v0, 32);
  v2 += v3;
  v3 = rotateLeft(v3, 0xf);
  v3 ^= v2;
  v0 += v3;
  v3 = rotateLeft(v3, 21);
  v2 += v1;
  v1 = rotateLeft(v1, 0x10);
  v3 ^= v0;
  v2 = rotateLeft(v2, 32);
  v1 ^= v2;
}
unsigned long long QuickSandHeader::sipHash24(unsigned long long msg){
  auto v0=data[0];
  auto v1=data[1];
  auto v2=data[2];
  auto v3=data[3];
  v3^=msg;
  sipRound(v0,v1,v2,v3);
  sipRound(v0,v1,v2,v3);
  v2^=0xff;
  v0^=msg;
  sipRound(v0,v1,v2,v3);
  sipRound(v0,v1,v2,v3);
  sipRound(v0,v1,v2,v3);
  sipRound(v0,v1,v2,v3);
  return v0^v1^v2^v3;
}
unsigned long long QuickSandHeader::sipNode(unsigned int seed, unsigned int parity){
  return (unsigned int)(sipHash24(parity+2*seed))&field1;
}
QuickSandHeader::sipNoderes QuickSandHeader::sipEdge(unsigned int msg){
  sipNoderes res{0,0};
  res.node1 = sipNode(msg,0);
  res.node2 = sipNode(msg,1);
  return res;
}
QuickSandSolver::QuickSandSolver(unsigned int size, int edgePercentage){
  stopFlag=0;
  this->size=size;
  this->edgePercentage=edgePercentage;
}
std::vector<unsigned int> QuickSandSolver::solve(QuickSandHeader* qhInstance){
  auto numCycles = qhInstance->getSize()*edgePercentage/100;
  std::vector<unsigned int> v0;
  std::vector<unsigned int> result;
  auto size = qhInstance->getSize()+1;
  if (size!=0) {
    if (size>0x3fffffff)
      throw std::bad_alloc();
    v0.assign(size,0);
  }
  std::vector<unsigned int> v1(8192,0);
  std::vector<unsigned int> v2(8192,0);
  if (numCycles ==0)
    return result;
  for (unsigned int cycle = 0; cycle < numCycles && !stopFlag;cycle++){
    auto edge = qhInstance->sipEdge(cycle);
    auto node1 = edge.node1;
    auto node2 = edge.node2;
    auto node1m = node1+1;
    auto node2m = node2+qhInstance->getHalfSize()+1;
    if (v0[node2m]==node1m || v0[node1m]==node2m)
      continue;
    v1[0]=node1m;
    v2[0]=node2m;
    auto path1 = path(v0[node1m],v1,v0);
    auto path2 = path(v0[node2m],v2,v0);
    if (v1[path1]==v2[path2]){
      if (path2>path1){
        path2-=path1;
        path1=0;
      }
      else {
        path1-=path2;
        path2=0;
      }
      while(v1[path1]!=v2[path2]){
        path1++;
        path2++;
      }
      if (this->size==path1+path2+1){
        recoverSolution(result, path1,path2,v1,v2,qhInstance,this->size,numCycles);
        return result;
      }
    }
    else if (path1<path2) {
      while (path1 != 0) {
        v0[v1[path1]]=v1[path1-1];
        path1--;
      }
      v0[node1m]=node2m;
    }
    else {
      while (path2 != 0) {
        v0[v2[path2]]=v2[path2-1];
        path2--;
      }
      v0[node2m]=node1m;
    }
  }
  return result;
}
unsigned int QuickSandSolver::path(unsigned int value, std::vector<unsigned int>& v1, std::vector<unsigned int>& v2){
  if (!value)
    return 0;
  unsigned int i;
  for (i =1;i<8192;i++){
    v1[i]=value;
    value=v2[value];
    if (!value)
      return i;
  }
  for (i=8191;i>0;i--)
    if (v1[i]==value)
      throw std::runtime_error("Illegal cycle has occured");
  throw std::runtime_error("Maximum path length was exceeded");
}
void QuickSandSolver::recoverSolution(std::vector<unsigned int>& res, unsigned int index1, unsigned int index2, std::vector<unsigned int>& v1, std::vector<unsigned int>& v2, QuickSandHeader* qhInstance, unsigned int size, unsigned long long numCycles){
  auto var1 = numCycles;
  res.resize(size);
  std::set<std::pair<unsigned int, unsigned int>> set;
  set.insert(std::make_pair(v1[0],v2[0]));
  while (index1){
    set.insert(std::make_pair(v1[index1&0xfffffffe],v1[(index1-1)|1]));
    index1--;
  }
  while(index2){
    set.insert(std::make_pair(v2[(index2-1)|1], v2[index2&0xfffffffe]));
    index2--;
  }
  if (!numCycles)
    return;
  unsigned int cycle=0;
  unsigned int i =0;
  do {
    auto hs = qhInstance->getHalfSize();
    auto res1 = qhInstance->sipNode(cycle,1);
    res1+=hs+1;
    auto res2 = qhInstance->sipNode(cycle,0);
    res2++;
      auto node = set.find(std::make_pair(res2,res1));
      if (node == set.end()){
        cycle++;
        continue;
      }
      res[i++] = cycle;
      set.erase(node);
    cycle++;
  } while(cycle<numCycles);
  return;
}



