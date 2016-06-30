#!/usr/bin/python3
import ctypes
import hashlib
import sys
import copy
import datetime

def generateHeader(nums):
    result=""
    for i in nums:
        result+=str(i)+"="
    result=result[:-1]
    return hashlib.sha256(result.encode()).hexdigest()

def generateStamp(iterations, size, edgePercentage, shift, header):
    result=[]
    qs = QuickSandSolver(size,edgePercentage)
    curIter = 0
    iterations = int(iterations)
    shift = int (shift)
    edgePercentage = int(edgePercentage)
    size = int(size)
    while curIter<iterations:
        print(curIter)
        qh = QuickSandHeader(header,shift)
        solved = qs.solve(qh)
        if len(solved) == size:
            header =  generateHeader(solved)
            result.append(solved)
        else:
            curIter-=1
        curIter+=1
    resString=""
    for i in range(len(result)):
        for j in range(len(result[j])):
            resString+=result[i][j]
            if j!=len(result[i])-1:
                resString+=","
        if i!=len(result)-1:
            res+="|"
    return resString


class QuickSandHeader:
    size = 0
    halfSize = 0
    field1 = ctypes.c_uint32(0)
    data=[]
    def __init__(self, header, shift):
        if (shift&32) == 0:
            self.size=1<<shift
        self.halfSize=self.size>>1
        self.field1=ctypes.c_uint32(self.halfSize-2)
        hash_buff = hashlib.sha256(header.encode()).digest()
        res = int.from_bytes(hash_buff[:8:],'little')
        res2 = int.from_bytes(hash_buff[8:16:],'little')
        self.data.clear()
        self.data.append(ctypes.c_uint64(res^0x736f6d6670736575))
        self.data.append(ctypes.c_uint64(res2^0x646f72616e646f6d))
        self.data.append(ctypes.c_uint64(res^0x6c7967656e657261))
        self.data.append(ctypes.c_uint64(res2^0x7465646279746573))

    def rotateLeft(numToRotate, count):
        return (numToRotate.value<<count)|(numToRotate.value>>(64-count));

    def sipRound(v0,v1,v2,v3):
        v0.value += v1.value
        v1.value = QuickSandHeader.rotateLeft(v1, 0xe)
        v1.value ^= v0.value
        v0.value = QuickSandHeader.rotateLeft(v0, 32)
        v2.value += v3.value
        v3.value = QuickSandHeader.rotateLeft(v3, 0xf)
        v3.value ^= v2.value
        v0.value += v3.value
        v3.value = QuickSandHeader.rotateLeft(v3, 21)
        v2.value += v1.value
        v1.value = QuickSandHeader.rotateLeft(v1, 0x10)
        v3.value ^= v0.value
        v2.value = QuickSandHeader.rotateLeft(v2, 32)
        v1.value ^= v2.value

    def sipHash24(self,msg):
        v0=copy.deepcopy(self.data[0])
        v1=copy.deepcopy(self.data[1])
        v2=copy.deepcopy(self.data[2])
        v3=copy.deepcopy(self.data[3])
        v3.value^=msg
        QuickSandHeader.sipRound(v0,v1,v2,v3)
        QuickSandHeader.sipRound(v0,v1,v2,v3)
        v2.value^=0xff
        v0.value^=msg
        QuickSandHeader.sipRound(v0,v1,v2,v3)
        QuickSandHeader.sipRound(v0,v1,v2,v3)
        QuickSandHeader.sipRound(v0,v1,v2,v3)
        QuickSandHeader.sipRound(v0,v1,v2,v3)
        return v0.value^v1.value^v2.value^v3.value
        

    def sipNode(self,seed, parity):
        return ctypes.c_uint32(self.sipHash24(parity+2*seed)&(self.field1.value))

    def sipEdge(self, msg):
        res=[]
        res.append(self.sipNode(msg,0))
        res.append(self.sipNode(msg,1))
        return res;
    def getSize(self):
        return self.size
    def getHalfSize(self):
        return self.halfSize

class QuickSandSolver:
    size = 0
    edgePercentage = 0
    def __init__(self,size,edgePercentage):
        self.size = int(size)
        self.edgePercentage = int(edgePercentage)
    def solve(self,qhInstance):
        numCycles = int(qhInstance.getSize()*self.edgePercentage/100)
        v0=[]
        result=[]
        size = qhInstance.getSize()+1
        if size != 0:
            v0=[0 for i in range(size)]
        v1=[0 for i in range(8192)]
        v2=[0 for i in range(8192)]
        if (numCycles ==0):
            return 0
        for cycle in range(numCycles):
            edge = qhInstance.sipEdge(cycle)
            node1 = edge[0]
            node2 = edge[1]
            node1m = node1.value+1
            node2m = node2.value+qhInstance.getHalfSize()+1
            if v0[node2m]==node1m or v0[node1m]==node2m:
                continue
            v1[0]=node1m
            v2[0]=node2m
            path1 = QuickSandSolver.path(v0[node1m],v1,v0)
            path2 = QuickSandSolver.path(v0[node2m],v2,v0)
            if v1[path1]==v2[path2]:
                if path2>path1:
                    path2-=path1
                    path1=0
                else:
                    path1-=path2
                    path2=0
                while v1[path1]!=v2[path2]:
                    path1+=1
                    path2+=1
                if self.size==path1+path2+1:
                    result = QuickSandSolver.recoverSolution(path1,path2,v1,v2,qhInstance,self.size,numCycles)
                    return result
            elif path1<path2:
                while path1 != 0:
                    v0[v1[path1]]=v1[path1-1]
                    path1-=1
                v0[node1m]=node2m
            else:
                while path2 != 0:
                    v0[v2[path2]]=v2[path2-1]
                    path2-=1
                v0[node2m]=node1m
        return result

    def path(value, v1, v2):
        if value == 0:
            return 0
        for i in range(1,8192):
            v1[i]=value
            value=v2[value]
            if value == 0:
                return i
        for i in range (8191,0,-1):
            if v1[i]==value:
                raise Exception("Illegal cycle has occured");
        raise Exception("Maximum path length was exceeded");

    def recoverSolution(index1, index2, v1, v2, qhInstance, size, numCycles):
        var1 = numCycles
        result = [0 for i in range(size)]
        resSet=set()
        resSet.add((v1[0],v2[0]))
        while index1 != 0:
            resSet.add((v1[index1&0xfffffffe],v1[(index1-1)|1]))
            index1-=1
        while index2 != 0:
            resSet.add((v2[(index2-1)|1], v2[index2&0xfffffffe]))
            index2-=1
        if numCycles == 0:
            return
        cycle = 0
        i = 0
        while cycle < numCycles:
            hs = qhInstance.getHalfSize()
            res1 = qhInstance.sipNode(cycle,1).value
            res1+=hs+1
            res2 = qhInstance.sipNode(cycle,0).value
            res2+=1
            if (res2,res1) not in resSet:
                cycle+=1
                continue
            result[i] = cycle;
            i+=1
            resSet.remove((res2,res1))
            cycle+=1
        return result

if len(sys.argv)==1:
    print("qs_timestamp generator\nUsage: qs iterations size edgePercentage shift header\n")
    exit(1)
if len(sys.argv) != 6:
    print("Wrong number of parameters.\n")
    exit(1)
start = datetime.datetime.now()
print(generateStamp(sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4],sys.argv[5]))
print ("Finished in " + str(datetime.datetime.now()-start))
exit(0)
