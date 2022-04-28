# CiscoPacketTracerCrack
思科模拟器免登录破解

**MFC项目，仅x86编译**  
Visual Studio 2017开发

**破解思路：**  
x64dbg 附加进程，搜索登录窗口标题，定位到调用地址，jne改jmp爆破

**主要技术：**  
Wow64进程 32位进程切换至64位模式执行64位 ShellCode

**当前破解支持版本**     
7.3（x86）  
7.3（x64）  
8.0（x64）
