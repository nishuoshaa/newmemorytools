/*
    毛毛虫制作内存工具v1.0
    修改留版权，谢谢合作
    开源免费，不再更新
*/

#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/syscall.h>

#define ALLOC(num, type)  (type *)alloc(num * sizeof(type))


typedef unsigned long Addr;
typedef int8_t BYTE;
typedef int16_t WORD;
typedef int32_t DWORD;
typedef int64_t QWORD;
typedef float FLOAT;
typedef double DOUBLE;

struct Module
{
	int index;
	Addr start;
	Addr end;
	char type[5];
	struct Module *next;
};

struct Map
{
	Addr start;
	Addr end;
	struct Map *next;
};

struct Result
{
	Addr address;
	struct Result *next;
};

enum Type
{
	All = 0,
	Ch = 1 << 0,
	Jh = 1 << 1,
	Ca = 1 << 2,
	Cd = 1 << 3,
	Cb = 1 << 4,
	A = 1 << 5,
	S = 1 << 6,
	Xa = 1 << 7,
	Xs = 1 << 8,
	As = 1 << 9,
	B = 1 << 10,
	PS = 1 << 11,
	V = 1 << 12,
	O = 1 << 13,
};

//获取进程pid
int get_Pid(char *packageName);
//获取进程pid
int getPid(char *packageName);
void *allocPage(size_t length);
void freePage(void *addr, size_t length);
size_t writeValue(Addr address, void *buffer, size_t size);
size_t readValue(Addr address, void *buffer, size_t size);
Module *getModule(const char *moduleName);
void *alloc(size_t size);
//获取模块基地址
Addr getModuleBase(const char *moduleName);
void writeAddr(Addr address, void *buffer, size_t size);
//设置内存搜索范围(范围类型, 多少位<仅影响A内存>, 模块名称<影响Cd, Xa,Xs>)
//例子: setRange(A|Ca|Cd|Cb, 64, NULL);
void setRange(int type, int bit, char *moduleName);
//释放maps链表
void freeMap(Map * head);
//清除结果链表
void clearResults(Result * head);
//打印结果地址
void printResultsAddress();

//读取数据(地址)
//例子: GetValue<DOUBLE>(0x752560AA10);
//读取地址0x752560AA10的double 类型数据
template < typename T > T GetValue(Addr address);
//修改数据(地址, 数据)
//例子: SetValue<FLOAT>(0x751A08125C, 8888);
//修改地址0x751A08125C的数据为float 8888
template < typename T > void SetValue(Addr address, T value);
//搜索数据,第一次会清理结果(数据, 地址蒙版, 从哪开始搜, 搜到哪)
//例子: Search<FLOAT>(10000, 0x1C, 0x7100000000, 0x7500000000)
//从0x7100000000到0x7500000000之间搜索float 10000, 地址结尾蒙版为0x1C
template < typename T > void Search(T value, int mask, long from, long to);
//再次确认结果(数据, 地址蒙版) 
//例子: Refine<FLOAT>(10000, 0)
//再次确认结果是否为float 10000, 地址蒙版未设置
template < typename T > void Refine(T value, int mask);
//判断偏移条件(数据, 偏移) 
//例子: CheckOffset<DWORD>(1000, -0x10);
//判断结果偏移-0x10的位置是否为int 1000
template < typename T > void CheckOffset(T value, long offset);
//修改全部结果(数据, 偏移) 
//例子: EditAll<DOUBLE>(9999.99, 0x10); 
//修改结果偏移+0x10的位置为double 9999.99
template < typename T > void EditAll(T value, long offset);



// 全局记录进程pid
int pid = 0;
// 全局存放指定内存
Map *maps = NULL;
// 全局存放搜索结果的地址
Result *results = NULL;


int main()
{
	char name[128] = "com.miHoYo.hkrpg";
	pid = get_Pid(name);
	setRange(O, 64, "libil2cpp.so");
	while (maps != NULL)
	{
		printf("内存页起始地址为: %p, 结束地址为 : %p\n", maps->start, maps->end);
		maps = maps->next;
		}
	/*
	Search < DWORD > (10000, 0, 0, -1);
	CheckOffset < DWORD > (10000000, 4);
	CheckOffset < DWORD > (114, -4);
	printResultsAddress();
	EditAll < DWORD > (99999, 0);
	*/
	return 0;
}


int get_Pid(char *packageName)
{
	char buf[256];
	char buffer[50];
	FILE *fp = NULL;
	sprintf(buf, "ps -ef | grep -E %s$ | grep -v grep | awk '{print $2}' ", packageName);
	fp = popen(buf, "r");
	if (fgets(buffer, 50, fp) == NULL)
	{
		printf("获取进程pid失败");
		exit(1);
	}
	pclose(fp);
	return atoi(buffer);
}


int getPid(char *packageName)
{
	DIR *dir = NULL;
	struct dirent *ptr = NULL;
	FILE *fp = NULL;
	char filepath[256];			// 大小随意，能装下cmdline文件的路径即可
	char filetext[128];			// 大小随意，能装下要识别的命令行文本即可
	dir = opendir("/proc");		// 打开路径
	if (NULL != dir)
	{
		while ((ptr = readdir(dir)) != NULL)	// 循环读取路径下的每一个文件/文件夹
		{
			// 如果读取到的是"."或者".."则跳过，读取到的不是文件夹名字也跳过
			if ((strcmp(ptr->d_name, ".") == 0) || (strcmp(ptr->d_name, "..") == 0))
				continue;
			if (ptr->d_type != DT_DIR)
				continue;
			sprintf(filepath, "/proc/%s/cmdline", ptr->d_name);	// 生成要读取的文件的路径
			fp = fopen(filepath, "r");	// 打开文件
			if (NULL != fp)
			{
				fgets(filetext, sizeof(filetext), fp);	// 读取文件
				if (strcmp(filetext, packageName) == 0)
				{
					// puts(filepath);
					// printf(" packagename: %s \ n ",filetext);
					break;
				}
				fclose(fp);
			}
		}
	}
	if (readdir(dir) == NULL)
	{
		// puts(" Get pid fail ");
		return 0;
	}
	closedir(dir);				// 关闭路径
	return atoi(ptr->d_name);
}

void *allocPage(size_t length)
{
	void *ptr =
		mmap(NULL, length, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (ptr == MAP_FAILED)
	{
		perror("分配内存页失败");
		exit(1);
	}
	return ptr;
}

void freePage(void *addr, size_t length)
{
	int flag;
	flag = munmap(addr, length);
	if (flag == -1)
	{
		perror("释放内存页失败");
		exit(1);
	}
}

size_t writeValue(Addr address, void *buffer, size_t size)
{
	struct iovec iov_WriteBuffer, iov_WriteOffset;
	iov_WriteBuffer.iov_base = buffer;
	iov_WriteBuffer.iov_len = size;
	iov_WriteOffset.iov_base = (void *)address;
	iov_WriteOffset.iov_len = size;
	return syscall(SYS_process_vm_writev, pid, &iov_WriteBuffer, 1, &iov_WriteOffset, 1, 0);
}

size_t readValue(Addr address, void *buffer, size_t size)
{
	struct iovec iov_ReadBuffer, iov_ReadOffset;
	iov_ReadBuffer.iov_base = buffer;
	iov_ReadBuffer.iov_len = size;
	iov_ReadOffset.iov_base = (void *)address;
	iov_ReadOffset.iov_len = size;
	return syscall(SYS_process_vm_readv, pid, &iov_ReadBuffer, 1, &iov_ReadOffset, 1, 0);
}


Module *getModule(const char *moduleName)
{
	Module *new_m, *current;
	Module *head = NULL;
	int i = 0;
	char line[1024] = { 0 };
	char fname[128];
	sprintf(fname, "/proc/%d/maps", pid);
	FILE *fp = fopen(fname, "r");
	if (fp)
	{
		while (fgets(line, sizeof(line), fp))
		{
			if (strstr(line, moduleName) != NULL)
			{
				i++;
				new_m = ALLOC(1, Module);
				new_m->index = i;
				sscanf(line, "%lx-%lx %s", &new_m->start, &new_m->end, &new_m->type);
				new_m->next = NULL;
				if (head == NULL)
				{
					head = new_m;
					current = new_m;
				}
				else
				{
					current->next = new_m;
					current = new_m;
				}
			}
		}
		fclose(fp);
	}
	return head;
}

void *alloc(size_t size)
{
	void *new_mem = malloc(size);
	if (new_mem == NULL)
	{
		printf("内存分配失败: out of memory");
		exit(1);
	}
	return new_mem;
}

Addr getModuleBase(const char *moduleName)
{
	Module *target;
	target = getModule(moduleName);
	Addr address;
	int elf_head = 0x464C457F;
	while (target != NULL)
	{
		int tmp = GetValue < DWORD > (target->start);
		if (tmp == elf_head)
		{
			address = target->start;
			target = target->next;
			int ttmp = GetValue < DWORD > (target->start);
			if (ttmp == elf_head)
				address = target->start;
			break;
		}
		else
		{
			if (target->type == "r-xp")
			{
				address = target->start;
				break;
			}
		}
		target = target->next;
	}
	return address;
}

void writeAddr(Addr address, void *buffer, size_t size)
{
	char path[64];
	sprintf(path, "/proc/%d/mem", pid);
	int handle = open(path, O_RDWR);
	if (handle == 0)
	{
		printf("获取mem失败!");
		exit(1);
	}
	lseek(handle, 0, SEEK_SET);
	pwrite64(handle, buffer, 4, address);
}

template < typename T > T GetValue(Addr address)
{
	T value = 0;
	readValue(address, &value, sizeof(T));
	return value;
}

template < typename T > void SetValue(Addr address, T value)
{
	int success = 0;
	success = writeValue(address, &value, sizeof(T));
	if (success == -1)
	{
		writeAddr(address, &value, sizeof(T));
	}
}

void setRange(int type, int bit, char *moduleName)
{
	if (maps != NULL)
	{
		freeMap(maps);
	}
	Map *current, *new_map;
	char path[50];
	char buffer[256];
	snprintf(path, sizeof(path), "/proc/%d/maps", pid);
	FILE *fp = fopen(path, "r");
	if (fp)
	{
		while (fgets(buffer, sizeof(buffer), fp))
		{
			if (type == 0)
			{
				if ((strstr(buffer, "rw") || strstr(buffer, "r--p") || strstr(buffer, "r-xp"))
					&& !feof(fp))
				{
					new_map = ALLOC(1, Map);
					sscanf(buffer, "%p-%p", &new_map->start, &new_map->end);
					new_map->next = NULL;
				}
			}
			else
			{
				if ((type & Ch) == Ch)
				{
					if (strstr(buffer, "rw") && !feof(fp) && strstr(buffer, "[heap]"))
					{
						new_map = ALLOC(1, Map);
						sscanf(buffer, "%p-%p", &new_map->start, &new_map->end);
						new_map->next = NULL;
					}
				}
				if ((type & Jh) == Jh)
				{
					if (strstr(buffer, "rw") && !feof(fp) && strstr(buffer, "anon:darvik"))
					{
						new_map = ALLOC(1, Map);
						sscanf(buffer, "%p-%p", &new_map->start, &new_map->end);
						new_map->next = NULL;
					}
				}
				if ((type & Ca) == Ca)
				{
					if (strstr(buffer, "rw") && !feof(fp)
						&& (strstr(buffer, "[anon:libc_malloc]")
							|| strstr(buffer, "[anon:scudo:primary]")))
					{
						new_map = ALLOC(1, Map);
						sscanf(buffer, "%p-%p", &new_map->start, &new_map->end);
						new_map->next = NULL;
					}
				}
				if ((type & Cd) == Cd)
				{
					if (moduleName == NULL)
					{
						if ((strstr(buffer, "rw-p") || (strstr(buffer, "r--p"))) && !feof(fp)
							&& (strstr(buffer, "/data/app/") || strstr(buffer, "/data/user/")))
						{
							new_map = ALLOC(1, Map);
							sscanf(buffer, "%p-%p", &new_map->start, &new_map->end);
							new_map->next = NULL;
						}
					}
					else
					{
						if ((strstr(buffer, "rw-p") || (strstr(buffer, "r--p"))) && !feof(fp)
							&& (strstr(buffer, "/data/app/") || strstr(buffer, "/data/user/"))
							&& strstr(buffer, moduleName))
						{
							new_map = ALLOC(1, Map);
							sscanf(buffer, "%p-%p", &new_map->start, &new_map->end);
							new_map->next = NULL;
						}
					}
				}
				if ((type & Cb) == Cb)
				{
					if (strstr(buffer, "rw") && !feof(fp) && strstr(buffer, "[anon:.bss]"))
					{
						new_map = ALLOC(1, Map);
						sscanf(buffer, "%p-%p", &new_map->start, &new_map->end);
						new_map->next = NULL;
					}
				}
				if ((type & A) == A)
				{
					if (bit == 32)
					{
						if (strstr(buffer, "rw") && !feof(fp) && (strlen(buffer) < 42))
						{
							new_map = ALLOC(1, Map);
							sscanf(buffer, "%p-%p", &new_map->start, &new_map->end);
							new_map->next = NULL;
						}
					}
					else
					{
						if (strstr(buffer, "rw") && !feof(fp) && (strlen(buffer) < 46))
						{
							new_map = ALLOC(1, Map);
							sscanf(buffer, "%p-%p", &new_map->start, &new_map->end);
							new_map->next = NULL;
						}
					}
				}
				if ((type & S) == S)
				{
					if (strstr(buffer, "rw") && !feof(fp) && strstr(buffer, "[stack]"))
					{
						new_map = ALLOC(1, Map);
						sscanf(buffer, "%p-%p", &new_map->start, &new_map->end);
						new_map->next = NULL;
					}
				}
				if ((type & Xa) == Xa)
				{
					if (moduleName == NULL)
					{
						if (strstr(buffer, "r-x") && !feof(fp)
							&& (strstr(buffer, "/data/app/") || strstr(buffer, "/data/user/")))
						{
							new_map = ALLOC(1, Map);
							sscanf(buffer, "%p-%p", &new_map->start, &new_map->end);
							new_map->next = NULL;
						}
					}
					else
					{
						if (strstr(buffer, "r-x") && !feof(fp)
							&& (strstr(buffer, "/data/app/") || strstr(buffer, "/data/user/"))
							&& strstr(buffer, moduleName))
						{
							new_map = ALLOC(1, Map);
							sscanf(buffer, "%p-%p", &new_map->start, &new_map->end);
							new_map->next = NULL;
						}
					}
				}
				if ((type & Xs) == Xs)
				{
					if (moduleName == NULL)
					{
						if (strstr(buffer, "r-x") && !feof(fp)
							&& (strstr(buffer, "/system/") || strstr(buffer, "/apex/")
								|| strstr(buffer, "/vendor/")))
						{
							new_map = ALLOC(1, Map);
							sscanf(buffer, "%p-%p", &new_map->start, &new_map->end);
							new_map->next = NULL;
						}
					}
					else
					{
						if (strstr(buffer, "r-x") && !feof(fp)
							&& (strstr(buffer, "/system/") || strstr(buffer, "/apex/")
								|| strstr(buffer, "/vendor/")) && strstr(buffer, moduleName))
						{
							new_map = ALLOC(1, Map);
							sscanf(buffer, "%p-%p", &new_map->start, &new_map->end);
							new_map->next = NULL;
						}
					}
				}
				if ((type & As) == As)
				{
					if (strstr(buffer, "rw") && !feof(fp) && strstr(buffer, "/dev/ashmem/"))
					{
						new_map = ALLOC(1, Map);
						sscanf(buffer, "%p-%p", &new_map->start, &new_map->end);
						new_map->next = NULL;
					}
				}
				if ((type & B) == B)
				{
					if (strstr(buffer, "r--s") && !feof(fp) && strstr(buffer, "/system/fonts/"))
					{
						new_map = ALLOC(1, Map);
						sscanf(buffer, "%p-%p", &new_map->start, &new_map->end);
						new_map->next = NULL;
					}
				}
				if ((type & PS) == PS)
				{
					if (strstr(buffer, "rw") && !feof(fp) && strstr(buffer, "PPSSPP"))
					{
						new_map = ALLOC(1, Map);
						sscanf(buffer, "%p-%p", &new_map->start, &new_map->end);
						new_map->next = NULL;
					}
				}
				if ((type & V) == V)
				{
					if (strstr(buffer, "rw") && !feof(fp) && strstr(buffer, "/dev/kgsl-3d0"))
					{
						new_map = ALLOC(1, Map);
						sscanf(buffer, "%p-%p", &new_map->start, &new_map->end);
						new_map->next = NULL;
					}
				}
				if ((type & O) == O)
				{
					if (strstr(buffer, "rw") && !feof(fp) && (!strstr(buffer, "[heap]") && !strstr(buffer, "anon:darvik") && !strstr(buffer, "[anon:scudo:primary]") && !strstr(buffer, "[anon:libc_malloc]") && !strstr(buffer, "[anon:.bss]") && !strstr(buffer, "/data/app/") && !strstr(buffer, "/data/user/") && !strstr(buffer, "[stack]") && !strstr(buffer, "/dev/ashmem/") && !strstr(buffer, "PPSSPP") && !strstr(buffer, "/dev/kgsl-3d0") && strlen(buffer) > 46))
					{
						new_map = ALLOC(1, Map);
						sscanf(buffer, "%p-%p", &new_map->start, &new_map->end);
						new_map->next = NULL;
					}
				}
			}
			if (maps == NULL)
			{
				maps = new_map;
				current = new_map;
			}
			else
			{
				current->next = new_map;
				current = new_map;
			}
		}
		new_map->next = NULL;
		free(new_map);
		fclose(fp);
	}
}



void freeMap(Map * head)
{
	Map *temp;
	while (head != NULL)
	{
		temp = head;
		head = head->next;
		free(temp);
	}
}

void clearResults(Result * head)
{
	Result *temp;
	while (head != NULL)
	{
		temp = head;
		head = head->next;
		free(temp);
	}
}

template < typename T > void Search(T value, int mask, long from, long to)
{
	if (results != NULL)
	{
		clearResults(results);
	}
	Result *current, *new_result;
	int count = 0;
	while (maps != NULL)
	{
		if ((maps->end < from) || (maps->end > (Addr) to))
		{
			continue;
		}
		void *addr = alloc(maps->end - maps->start);
		readValue(maps->start, addr, maps->end - maps->start);
		for (int i = 0; i < (maps->end - maps->start) / sizeof(T); i++)
		{
			if (*(T *) (addr + i * sizeof(T)) == value
				&& ((maps->start + i * sizeof(T)) & mask) == mask)
			{

				count++;
				new_result = ALLOC(1, Result);
				new_result->address = maps->start + i * sizeof(T);
				new_result->next = NULL;
				if (results == NULL)
				{
					results = new_result;
					current = new_result;
				}
				else
				{
					current->next = new_result;
					current = new_result;
				}
			}
		}
		free(addr);
		maps = maps->next;
	}
	printf("总共搜索到: %d个数据\n", count);
}

template < typename T > void Refine(T value, int mask)
{
	int count = 0;
	Result *temp, *prev;
	temp = results;
	while (temp != NULL && (GetValue < T > (temp->address) != value)
		   || ((temp->address & mask) != mask))
	{
		results = temp->next;
		free(temp);
		temp = results;
	}
	while (temp != NULL)
	{
		while (temp != NULL && (GetValue < T > (temp->address) == value)
			   && ((temp->address & mask) == mask))
		{
			count++;
			prev = temp;
			temp = temp->next;
		}
		if (temp == NULL)
		{
			printf("当前还有%d个数据\n", count);
			return;
		}
		prev->next = temp->next;
		free(temp);
		temp = prev->next;
	}
	printf("当前还有%d个数据\n", count);
}

template < typename T > void CheckOffset(T value, long offset)
{
	int count = 0;
	Result *temp, *prev;
	temp = results;
	while (temp != NULL && GetValue < T > (temp->address + offset) != value)
	{
		results = temp->next;
		free(temp);
		temp = results;
	}
	while (temp != NULL)
	{
		while (temp != NULL && GetValue < T > (temp->address + offset) == value)
		{
			count++;
			prev = temp;
			temp = temp->next;
		}
		if (temp == NULL)
		{
			printf("通过当前判断还剩%d个数据\n", count);
			return;
		}
		prev->next = temp->next;
		free(temp);
		temp = prev->next;
	}
	printf("通过当前判断还剩%d个数据\n", count);
}



template < typename T > void EditAll(T value, long offset)
{
	Result *move;
	move = results;
	while (move != NULL)
	{
		SetValue(move->address + offset, value);
		move = move->next;
	}
	printf("全部结果已修改");
}

void printResultsAddress()
{
	int count = 1;
	Result *move;
	move = results;
	while (move != NULL)
	{
		printf("搜索或者判断后的第%d个地址为: %p\n", count++, move->address);
		move = move->next;
	}
}
