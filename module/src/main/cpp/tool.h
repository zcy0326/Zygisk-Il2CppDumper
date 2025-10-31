#include <string.h> 
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <memory>
#include <dirent.h>
#include <thread>
#include <sstream>
#include <cinttypes>
#include <fstream>
#include <regex>
#include <iostream>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/socket.h>
#include <malloc.h>
#include <math.h>
#include <iostream>
#include <sys/stat.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <iostream>
#include <locale>
#include <string>
#include <codecvt>

int getProcessID(const char *packageName)
{
    int id = -1;
    DIR *dir;
    FILE *fp;
    char filename[64];
    char cmdline[64];
    struct dirent *entry;
    dir = opendir("/proc");
    while ((entry = readdir(dir)) != NULL)
    {
        id = atoi(entry->d_name);
        if (id != 0)
        {
            sprintf(filename, "/proc/%d/cmdline", id);
            fp = fopen(filename, "r");
            if (fp)
            {
                fgets(cmdline, sizeof(cmdline), fp);
                fclose(fp);
                if (strcmp(packageName, cmdline) == 0)
                {
                    return id;
                }
            }
        }
    }
    closedir(dir);
    return -1;
}

unsigned long 获取地址(int pid, const char *module_name) {
    char path[256];
    char line[1024];
    unsigned long base_addr = 0;
    FILE *fp;
    
    sprintf(path, "/proc/%d/maps", pid);
    
    fp = fopen(path, "r");
    if (!fp) {
        perror("fopen");
        return 0;
    }
    
    // 根据是否有模块名来构建不同的搜索策略
    if (module_name && strlen(module_name) > 0) {
        // 有模块名的情况：构建搜索字符串
        char search_str[256];
        snprintf(search_str, sizeof(search_str), "/%s", module_name);
        
        while (fgets(line, sizeof(line), fp)) {
            // 搜索rwxp权限且包含模块名的行
            if (strstr(line, "r-xp") && strstr(line, search_str)) {
                unsigned long start, end;
                if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
                    base_addr = start;
                    break;
                }
            }
        }
    } else {
        // 无模块名的情况：只搜索rwxp权限的行（通常是匿名内存）
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "rwxp")) {
                unsigned long start, end;
                if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
                    base_addr = start;
                    break; // 找到第一个就返回，或者你可以收集所有
                }
            }
        }
    }
    
    fclose(fp);
    return base_addr;
}

