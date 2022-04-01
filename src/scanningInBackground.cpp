#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <thread>
#include <unistd.h>

#include "../include/antivirus2021/hashing.h"
#include "../include/antivirus2021/quarantine.h"
#include "../include/antivirus2021/saveStats.h"
#include "../include/antivirus2021/scanning.h"

std::atomic<bool> stop;

void handler(int signum) {
  string sign = std::to_string(signum);
  syslog(LOG_NOTICE, "%s", sign.c_str());
  syslog(LOG_NOTICE, "turning off passive scan...");
  stop.store(true);
}

typedef void (*sighandler_t)(int);

int loadPid() {

  int pid;
  fstream file_in;
  file_in.open("/usr/local/share/antivirus2021/pid.txt");
  if (!file_in.good())
    return -1;

  file_in >> pid;
  file_in.close();
  if (!file_in.good())
    return -1;
  return pid;
}
int savePid(int pid) {

  ofstream file_out;
  file_out.open("/usr/local/share/antivirus2021/pid.txt");
  if (!file_out.good())
    return -1;

  file_out << pid << endl;

  file_out.close();
  if (!file_out.good())
    return -1;
  return 0;
}

void scanningInBackground() {
  sighandler_t ret;
  pid_t pid;
  pid = fork();

  if (pid < 0) {
    perror("child not created");
    return;
  }

  if (pid > 0) {
    savePid((int)pid);
    return;
  }

  if (setsid() < 0)
    exit(EXIT_FAILURE);

  ret = signal(SIGINT, &handler);

  if (ret == SIG_ERR) {
    exit(EXIT_FAILURE);
  }

  umask(0);

  int x;
  for (x = sysconf(_SC_OPEN_MAX); x >= 0; x--) {
    close(x);
  }

  openlog("passiveScan", LOG_PID, LOG_DAEMON);
  syslog(LOG_NOTICE, "Passive scan started.");

  std::string path = "/usr/local/share/antivirus2021/tests";
  while (!stop) {
    scanDirectory(path);
    syslog(LOG_NOTICE, "Scanning...");
    saveStatsChild();
    std::this_thread::sleep_for(std::chrono::milliseconds(10000));
  }

  syslog(LOG_NOTICE, "Passive scan terminated.");
  closelog();

  exit(EXIT_SUCCESS);
}
