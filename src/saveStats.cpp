#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <thread>

#include "../include/antivirus2021/scanning.h"

int saveStatsChild() {
  int tsfo, tsfi, tvf;

  fstream file_in;
  file_in.open("/usr/local/share/antivirus2021/statsChild.txt");
  if (!file_in.good())
    return -1;

  file_in >> tsfo;
  file_in >> tsfi;
  file_in >> tvf;

  file_in.close();
  if (!file_in.good())
    return -1;

  ofstream file_out;
  file_out.open("/usr/local/share/antivirus2021/statsChild.txt");
  if (!file_out.good())
    return -1;

  file_out << totalScannedFolders.load() + tsfo << endl;
  file_out << totalScannedFiles.load() + tsfi << endl;
  file_out << totalVirusesFound.load() + tvf << endl;

  totalScannedFolders.store(0);
  totalScannedFiles.store(0);
  totalVirusesFound.store(0);

  file_out.close();
  if (!file_out.good())
    return -1;
  return 0;
}

int saveStatsParent() {
  int tsfo, tsfi, tvf;

  fstream file_in;
  file_in.open("/usr/local/share/antivirus2021/statsParent.txt");
  if (!file_in.good())
    return -1;

  file_in >> tsfo;
  file_in >> tsfi;
  file_in >> tvf;

  file_in.close();
  if (!file_in.good())
    return -1;

  ofstream file_out;
  file_out.open("/usr/local/share/antivirus2021/statsParent.txt");
  if (!file_out.good())
    return -1;

  file_out << totalScannedFolders.load() + tsfo << endl;
  file_out << totalScannedFiles.load() + tsfi << endl;
  file_out << totalVirusesFound.load() + tvf << endl;

  totalScannedFolders.store(0);
  totalScannedFiles.store(0);
  totalVirusesFound.store(0);

  file_out.close();
  if (!file_out.good())
    return -1;
  return 0;
}

int printTotalStats() {

  int check = saveStatsParent();
  if (check < 0){
    return -1;
  }

  int tsfo, tsfi, tvf, tsfo2, tsfi2, tvf2;

  fstream file_in_child;
  file_in_child.open("/usr/local/share/antivirus2021/statsChild.txt");
  if (!file_in_child.good())
    return -1;

  file_in_child >> tsfo;
  file_in_child >> tsfi;
  file_in_child >> tvf;

  file_in_child.close();
  if (!file_in_child.good())
    return -1;

  fstream file_in_parent;
  file_in_parent.open("/usr/local/share/antivirus2021/statsParent.txt");
  if (!file_in_parent.good())
    return -1;

  file_in_parent >> tsfo2;
  file_in_parent >> tsfi2;
  file_in_parent >> tvf2;

  file_in_parent.close();
  if (!file_in_parent.good())
    return -1;

  cout << endl << "TOTAL STATISTICS:" << endl;
  cout << "Scanned folders: " << tsfo + tsfo2 << endl;
  cout << "Scanned files: " << tsfi + tsfi2 << endl;
  cout << "Viruses found: " << tvf + tvf2 << endl << endl;
  return 0;
}
