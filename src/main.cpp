#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <dirent.h>
#include <fstream>
#include <iostream>
#include <memory>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

#include "../include/antivirus2021/quarantine.h"
#include "../include/antivirus2021/saveStats.h"
#include "../include/antivirus2021/scanning.h"
#include "../include/antivirus2021/scanningInBackground.h"

using std::string;
using std::cin;
using std::cout;
using std::endl;

void menu() {
  bool run = true;
  while (run) {
    int pid = loadPid();

    cout << "1    -    scan a file" << endl;
    cout << "2    -    scan a directory" << endl;
    cout << "3    -    show statistics" << endl;
    cout << "4    -    show files in quarantine" << endl;
    cout << "5    -    move file to quarantine" << endl;
    cout << "6    -    move file from quarantine" << endl;
    cout << "7    -    add virus signature" << endl;
    if (pid == 0) {
      cout << "8    -    turn on passive scan" << endl;
    } else {
      cout << "8    -    turn off passive scan" << endl;
    }
    cout << "0    -    exit" << endl << endl;
    char option;
    int check;
    bool result;
    string sciezka;
    cin >> option;
    switch (option) {
    case '1':
      cout << "Enter path to the file" << endl;
      cin >> sciezka;
      scanFile(sciezka);
      saveStatsParent();
      break;
    case '2':
      cout << "Enter path to the directory" << endl;
      cin >> sciezka;
      scanDirectory(sciezka);
      saveStatsParent();
      break;
    case '3':
      check = saveStatsParent();
      if (check < 0) {
        perror("showing statistics failed");
        break;
      }
      check = printTotalStats();
      if (check < 0) {
        perror("showing statistics failed");
      }
      break;
    case '4':
      showQuarantineFiles();
      break;
    case '5':
      cout << "Enter path to the file" << endl;
      cin >> sciezka;
      check = moveToQuarantine(sciezka);
      if (check == 0) {
        cout << "File moved to quarantine" << endl;
      } else {
        perror("Moving to quarantine failed");
      }
      break;
    case '6':
      cout << "Enter name of file" << endl;
      cin >> sciezka;
      check = moveFromQuarantine(sciezka);
      if (check == 0) {
        cout << "File moved from quarantine" << endl;
      } else {
        perror("Moving from quarantine failed");
      }
      break;
    case '7':
      cout << "Enter path to the file" << endl;
      cin >> sciezka;
      result = addSignature(sciezka);
      if (result) {
        cout << "Signature added" << endl;
      } else {
        perror("Adding signature failed");
      }
      break;
    case '8':
      if (pid == 0) {
        scanningInBackground();
        cout << "Passive scanning started" << endl;
      } else {
        if (pid < 0) {
          perror("Loading pid failed");
        } else if (pid > 0) {
          kill(pid, SIGINT);
          cout << "Passive scanning stopped" << endl;
          savePid(0);
        }
      }
      break;
    case '0':
      run = false;
      break;
    default:
      cout << "Invalid argument. Try again" << endl;
      break;
    }
  }
}

int main() {
  // stworzenie folderu dla plikow na kwarantanne
  makeDirectory();
  bool success = readDatabase();
  if (!success) {
    cout << "Exiting..." << endl;
    return EXIT_FAILURE;
  }
  totalScannedFolders.store(0);
  totalScannedFiles.store(0);
  totalVirusesFound.store(0);

  stop.store(false);

  // glowne menu programu
  menu();

  return 0;
}
