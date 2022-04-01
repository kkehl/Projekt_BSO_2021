#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <iostream>
#include <openssl/aes.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../include/antivirus2021/aes.h"
#include "../include/antivirus2021/quarantine.h"
#include "../include/antivirus2021/scanning.h"

using std::string;
using std::cin;
using std::cout;
using std::endl;

static string qPath = "/usr/local/share/antivirus2021/quarantine/";

// tworzenie katalogu o ograniczonym dostepie
void makeDirectory() {
  int check;
  string dirName = qPath;
  errno = 0;
  check = mkdir(dirName.c_str(), 0000);
  if (check != 0 && errno != EEXIST) {
    perror("directory not created");
  }
}

// wrzucanie pliku do folderu kwarantanny
int moveToQuarantine(const string &filePath) {
  int check;
  int index = filePath.find_last_of("/");
  string fileName = filePath.substr(index);

  bool exist = fileExists(qPath + fileName);
  while (exist) {
    fileName += "(1)";
    exist = fileExists(qPath + fileName);
  }
  // int check = rename(filePath.c_str(), ("quarantine/" + fileName).c_str());

  check = cipher(filePath, qPath + fileName, AES_ENCRYPT);
  if (check != 0) {
    return check;
  }

  check = remove(filePath.c_str());
  return check;
}

// wyjmowanie pliku z kwarantanny
int moveFromQuarantine(const string &fileName) {
  int check;
  bool exist = fileExists(qPath + fileName);
  if (!exist) {
    return -1;
  }

  string filePath = qPath + fileName;
  check = cipher(filePath, "/usr/local/share/antivirus2021/" + fileName,
                 AES_DECRYPT);
  if (check != 0) {
    return check;
  }

  check = remove(filePath.c_str());
  return check;
}

void showQuarantineFiles() {
  struct dirent *entry;
  DIR *directory = opendir(qPath.c_str());

  if (directory == nullptr) {
    perror("Could not open the directory");
  }

  while ((entry = readdir(directory)) != nullptr) {
    string fileName = entry->d_name;
    if (fileName == "." || fileName == "..") {
      continue;
    }
    cout << fileName << endl;
  }
  cout << endl;
  closedir(directory);
}
