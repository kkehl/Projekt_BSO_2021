#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <iostream>
#include <linux/magic.h>
#include <mutex>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <vector>

#include "../include/antivirus2021/hashing.h"
#include "../include/antivirus2021/quarantine.h"
#include "../include/antivirus2021/scanning.h"

using std::string;
using std::cin;
using std::cout;
using std::endl;

// baza hashy
static vector<unsigned long long> database;

// zmienne dla statystyk
static atomic<int> scannedFolders;
static atomic<int> scannedFiles;
static atomic<int> virusesFound;

atomic<int> totalScannedFolders;
atomic<int> totalScannedFiles;
atomic<int> totalVirusesFound;

// funkcja sprawdzająca czy plik istnieje
bool fileExists(const string &path) {
  struct stat s;
  if (stat(path.c_str(), &s) == 0 && (s.st_mode & S_IFREG)) {
    return true;
  } else {
    errno = ENOENT;
    return false;
  }
}

// sprawdzanie czy to normalny plik
// return:
// 1	- normal file
// 0	- not normal file, skip while scanning
//-1	- error
int ifNormalFile(const string &path) {
  struct statfs buf;

  int status = statfs(path.c_str(), &buf);
  if (status != 0) {
    perror("Cannot define type of file");
    return -1;
  }

  else if (buf.f_type == EXT4_SUPER_MAGIC) {
    return 1;
  } else {
    return 0;
  }
}

// wczytanie bazy danych do programu
bool readDatabase() {
  ifstream file;
  file.open("/usr/local/share/antivirus2021/database.txt");

  if (!file.good()) {
    perror("Couldn't find a database file");
    return false;
  }

  unsigned long long data;

  while (file >> data) {
    database.push_back(data);
  }
  file.close();
  return true;
}

// sprawdzenie czy hash znajduje sie w bazie
bool checkDatabase(unsigned long long hash[]) {
  unsigned long long part1;
  unsigned long long part2;
  unsigned long long part3;
  unsigned long long part4;

  for (size_t i = 0; i < database.size(); i += 4) {
    part1 = database.at(i);
    part2 = database.at(i + 1);
    part3 = database.at(i + 2);
    part4 = database.at(i + 3);

    if (hash[0] == part1 && hash[1] == part2 && hash[2] == part3 &&
        hash[3] == part4) {
      return true;
    }
  }
  return false;
}

// porownywanie hashu pliku z sygnaturami z bazy
// return:
// 1 - wirus, przeniesiony do kwarantanny
// 0 - plik bezpieczny
//-1 - wirus, nie udalo sie przeniesc do kwarantanny LUB nie udalo sie
// przeskanowac
static int checkFile(const string &filename) {

  int check = ifNormalFile(filename);
  if (check == -1) {
    return -1;
  } else if (check == 0) {

    cout << endl;
    return 0;
  } else {

    bool exist = fileExists(filename);
    if (!exist) {
      perror("File does not exist");
      return -1;
    }

    unsigned long long *hash = SHA256(filename.c_str());

    if (checkDatabase(hash)) {
      int check = moveToQuarantine(filename);

      cout << "				VIRUS!!!!! " << endl;
      // wirus przeniesiony na kwarantanne
      if (check == 0) {
        cout << "File moved to quarantine" << endl;
        return 1;
      }
      // nie udalo sie przeniesc wirusa na kwarantanne
      else {
        perror("Moving to quarantine failed");
        return -1;
      }
    }
    // plik jest bezpieczny
    else {
      cout << endl;
      return 0;
    }
  }
}

// skanowanie pliku
void scanFile(const string &path) {
  cout << "Scanning..." << endl;
  int status = checkFile(path);
  totalScannedFiles.store(totalScannedFiles.load() + 1);
  if (status == 0) {
    cout << "The file is safe" << endl;
  } else {
    if (status == -1) {
      cout << "Scanning file failed" << endl;
    }
    virusesFound.store(virusesFound.load() + 1);
    totalVirusesFound.store(totalVirusesFound.load() + 1);
  }
}

// skanowanie katalogu
// return:
// 0	- skanowanie sie powiodlo
//-1	- nie mozna otworzyc folderu
static int recursiveDirectoryScan(string &folderPath) {

  struct dirent *entry;
  folderPath += "/";
  DIR *directory = opendir(folderPath.c_str());
  int failure = 0;
  // opendir zwraca NULL gdy nie moze otworzyc folderu
  if (directory == nullptr) {
    perror("Could not open the directory");
    return -1;
  }

  while ((entry = readdir(directory)) != nullptr) {
    string fileName = entry->d_name;
    if (fileName == "." || fileName == "..") {
      continue;
    }

    if (entry->d_type == DT_DIR) {
      totalScannedFolders.store(totalScannedFolders.load() + 1);
      scannedFolders.store(scannedFolders.load() + 1);
      string path = folderPath + fileName;
      failure = recursiveDirectoryScan(path);
    } else {
      totalScannedFiles.store(totalScannedFiles.load() + 1);
      scannedFiles.store(scannedFiles.load() + 1);
      cout << folderPath << fileName;

      int status = checkFile(folderPath + fileName);
      if (status != 0) {
        virusesFound.store(virusesFound.load() + 1);
        totalVirusesFound.store(totalVirusesFound.load() + 1);
      }
    }
  }

  closedir(directory);
  return failure;
}

static void printStats() {
  cout << endl << "SCAN COMPLETED" << endl << "STATISTICS:" << endl;
  cout << "Scanned folders: " << scannedFolders.load() << endl;
  cout << "Scanned files: " << scannedFiles.load() << endl;
  cout << "Viruses found: " << virusesFound.load() << endl << endl;
}

void scanDirectory(string &folder) {
  scannedFolders.store(0);
  scannedFiles.store(0);
  virusesFound.store(0);

  cout << "Files scanned:" << endl;

  int check = recursiveDirectoryScan(folder);
  if (check == -1) {
    cout << "Scanning completed, but not all directories were scanned." << endl;
  }
  printStats();
}

bool addSignature(const string &filePath) {
  unsigned long long *hash;
  hash = SHA256(filePath.c_str());

  ofstream file_out;
  file_out.open("/usr/local/share/antivirus2021/database.txt",
                std::ios_base::app);
  if (!file_out.good())
    return false;

  file_out << hash[0] << endl;
  file_out << hash[1] << endl;
  file_out << hash[2] << endl;
  file_out << hash[3] << endl;
  file_out.close();
  if (!file_out.good())
    return false;

  database.clear();
  readDatabase();
  return true;
}
