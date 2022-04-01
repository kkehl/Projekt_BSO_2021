using namespace std;


extern atomic<int> totalScannedFolders;
extern atomic<int> totalScannedFiles;
extern atomic<int> totalVirusesFound;

bool fileExists(const string& path);

bool readDatabase();

int ifNormalFile(const string& path);

bool checkDatabase(unsigned long long hash[]);

void scanFile(const string& path);

void scanDirectory(string& folder);

bool addSignature(const string& filePath);
