extern std::atomic<bool> stop;

void scanningInBackground();

int savePid(int pid);

int loadPid();
