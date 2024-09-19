#include <iostream>
#include <fstream>
#include <iomanip>
#include <random>
#include <sstream>
#include <cstring>

std::string generateRandomHexKey(size_t length) {
    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<int> dist(0, 255);

    std::ostringstream oss;
    for (size_t i = 0; i < length; ++i) {
        if (i > 0) oss << " ";
        oss << std::hex << std::setw(2) << std::setfill('0') << dist(mt);
    }

    return oss.str();
}

void printHelp() {
    std::cout << "Использование: keygen [имя_файла] [-h]\n";
}

int main(int argc, char* argv[]) {

    if (argc > 1 && std::strcmp(argv[1], "-h") == 0) {
        printHelp();
        return 0;
    }

    if (argc < 2) {
        std::cerr << "Ошибка: имя файла не указано\n";
        printHelp();
        return 1;
    }

    const size_t keyLength = 16;
    std::string key = generateRandomHexKey(keyLength);

    std::ofstream outFile(argv[1]);
    if (outFile.is_open()) {
        outFile << key;
        outFile.close();
    } else {
        std::cerr << "Не удалось открыть файл для записи: " << argv[1] << std::endl;
        return 1;
    }

    return 0;
}
