import sys
import os
from binascii import hexlify

def help():
    print('Usage:   python3 dexor_QB.py <folder_with_kasper_files> <folder_to_save_output>')
    print('Usage:   python3 dexor_QB.py "C:\\ProgramData\\Kaspersky Lab\\KES\\QB\\" "C:\\folder\\"')
    exit(0)

def parseFiles(directory, directoryOut):
    # There should not be spaces in directories names
    if os.path.exists(directory) and os.path.exists(directoryOut):
        for filename in os.listdir(directory):
            outFile = open(directoryOut + filename + "Out", "wb")
            inFile = open(directory + filename, "rb")
            inFileSize = (os.path.getsize(directory + filename) - 64) // 8 + 1
            key = [0xe2, 0x45, 0x48, 0xec, 0x69, 0x0e, 0x5c, 0xac]
            key = key + key * inFileSize

            # if not os.path.isdir(filename)
            print("\n" + "Filename: " + filename)

            inFile.seek(63)
            byte = inFile.read(1)
            #for i in range(40):

            i = 0
            while byte:
                byte = inFile.read(1)
                #sys.stdout.buffer.write(byte)
                outFile.write((int.from_bytes(byte, "big")  ^ key[i]).to_bytes(1, byteorder='big'))
                #print("0x" + str(hexlify(byte), "utf-8"), end=" ")
                i += 1
            
            outFile.close()
            inFile.close()
    else:
        print("No such directory!")
        exit(0)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        help()

    localDirectory = sys.argv[1]
    localDirectoryOut = sys.argv[2]

    if localDirectory != "\\":
        localDirectory = localDirectory + "\\"

    if localDirectoryOut != "\\":
        localDirectoryOut = localDirectoryOut + "\\"
    
    parseFiles(localDirectory, localDirectoryOut)