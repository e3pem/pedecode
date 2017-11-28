#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winnt.h>

/** This program is used to analyze pe files
 *
 */

IMAGE_DOS_HEADER image_dos_header;
IMAGE_NT_HEADERS32 image_nt_headers32;

int main()
{
    printf("Please input the file to analyze:\n>>");
//    char filename[128]={0};
    char filename[128]="E:\\Myproject\\pedecode\\peanalyze\\ReverseMe.exe";
//    scanf("%s",filename);
    FILE * fp = NULL;
    fp = fopen(filename,"rb");
    if(fp==NULL){
        puts("read file error!\n");
        return -1;
        }
    puts("read file sucess!\n");
    decodeDosHeader(fp);
    decodeNTHeader(fp);


    fclose(fp);
//    system("pause");
    return 0;
}
/** This function to decode pe's DOS header
 *
 * \param fp --> a pointer to pe file
 *
 * \return void
 *
 */

void decodeDosHeader(FILE * fp){
    fread(&image_dos_header,sizeof(IMAGE_DOS_HEADER),1,fp);
    printf("%x\n",image_dos_header.e_magic);
    printf("%x\n",image_dos_header.e_lfanew);
}

void decodeNTHeader(FILE *fp){
    fseek(fp,image_dos_header.e_lfanew,SEEK_SET);
    fread(&image_nt_headers32,sizeof(IMAGE_NT_HEADERS32),1,fp);
    printf("signature:0x%x\n",image_nt_headers32.Signature);
    printf("machine:0x%x\n",image_nt_headers32.FileHeader.Machine);
    printf("number of sections:%d\n",image_nt_headers32.FileHeader.NumberOfSections);
    printf("size of optional header:0x%x\n",image_nt_headers32.FileHeader.SizeOfOptionalHeader);

    printf("image base:0x%x\n",image_nt_headers32.OptionalHeader.ImageBase);
    printf("address of entry point:0x%x\n",image_nt_headers32.OptionalHeader.AddressOfEntryPoint+image_nt_headers32.OptionalHeader.ImageBase);
}

