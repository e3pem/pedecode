
#include "stdafx.h"
#define MAX_HEADER 20
#define MAX_IID 30

IMAGE_DOS_HEADER image_dos_header;
IMAGE_NT_HEADERS32 image_nt_headers32;
IMAGE_SECTION_HEADER image_section_headers[MAX_HEADER];
IMAGE_IMPORT_DESCRIPTOR image_import_descriptors[MAX_IID];

void decodeDosHeader(FILE * fp);
void decodeNTHeader(FILE * fp);
void decodeSectionHeader(FILE * fp);
void showHeaderInfo();
void showSectionInfo();
void showIAT(FILE * fp);


int main()
{
	printf("Please input the file to analyze:\n>>");
	//    char filename[128]={0};
	//char filename[128] = "E:\\Myproject\\pedecode\\peanalyze\\ReverseMe.exe";
	char filename[128] = "E:\\workspace\\rev\\practice\\upackAnalyze\\ReverseMe.exe";
	//    scanf("%s",filename);+++
	FILE * fp = NULL;
	fp = fopen(filename, "rb");
	int flag;
	if (fp == NULL) {
		puts("read file error!\n");
		return -1;
	}
	puts("read file sucess!\n");
	decodeDosHeader(fp);
	decodeNTHeader(fp);
	decodeSectionHeader(fp);
	flag = 1;
	while (flag) {
		printf("\npress 0 to quit.\npress 1 to show HeaderInfo.\npress 2 to show Section info.\npress 3 to show IAT info.\n>>");
		scanf("%d", &flag);
		switch (flag){
		case 0:
			break;
		case 1:
			showHeaderInfo();
			break;
		case 2:
			showSectionInfo();
			break;
		case 3:
			showIAT(fp);
			break;
		default:
			break;
		}

	}
	fclose(fp);
	return 0;
}


void decodeDosHeader(FILE * fp) {
	fread(&image_dos_header, sizeof(IMAGE_DOS_HEADER), 1, fp);
}

void decodeNTHeader(FILE *fp) {
	puts("Analyze NT Header......\n");
	fseek(fp, image_dos_header.e_lfanew, SEEK_SET);
	fread(&image_nt_headers32, sizeof(IMAGE_NT_HEADERS32), 1, fp);
}

void decodeSectionHeader(FILE * fp) {
	puts("Analyze Section Header......\n");
	int section_num = image_nt_headers32.FileHeader.NumberOfSections;
	int i = 0;
	fseek(fp, image_nt_headers32.FileHeader.SizeOfOptionalHeader + image_dos_header.e_lfanew + sizeof(IMAGE_FILE_HEADER)+sizeof(DWORD),SEEK_SET);
	for (i = 0; i < section_num; ++i)
	{
		fread(&image_section_headers[i], sizeof(IMAGE_SECTION_HEADER), 1, fp);
		//printf("name address: %s\n", image_section_headers[i].Name);
	}
}

void showHeaderInfo() {
	printf("Machine:\t0x%x\n", image_nt_headers32.FileHeader.Machine);
	printf("Number of Sections:\t%d\n", image_nt_headers32.FileHeader.NumberOfSections);
	printf("Size of Optional Header:\t0x%x\n", image_nt_headers32.FileHeader.SizeOfOptionalHeader);
	printf("Size of Code:\t0x%x\n", image_nt_headers32.OptionalHeader.SizeOfCode);
	printf("Size of Initiallized Data:\t0x%x\n", image_nt_headers32.OptionalHeader.SizeOfInitializedData);
	printf("Size of Uninitiallized Data:\t0x%x\n", image_nt_headers32.OptionalHeader.SizeOfUninitializedData);
	printf("Size of Image:\t0x%x\n", image_nt_headers32.OptionalHeader.SizeOfImage);
	printf("Size of Header:\t0x%x\n", image_nt_headers32.OptionalHeader.SizeOfHeaders);
	printf("FileAlignment:\t0x%x\n", image_nt_headers32.OptionalHeader.FileAlignment);
	printf("SectionAlignment:\t0x%x\n", image_nt_headers32.OptionalHeader.SectionAlignment);
	printf("Base of Code:\t0x%x\n", image_nt_headers32.OptionalHeader.BaseOfCode);
	printf("Base of Data:\t0x%x\n", image_nt_headers32.OptionalHeader.BaseOfData);
	printf("Image Base:\t0x%x\n", image_nt_headers32.OptionalHeader.ImageBase);
	printf("Address of EntryPoint:\t0x%x\n", image_nt_headers32.OptionalHeader.ImageBase + image_nt_headers32.OptionalHeader.AddressOfEntryPoint);

}

void showSectionInfo() {
	printf("Section Info:\n");
	int section_num = image_nt_headers32.FileHeader.NumberOfSections;
	int i;
	for (i = 0; i < section_num; ++i) {
		//putchar('\n');
		printf("%s\n", (image_section_headers[i].Name));
		printf("Virtual Size:0x%x\n", image_section_headers[i].Misc.VirtualSize);
		printf("Virtual Address:0x%x\n", image_section_headers[i].VirtualAddress + image_nt_headers32.OptionalHeader.ImageBase);
		printf("Size of RawData:0x%x\n", image_section_headers[i].SizeOfRawData);
		printf("Pointer to RawData:0x%x\n", image_section_headers[i].PointerToRawData);
		printf("Pointer to Relocatioons:0x%x\n", image_section_headers[i].PointerToRelocations);
		putchar('\n');
	}

}

int Rva2Raw(int IATRAddress) {
	int i;
	int section_num = image_nt_headers32.FileHeader.NumberOfSections;
	for (i = 0; i < section_num; ++i) {
		if (IATRAddress >= image_section_headers[i].VirtualAddress&&IATRAddress <= (image_section_headers[i].VirtualAddress + image_section_headers[i].Misc.VirtualSize))
			return IATRAddress - image_section_headers[i].VirtualAddress + image_section_headers[i].PointerToRawData;
	}
	return 0;

}

void showIAT(FILE *fp) {
	printf("IAT info:\n");
	//IAT relative address
	int IATRAddress = image_nt_headers32.OptionalHeader.DataDirectory[1].VirtualAddress;
	int IATSize = image_nt_headers32.OptionalHeader.DataDirectory[1].Size;
	//printf("raddress:%x\n", IATRAddress);
	int IATAddress = Rva2Raw(IATRAddress);
	//printf("address:%x\n", IATAddress);
	//printf("size:%x", IATSize);
	int IAT_num = IATSize / 20;
	int i,j,k;
	char dllname[50];
	char funcname[50];
	int INT_address;
	int IAT_address;
	IMAGE_IMPORT_BY_NAME image_import_by_name;

	
	//printf("%x",ftell(fp));
	for (i = 0; i < IAT_num-1; ++i) {
		fseek(fp, IATAddress+20*i, SEEK_SET);
		fread(&image_import_descriptors[i], sizeof(IMAGE_IMPORT_DESCRIPTOR),1 , fp);
		putchar('\n');
		j = 0;
		//to get dll name
		fseek(fp, Rva2Raw(image_import_descriptors[i].Name),SEEK_SET);
		do {
			fread(&dllname[j], 1, 1, fp);
			if (dllname[j] == '\0')
				break;
			++j;
		} while (1);
		printf("dll name:%s\n", dllname);
		//to get INT
		j = 0;
		do {
			k = 0;
			fseek(fp, Rva2Raw(image_import_descriptors[i].OriginalFirstThunk+j*sizeof(DWORD)), SEEK_SET);
			fread(&INT_address, sizeof(DWORD), 1, fp);
			if (INT_address == NULL)
				break;
			fseek(fp, Rva2Raw(INT_address), SEEK_SET);
			fread(&image_import_by_name.Hint, sizeof(WORD), 1, fp);
			while (1) {
				fread(&funcname[k], 1, 1, fp);
				if (funcname[k] == '\0')
					break;
				++k;
			}
			printf("hint:0x%x\n", image_import_by_name.Hint);
			printf("function name:%s\n", funcname);
			fseek(fp, Rva2Raw(image_import_descriptors[i].FirstThunk + j * sizeof(int)), SEEK_SET);
			fread(&IAT_address, sizeof(int), 1, fp);
			printf("function IAT address:(virtual addr)0x%x\t(raw addr)0x%x\n", IAT_address, Rva2Raw(IAT_address));
			++j;
		} while (1);
	}


}
