using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using Microsoft.Samples.Debugging.CorDebug;

namespace Microsoft.Samples.Tools.Mdbg
{
    public class PEReader
    {

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DOS_HEADER
        {
            public UInt16 e_magic;
            public UInt16 e_cblp;
            public UInt16 e_cp;
            public UInt16 e_crlc;
            public UInt16 e_cparhdr;
            public UInt16 e_minalloc;
            public UInt16 e_maxalloc;
            public UInt16 e_ss;
            public UInt16 e_sp;
            public UInt16 e_csum;
            public UInt16 e_ip;
            public UInt16 e_cs;
            public UInt16 e_lfarlc;
            public UInt16 e_ovno;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public UInt16[] e_res1;
            public UInt16 e_oemid;
            public UInt16 e_oeminfo;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public UInt16[] e_res2;
            public UInt32 e_lfanew;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_NT_HEADERS32
        {
            public UInt32 Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER32 OptionalHeader32;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_NT_HEADERS64
        {
            public UInt32 Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER64 OptionalHeader64;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_FILE_HEADER
        {
            public UInt16 Machine;
            public UInt16 NumberOfSections;
            public UInt32 TimeDateStamp;
            public UInt32 PointerToSymbolTable;
            public UInt32 NumberOfSymbols;
            public UInt16 SizeOfOptionalHeader;
            public UInt16 Characteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_OPTIONAL_HEADER32
        {
            public UInt16 Magic;
            public Byte MajorLinkerVersion;
            public Byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;
            public UInt32 BaseOfData;
            public UInt32 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public UInt16 MajorOperatingSystemVersion;
            public UInt16 MinorOperatingSystemVersion;
            public UInt16 MajorImageVersion;
            public UInt16 MinorImageVersion;
            public UInt16 MajorSubsystemVersion;
            public UInt16 MinorSubsystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public UInt16 Subsystem;
            public UInt16 DllCharacteristics;
            public UInt32 SizeOfStackReserve;
            public UInt32 SizeOfStackCommit;
            public UInt32 SizeOfHeapReserve;
            public UInt32 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public IMAGE_DATA_DIRECTORY[] DataDirectory;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            public UInt16 Magic;
            public Byte MajorLinkerVersion;
            public Byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;
            public UInt64 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public UInt16 MajorOperatingSystemVersion;
            public UInt16 MinorOperatingSystemVersion;
            public UInt16 MajorImageVersion;
            public UInt16 MinorImageVersion;
            public UInt16 MajorSubsystemVersion;
            public UInt16 MinorSubsystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public UInt16 Subsystem;
            public UInt16 DllCharacteristics;
            public UInt64 SizeOfStackReserve;
            public UInt64 SizeOfStackCommit;
            public UInt64 SizeOfHeapReserve;
            public UInt64 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public IMAGE_DATA_DIRECTORY[] DataDirectory;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public UInt32 VirtualAddress;
            public UInt32 Size;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_SECTION_HEADER
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 8)]
            public string Name;
            public Misc Misc;
            public UInt32 VirtualAddress;
            public UInt32 SizeOfRawData;
            public UInt32 PointerToRawData;
            public UInt32 PointerToRelocations;
            public UInt32 PointerToLinenumbers;
            public UInt16 NumberOfRelocations;
            public UInt16 NumberOfLinenumbers;
            public UInt32 Characteristics;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct Misc
        {
            [FieldOffset(0)]
            public UInt32 PhysicalAddress;
            [FieldOffset(0)]
            public UInt32 VirtualSize;
        }
        public static byte[] ReadFullPeFromProcess(long addr, CorProcess proc)
        {
            byte[] dos_header_data = new byte[Marshal.SizeOf(typeof(IMAGE_DOS_HEADER))];
            proc.ReadMemory(addr, dos_header_data);
            IMAGE_DOS_HEADER dos_header = StructFromBytes<IMAGE_DOS_HEADER>(dos_header_data);
            long ntHeadersAddr = addr + dos_header.e_lfanew;
            byte[] nt_headers_data = new byte[Marshal.SizeOf(typeof(IMAGE_NT_HEADERS32))];
            proc.ReadMemory(ntHeadersAddr, nt_headers_data);
            IMAGE_NT_HEADERS32 nt_headers32 = StructFromBytes<IMAGE_NT_HEADERS32>(nt_headers_data);
            ushort opt_magic = nt_headers32.OptionalHeader32.Magic;
            long optionalHeaderAddr = ntHeadersAddr + 4 + Marshal.SizeOf(typeof(IMAGE_FILE_HEADER));
            if(opt_magic == 0x10b)
            {
                //32-bit
                long sectionHeadersAddr = optionalHeaderAddr + nt_headers32.FileHeader.SizeOfOptionalHeader;
                long sections_current = sectionHeadersAddr;
                long pe_size = 0; //first calculate the PE size.
                long max_section_offset = 0;
                long max_section_size = 0;
                for(int i = 0; i < nt_headers32.FileHeader.NumberOfSections; i++)
                {
                    byte[] section_header_data = new byte[Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER))];
                    proc.ReadMemory(sections_current, section_header_data);
                    IMAGE_SECTION_HEADER section_header = StructFromBytes<IMAGE_SECTION_HEADER>(section_header_data);
                    if(max_section_offset <= section_header.PointerToRawData)
                    {
                        max_section_offset = section_header.PointerToRawData;
                        max_section_size = section_header.SizeOfRawData;
                    }
                    sections_current += section_header_data.Length;
                }

                pe_size = max_section_offset + max_section_size;
                //first copy the headers
                byte[] full_pe = new byte[pe_size];
                long size_of_headers = nt_headers32.OptionalHeader32.SizeOfHeaders;
                byte[] headers_data = new byte[size_of_headers];
                proc.ReadMemory(addr, headers_data);
                Array.Copy(headers_data, full_pe, headers_data.Length);

                //now for the sections.
                sections_current = sectionHeadersAddr;
                for (int i = 0; i < nt_headers32.FileHeader.NumberOfSections; i++)
                {
                    byte[] section_header_data = new byte[Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER))];
                    proc.ReadMemory(sections_current, section_header_data);
                    IMAGE_SECTION_HEADER section_header = StructFromBytes<IMAGE_SECTION_HEADER>(section_header_data);
                    byte[] section_data = new byte[section_header.SizeOfRawData];
                    proc.ReadMemory(addr + section_header.VirtualAddress, section_data);
                    Array.Copy(section_data, 0, full_pe, section_header.PointerToRawData, section_data.Length);
                    sections_current += section_header_data.Length;
                }

                return full_pe;

            }
            else if(opt_magic == 0x20b)
            {
                //64 bit
                nt_headers_data = new byte[Marshal.SizeOf(typeof(IMAGE_NT_HEADERS64))];
                proc.ReadMemory(ntHeadersAddr, nt_headers_data);
                IMAGE_NT_HEADERS64 nt_headers64 = StructFromBytes<IMAGE_NT_HEADERS64>(nt_headers_data);
                long sectionHeadersAddr = optionalHeaderAddr + nt_headers64.FileHeader.SizeOfOptionalHeader;
                long sections_current = sectionHeadersAddr;
                long pe_size = 0; //first calculate the PE size.
                long max_section_offset = 0;
                long max_section_size = 0;
                for (int i = 0; i < nt_headers64.FileHeader.NumberOfSections; i++)
                {
                    byte[] section_header_data = new byte[Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER))];
                    proc.ReadMemory(sections_current, section_header_data);
                    IMAGE_SECTION_HEADER section_header = StructFromBytes<IMAGE_SECTION_HEADER>(section_header_data);
                    if (max_section_offset <= section_header.PointerToRawData)
                    {
                        max_section_offset = section_header.PointerToRawData;
                        max_section_size = section_header.SizeOfRawData;
                    }
                    sections_current += section_header_data.Length;
                }

                pe_size = max_section_offset + max_section_size;
                //first copy the headers
                byte[] full_pe = new byte[pe_size];
                long size_of_headers = nt_headers64.OptionalHeader64.SizeOfHeaders;
                byte[] headers_data = new byte[size_of_headers];
                proc.ReadMemory(addr, headers_data);
                Array.Copy(headers_data, full_pe, headers_data.Length);

                //now for the sections.
                sections_current = sectionHeadersAddr;
                for (int i = 0; i < nt_headers64.FileHeader.NumberOfSections; i++)
                {
                    byte[] section_header_data = new byte[Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER))];
                    proc.ReadMemory(sections_current, section_header_data);
                    IMAGE_SECTION_HEADER section_header = StructFromBytes<IMAGE_SECTION_HEADER>(section_header_data);
                    byte[] section_data = new byte[section_header.SizeOfRawData];
                    proc.ReadMemory(addr + section_header.VirtualAddress, section_data);
                    Array.Copy(section_data, 0, full_pe, section_header.PointerToRawData, section_data.Length);
                    sections_current += section_header_data.Length;
                }

                return full_pe;
            }
            return null;
        }

        public static T StructFromBytes<T>(byte[] data)
            where T : struct
        {
            int size = Marshal.SizeOf(typeof(T));
            IntPtr ptr = Marshal.AllocHGlobal(size);
            Marshal.Copy(data, 0, ptr, size);
            T result = (T)Marshal.PtrToStructure(ptr, typeof(T));
            Marshal.FreeHGlobal(ptr);
            return result;
        }
    }
}
